from __future__ import annotations
from pathlib import Path
import asyncio,uuid,json
from fastapi import FastAPI,HTTPException,WebSocket
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .models import Incident
from .storage import db,save_incident,get_incident,list_incidents,list_audit,upsert_host_status,decode_payload
from .scenarios import make,SCENARIOS
from .agents import investigate,approve,reject
from .events import bus
from .tools import registry
from .ares import run_ares

app=FastAPI(title="AEGIS",version="0.6.0")
FRONT=Path("/app/frontend")
if not FRONT.exists(): FRONT=Path(__file__).resolve().parents[2]/"frontend"
app.mount("/static",StaticFiles(directory=str(FRONT)),name="static")

@app.get("/")
async def index(): return FileResponse(FRONT/"index.html")
@app.get("/api/health")
async def health(): return {"status":"ok","version":"0.6.0","database":"postgres" if db.pg else "sqlite-fallback","redis":bool(bus.redis),"llm":__import__("app.llm",fromlist=["llm"]).llm.enabled()}
@app.get("/api/summary")
async def summary():
    inc=list_incidents(); audits=list_audit(); hosts=db.all("SELECT * FROM hosts")
    return {"incidents":len(inc),"hosts":len(hosts),"agents":7,"actions":len(audits),
            "critical":sum(x["severity"]=="CRITICAL" for x in inc),"contained":sum(x["status"]=="CLOSED" for x in inc),
            "escalated":sum(x["status"]=="ESCALATED" for x in inc),"events":sum(len(x.get("events",[])) for x in inc),
            "events_per_sec":24,"uptime":"2h 34m"}
@app.get("/api/incidents")
async def incidents(): return list_incidents()
@app.get("/api/incidents/{iid}")
async def incident(iid):
    x=get_incident(iid)
    if not x: raise HTTPException(404,"Incident not found")
    return x
@app.get("/api/audit")
async def audit(): return list_audit()
@app.get("/api/hosts")
async def hosts(): return db.all("SELECT * FROM hosts ORDER BY risk DESC")
@app.post("/api/hosts/{hid}/isolate")
async def isolate(hid):
    if not db.one("SELECT * FROM hosts WHERE id=?",(hid,)): raise HTTPException(404,"Host not found")
    upsert_host_status(hid,"ISOLATED",.99); await bus.emit({"type":"host","host_id":hid,"status":"ISOLATED","simulated":True})
    return {"ok":True,"status":"ISOLATED","simulated":True}
@app.post("/api/hosts/{hid}/restore")
async def restore(hid):
    if not db.one("SELECT * FROM hosts WHERE id=?",(hid,)): raise HTTPException(404,"Host not found")
    upsert_host_status(hid,"ONLINE",.10); await bus.emit({"type":"host","host_id":hid,"status":"ONLINE","simulated":True})
    return {"ok":True,"status":"ONLINE","simulated":True}
@app.get("/api/iocs")
async def iocs(): return db.all("SELECT * FROM iocs ORDER BY confidence DESC")
@app.get("/api/agents")
async def agents():
    return [
    {"id":"sentinel","name":"Sentinel","role":"Detection","status":"ONLINE","accuracy":98,"latency":"12ms"},
    {"id":"planner","name":"Mission Planner","role":"Tool Planning","status":"ONLINE","accuracy":95,"latency":"31ms"},
    {"id":"investigator","name":"Investigator","role":"Evidence Collection","status":"ONLINE","accuracy":94,"latency":"18ms"},
    {"id":"analyst","name":"Threat Analyst","role":"Correlation","status":"ONLINE","accuracy":96,"latency":"24ms"},
    {"id":"decision","name":"Decision Agent","role":"Response Planning","status":"ONLINE","accuracy":92,"latency":"15ms"},
    {"id":"guardian","name":"Policy Guardian","role":"Safety Gate","status":"ONLINE","accuracy":100,"latency":"4ms"},
    {"id":"verification","name":"Verification Agent","role":"Post-action Validation","status":"ONLINE","accuracy":97,"latency":"11ms"}]
@app.get("/api/tools")
async def tools(): return registry.catalog()
@app.get("/api/policies")
async def policies(): return db.all("SELECT * FROM policies ORDER BY id")
@app.post("/api/policies/{pid}/toggle")
async def toggle(pid):
    p=db.one("SELECT * FROM policies WHERE id=?",(pid,))
    if not p: raise HTTPException(404,"Policy not found")
    n=0 if p["enabled"] else 1; db.execute("UPDATE policies SET enabled=? WHERE id=?",(n,pid))
    return {"ok":True,"enabled":bool(n)}
@app.get("/api/approvals")
async def approvals(): return db.all("SELECT * FROM approvals ORDER BY created_at DESC")
@app.post("/api/approvals/{aid}/approve")
async def approve_api(aid):
    row=db.one("SELECT * FROM approvals WHERE approval_id=?",(aid,))
    if not row: raise HTTPException(404,"Approval not found")
    result=await approve(row["incident_id"],aid)
    db.execute("UPDATE approvals SET status='APPROVED',payload=? WHERE approval_id=?" if not db.pg else "UPDATE approvals SET status='APPROVED',payload=%s::jsonb WHERE approval_id=%s",(json.dumps(result),aid))
    return result
@app.post("/api/approvals/{aid}/reject")
async def reject_api(aid):
    row=db.one("SELECT * FROM approvals WHERE approval_id=?",(aid,))
    if not row: raise HTTPException(404,"Approval not found")
    result=await reject(row["incident_id"],aid)
    db.execute("UPDATE approvals SET status='REJECTED',payload=? WHERE approval_id=?" if not db.pg else "UPDATE approvals SET status='REJECTED',payload=%s::jsonb WHERE approval_id=%s",(json.dumps(result),aid))
    return result
@app.post("/api/incidents/{iid}/rollback")
async def rollback(iid):
    raw=get_incident(iid)
    if not raw: raise HTTPException(404,"Incident not found")
    i=Incident.model_validate(raw)
    if i.status!="CLOSED" or i.response.get("action")!="ISOLATE_HOST": raise HTTPException(400,"Only successfully contained simulated isolation can be rolled back.")
    upsert_host_status(i.host,"ONLINE",.10)
    i.rollback={"status":"SUCCESS","target":i.host,"timestamp":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),"performed_by":"SOC_OPERATOR"}
    i.response["rollback"]="COMPLETED"; save_incident(i)
    await bus.emit({"type":"rollback","incident_id":iid,"data":i.rollback})
    return i.model_dump()
@app.get("/api/settings")
async def settings(): return {x["key"]:x["value"] for x in db.all("SELECT * FROM settings")}
@app.post("/api/settings")
async def update_settings(payload:dict):
    for k,v in payload.items():
        db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value" if not db.pg else "INSERT INTO settings(key,value) VALUES(%s,%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",(k,str(v)))
    return {"ok":True}
@app.get("/api/search")
async def search(q:str):
    q=q.lower().strip();out=[]
    for i in list_incidents():
        if q in json.dumps(i).lower(): out.append({"type":"incident","id":i["id"],"title":i["summary"] or i["scenario"]})
    for h in db.all("SELECT * FROM hosts"):
        if q in json.dumps(h).lower(): out.append({"type":"host","id":h["id"],"title":h["name"]})
    for x in db.all("SELECT * FROM iocs"):
        if q in json.dumps(x).lower(): out.append({"type":"ioc","id":x["id"],"title":x["value"]})
    return out[:30]
@app.post("/api/scenarios/{scenario}/run")
async def run_scenario(scenario):
    if scenario not in SCENARIOS: raise HTTPException(400,"Unknown scenario")
    events=make(scenario); i=Incident(id=f"INC-{uuid.uuid4().hex[:8].upper()}",created_at=events[0].timestamp,scenario=scenario,host=events[0].host,events=events)
    save_incident(i); asyncio.create_task(investigate(i)); return {"ok":True,"incident_id":i.id}
@app.get("/api/scenarios")
async def scenarios(): return [{"id":k,"name":v[0],"description":v[1]} for k,v in SCENARIOS.items()]
@app.post("/api/ares/run")
async def ares(): return await run_ares()
@app.get("/api/ares/latest")
async def ares_latest():
    row=db.one("SELECT payload FROM ares_runs ORDER BY started_at DESC LIMIT 1")
    return decode_payload(row["payload"]) if row else None
@app.get("/api/reports/{iid}")
async def report(iid):
    i=get_incident(iid)
    if not i: raise HTTPException(404,"Incident not found")
    content=f"""AEGIS INCIDENT REPORT\n=====================\nIncident: {i['id']}\nScenario: {i['scenario']}\nHost: {i['host']}\nStatus: {i['status']}\nSeverity: {i['severity']}\nConfidence: {i['confidence']:.0%}\n\nSUMMARY\n{i['summary']}\n\nCONFIDENCE TRACE\n{json.dumps(i.get('confidence_trace',{}),indent=2)}\n\nPLAN\n{json.dumps(i.get('plan',[]),indent=2)}\n\nDECISION\n{json.dumps(i.get('decision',{}),indent=2)}\n\nPOLICY\n{json.dumps(i.get('policy',{}),indent=2)}\n\nRESPONSE\n{json.dumps(i.get('response',{}),indent=2)}\n\nVERIFICATION\n{json.dumps(i.get('verification',{}),indent=2)}\n\nEVIDENCE\n"""+"\n".join(f"- {e['id']} | {e['title']} | {e['source']} | contribution={e['contribution']:.2f} | {e['detail']}" for e in i.get("evidence",[]))
    return {"incident_id":iid,"filename":f"{iid}.txt","content":content}
@app.websocket("/ws")
async def websocket_endpoint(ws:WebSocket):
    await bus.connect(ws)
    try:
        await ws.send_json({"type":"hello","message":"AEGIS realtime channel connected"})
        while True: await ws.receive_text()
    except: bus.disconnect(ws)
