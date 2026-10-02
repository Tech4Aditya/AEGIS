from __future__ import annotations
import asyncio,uuid
from datetime import datetime,timezone
from .models import Incident,Evidence,AuditRecord,ApprovalRequest,AgentRun
from .storage import save_incident,save_audit,db,upsert_host_status
from .events import bus
from .policy import evaluate
from .confidence import score_incident
from .tools import registry
from .llm import llm

def now(): return datetime.now(timezone.utc).isoformat()

async def agent(i,agent,status,message,detail=None):
    x=AgentRun(agent=agent,status=status,message=message,detail=detail or {},timestamp=now())
    i.agents.append(x)
    save_incident(i)
    await bus.emit({"type":"agent","incident_id":i.id,**x.model_dump()})
    await asyncio.sleep(.22)

async def plan(i):
    fallback={"steps":[
      {"step":1,"tool":"query_auth","purpose":"Validate authentication anomalies."},
      {"step":2,"tool":"inspect_endpoint","purpose":"Inspect suspicious endpoint processes."},
      {"step":3,"tool":"inspect_network","purpose":"Correlate outbound connections."},
      {"step":4,"tool":"inspect_integrity","purpose":"Check sensitive file integrity."},
      {"step":5,"tool":"lookup_ioc","purpose":"Correlate observed indicators."}]}
    user=f"Create a security investigation plan for host {i.host}. Available tools: {registry.catalog()}. Events: {[e.model_dump() for e in i.events]}"
    result=await llm.structured(
      "You are the AEGIS mission planner. Return JSON with steps. Only choose tools from the supplied catalog. Never request arbitrary shell execution.",
      user,fallback)
    return result

async def investigate(i):
    i.status="INVESTIGATING"; save_incident(i)
    await agent(i,"SENTINEL","RUNNING","Mission received. Establishing investigation scope.")
    await agent(i,"SENTINEL","DONE",f"Detected {len(i.events)} correlated telemetry events.",{"event_ids":[e.id for e in i.events]})
    await agent(i,"MISSION PLANNER","RUNNING","Constructing an investigation plan from the available bounded tools.")
    i.plan=(await plan(i)).get("steps",[])
    await agent(i,"MISSION PLANNER","DONE",f"Plan created with {len(i.plan)} tool steps.",{"plan":i.plan,"llm_enabled":llm.enabled()})
    await agent(i,"INVESTIGATOR","RUNNING","Executing read-only investigation tools.")
    for step in i.plan:
        tool=step.get("tool")
        if tool not in registry.tools: continue
        args={"host":i.host}
        if tool=="lookup_ioc":
            vals=[v for e in i.events for v in [e.data.get("destination"),e.data.get("source_ip"),e.data.get("domain")] if v]
            args["value"]=vals[0] if vals else ""
        try: result=registry.execute(tool,args)
        except Exception as ex: result={"error":str(ex)}
        i.tool_calls.append({"tool":tool,"args":args,"result":result,"risk":registry.tools[tool].risk,"timestamp":now()})
        save_incident(i); await bus.emit({"type":"tool","incident_id":i.id,"tool":tool,"result":result})
        await asyncio.sleep(.15)
    weights={"AUTH_FAILURE":.08,"AUTH_SUCCESS":.18,"PROCESS_START":.18,"NETWORK_CONNECTION":.20,"FILE_MODIFIED":.28,"DNS_ANOMALY":.10}
    for e in i.events:
        w=weights.get(e.kind,.05)+(.12 if e.severity=="CRITICAL" else .07 if e.severity=="HIGH" else 0)
        i.evidence.append(Evidence(id=f"EVD-{uuid.uuid4().hex[:8].upper()}",event_id=e.id,title=e.kind.replace("_"," ").title(),detail=f"{e.source}: {e.data}",weight=w,source=e.source))
        i.timeline.append({"timestamp":e.timestamp,"kind":e.kind,"source":e.source,"severity":e.severity,"detail":e.data})
    await agent(i,"INVESTIGATOR","DONE",f"Collected {len(i.evidence)} evidence items and executed {len(i.tool_calls)} bounded tools.")
    await agent(i,"THREAT ANALYST","RUNNING","Correlating indicators across independent telemetry sources.")
    confidence,trace=score_incident(i.events,i.evidence); i.confidence=confidence;i.confidence_trace=trace
    for e in i.evidence:
        match=next((x for x in trace["base_signals"] if x["signal"].lower().replace(" ","_")==e.title.lower().replace(" ","_")),None)
        e.contribution=match["impact"] if match else e.weight
        e.confidence_effect="positive" if e.contribution>0 else "negative"
    i.severity="CRITICAL" if confidence>=.85 else "HIGH" if confidence>=.65 else "MEDIUM"
    i.summary=f"Correlated activity on {i.host} indicates {'a high-confidence multi-stage security incident' if confidence>=.85 else 'an ambiguous security anomaly'}."
    await agent(i,"THREAT ANALYST","DONE",f"Threat confidence: {confidence:.0%}.",{"confidence":confidence,"trace":trace})
    await agent(i,"DECISION AGENT","RUNNING","Selecting a bounded response from the evidence and confidence.")
    requested="ISOLATE_HOST" if confidence>=.60 else "NO_ACTION"
    i.decision={"requested_action":requested,"confidence":confidence,"rationale":"Multiple correlated indicators justify containment." if requested!="NO_ACTION" else "Evidence is insufficient for containment.","evidence_count":len(i.evidence)}
    await agent(i,"DECISION AGENT","DONE",f"Recommended action: {requested}.",i.decision)
    await agent(i,"POLICY GUARDIAN","RUNNING","Validating the recommendation against deterministic safety policy.")
    i.policy=evaluate(confidence,i.severity,requested)
    await agent(i,"POLICY GUARDIAN","DONE","Policy gate passed." if i.policy["allowed"] else "Automatic containment blocked; approval required.",i.policy)
    if i.policy["allowed"]:
        await execute_containment(i)
    else:
        i.status="ESCALATED"
        if requested!="NO_ACTION":
            approval_id=f"APR-{uuid.uuid4().hex[:8].upper()}"
            i.approval={"approval_id":approval_id,"status":"PENDING","action":requested,"target":i.host,"created_at":now(),"reason":i.policy["reason"]}
            if db.pg:
                db.execute("""INSERT INTO approvals(approval_id,incident_id,action,target,confidence,reason,status,created_at,payload)
                           VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                           ON CONFLICT(approval_id) DO UPDATE SET payload=EXCLUDED.payload""",
                           (approval_id,i.id,requested,i.host,i.confidence,i.policy["reason"],"PENDING",now(),i.model_dump_json()))
            else:
                db.execute("""INSERT OR REPLACE INTO approvals(approval_id,incident_id,action,target,confidence,reason,status,created_at,payload)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                           (approval_id,i.id,requested,i.host,i.confidence,i.policy["reason"],"PENDING",now(),i.model_dump_json()))
        i.response={"action":requested,"target":i.host,"status":"PENDING_HUMAN_APPROVAL","simulated":True,"message":"Automatic response blocked by policy."}
        save_incident(i); await agent(i,"RESPONSE AGENT","WAITING","Escalated to human approval.",i.response)
    await verify(i)

async def execute_containment(i):
    await agent(i,"RESPONSE AGENT","RUNNING",f"Executing simulated {i.policy['action']}.")
    i.response={"action":i.policy["action"],"target":i.host,"status":"SUCCESS","simulated":True,"message":f"{i.host} isolated in the AEGIS cyber-range."}
    i.status="CONTAINED"; upsert_host_status(i.host,"ISOLATED",.94)
    a=AuditRecord(id=f"AUD-{uuid.uuid4().hex[:8].upper()}",timestamp=now(),actor="RESPONSE_AGENT",action=i.policy["action"],target=i.host,reason=i.policy["reason"],result="SUCCESS",incident_id=i.id,evidence_ids=[e.id for e in i.evidence])
    save_audit(a); await bus.emit({"type":"audit","incident_id":i.id,**a.model_dump()})
    await agent(i,"RESPONSE AGENT","DONE","Host isolation completed.",i.response)

async def verify(i):
    await agent(i,"VERIFICATION AGENT","RUNNING","Verifying response state and generating post-action validation.")
    i.verification={"verified":i.status=="CONTAINED","network_access":"BLOCKED" if i.status=="CONTAINED" else "UNCHANGED","active_session":"REVOKED" if i.status=="CONTAINED" else "ACTIVE","containment":"EFFECTIVE" if i.status=="CONTAINED" else "NOT_EXECUTED"}
    await agent(i,"VERIFICATION AGENT","DONE","Verification complete.",i.verification)
    if i.status=="CONTAINED": i.status="CLOSED"
    save_incident(i); await bus.emit({"type":"incident","incident_id":i.id,"data":i.model_dump()})

async def approve(incident_id,approval_id):
    from .storage import get_incident
    raw=get_incident(incident_id)
    if not raw: raise ValueError("Incident not found")
    i=Incident.model_validate(raw)
    if i.approval.get("approval_id")!=approval_id or i.approval.get("status")!="PENDING": raise ValueError("Approval not pending")
    i.approval["status"]="APPROVED"; i.approval["approved_at"]=now(); i.approval["approved_by"]="SOC_OPERATOR"
    i.policy["allowed"]=True; i.policy["reason"]="Human operator approved bounded response."
    save_incident(i)
    await execute_containment(i); await verify(i)
    return i.model_dump()

async def reject(incident_id,approval_id):
    raw=__import__("json").loads(get_incident(incident_id).__str__()) if False else get_incident(incident_id)
    if not raw: raise ValueError("Incident not found")
    i=Incident.model_validate(raw)
    if i.approval.get("approval_id")!=approval_id: raise ValueError("Approval not found")
    i.approval["status"]="REJECTED";i.approval["rejected_at"]=now();i.approval["rejected_by"]="SOC_OPERATOR"
    i.status="ESCALATED";i.response={"action":i.decision.get("requested_action"),"status":"REJECTED","message":"Human operator rejected containment."}
    save_incident(i); await bus.emit({"type":"incident","incident_id":i.id,"data":i.model_dump()})
    return i.model_dump()
