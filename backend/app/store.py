from __future__ import annotations
from .db import db
from .models import Incident, AuditRecord
import json

def save_incident(i: Incident):
    db.execute("""
      INSERT INTO incidents(id,created_at,scenario,host,status,severity,confidence,summary,payload)
      VALUES(?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET
      created_at=excluded.created_at,scenario=excluded.scenario,host=excluded.host,
      status=excluded.status,severity=excluded.severity,confidence=excluded.confidence,
      summary=excluded.summary,payload=excluded.payload
    """, (i.id,i.created_at,i.scenario,i.host,i.status,i.severity,i.confidence,i.summary,i.model_dump_json()))

def get_incident(iid):
    row = db.one("SELECT payload FROM incidents WHERE id=?", (iid,))
    return json.loads(row["payload"]) if row else None

def list_incidents():
    rows = db.all("SELECT payload FROM incidents ORDER BY created_at DESC")
    return [json.loads(r["payload"]) for r in rows]

def save_audit(a: AuditRecord):
    db.execute("""
      INSERT OR REPLACE INTO audits(id,timestamp,actor,action,target,reason,result,incident_id,payload)
      VALUES(?,?,?,?,?,?,?,?,?)
    """, (a.id,a.timestamp,a.actor,a.action,a.target,a.reason,a.result,a.incident_id,a.model_dump_json()))

def list_audit():
    return [json.loads(r["payload"]) for r in db.all("SELECT payload FROM audits ORDER BY timestamp DESC LIMIT 100")]

def seed():
    hosts = [
        ("HOST-01","WORKSTATION-01","10.0.0.11","Windows 11","Engineering","ONLINE",0.12,"2m ago","dev,windows"),
        ("HOST-02","WORKSTATION-02","10.0.0.12","Windows 11","Design","ONLINE",0.08,"1m ago","design"),
        ("HOST-03","BUILD-SERVER","10.0.0.21","Ubuntu 24.04","Platform","ONLINE",0.22,"30s ago","linux,build"),
        ("HOST-04","DB-PRIMARY","10.0.0.31","Ubuntu 24.04","Data","ONLINE",0.18,"20s ago","database,critical"),
        ("HOST-05","SOC-01","10.0.0.41","Ubuntu 24.04","Security","ONLINE",0.05,"12s ago","soc"),
        ("HOST-06","LAPTOP-06","10.0.0.46","Windows 11","Sales","ONLINE",0.09,"2m ago","sales"),
        ("HOST-07","LAPTOP-07","10.0.0.47","Windows 11","Admin","ONLINE",0.54,"8s ago","admin,watch"),
        ("HOST-08","LAPTOP-08","10.0.0.48","Windows 11","HR","ONLINE",0.07,"1m ago","hr"),
        ("HOST-09","API-EDGE","10.0.0.51","Ubuntu 24.04","Platform","ONLINE",0.29,"15s ago","api,edge"),
        ("HOST-10","MAIL-01","10.0.0.61","Ubuntu 24.04","IT","ONLINE",0.14,"35s ago","mail"),
        ("HOST-11","JUMP-01","10.0.0.71","Ubuntu 24.04","Security","ONLINE",0.31,"1m ago","jump"),
        ("HOST-12","BACKUP-01","10.0.0.81","Ubuntu 24.04","IT","ONLINE",0.11,"2m ago","backup"),
    ]
    for h in hosts:
        db.execute("""INSERT OR IGNORE INTO hosts(id,name,ip,os,owner,status,risk,last_seen,tags)
                      VALUES(?,?,?,?,?,?,?,?,?)""", h)
    iocs = [
        ("IOC-001","IP","203.0.113.77","HIGH","AEGIS Synthetic Feed",0.96,"ACTIVE"),
        ("IOC-002","IP","198.51.100.45","MEDIUM","AEGIS Synthetic Feed",0.82,"ACTIVE"),
        ("IOC-003","DOMAIN","odd-example.invalid","MEDIUM","AEGIS Synthetic Feed",0.77,"ACTIVE"),
        ("IOC-004","HASH","9ff-synthetic","HIGH","AEGIS Integrity Feed",0.91,"ACTIVE"),
    ]
    for x in iocs:
        db.execute("INSERT OR IGNORE INTO iocs VALUES(?,?,?,?,?,?,?)", x)
    policies = [
        ("POL-001","Critical Host Isolation","ISOLATE_HOST",0.85,1,"AUTO","Auto-isolate HIGH/CRITICAL hosts at >=85% confidence."),
        ("POL-002","Session Revocation","REVOKE_SESSION",0.75,1,"AUTO","Revoke suspicious sessions at >=75% confidence."),
        ("POL-003","File Quarantine","QUARANTINE_FILE",0.75,1,"AUTO","Quarantine synthetic files at >=75% confidence."),
        ("POL-004","User Disable","DISABLE_USER",0.90,1,"HUMAN","Always require human approval."),
    ]
    for p in policies:
        db.execute("INSERT OR IGNORE INTO policies VALUES(?,?,?,?,?,?,?)", p)
    db.execute("INSERT OR IGNORE INTO settings VALUES('org_name','AEGIS Lab')")
    db.execute("INSERT OR IGNORE INTO settings VALUES('theme','JIIT')")
    db.execute("INSERT OR IGNORE INTO settings VALUES('auto_refresh','true')")

seed()
