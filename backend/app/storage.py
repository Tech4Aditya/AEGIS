from __future__ import annotations
import json, os
from datetime import datetime, timezone
from threading import Lock
from .config import DATABASE_URL

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None
    dict_row = None

SQL = [
"""CREATE TABLE IF NOT EXISTS incidents(
id TEXT PRIMARY KEY, created_at TEXT, scenario TEXT, host TEXT, status TEXT,
severity TEXT, confidence DOUBLE PRECISION, payload JSONB NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS audits(
id TEXT PRIMARY KEY, timestamp TEXT, actor TEXT, action TEXT, target TEXT,
reason TEXT, result TEXT, incident_id TEXT, payload JSONB NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS hosts(
id TEXT PRIMARY KEY, name TEXT, ip TEXT, os TEXT, owner TEXT, status TEXT,
risk DOUBLE PRECISION, last_seen TEXT, tags TEXT)""",
"""CREATE TABLE IF NOT EXISTS iocs(
id TEXT PRIMARY KEY, type TEXT, value TEXT, severity TEXT, source TEXT,
confidence DOUBLE PRECISION, status TEXT)""",
"""CREATE TABLE IF NOT EXISTS policies(
id TEXT PRIMARY KEY, name TEXT, action TEXT, threshold DOUBLE PRECISION,
enabled INTEGER, approval TEXT, description TEXT)""",
"""CREATE TABLE IF NOT EXISTS approvals(
approval_id TEXT PRIMARY KEY, incident_id TEXT, action TEXT, target TEXT,
confidence DOUBLE PRECISION, reason TEXT, status TEXT, created_at TEXT, payload JSONB NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS ares_runs(
id TEXT PRIMARY KEY, started_at TEXT, completed_at TEXT, payload JSONB NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS settings(
key TEXT PRIMARY KEY, value TEXT)"""
]

class Storage:
    def __init__(self):
        self.lock=Lock()
        self.pg=bool(DATABASE_URL and psycopg)
        self.conn=None
        if self.pg:
            try:
                self.conn=psycopg.connect(DATABASE_URL, autocommit=True)
                with self.conn.cursor() as c:
                    for sql in SQL: c.execute(sql)
            except Exception:
                self.pg=False
        if not self.pg:
            import sqlite3
            self.conn=sqlite3.connect("/app/data/aegis.db",check_same_thread=False)
            self.conn.row_factory=sqlite3.Row
            with self.conn:
                for sql in SQL:
                    self.conn.execute(sql.replace("JSONB","TEXT").replace("DOUBLE PRECISION","REAL").replace("INTEGER","INTEGER"))

    def execute(self,sql,params=()):
        with self.lock:
            if self.pg:
                with self.conn.cursor() as c:
                    c.execute(sql,params)
                    return c
            cur=self.conn.execute(sql,params); self.conn.commit(); return cur

    def one(self,sql,params=()):
        if self.pg:
            with self.lock:
                with self.conn.cursor(row_factory=dict_row) as c:
                    c.execute(sql,params); r=c.fetchone()
                    return dict(r) if r else None
        r=self.execute(sql,params).fetchone()
        return dict(r) if r else None

    def all(self,sql,params=()):
        if self.pg:
            with self.lock:
                with self.conn.cursor(row_factory=dict_row) as c:
                    c.execute(sql,params); return [dict(x) for x in c.fetchall()]
        return [dict(x) for x in self.execute(sql,params).fetchall()]

db=Storage()

def payload(v): return json.dumps(v)

def decode_payload(v):
    # PostgreSQL JSONB drivers return Python dict/list values directly;
    # SQLite stores the same payload as JSON text.
    if isinstance(v, (dict, list)):
        return v
    return json.loads(v)

def save_incident(i):
    p=i.model_dump_json()
    if db.pg:
        db.execute("""INSERT INTO incidents(id,created_at,scenario,host,status,severity,confidence,payload)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        ON CONFLICT(id) DO UPDATE SET created_at=EXCLUDED.created_at,scenario=EXCLUDED.scenario,
        host=EXCLUDED.host,status=EXCLUDED.status,severity=EXCLUDED.severity,confidence=EXCLUDED.confidence,payload=EXCLUDED.payload""",
        (i.id,i.created_at,i.scenario,i.host,i.status,i.severity,i.confidence,p))
    else:
        db.execute("""INSERT OR REPLACE INTO incidents VALUES(?,?,?,?,?,?,?,?)""",
        (i.id,i.created_at,i.scenario,i.host,i.status,i.severity,i.confidence,p))

def get_incident(iid):
    r=db.one("SELECT payload FROM incidents WHERE id=%s" if db.pg else "SELECT payload FROM incidents WHERE id=?", (iid,))
    return decode_payload(r["payload"]) if r else None

def list_incidents():
    rows=db.all("SELECT payload FROM incidents ORDER BY created_at DESC")
    return [decode_payload(x["payload"]) for x in rows]

def save_audit(a):
    p=a.model_dump_json()
    if db.pg:
        db.execute("""INSERT INTO audits VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload""",
        (a.id,a.timestamp,a.actor,a.action,a.target,a.reason,a.result,a.incident_id,p))
    else:
        db.execute("INSERT OR REPLACE INTO audits VALUES(?,?,?,?,?,?,?,?,?)",
                   (a.id,a.timestamp,a.actor,a.action,a.target,a.reason,a.result,a.incident_id,p))

def list_audit():
    return [decode_payload(x["payload"]) for x in db.all("SELECT payload FROM audits ORDER BY timestamp DESC LIMIT 200")]

def upsert_host_status(host,status,risk):
    db.execute("UPDATE hosts SET status=?,risk=? WHERE id=?" if not db.pg else "UPDATE hosts SET status=%s,risk=%s WHERE id=%s",(status,risk,host))

def seed():
    hosts=[
    ("HOST-01","WORKSTATION-01","10.0.0.11","Windows 11","Engineering","ONLINE",.12,"2m ago","dev,windows"),
    ("HOST-02","WORKSTATION-02","10.0.0.12","Windows 11","Design","ONLINE",.08,"1m ago","design"),
    ("HOST-03","BUILD-SERVER","10.0.0.21","Ubuntu 24.04","Platform","ONLINE",.22,"30s ago","linux,build"),
    ("HOST-04","DB-PRIMARY","10.0.0.31","Ubuntu 24.04","Data","ONLINE",.18,"20s ago","database,critical"),
    ("HOST-05","SOC-01","10.0.0.41","Ubuntu 24.04","Security","ONLINE",.05,"12s ago","soc"),
    ("HOST-06","LAPTOP-06","10.0.0.46","Windows 11","Sales","ONLINE",.09,"2m ago","sales"),
    ("HOST-07","LAPTOP-07","10.0.0.47","Windows 11","Admin","ONLINE",.54,"8s ago","admin,watch"),
    ("HOST-08","LAPTOP-08","10.0.0.48","Windows 11","HR","ONLINE",.07,"1m ago","hr"),
    ("HOST-09","API-EDGE","10.0.0.51","Ubuntu 24.04","Platform","ONLINE",.29,"15s ago","api,edge"),
    ("HOST-10","MAIL-01","10.0.0.61","Ubuntu 24.04","IT","ONLINE",.14,"35s ago","mail"),
    ("HOST-11","JUMP-01","10.0.0.71","Ubuntu 24.04","Security","ONLINE",.31,"1m ago","jump"),
    ("HOST-12","BACKUP-01","10.0.0.81","Ubuntu 24.04","IT","ONLINE",.11,"2m ago","backup")]
    for h in hosts:
        db.execute("""INSERT INTO hosts(id,name,ip,os,owner,status,risk,last_seen,tags)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(id) DO NOTHING""" if db.pg else
        """INSERT OR IGNORE INTO hosts VALUES(?,?,?,?,?,?,?,?,?)""",h)
    iocs=[
    ("IOC-001","IP","203.0.113.77","HIGH","AEGIS Synthetic Feed",.96,"ACTIVE"),
    ("IOC-002","IP","198.51.100.45","MEDIUM","AEGIS Synthetic Feed",.82,"ACTIVE"),
    ("IOC-003","DOMAIN","odd-example.invalid","MEDIUM","AEGIS Synthetic Feed",.77,"ACTIVE"),
    ("IOC-004","HASH","9ff-synthetic","HIGH","AEGIS Integrity Feed",.91,"ACTIVE")]
    for x in iocs:
        db.execute("""INSERT INTO iocs VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(id) DO NOTHING""" if db.pg else "INSERT OR IGNORE INTO iocs VALUES(?,?,?,?,?,?,?)",x)
    policies=[
    ("POL-001","Critical Host Isolation","ISOLATE_HOST",.85,1,"AUTO","Auto-isolate HIGH/CRITICAL hosts at >=85% confidence."),
    ("POL-002","Session Revocation","REVOKE_SESSION",.75,1,"AUTO","Revoke suspicious sessions at >=75% confidence."),
    ("POL-003","File Quarantine","QUARANTINE_FILE",.75,1,"AUTO","Quarantine synthetic files at >=75% confidence."),
    ("POL-004","User Disable","DISABLE_USER",.90,1,"HUMAN","Always require human approval.")]
    for x in policies:
        db.execute("""INSERT INTO policies VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(id) DO NOTHING""" if db.pg else "INSERT OR IGNORE INTO policies VALUES(?,?,?,?,?,?,?)",x)
    for k,v in [("org_name","AEGIS Lab"),("theme","JIIT"),("auto_refresh","true")]:
        db.execute("""INSERT INTO settings VALUES(%s,%s) ON CONFLICT(key) DO NOTHING""" if db.pg else "INSERT OR IGNORE INTO settings VALUES(?,?)",(k,v))

seed()
