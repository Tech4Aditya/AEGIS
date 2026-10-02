from __future__ import annotations
from .storage import db

class Tool:
    def __init__(self,name,description,risk,fn):
        self.name=name; self.description=description; self.risk=risk; self.fn=fn

    def schema(self):
        return {"name":self.name,"description":self.description,"risk":self.risk}

class ToolRegistry:
    def __init__(self): self.tools={}
    def register(self,t): self.tools[t.name]=t
    def catalog(self): return [x.schema() for x in self.tools.values()]
    def execute(self,name,args):
        if name not in self.tools: raise ValueError("Tool not registered")
        return self.tools[name].fn(args)

def query_auth(args):
    host=args.get("host","HOST-07")
    return db.all("SELECT id,status,risk FROM hosts WHERE id=?",(host,))

def inspect_endpoint(args):
    return {"host":args.get("host","HOST-07"),"processes":["powershell","archive-tool"],"signed_state":"mixed"}

def inspect_network(args):
    return {"host":args.get("host","HOST-07"),"connections":["203.0.113.77","198.51.100.45"],"anomalies":2}

def inspect_integrity(args):
    return {"host":args.get("host","HOST-07"),"modified_files":["/sensitive/data.db","/sensitive/users.db"]}

def get_ioc(args):
    value=args.get("value","")
    return db.all("SELECT * FROM iocs WHERE value=?",(value,))

def simulate_isolate(args):
    return {"simulated":True,"target":args["host"],"state":"ISOLATED","reversible":True}

def simulate_restore(args):
    return {"simulated":True,"target":args["host"],"state":"ONLINE","reversible":True}

registry=ToolRegistry()
for t in [
    Tool("query_auth","Read synthetic authentication telemetry","READ",query_auth),
    Tool("inspect_endpoint","Read synthetic process/endpoint telemetry","READ",inspect_endpoint),
    Tool("inspect_network","Read synthetic network telemetry","READ",inspect_network),
    Tool("inspect_integrity","Read synthetic file-integrity telemetry","READ",inspect_integrity),
    Tool("lookup_ioc","Look up an indicator in the synthetic threat-intel store","READ",get_ioc),
    Tool("isolate_host","Simulate reversible host isolation","WRITE_BOUNDED",simulate_isolate),
    Tool("restore_host","Reverse simulated host isolation","WRITE_BOUNDED",simulate_restore),
]:
    registry.register(t)
