from datetime import datetime,timedelta,timezone
import uuid
from .models import Event

def make(name,variant=None):
    now=datetime.now(timezone.utc).replace(microsecond=0)
    def e(n,kind,source,severity,data,actor="system",host="HOST-07"):
        return Event(id=f"EVT-{uuid.uuid4().hex[:8].upper()}",timestamp=(now+timedelta(seconds=n*6)).isoformat(),
        host=host,kind=kind,actor=actor,source=source,severity=severity,data=data)
    base={
    "multi_stage":[
      e(0,"AUTH_FAILURE","auth","MEDIUM",{"attempts":14,"source_ip":"10.20.4.23"},"admin"),
      e(1,"AUTH_SUCCESS","auth","HIGH",{"source_ip":"10.20.4.23","privileged":True},"admin"),
      e(2,"PROCESS_START","endpoint","HIGH",{"process":"powershell","parent":"winlogon"},"admin"),
      e(3,"NETWORK_CONNECTION","network","HIGH",{"destination":"203.0.113.77","bytes_out":920000},"admin"),
      e(4,"FILE_MODIFIED","integrity","CRITICAL",{"path":"/sensitive/data.db","hash_before":"abc","hash_after":"9ff"}),
      e(5,"PROCESS_START","endpoint","HIGH",{"process":"archive-tool","parent":"powershell"},"admin")],
    "credential_abuse":[
      e(0,"AUTH_FAILURE","auth","MEDIUM",{"attempts":9,"source_ip":"10.20.4.23"},"admin"),
      e(1,"AUTH_FAILURE","auth","MEDIUM",{"attempts":11,"source_ip":"10.20.4.23"},"admin"),
      e(2,"AUTH_SUCCESS","auth","HIGH",{"source_ip":"10.20.4.23","privileged":True},"admin"),
      e(3,"PROCESS_START","endpoint","HIGH",{"process":"powershell","parent":"winlogon"},"admin"),
      e(4,"NETWORK_CONNECTION","network","HIGH",{"destination":"203.0.113.77","bytes_out":812000},"admin")],
    "data_tampering":[
      e(0,"PROCESS_START","endpoint","HIGH",{"process":"unknown_updater","signed":False}),
      e(1,"FILE_MODIFIED","integrity","CRITICAL",{"path":"/sensitive/data.db","hash_before":"abc","hash_after":"9ff"}),
      e(2,"FILE_MODIFIED","integrity","HIGH",{"path":"/sensitive/users.db","hash_before":"def","hash_after":"101"}),
      e(3,"NETWORK_CONNECTION","network","HIGH",{"destination":"203.0.113.77","bytes_out":420000})],
    "network_anomaly":[
      e(0,"PROCESS_START","endpoint","MEDIUM",{"process":"backup-agent","signed":True}),
      e(1,"NETWORK_CONNECTION","network","HIGH",{"destination":"198.51.100.45","bytes_out":1200000}),
      e(2,"NETWORK_CONNECTION","network","HIGH",{"destination":"198.51.100.45","bytes_out":1800000}),
      e(3,"DNS_ANOMALY","network","MEDIUM",{"domain":"odd-example.invalid","entropy":4.9})],
    "ambiguous":[
      e(0,"AUTH_FAILURE","auth","MEDIUM",{"attempts":2,"source_ip":"10.20.9.44"},"student"),
      e(1,"PROCESS_START","endpoint","LOW",{"process":"powershell","parent":"explorer"},"student"),
      e(2,"NETWORK_CONNECTION","network","LOW",{"destination":"198.51.100.20","bytes_out":4000},"student")]}
    return base[name]

SCENARIOS={
"multi_stage":("Multi-Stage Intrusion","Credential abuse → endpoint → network → integrity"),
"credential_abuse":("Credential Abuse","Authentication anomaly"),
"data_tampering":("Data Tampering","File integrity violation"),
"network_anomaly":("Network Anomaly","Suspicious outbound traffic"),
"ambiguous":("Ambiguous Activity","Low-confidence safety test")
}
