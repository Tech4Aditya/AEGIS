from .storage import db

def evaluate(confidence,severity,action):
    if action=="NO_ACTION":
        return {"allowed":False,"action":action,"threshold":1.0,"reason":"No response was recommended.","requires_human":True}
    row=db.one("SELECT * FROM policies WHERE action=? AND enabled=1",(action,))
    if not row:
        return {"allowed":False,"action":action,"threshold":1.0,"reason":"No enabled policy authorizes this action.","requires_human":True}
    threshold=float(row["threshold"])
    allowed=confidence>=threshold and (action!="ISOLATE_HOST" or severity in ("HIGH","CRITICAL"))
    if row["approval"]=="HUMAN": allowed=False
    return {
      "allowed":allowed,"action":action,"threshold":threshold,"approval":row["approval"],
      "reason":f"Policy {row['name']} passed: {confidence:.0%} >= {threshold:.0%}." if allowed else
               f"Policy {row['name']} denied automatic execution: requires >= {threshold:.0%} confidence or human approval.",
      "requires_human":not allowed or row["approval"]=="HUMAN"
    }
