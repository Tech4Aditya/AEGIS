def score_incident(events,evidence):
    weights={"AUTH_FAILURE":.08,"AUTH_SUCCESS":.18,"PROCESS_START":.18,"NETWORK_CONNECTION":.20,"FILE_MODIFIED":.28,"DNS_ANOMALY":.10}
    positives=[]
    score=0
    for e in events:
        x=weights.get(e.kind,.05)
        if e.severity=="CRITICAL": x+=.12
        elif e.severity=="HIGH": x+=.07
        score+=x
        positives.append({"signal":e.kind.replace("_"," ").title(),"impact":round(x,2),"reason":f"{e.source} telemetry reported {e.kind}."})
    sources=len(set(e.source for e in events))
    correlation=.08 if sources>=3 else 0
    file_bonus=.06 if any(e.kind=="FILE_MODIFIED" for e in events) else 0
    contradiction=-.08 if len(set(e.severity for e in events))==1 and len(events)>3 else 0
    missing=-.04 if sources<2 else 0
    score=max(.01,min(.99,score+correlation+file_bonus+contradiction+missing))
    return round(score,2),{
      "base_signals":positives,
      "cross_source_correlation":{"impact":correlation,"sources":sources},
      "file_integrity_bonus":{"impact":file_bonus},
      "contradiction_penalty":{"impact":contradiction},
      "missing_telemetry_penalty":{"impact":missing},
      "final":round(score,2),
      "evidence_strength":"HIGH" if score>=.85 else "MEDIUM" if score>=.65 else "LOW",
      "independent_sources":sources
    }
