import asyncio
from app.scenarios import build_scenario
from app.policy import policy_engine

def test_scenarios():
    for name in ["credential_abuse","data_tampering","network_anomaly","multi_stage","ambiguous"]:
        assert len(build_scenario(name)) >= 3

def test_policy():
    assert policy_engine.evaluate(.94, "CRITICAL", "ISOLATE_HOST").allowed
    assert not policy_engine.evaluate(.63, "MEDIUM", "ISOLATE_HOST").allowed
