from app.policy import evaluate

def test_high_confidence_isolation_allowed():
    assert evaluate(.95, 'CRITICAL', 'ISOLATE_HOST')['allowed'] is True

def test_low_confidence_isolation_blocked():
    assert evaluate(.40, 'HIGH', 'ISOLATE_HOST')['allowed'] is False

def test_unknown_action_blocked():
    assert evaluate(.99, 'CRITICAL', 'EXECUTE_SHELL')['allowed'] is False
