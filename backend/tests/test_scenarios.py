from app.scenarios import make, SCENARIOS

def test_all_scenarios_generate_events():
    for name in SCENARIOS:
        events=make(name)
        assert len(events) >= 3
        for e in events:
            assert e.id and e.host and e.source and e.severity
