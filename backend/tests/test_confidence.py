from app.scenarios import make
from app.confidence import score_incident

def test_multistage_has_high_confidence():
    c,t=score_incident(make('multi_stage'),[])
    assert c >= .80
    assert t['independent_sources'] >= 3

def test_ambiguous_is_lower_risk():
    c,_=score_incident(make('ambiguous'),[])
    assert c < .80
