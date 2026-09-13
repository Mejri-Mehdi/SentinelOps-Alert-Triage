"""Tests for the Automated SOAR Responder."""

from datetime import datetime
import pytest

from src.models import Alert, Case, ResponseAction, get_engine, get_session, init_db
from src.responder import MockActionExecutor, Responder


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    session = get_session(engine)
    yield session
    session.close()


def test_mock_disable_user():
    """Simulate account disablement."""
    result = MockActionExecutor.disable_user("alice@corp.com")
    assert result["status"] == "completed"
    assert result["user"] == "alice@corp.com"
    assert "disabled" in result["result"]


def test_mock_isolate_host():
    """Simulate EDR host network isolation."""
    result = MockActionExecutor.isolate_host("WS-01")
    assert result["status"] == "completed"
    assert "WS-01" in result["result"]


def test_mock_virustotal():
    """Simulate VirusTotal threat intelligence reputation lookup."""
    result = MockActionExecutor.enrich_virustotal("185.220.101.42")
    assert result["result"] == "malicious"

    result_clean = MockActionExecutor.enrich_virustotal("8.8.8.8")
    assert result_clean["result"] == "clean"


def test_responder_creates_actions(db_session):
    """Verify that automated response writes persistent audit records."""
    case = Case(
        case_id="CASE-RESP-001",
        status="open",
        entity_type="host",
        entity_value="WS-MALWARE",
        alert_count=1,
        risk_score=85.0,
    )
    db_session.add(case)
    db_session.commit()

    alert = Alert(
        alert_id="RESP-1",
        fingerprint="fp-resp-1",
        timestamp=datetime.utcnow(),
        source="test",
        severity="critical",
        host="WS-MALWARE",
        alert_type="malware_detected",
        description="Ransomware payload execution",
        status="correlated",
        case_id=case.id,
    )
    db_session.add(alert)
    db_session.commit()

    responder = Responder(session=db_session, auto_train=False)
    result = responder.respond_to_case(case, force=True)

    assert result["status"] in ["contained", "in_progress"]
    assert len(result["actions"]) > 0

    db_actions = db_session.query(ResponseAction).filter(ResponseAction.case_id == case.id).all()
    assert len(db_actions) > 0
    assert all(a.mock for a in db_actions)
