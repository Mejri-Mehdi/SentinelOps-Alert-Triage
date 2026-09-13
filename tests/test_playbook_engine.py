"""Tests for the Playbook Engine and YAML Matcher."""

from datetime import datetime
import pytest

from src.models import Alert, Case, get_engine, get_session, init_db
from src.playbook_engine import PlaybookEngine


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    session = get_session(engine)
    yield session
    session.close()


@pytest.fixture
def temp_playbooks(tmp_path):
    """Generate temporary test playbooks."""
    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()

    brute_force = """
id: test_brute_force
name: Test Brute Force
enabled: true
min_risk_score: 50
triggers:
  - type: alert_type
    alert_type: failed_login
    count: 5
    window_minutes: 10
actions:
  - type: notify
    channel: slack
    message: "Brute force on {{user}}"
"""
    (playbooks_dir / "test_brute_force.yml").write_text(brute_force, encoding="utf-8")
    return str(playbooks_dir)


def test_load_playbooks(temp_playbooks, db_session):
    """Playbook parser must load YAML files correctly."""
    engine = PlaybookEngine(session=db_session, playbooks_dir=temp_playbooks)
    assert len(engine.playbooks) == 1
    assert engine.playbooks[0].id == "test_brute_force"


def test_match_brute_force(db_session, temp_playbooks):
    """Playbook must match when trigger criteria are met."""
    case = Case(
        case_id="CASE-BF-001",
        status="open",
        entity_type="user",
        entity_value="alice",
        alert_count=5,
        risk_score=65.0,
    )
    db_session.add(case)
    db_session.commit()

    now = datetime.utcnow()
    for i in range(5):
        alert = Alert(
            alert_id=f"BF-{i}",
            fingerprint=f"fp-bf-{i}",
            timestamp=now,
            source="test",
            severity="medium",
            user="alice",
            host="WS-01",
            alert_type="failed_login",
            description="Failed authentication",
            status="correlated",
            case_id=case.id,
        )
        db_session.add(alert)
    db_session.commit()

    engine = PlaybookEngine(session=db_session, playbooks_dir=temp_playbooks)
    matches = engine.match_playbooks(case)

    assert len(matches) == 1
    assert matches[0].id == "test_brute_force"


def test_action_resolution(db_session, temp_playbooks):
    """Context template variables like {{user}} must interpolate properly."""
    case = Case(
        case_id="CASE-RES-001",
        status="open",
        entity_type="user",
        entity_value="bob",
        alert_count=1,
        risk_score=70.0,
    )
    db_session.add(case)
    db_session.commit()

    alert = Alert(
        alert_id="RES-1",
        fingerprint="fp-res-1",
        timestamp=datetime.utcnow(),
        source="test",
        severity="high",
        user="bob",
        host="WS-99",
        alert_type="failed_login",
        description="Test alert",
        status="correlated",
        case_id=case.id,
    )
    db_session.add(alert)
    db_session.commit()

    engine = PlaybookEngine(session=db_session, playbooks_dir=temp_playbooks)
    playbook = engine.playbooks[0]
    actions = engine.get_actions(case, playbook)

    assert "bob" in actions[0]["message"]
