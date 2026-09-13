"""Tests for the Sliding-Window Alert Correlator."""

from datetime import datetime, timedelta
import pytest

from src.correlator import AlertCorrelator
from src.models import Alert, Case, get_engine, get_session, init_db


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    session = get_session(engine)
    yield session
    session.close()


def create_test_alert(session, alert_id, timestamp, alert_type, source_ip, user, host, severity="high"):
    alert = Alert(
        alert_id=alert_id,
        fingerprint=f"fp-{alert_id}",
        timestamp=timestamp,
        source="test",
        severity=severity,
        source_ip=source_ip,
        user=user,
        host=host,
        alert_type=alert_type,
        description="Test description",
        status="ingested",
    )
    session.add(alert)
    session.commit()
    return alert


def test_correlation_by_ip(db_session):
    """Alerts from same IP within correlation window must group into one Case."""
    now = datetime.utcnow()

    create_test_alert(db_session, "A1", now, "failed_login", "192.168.1.100", "alice", "WS-01")
    create_test_alert(db_session, "A2", now + timedelta(minutes=2), "failed_login", "192.168.1.100", "alice", "WS-01")
    create_test_alert(db_session, "A3", now + timedelta(minutes=5), "failed_login", "192.168.1.100", "alice", "WS-01")

    correlator = AlertCorrelator(session=db_session, window_minutes=10)
    stats = correlator.run_correlation()

    assert stats["new_cases"] == 1
    assert stats["correlated"] == 2

    case = db_session.query(Case).first()
    assert case.alert_count == 3
    assert case.entity_value in ["alice", "WS-01", "192.168.1.100"]


def test_correlation_by_user(db_session):
    """Alerts with same user across different IPs must correlate together."""
    now = datetime.utcnow()

    create_test_alert(db_session, "B1", now, "failed_login", "10.0.0.1", "bob", "WS-02")
    create_test_alert(db_session, "B2", now + timedelta(minutes=3), "privilege_escalation", "10.0.0.2", "bob", "WS-03")

    correlator = AlertCorrelator(session=db_session, window_minutes=10)
    correlator.run_correlation()

    case = db_session.query(Case).first()
    assert case is not None
    assert case.alert_count == 2


def test_no_correlation_outside_window(db_session):
    """Alerts occurring outside the time window must form separate Cases."""
    now = datetime.utcnow()

    create_test_alert(db_session, "C1", now, "failed_login", "10.0.0.5", "eve", "WS-05")
    create_test_alert(db_session, "C2", now + timedelta(minutes=25), "failed_login", "10.0.0.5", "eve", "WS-05")

    correlator = AlertCorrelator(session=db_session, window_minutes=10)
    stats = correlator.run_correlation()

    assert stats["new_cases"] == 2


def test_case_details(db_session):
    """Verify case drill-down report returns aggregated metrics and timeline."""
    now = datetime.utcnow()
    create_test_alert(db_session, "D1", now, "malware_detected", "10.0.0.1", "dave", "SRV-01", "critical")

    correlator = AlertCorrelator(session=db_session)
    correlator.run_correlation()

    case = db_session.query(Case).first()
    details = correlator.get_case_details(case.case_id)

    assert details is not None
    assert details["case"]["case_id"] == case.case_id
    assert len(details["alerts"]) == 1
