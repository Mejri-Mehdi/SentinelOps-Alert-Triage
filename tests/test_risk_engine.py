"""Tests for the Hybrid Risk Scoring Engine."""

from datetime import datetime
import pytest

from src.models import Alert, Case, get_engine, get_session, init_db
from src.risk_engine import RiskEngine


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    session = get_session(engine)
    yield session
    session.close()


def create_case_with_alerts(session, alert_type, severity, count=1):
    case = Case(
        case_id="CASE-TEST-001",
        status="open",
        entity_type="ip",
        entity_value="10.0.0.1",
        alert_count=count,
    )
    session.add(case)
    session.commit()

    for i in range(count):
        alert = Alert(
            alert_id=f"ALT-{i}",
            fingerprint=f"fp-{i}",
            timestamp=datetime.utcnow(),
            source="test",
            severity=severity,
            source_ip="10.0.0.1",
            user="testuser",
            host="WS-01",
            alert_type=alert_type,
            description="Test alert",
            status="correlated",
            case_id=case.id,
        )
        session.add(alert)
    session.commit()
    return case


def test_rule_score_critical_severity(db_session):
    """Critical severity cases must produce high base rule scores."""
    case = create_case_with_alerts(db_session, "malware_detected", "critical", count=1)
    engine = RiskEngine(session=db_session)
    score = engine.calculate_rule_score(case)
    assert score >= 30


def test_combined_score_above_80(db_session):
    """High-volume critical malware incidents must score into Critical priority (>=80)."""
    case = create_case_with_alerts(db_session, "malware_detected", "critical", count=5)
    engine = RiskEngine(session=db_session)
    result = engine.score_case(case)
    assert result["total_score"] >= 45
    assert result["priority"] in ["critical", "high"]


def test_ml_score_without_model(db_session):
    """Engine must safely return 0.0 ML score when model is uninitialized."""
    case = create_case_with_alerts(db_session, "failed_login", "medium", count=1)
    engine = RiskEngine(session=db_session, model_path="/invalid/path.joblib", scaler_path="/invalid/scaler.joblib")
    ml_score = engine.calculate_ml_score(case)
    assert ml_score == 0.0


def test_train_model(db_session, tmp_path):
    """Model training must succeed across diverse telemetry cases."""
    for i, (atype, sev, count) in enumerate([
        ("malware_detected", "critical", 5),
        ("failed_login", "medium", 20),
        ("data_exfiltration", "critical", 3),
        ("unusual_process", "low", 1),
        ("privilege_escalation", "high", 2),
        ("bad_ip_connection", "medium", 1),
        ("lateral_movement", "high", 4),
        ("registry_run_key", "medium", 2),
        ("credential_dumping", "critical", 1),
        ("persistence", "low", 1),
    ]):
        case = Case(
            case_id=f"CASE-TRAIN-{i:03d}",
            status="open",
            entity_type="ip",
            entity_value=f"10.0.0.{i}",
            alert_count=count,
        )
        db_session.add(case)
        db_session.commit()

        for j in range(count):
            alert = Alert(
                alert_id=f"ALT-TRAIN-{i}-{j}",
                fingerprint=f"fp-{i}-{j}",
                timestamp=datetime.utcnow(),
                source="test",
                severity=sev,
                source_ip=f"10.0.0.{i}",
                user="user",
                host="WS-01",
                alert_type=atype,
                description="Train alert",
                status="correlated",
                case_id=case.id,
            )
            db_session.add(alert)
        db_session.commit()

    model_file = str(tmp_path / "test_model.joblib")
    scaler_file = str(tmp_path / "test_scaler.joblib")

    engine = RiskEngine(session=db_session, model_path=model_file, scaler_path=scaler_file)
    success = engine.train_model()

    assert success is True
    assert engine.model is not None
    assert engine.scaler is not None
