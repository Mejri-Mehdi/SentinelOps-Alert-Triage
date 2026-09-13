"""Tests for the Alert Ingestor and Deduplication Engine."""

import json
from datetime import datetime
import pytest

from src.ingestor import AlertIngestor
from src.models import Alert, get_engine, get_session, init_db


@pytest.fixture
def db_session():
    """Create a clean in-memory database session for testing."""
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    session = get_session(engine)
    yield session
    session.close()


@pytest.fixture
def ingestor(db_session):
    """Create an ingestor instance using the test session."""
    return AlertIngestor(session=db_session, dedup_window=5)


def test_normalize_alert(ingestor):
    """Verify that disparate vendor fields are normalized to canonical schema."""
    raw = {
        "alert_id": "ALT-TEST-001",
        "timestamp": "2027-06-15T10:30:00",
        "severity": "HIGH",
        "src_ip": "192.168.1.50",
        "username": "alice",
        "hostname": "WS-001",
        "alert_name": "failed_login",
        "msg": "Test alert payload",
    }
    normalized = ingestor._normalize_alert(raw)

    assert normalized["alert_id"] == "ALT-TEST-001"
    assert normalized["severity"] == "high"
    assert normalized["source_ip"] == "192.168.1.50"
    assert normalized["user"] == "alice"
    assert normalized["host"] == "WS-001"
    assert normalized["alert_type"] == "failed_login"


def test_deduplication(ingestor):
    """Verify identical alerts within the deduplication window are dropped."""
    raw = {
        "alert_id": "ALT-001",
        "timestamp": datetime.utcnow().isoformat(),
        "severity": "high",
        "source_ip": "10.0.0.1",
        "user": "bob",
        "host": "WS-002",
        "alert_type": "failed_login",
        "description": "Brute force attempt",
    }

    first = ingestor.ingest_single(raw)
    assert first is not None

    # Exact duplicate alert immediately after should be dropped
    raw["alert_id"] = "ALT-002"
    second = ingestor.ingest_single(raw)
    assert second is None


def test_ingest_from_jsonl(ingestor, tmp_path):
    """Verify batch ingestion from JSONL files."""
    alerts = [
        {
            "alert_id": "ALT-001",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "critical",
            "alert_type": "malware_detected",
            "source_ip": "1.2.3.4",
            "user": "admin",
            "host": "SRV-01",
            "description": "Ransomware payload detected",
        },
        {
            "alert_id": "ALT-002",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "high",
            "alert_type": "failed_login",
            "source_ip": "1.2.3.5",
            "user": "alice",
            "host": "WS-01",
            "description": "Failed authentication burst",
        },
    ]

    jsonl_file = tmp_path / "test_alerts.jsonl"
    with open(jsonl_file, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")

    stats = ingestor.ingest_from_jsonl(str(jsonl_file))
    assert stats["ingested"] == 2
    assert stats["duplicates"] == 0
    assert stats["total"] == 2


def test_unprocessed_alerts(ingestor):
    """Verify querying unprocessed alerts."""
    raw = {
        "alert_id": "ALT-003",
        "timestamp": datetime.utcnow().isoformat(),
        "severity": "medium",
        "alert_type": "unusual_process",
        "source_ip": "10.0.0.5",
        "user": "charlie",
        "host": "WS-003",
        "description": "Noise event",
    }
    ingestor.ingest_single(raw)

    unprocessed = ingestor.get_unprocessed_alerts()
    assert len(unprocessed) == 1
    assert unprocessed[0].alert_id == "ALT-003"
