"""Alert Ingestion and Deduplication Engine.

Normalizes raw incoming alert data, enriches it with MITRE ATT&CK taxonomy,
and deduplicates repeated alerts within a configurable time window using MD5 hashing.
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from src.config import (
    DEDUPLICATION_WINDOW_MINUTES,
    MITRE_MAPPING,
)
from src.models import Alert, get_engine, get_session, init_db


class AlertIngestor:
    """Ingests, normalizes, deduplicates, and enriches security telemetry."""

    def __init__(self, session: Optional[Session] = None, dedup_window: int = DEDUPLICATION_WINDOW_MINUTES):
        self.session = session or get_session()
        self.dedup_window = dedup_window

    def _normalize_alert(self, raw: dict) -> dict:
        """Map disparate vendor field names to our canonical schema."""
        # Normalize timestamp
        ts = raw.get("timestamp")
        if isinstance(ts, str):
            try:
                parsed_time = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                parsed_time = datetime.utcnow()
        elif isinstance(ts, datetime):
            parsed_time = ts
        else:
            parsed_time = datetime.utcnow()

        # Handle field aliases from different security tooling
        source_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("ip_address") or raw.get("client_ip")
        user = raw.get("user") or raw.get("username") or raw.get("user_id") or raw.get("account")
        host = raw.get("host") or raw.get("hostname") or raw.get("device_name") or raw.get("computer_name")
        alert_type = raw.get("alert_type") or raw.get("alert_name") or raw.get("event_type") or "unknown_event"
        severity = str(raw.get("severity", "medium")).lower()
        description = raw.get("description") or raw.get("msg") or raw.get("message") or ""
        alert_id = raw.get("alert_id") or f"ALT-{hashlib.md5(f'{parsed_time}{source_ip}{alert_type}'.encode()).hexdigest()[:10].upper()}"

        return {
            "alert_id": alert_id,
            "timestamp": parsed_time,
            "source": raw.get("source", "synthetic-siem"),
            "severity": severity,
            "source_ip": source_ip,
            "user": user,
            "host": host,
            "alert_type": alert_type,
            "description": description,
        }

    def _compute_fingerprint(self, alert_data: dict) -> str:
        """Generate a deterministic MD5 hash based on core entity attributes."""
        raw_key = f"{alert_data['alert_type']}|{alert_data['source_ip']}|{alert_data['user']}|{alert_data['host']}"
        return hashlib.md5(raw_key.encode("utf-8")).hexdigest()

    def _is_duplicate(self, fingerprint: str, alert_time: datetime) -> bool:
        """Check if an alert with identical fingerprint exists within the deduplication window."""
        window_start = alert_time - timedelta(minutes=self.dedup_window)
        window_end = alert_time + timedelta(minutes=self.dedup_window)

        existing = (
            self.session.query(Alert.id)
            .filter(
                Alert.fingerprint == fingerprint,
                Alert.timestamp >= window_start,
                Alert.timestamp <= window_end,
            )
            .first()
        )
        return existing is not None

    def ingest_single(self, raw: dict) -> Optional[Alert]:
        """Ingest, validate, deduplicate, and persist a single alert."""
        normalized = self._normalize_alert(raw)
        fingerprint = self._compute_fingerprint(normalized)

        # Check deduplication window
        if self._is_duplicate(fingerprint, normalized["timestamp"]):
            return None

        # Enrich with MITRE ATT&CK taxonomy
        mitre_info = MITRE_MAPPING.get(normalized["alert_type"], {})

        alert = Alert(
            alert_id=normalized["alert_id"],
            fingerprint=fingerprint,
            timestamp=normalized["timestamp"],
            source=normalized["source"],
            severity=normalized["severity"],
            source_ip=normalized["source_ip"],
            user=normalized["user"],
            host=normalized["host"],
            alert_type=normalized["alert_type"],
            mitre_technique_id=mitre_info.get("technique_id"),
            mitre_technique_name=mitre_info.get("technique_name"),
            mitre_tactic=mitre_info.get("tactic"),
            description=normalized["description"],
            status="ingested",
        )

        self.session.add(alert)
        self.session.commit()
        return alert

    def ingest_from_jsonl(self, filepath: str, batch_size: int = 1000) -> dict:
        """Batch ingest alerts from a JSONL file with batch commits for high performance."""
        stats = {"total": 0, "ingested": 0, "duplicates": 0, "errors": 0}
        alerts_to_commit = []

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                stats["total"] += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    raw = json.loads(line)
                    normalized = self._normalize_alert(raw)
                    fingerprint = self._compute_fingerprint(normalized)

                    if self._is_duplicate(fingerprint, normalized["timestamp"]):
                        stats["duplicates"] += 1
                        continue

                    mitre_info = MITRE_MAPPING.get(normalized["alert_type"], {})

                    alert = Alert(
                        alert_id=normalized["alert_id"],
                        fingerprint=fingerprint,
                        timestamp=normalized["timestamp"],
                        source=normalized["source"],
                        severity=normalized["severity"],
                        source_ip=normalized["source_ip"],
                        user=normalized["user"],
                        host=normalized["host"],
                        alert_type=normalized["alert_type"],
                        mitre_technique_id=mitre_info.get("technique_id"),
                        mitre_technique_name=mitre_info.get("technique_name"),
                        mitre_tactic=mitre_info.get("tactic"),
                        description=normalized["description"],
                        status="ingested",
                    )
                    alerts_to_commit.append(alert)
                    stats["ingested"] += 1

                    # Commit in batches for speed
                    if len(alerts_to_commit) >= batch_size:
                        self.session.bulk_save_objects(alerts_to_commit)
                        self.session.commit()
                        alerts_to_commit.clear()

                except Exception as e:
                    stats["errors"] += 1

        # Commit remaining alerts
        if alerts_to_commit:
            self.session.bulk_save_objects(alerts_to_commit)
            self.session.commit()
            alerts_to_commit.clear()

        return stats

    def get_unprocessed_alerts(self) -> list[Alert]:
        """Fetch all alerts awaiting correlation."""
        return (
            self.session.query(Alert)
            .filter(Alert.status == "ingested")
            .order_by(Alert.timestamp.asc())
            .all()
        )
