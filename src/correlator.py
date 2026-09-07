"""Alert Correlator Engine.

Groups related security alerts into cohesive security incidents (Cases)
using an entity-pivot sliding time window (IP, User, Host).
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from src.config import CORRELATION_WINDOW_MINUTES
from src.models import Alert, Case, get_engine, get_session


class AlertCorrelator:
    """Correlates individual alerts into incident Cases based on shared entities and time windows."""

    def __init__(self, session: Optional[Session] = None, window_minutes: int = CORRELATION_WINDOW_MINUTES):
        self.session = session or get_session()
        self.window_minutes = window_minutes

    def _find_matching_case(self, alert: Alert) -> Optional[Case]:
        """Find an existing active case within the time window that shares an entity."""
        window_start = alert.timestamp - timedelta(minutes=self.window_minutes)

        # Look for active cases within the sliding window
        candidate_cases = (
            self.session.query(Case)
            .filter(
                Case.status == "open",
                Case.updated_at >= window_start,
            )
            .order_by(Case.updated_at.desc())
            .all()
        )

        for case in candidate_cases:
            # Check primary entity match
            if case.entity_type == "ip" and alert.source_ip and case.entity_value == alert.source_ip:
                return case
            if case.entity_type == "user" and alert.user and case.entity_value == alert.user:
                return case
            if case.entity_type == "host" and alert.host and case.entity_value == alert.host:
                return case

            # Secondary check: inspect alerts already tied to this case
            for case_alert in case.alerts:
                if alert.source_ip and case_alert.source_ip == alert.source_ip:
                    return case
                if alert.user and case_alert.user == alert.user:
                    return case
                if alert.host and case_alert.host == alert.host:
                    return case

        return None

    def _determine_primary_entity(self, alert: Alert) -> tuple[str, str]:
        """Select the most actionable pivot entity (User > Host > IP)."""
        if alert.user and alert.user != "unknown":
            return "user", alert.user
        if alert.host and alert.host != "unknown":
            return "host", alert.host
        if alert.source_ip:
            return "ip", alert.source_ip
        return "system", "unspecified"

    def _map_severity_to_priority(self, severity: str) -> str:
        """Map alert severity to initial case priority."""
        sev = severity.lower()
        if sev == "critical":
            return "critical"
        if sev == "high":
            return "high"
        if sev == "medium":
            return "medium"
        return "low"

    def run_correlation(self) -> dict:
        """Process all un-correlated alerts into new or existing cases."""
        unprocessed_alerts = (
            self.session.query(Alert)
            .filter(Alert.status == "ingested")
            .order_by(Alert.timestamp.asc())
            .all()
        )

        stats = {
            "processed": len(unprocessed_alerts),
            "new_cases": 0,
            "correlated": 0,
        }

        if not unprocessed_alerts:
            return stats

        for alert in unprocessed_alerts:
            case = self._find_matching_case(alert)

            if case:
                # Add alert to existing case
                alert.case_id = case.id
                alert.status = "correlated"
                case.alert_count += 1
                case.updated_at = max(case.updated_at, alert.timestamp)

                # Escalate case priority if a higher severity alert arrives
                if alert.severity == "critical":
                    case.priority = "critical"
                elif alert.severity == "high" and case.priority not in ["critical"]:
                    case.priority = "high"

                stats["correlated"] += 1

            else:
                # Create a new Case incident
                entity_type, entity_value = self._determine_primary_entity(alert)
                new_case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

                case = Case(
                    case_id=new_case_id,
                    title=f"Security Incident involving {entity_type}: {entity_value}",
                    status="open",
                    priority=self._map_severity_to_priority(alert.severity),
                    entity_type=entity_type,
                    entity_value=entity_value,
                    created_at=alert.timestamp,
                    updated_at=alert.timestamp,
                    alert_count=1,
                )
                self.session.add(case)
                self.session.flush()  # Flush to populate case.id for foreign key

                alert.case_id = case.id
                alert.status = "correlated"
                stats["new_cases"] += 1

        self.session.commit()
        return stats

    def get_case_details(self, case_id_str: str) -> Optional[dict]:
        """Fetch full case report with timeline and MITRE coverage for analysis."""
        case = self.session.query(Case).filter(Case.case_id == case_id_str).first()
        if not case:
            return None

        alerts = (
            self.session.query(Alert)
            .filter(Alert.case_id == case.id)
            .order_by(Alert.timestamp.asc())
            .all()
        )

        mitre_techniques = set()
        mitre_tactics = set()
        entities = {"ips": set(), "users": set(), "hosts": set()}

        alert_records = []
        for a in alerts:
            if a.mitre_technique_id:
                mitre_techniques.add(f"{a.mitre_technique_id}: {a.mitre_technique_name}")
            if a.mitre_tactic:
                mitre_tactics.add(a.mitre_tactic)
            if a.source_ip:
                entities["ips"].add(a.source_ip)
            if a.user:
                entities["users"].add(a.user)
            if a.host:
                entities["hosts"].add(a.host)

            alert_records.append({
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "severity": a.severity,
                "alert_type": a.alert_type,
                "description": a.description,
                "technique": a.mitre_technique_name,
            })

        return {
            "case": {
                "id": case.id,
                "case_id": case.case_id,
                "title": case.title,
                "status": case.status,
                "priority": case.priority,
                "risk_score": case.risk_score,
                "alert_count": case.alert_count,
                "entity_type": case.entity_type,
                "entity_value": case.entity_value,
                "created_at": case.created_at.isoformat(),
                "updated_at": case.updated_at.isoformat(),
            },
            "alerts": alert_records,
            "mitre_summary": {
                "techniques": list(mitre_techniques),
                "tactics": list(mitre_tactics),
            },
            "entities": {k: list(v) for k, v in entities.items()},
        }
