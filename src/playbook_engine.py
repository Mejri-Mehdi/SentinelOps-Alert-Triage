"""YAML Playbook Parser and Incident Matcher.

Loads declarative SOAR response playbooks, matches them against Case telemetry,
and interpolates entity template variables into executable response instructions.
"""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

import yaml
from sqlalchemy.orm import Session

from src.config import PLAYBOOKS_DIR
from src.models import Alert, Case, get_engine, get_session


@dataclass
class Playbook:
    """In-memory representation of a parsed YAML SOAR playbook."""
    id: str
    name: str
    enabled: bool
    triggers: list[dict]
    actions: list[dict]
    min_risk_score: float = 0.0
    severity_threshold: Optional[str] = None
    raw_config: Optional[dict] = None


class PlaybookEngine:
    """Parses playbooks, evaluates trigger conditions, and resolves templated parameters."""

    def __init__(self, session: Optional[Session] = None, playbooks_dir: Optional[str] = None):
        self.session = session or get_session()
        self.playbooks_dir = Path(playbooks_dir or PLAYBOOKS_DIR)
        self.playbooks: list[Playbook] = []
        self.load_playbooks()

    def load_playbooks(self) -> int:
        """Load and parse all YAML playbooks from the playbooks directory."""
        self.playbooks.clear()
        if not self.playbooks_dir.exists():
            return 0

        for file_path in sorted(self.playbooks_dir.glob("*.y*ml")):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if not data or not isinstance(data, dict):
                        continue

                    pb = Playbook(
                        id=data.get("id", file_path.stem),
                        name=data.get("name", file_path.stem.replace("_", " ").title()),
                        enabled=data.get("enabled", True),
                        triggers=data.get("triggers", []),
                        actions=data.get("actions", []),
                        min_risk_score=float(data.get("min_risk_score", 0.0)),
                        severity_threshold=data.get("severity_threshold"),
                        raw_config=data,
                    )
                    self.playbooks.append(pb)
            except Exception as e:
                print(f"[!] Error loading playbook {file_path}: {e}")

        return len(self.playbooks)

    def _evaluate_triggers(self, case: Case, playbook: Playbook) -> bool:
        """Check if a case meets the trigger requirements of the playbook."""
        alerts = self.session.query(Alert).filter(Alert.case_id == case.id).all()
        if not alerts:
            return False

        # If playbook specifies no triggers, it triggers on risk score alone
        if not playbook.triggers:
            return True

        for trigger in playbook.triggers:
            t_type = trigger.get("type")

            if t_type == "alert_type":
                target_type = trigger.get("alert_type")
                min_count = trigger.get("count", 1)
                window_mins = trigger.get("window_minutes", 60)

                # Filter alerts matching alert_type
                matching_alerts = [a for a in alerts if a.alert_type == target_type]
                if len(matching_alerts) < min_count:
                    return False

                # Check window constraint if multiple alerts required
                if min_count > 1 and len(matching_alerts) >= min_count:
                    timestamps = sorted([a.timestamp for a in matching_alerts])
                    window_found = False
                    for i in range(len(timestamps) - min_count + 1):
                        delta = (timestamps[i + min_count - 1] - timestamps[i]).total_seconds() / 60.0
                        if delta <= window_mins:
                            window_found = True
                            break
                    if not window_found:
                        return False

            elif t_type == "mitre_technique":
                target_tech = trigger.get("technique_id")
                if not any(a.mitre_technique_id == target_tech for a in alerts):
                    return False

        return True

    def match_playbooks(self, case: Case) -> list[Playbook]:
        """Find all enabled playbooks whose triggers and thresholds match the given case."""
        matched = []

        for pb in self.playbooks:
            if not pb.enabled:
                continue

            # Check risk score threshold
            if (case.risk_score or 0.0) < pb.min_risk_score:
                continue

            # Evaluate triggers against case alerts
            if self._evaluate_triggers(case, pb):
                matched.append(pb)

        return matched

    def _extract_context(self, case: Case) -> dict[str, str]:
        """Extract entity values from the case and alerts for variable interpolation."""
        alerts = self.session.query(Alert).filter(Alert.case_id == case.id).all()

        user = case.entity_value if case.entity_type == "user" else "unknown_user"
        host = case.entity_value if case.entity_type == "host" else "unknown_host"
        source_ip = case.entity_value if case.entity_type == "ip" else "unknown_ip"

        # Fall back to alert attributes if entity is not explicitly the pivot
        for a in alerts:
            if user == "unknown_user" and a.user:
                user = a.user
            if host == "unknown_host" and a.host:
                host = a.host
            if source_ip == "unknown_ip" and a.source_ip:
                source_ip = a.source_ip

        return {
            "case_id": case.case_id or f"CASE-{case.id}",
            "user": user,
            "host": host,
            "source_ip": source_ip,
            "risk_score": f"{case.risk_score:.1f}" if case.risk_score else "0.0",
            "priority": case.priority or "medium",
            "entity_type": case.entity_type or "entity",
            "entity_value": case.entity_value or "target",
        }

    def _interpolate_value(self, val: Any, context: dict[str, str]) -> Any:
        """Recursively replace {{placeholder}} tokens with real context values."""
        if isinstance(val, str):
            res = val
            for k, v in context.items():
                res = res.replace(f"{{{{{k}}}}}", str(v))
            return res
        elif isinstance(val, dict):
            return {k: self._interpolate_value(v, context) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._interpolate_value(item, context) for item in val]
        return val

    def get_actions(self, case: Case, playbook: Playbook) -> list[dict]:
        """Return the list of actions with all template variables resolved."""
        context = self._extract_context(case)
        resolved_actions = []

        for action in playbook.actions:
            resolved_action = self._interpolate_value(action, context)
            resolved_actions.append(resolved_action)

        return resolved_actions
