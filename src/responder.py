"""Automated SOAR Incident Responder.

Executes automated containment, notification, and enrichment actions
defined in security playbooks. Maintains a persistent audit trail of all response actions.
"""

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from src.models import Case, ResponseAction, get_engine, get_session
from src.playbook_engine import Playbook, PlaybookEngine


class MockActionExecutor:
    """Simulates production SOAR API actions safely without touching real infrastructure."""

    KNOWN_MALICIOUS_IPS = {
        "185.220.101.42",
        "194.26.29.112",
        "45.154.255.89",
        "193.142.59.81",
        "91.240.118.172",
    }

    @classmethod
    def disable_user(cls, user: str) -> dict:
        """Simulate disabling a compromised identity in Okta / Active Directory."""
        return {
            "status": "completed",
            "action": "disable_user",
            "user": user,
            "target": user,
            "result": f"User {user} successfully disabled in Active Directory / Okta IdP. Active sessions revoked.",
        }

    @classmethod
    def isolate_host(cls, host: str) -> dict:
        """Simulate isolating an endpoint from the network via EDR agent."""
        return {
            "status": "completed",
            "action": "isolate_host",
            "host": host,
            "target": host,
            "result": f"Host {host} successfully isolated via EDR agent. Only SecOps management traffic permitted.",
        }

    @classmethod
    def block_ip(cls, ip: str) -> dict:
        """Simulate adding an IP to edge firewall / perimeter WAF blocklist."""
        return {
            "status": "completed",
            "action": "block_ip",
            "ip": ip,
            "target": ip,
            "result": f"IP {ip} added to perimeter firewall drop rule. Inbound/outbound traffic terminated.",
        }

    @classmethod
    def notify_slack(cls, channel: str, message: str) -> dict:
        """Simulate sending an urgent webhook card to a SOC Slack channel."""
        return {
            "status": "completed",
            "action": "notify_slack",
            "channel": channel,
            "target": f"#{channel}",
            "result": f"Notification broadcast to #{channel}: {message}",
        }

    @classmethod
    def enrich_virustotal(cls, indicator: str) -> dict:
        """Simulate querying VirusTotal threat intelligence reputation."""
        is_bad = indicator in cls.KNOWN_MALICIOUS_IPS or "malware" in indicator.lower()
        score = 65 if is_bad else 0
        verdict = "malicious" if is_bad else "clean"

        return {
            "status": "completed",
            "action": "enrich_virustotal",
            "target": indicator,
            "result": verdict,
            "positives": score,
            "total_engines": 72,
            "reputation_details": f"VirusTotal score: {score}/72 ({verdict})",
        }


class Responder:
    """Orchestrates SOAR automated responses for incident Cases."""

    def __init__(
        self,
        session: Optional[Session] = None,
        auto_train: bool = False,
        min_risk_for_action: float = 60.0,
    ):
        self.session = session or get_session()
        self.playbook_engine = PlaybookEngine(session=self.session)
        self.min_risk_for_action = min_risk_for_action

    def execute_action(self, case: Case, playbook_id: str, action: dict) -> ResponseAction:
        """Dispatch an individual playbook action to the executor and log audit record."""
        action_type = action.get("type")
        target = "system"
        details_dict = {}

        if action_type == "contain":
            sub_action = action.get("action")
            target = action.get("target", "unspecified")

            if sub_action == "disable_user":
                details_dict = MockActionExecutor.disable_user(target)
            elif sub_action == "isolate_host":
                details_dict = MockActionExecutor.isolate_host(target)
            elif sub_action == "block_ip":
                details_dict = MockActionExecutor.block_ip(target)
            else:
                details_dict = {"status": "completed", "result": f"Executed contain action: {sub_action} on {target}"}

        elif action_type == "notify":
            channel = action.get("channel", "soc-alerts")
            msg = action.get("message", "High risk incident detected")
            target = f"#{channel}"
            details_dict = MockActionExecutor.notify_slack(channel, msg)

        elif action_type == "enrich":
            source = action.get("source", "virustotal")
            query = action.get("query", case.entity_value)
            target = query
            if source == "virustotal":
                details_dict = MockActionExecutor.enrich_virustotal(query)
            else:
                details_dict = {"status": "completed", "result": f"Enriched with {source} for {query}"}

        # Persist audit record in DB
        record = ResponseAction(
            case_id=case.id,
            playbook_id=playbook_id,
            action_type=action_type,
            target=target,
            details=json.dumps(details_dict),
            status=details_dict.get("status", "completed"),
            mock=True,
            timestamp=datetime.utcnow(),
        )
        self.session.add(record)
        return record

    def respond_to_case(self, case: Case, force: bool = False) -> dict:
        """Match playbooks and execute automated response actions for an incident case."""
        # Gate: only trigger for high-risk cases unless forced
        if not force and (case.risk_score or 0.0) < self.min_risk_for_action:
            return {"case_id": case.case_id, "status": "skipped", "reason": "Risk score below threshold"}

        # Find matching playbooks
        matched_playbooks = self.playbook_engine.match_playbooks(case)
        if not matched_playbooks:
            # Fallback if high risk but no custom playbook matched: general containment
            if case.priority in ["critical", "high"] or force:
                action_spec = {
                    "type": "notify",
                    "channel": "soc-critical",
                    "message": f"Critical unclassified threat detected on {case.entity_type} {case.entity_value} (Case: {case.case_id})",
                }
                action_record = self.execute_action(case, "default_incident_alert", action_spec)
                case.status = "contained"
                self.session.commit()
                return {
                    "case_id": case.case_id,
                    "status": "contained",
                    "actions": [action_record.id],
                    "playbooks": ["default_incident_alert"],
                }

            return {"case_id": case.case_id, "status": "no_match", "playbooks": []}

        executed_actions = []
        applied_playbooks = []

        for pb in matched_playbooks:
            resolved_actions = self.playbook_engine.get_actions(case, pb)
            for act in resolved_actions:
                record = self.execute_action(case, pb.id, act)
                executed_actions.append(record)
            applied_playbooks.append(pb.id)

        # Update case status to 'contained'
        case.status = "contained"
        self.session.commit()

        return {
            "case_id": case.case_id,
            "status": "contained",
            "actions": [a.id for a in executed_actions],
            "playbooks": applied_playbooks,
        }

    def respond_to_all(self, min_risk: Optional[float] = None) -> dict:
        """Trigger automated response across all eligible open cases."""
        threshold = min_risk if min_risk is not None else self.min_risk_for_action
        eligible_cases = (
            self.session.query(Case)
            .filter(Case.status == "open", Case.risk_score >= threshold)
            .all()
        )

        stats = {
            "evaluated": len(eligible_cases),
            "contained": 0,
            "actions_executed": 0,
            "playbooks_triggered": set(),
        }

        for case in eligible_cases:
            res = self.respond_to_case(case)
            if res.get("status") == "contained":
                stats["contained"] += 1
                stats["actions_executed"] += len(res.get("actions", []))
                for pb_id in res.get("playbooks", []):
                    stats["playbooks_triggered"].add(pb_id)

        stats["playbooks_triggered"] = list(stats["playbooks_triggered"])
        return stats
