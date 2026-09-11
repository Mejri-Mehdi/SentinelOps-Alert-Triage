"""Hybrid Risk Scoring Engine.

Combines deterministic rule-based threat heuristics with unsupervised
machine learning (Isolation Forest anomaly detection) to prioritize incident cases.
"""

import math
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from src.config import (
    ALERT_TYPE_WEIGHTS,
    MODEL_PATH,
    RULE_WEIGHT,
    ML_WEIGHT,
    SCALER_PATH,
    SEVERITY_POINTS,
)
from src.models import Alert, Case, get_engine, get_session


class RiskEngine:
    """Calculates composite risk scores (0-100) for security incident Cases."""

    def __init__(
        self,
        session: Optional[Session] = None,
        model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
    ):
        self.session = session or get_session()
        self.model_path = Path(model_path or MODEL_PATH)
        self.scaler_path = Path(scaler_path or SCALER_PATH)
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._load_model()

    def _load_model(self):
        """Load trained IsolationForest model and scaler if available."""
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
            except Exception:
                self.model = None
                self.scaler = None

    def calculate_rule_score(self, case: Case) -> float:
        """Deterministic rule-based risk calculation (0 to 70 points max)."""
        alerts = self.session.query(Alert).filter(Alert.case_id == case.id).all()
        if not alerts:
            return 0.0

        # 1. Base Severity Score (takes highest severity present in the case)
        sev_rank = {"critical": 50, "high": 35, "medium": 20, "low": 10, "info": 0}
        base_sev_score = max(sev_rank.get(a.severity.lower(), 10) for a in alerts)

        # 2. Threat Category Weight (highest threat type present)
        threat_type_score = max(ALERT_TYPE_WEIGHTS.get(a.alert_type, 5) for a in alerts)

        # 3. Volume Burst Multiplier (logarithmic scale to reward rapid multi-alert attacks)
        count = len(alerts)
        volume_boost = min(15.0, math.log2(count + 1) * 3.5)

        # 4. Multi-Entity Blast Radius Bonus (multiple hosts or IPs = wider compromise)
        unique_hosts = len({a.host for a in alerts if a.host})
        blast_bonus = 5.0 if unique_hosts > 1 else 0.0

        # Calculate weighted sum capped at 70 points
        raw_score = (base_sev_score * 0.45) + (threat_type_score * 0.35) + volume_boost + blast_bonus
        return min(70.0, round(raw_score, 2))

    def _extract_case_features(self, case: Case, alerts: list[Alert]) -> list[float]:
        """Extract numerical feature vector representing case behavior for ML."""
        alert_count = len(alerts)
        unique_types = len({a.alert_type for a in alerts})
        unique_hosts = len({a.host for a in alerts if a.host})
        unique_ips = len({a.source_ip for a in alerts if a.source_ip})

        # Calculate time span in minutes
        timestamps = [a.timestamp for a in alerts]
        if len(timestamps) > 1:
            time_span_mins = max(0.1, (max(timestamps) - min(timestamps)).total_seconds() / 60.0)
        else:
            time_span_mins = 0.5

        # Critical alert ratio
        crit_count = sum(1 for a in alerts if a.severity.lower() in ["critical", "high"])
        critical_ratio = crit_count / max(1, alert_count)

        # Alert velocity (alerts per minute)
        velocity = alert_count / time_span_mins

        return [
            float(alert_count),
            float(unique_types),
            float(unique_hosts),
            float(unique_ips),
            float(time_span_mins),
            float(critical_ratio),
            float(velocity),
        ]

    def train_model(self) -> bool:
        """Train IsolationForest anomaly detector on existing incident cases."""
        cases = self.session.query(Case).all()
        if len(cases) < 5:
            return False

        feature_matrix = []
        valid_cases = []

        for case in cases:
            alerts = self.session.query(Alert).filter(Alert.case_id == case.id).all()
            if alerts:
                features = self._extract_case_features(case, alerts)
                feature_matrix.append(features)
                valid_cases.append(case)

        if len(feature_matrix) < 5:
            return False

        X = np.array(feature_matrix)

        # Normalize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train IsolationForest
        # contamination = estimated proportion of true severe attack outliers
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.10,
            random_state=42,
        )
        self.model.fit(X_scaled)

        # Save artifacts
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

        return True

    def calculate_ml_score(self, case: Case) -> float:
        """Calculate ML anomaly score (0 to 30 points max)."""
        if self.model is None or self.scaler is None:
            return 0.0

        alerts = self.session.query(Alert).filter(Alert.case_id == case.id).all()
        if not alerts:
            return 0.0

        features = np.array([self._extract_case_features(case, alerts)])
        features_scaled = self.scaler.transform(features)

        # IsolationForest decision_function: lower (negative) values indicate higher anomalies
        raw_anomaly = self.model.decision_function(features_scaled)[0]

        # Map decision function from [-0.5, 0.5] range to [0, 30] points
        # Negative scores = highly anomalous -> higher points
        normalized_anomaly = np.clip(1.0 - (raw_anomaly + 0.3) / 0.6, 0.0, 1.0)
        ml_points = normalized_anomaly * 30.0

        return round(float(ml_points), 2)

    def score_case(self, case: Case) -> dict:
        """Score a single case and persist the results."""
        rule_score = self.calculate_rule_score(case)
        ml_score = self.calculate_ml_score(case)
        total_score = round(min(100.0, rule_score + ml_score), 2)

        # Assign priority tier
        if total_score >= 80:
            priority = "critical"
        elif total_score >= 60:
            priority = "high"
        elif total_score >= 35:
            priority = "medium"
        else:
            priority = "low"

        # Update case record
        case.rule_score = rule_score
        case.ml_score = ml_score
        case.risk_score = total_score
        case.priority = priority

        self.session.commit()

        return {
            "case_id": case.case_id,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "total_score": total_score,
            "priority": priority,
        }

    def score_all_cases(self) -> dict:
        """Evaluate and score all incident cases in the database."""
        cases = self.session.query(Case).all()
        stats = {"total": len(cases), "critical": 0, "high": 0, "medium": 0, "low": 0}

        for case in cases:
            res = self.score_case(case)
            stats[res["priority"]] += 1

        return stats
