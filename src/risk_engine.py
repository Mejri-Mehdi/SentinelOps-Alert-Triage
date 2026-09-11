"""Hybrid Risk Scoring Engine.

Combines deterministic rule-based threat heuristics with anomaly detection.
Features a resilient fallback architecture: uses Scikit-Learn IsolationForest
when available, or a pure-Python Statistical Anomaly Detector if native C-DLLs
are restricted by Windows Application Control policies.
"""

import math
import pickle
from datetime import datetime
from pathlib import Path
from typing import Optional

# Resilient import: fallback if Windows AppControl blocks Scipy/Sklearn C-extensions
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except (ImportError, Exception):
    SKLEARN_AVAILABLE = False

try:
    import joblib
except ImportError:
    joblib = pickle

from sqlalchemy.orm import Session

from src.config import (
    ALERT_TYPE_WEIGHTS,
    MODEL_PATH,
    SCALER_PATH,
)
from src.models import Alert, Case, get_engine, get_session


# -------------------------------------------------------------------------
# Resilient Pure-Python Fallbacks (immune to Windows DLL / AppLocker blocks)
# -------------------------------------------------------------------------

class SimpleScaler:
    """Standardizes features (zero mean, unit variance) using pure Python."""

    def __init__(self):
        self.mean_ = []
        self.scale_ = []

    def fit_transform(self, X: list[list[float]]) -> list[list[float]]:
        if not X:
            return X
        n_samples = len(X)
        n_features = len(X[0])

        self.mean_ = [sum(X[i][j] for i in range(n_samples)) / n_samples for j in range(n_features)]
        self.scale_ = []
        for j in range(n_features):
            variance = sum((X[i][j] - self.mean_[j]) ** 2 for i in range(n_samples)) / n_samples
            std = math.sqrt(variance)
            self.scale_.append(std if std > 1e-6 else 1.0)

        return self.transform(X)

    def transform(self, X: list[list[float]]) -> list[list[float]]:
        return [
            [(X[i][j] - self.mean_[j]) / self.scale_[j] for j in range(len(self.mean_))]
            for i in range(len(X))
        ]


class StatisticalAnomalyDetector:
    """Multivariate statistical anomaly detector matching the IsolationForest interface.
    
    Measures standardized Euclidean distance from the operational centroid.
    Normal events produce positive decision values; outliers produce negative values.
    """

    def __init__(self, contamination: float = 0.10, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.threshold_ = 0.0

    def fit(self, X_scaled: list[list[float]]):
        if not X_scaled:
            return self
        distances = [math.sqrt(sum(v ** 2 for v in row)) for row in X_scaled]
        distances.sort()
        # Threshold at (1 - contamination) percentile
        idx = int(len(distances) * (1.0 - self.contamination))
        idx = min(idx, len(distances) - 1)
        self.threshold_ = distances[idx]
        return self

    def decision_function(self, X_scaled: list[list[float]]) -> list[float]:
        results = []
        for row in X_scaled:
            dist = math.sqrt(sum(v ** 2 for v in row))
            # If distance exceeds threshold, returns negative (anomalous)
            raw = (self.threshold_ - dist) / (self.threshold_ + 1e-5)
            results.append(raw)
        return results


# -------------------------------------------------------------------------
# Risk Engine Core
# -------------------------------------------------------------------------

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
        self.model = None
        self.scaler = None
        self._load_model()

    def _load_model(self):
        """Load trained model and scaler if available."""
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

        # 1. Base Severity Score
        sev_rank = {"critical": 50, "high": 35, "medium": 20, "low": 10, "info": 0}
        base_sev_score = max(sev_rank.get(a.severity.lower(), 10) for a in alerts)

        # 2. Threat Category Weight
        threat_type_score = max(ALERT_TYPE_WEIGHTS.get(a.alert_type, 5) for a in alerts)

        # 3. Volume Burst Multiplier
        count = len(alerts)
        volume_boost = min(15.0, math.log2(count + 1) * 3.5)

        # 4. Multi-Entity Blast Radius Bonus
        unique_hosts = len({a.host for a in alerts if a.host})
        blast_bonus = 5.0 if unique_hosts > 1 else 0.0

        raw_score = (base_sev_score * 0.45) + (threat_type_score * 0.35) + volume_boost + blast_bonus
        return min(70.0, round(raw_score, 2))

    def _extract_case_features(self, case: Case, alerts: list[Alert]) -> list[float]:
        """Extract numerical feature vector representing case behavior."""
        alert_count = len(alerts)
        unique_types = len({a.alert_type for a in alerts})
        unique_hosts = len({a.host for a in alerts if a.host})
        unique_ips = len({a.source_ip for a in alerts if a.source_ip})

        timestamps = [a.timestamp for a in alerts]
        if len(timestamps) > 1:
            time_span_mins = max(0.1, (max(timestamps) - min(timestamps)).total_seconds() / 60.0)
        else:
            time_span_mins = 0.5

        crit_count = sum(1 for a in alerts if a.severity.lower() in ["critical", "high"])
        critical_ratio = crit_count / max(1, alert_count)
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
        """Train anomaly detector on existing incident cases."""
        cases = self.session.query(Case).all()
        if len(cases) < 5:
            return False

        feature_matrix = []
        for case in cases:
            alerts = self.session.query(Alert).filter(Alert.case_id == case.id).all()
            if alerts:
                features = self._extract_case_features(case, alerts)
                feature_matrix.append(features)

        if len(feature_matrix) < 5:
            return False

        if SKLEARN_AVAILABLE:
            import numpy as np
            X = np.array(feature_matrix)
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            self.model = IsolationForest(n_estimators=100, contamination=0.10, random_state=42)
            self.model.fit(X_scaled)
        else:
            # Pure Python resilient path
            self.scaler = SimpleScaler()
            X_scaled = self.scaler.fit_transform(feature_matrix)
            self.model = StatisticalAnomalyDetector(contamination=0.10, random_state=42)
            self.model.fit(X_scaled)

        # Save artifacts
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

        return True

    def calculate_ml_score(self, case: Case) -> float:
        """Calculate anomaly score (0 to 30 points max)."""
        if self.model is None or self.scaler is None:
            return 0.0

        alerts = self.session.query(Alert).filter(Alert.case_id == case.id).all()
        if not alerts:
            return 0.0

        features = [self._extract_case_features(case, alerts)]

        if SKLEARN_AVAILABLE:
            import numpy as np
            features_scaled = self.scaler.transform(np.array(features))
            raw_anomaly = float(self.model.decision_function(features_scaled)[0])
        else:
            features_scaled = self.scaler.transform(features)
            raw_anomaly = float(self.model.decision_function(features_scaled)[0])

        # Map decision function: negative values = highly anomalous -> higher points
        normalized_anomaly = max(0.0, min(1.0, 1.0 - (raw_anomaly + 0.3) / 0.6))
        ml_points = normalized_anomaly * 30.0

        return round(float(ml_points), 2)

    def score_case(self, case: Case) -> dict:
        """Score a single case and persist the results."""
        rule_score = self.calculate_rule_score(case)
        ml_score = self.calculate_ml_score(case)
        total_score = round(min(100.0, rule_score + ml_score), 2)

        if total_score >= 80:
            priority = "critical"
        elif total_score >= 60:
            priority = "high"
        elif total_score >= 35:
            priority = "medium"
        else:
            priority = "low"

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
