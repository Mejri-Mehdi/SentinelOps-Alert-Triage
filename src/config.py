"""Configuration constants, MITRE ATT&CK mappings, and risk scoring weights."""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
PLAYBOOKS_DIR = BASE_DIR / "playbooks"
DB_PATH = BASE_DIR / "sentinelops.db"
MODEL_PATH = BASE_DIR / "models" / "isolation_forest.joblib"
SCALER_PATH = BASE_DIR / "models" / "scaler.joblib"

# Ensure models directory exists
(BASE_DIR / "models").mkdir(exist_ok=True)

# Correlation Parameters
CORRELATION_WINDOW_MINUTES = 10
DEDUPLICATION_WINDOW_MINUTES = 5

# Risk Engine Weights (0 to 100 max composite score)
RULE_WEIGHT = 0.70  # Rules contribute up to 70%
ML_WEIGHT = 0.30    # Machine Learning anomaly detection contributes up to 30%

# Base Severity Points
SEVERITY_POINTS = {
    "critical": 50,
    "high": 35,
    "medium": 20,
    "low": 10,
    "info": 0,
}

# Alert Type Threat Multipliers/Weights
ALERT_TYPE_WEIGHTS = {
    "malware_detected": 30,
    "credential_dumping": 30,
    "data_exfiltration": 30,
    "privilege_escalation": 25,
    "lateral_movement": 25,
    "bad_ip_connection": 20,
    "failed_login": 15,
    "registry_run_key": 15,
    "unusual_process": 10,
    "persistence": 15,
}

# MITRE ATT&CK Enterprise Framework Mapping
MITRE_MAPPING = {
    "failed_login": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "credential_dumping": {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
    },
    "malware_detected": {
        "technique_id": "T1204",
        "technique_name": "User Execution: Malicious File",
        "tactic": "Execution",
    },
    "unusual_process": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "privilege_escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    "registry_run_key": {
        "technique_id": "T1547.001",
        "technique_name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
    },
    "persistence": {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "Persistence",
    },
    "lateral_movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
    },
    "bad_ip_connection": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol: C2",
        "tactic": "Command and Control",
    },
    "data_exfiltration": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
    },
}
