# SentinelOps: AI-Powered Alert Triage & Automated Incident Response Platform

**Author:** Mehdi Mejri  
**Target Role:** Information Security Operations / SecOps Engineering  
**Core Technologies:** Python 3, SQLAlchemy, Scikit-Learn, Pandas, Plotly, Streamlit, PyYAML, Pytest  

---

## 1. Executive Summary

Modern Security Operations Centers (SOCs) face critical operational bottlenecks driven by alert fatigue, disparate telemetry formats, and delayed incident containment. **SentinelOps** is an end-to-end Security Orchestration, Automation, and Response (SOAR) and mini-SIEM engine designed to bridge the gap between raw detection telemetry and immediate remediation.

The platform executes a deterministic five-stage pipeline:
1. **Telemetry Ingestion & Deduplication**: Canonical normalization across multi-vendor schemas and MD5 sliding-window deduplication.
2. **Entity Correlation Engine**: Sliding-window temporal aggregation across shared network, host, and identity pivots (`source_ip`, `user`, `host`).
3. **Hybrid Risk Engine**: Deterministic threat heuristic scoring combined with unsupervised multivariate anomaly detection (`IsolationForest` / standardized Euclidean deviation).
4. **Declarative Playbook Orchestration**: Context-aware YAML playbooks with dynamic variable interpolation for targeted containment.
5. **Audited Remediation & Threat Intelligence**: Automated containment execution (identity revocation, endpoint quarantine, network blocking, and reputation enrichment) backed by an immutable SQLite audit log.

<!-- SCREENSHOT: Executive Dashboard Overview -->
<!-- Replace with your screenshot: ![SentinelOps Overview](docs/screenshots/overview.png) -->
> *Figure 1.0: SentinelOps Executive Dashboard displaying live threat posture, risk distribution, and severity breakdown.*

---

## 2. System Architecture & Pipeline Data Flow

The platform separates ingestion, correlation, risk modeling, and response execution into decoupled, testable layers:

```
+-------------------------------------------------------------------------+
|                           INCOMING TELEMETRY                            |
|             (Endpoint EDR, Identity IdP, Network Perimeter)             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| 1. ALERT INGESTOR & DEDUPLICATION (src/ingestor.py)                     |
|    - Schema normalization across disparate vendor fields                |
|    - MD5 entity fingerprinting (alert_type | source_ip | user | host)    |
|    - 5-minute sliding deduplication window                              |
|    - Automated MITRE ATT&CK taxonomy enrichment                         |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| 2. SLIDING-WINDOW CORRELATOR (src/correlator.py)                        |
|    - 10-minute sliding correlation window                               |
|    - Entity pivot clustering (IP, User, Host)                           |
|    - Case creation and state lifecycle management                       |
|    - Priority escalation based on threat progression                    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| 3. HYBRID RISK SCORING ENGINE (src/risk_engine.py)                      |
|    - Heuristic Layer (0-85 pts): Severity base, threat weight, volume   |
|    - ML Anomaly Layer (0-30 pts): Isolation Forest / Distance deviation|
|    - Composite Risk Normalization (0-100 pts) & Priority Tiers          |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| 4. PLAYBOOK ORCHESTRATOR & RESPONDER (src/playbook_engine.py & responder)|
|    - Declarative YAML Playbook evaluation (trigger conditions & windows)|
|    - Dynamic variable resolution ({{user}}, {{host}}, {{source_ip}})    |
|    - Automated action execution (disable user, isolate host, block IP)  |
|    - Immutable persistence in ResponseAction audit table                |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| 5. SOC OPERATIONS DASHBOARD (dashboard/app.py)                          |
|    - Real-time telemetry feed, case drill-down, MITRE coverage heatmap  |
+-------------------------------------------------------------------------+
```

---

## 3. Core Subsystems

### 3.1 Alert Ingestor & Sliding Deduplication (`src/ingestor.py`)
Disparate security solutions output non-standard telemetry schemas (e.g., `src_ip` vs. `source_ip` vs. `client_ip`). The `AlertIngestor` maps incoming events to an internal canonical format and generates an MD5 cryptographic fingerprint:

$$\text{Fingerprint} = \text{MD5}(\text{alert\_type} \parallel \text{source\_ip} \parallel \text{user} \parallel \text{host})$$

If an identical fingerprint arrives within a 5-minute sliding window, the event is flagged as redundant noise and suppressed, preventing alert fatigue and database inflation.

### 3.2 Sliding-Window Correlation Engine (`src/correlator.py`)
Rather than forcing analysts to examine thousands of isolated alerts, the `AlertCorrelator` evaluates events across a sliding 10-minute temporal window. Events sharing common pivot entities are aggregated into a single unified `Case`:
- **Identity Pivot (`user`)**: Correlates credential stuffing on a workstation with subsequent privileged account usage on a server.
- **Endpoint Pivot (`host`)**: Chains suspicious PowerShell invocations to malware execution and subsequent persistence registry keys.
- **Network Pivot (`source_ip`)**: Links perimeter port scanning, credential brute-forcing, and external command-and-control (C2) beaconing.

### 3.3 Hybrid Risk Scoring Engine (`src/risk_engine.py`)
To prevent the opacity of pure black-box ML while avoiding the brittleness of pure rule sets, SentinelOps implements a dual-layer scoring architecture:

1. **Heuristic Threat Layer (Up to 85 points)**:
   - **Base Severity**: Critical (+50), High (+35), Medium (+20), Low (+10).
   - **Threat Category Multiplier**: Targeted weights for high-impact techniques (Ransomware, Data Exfiltration, LSASS Credential Dumping).
   - **Burst Velocity Multiplier**: Scaled linear boost based on alert frequency over the case duration.
   - **Blast Radius Bonus**: Penalty for incidents impacting multiple hosts or network segments.

2. **Unsupervised Anomaly Layer (Up to 30 points)**:
   - Extracts 7-dimensional behavioral feature vectors: `[alert_count, unique_types, unique_hosts, unique_ips, time_span_mins, critical_ratio, velocity]`.
   - Employs an `IsolationForest` model (with an automated fallback to multivariate statistical distance in environments where native C-extensions are restricted by security policies).
   - Persists trained estimators via `joblib`.

3. **Composite Scoring & Triage Tiers**:
   - **Critical** ($\ge 80$): Immediate automated containment triggered.
   - **High** ($60 - 79$): Escalated to Tier-2 SOC queue with automated enrichment.
   - **Medium** ($35 - 59$): Queued for routine triage.
   - **Low** ($< 35$): Logged for threat hunting and baseline auditing.

<!-- SCREENSHOT: Incident Cases Drill-down & Timeline -->
<!-- Replace with your screenshot: ![Case Timeline](docs/screenshots/case_investigation.png) -->
> *Figure 2.0: Incident Case Investigation view showing correlated attack progression, pivot entity tracking, and linked playbooks.*

### 3.4 Declarative Playbooks & Automated SOAR Responder (`src/responder.py`)
Incident response procedures are defined in declarative YAML playbooks within `playbooks/`. The Playbook Engine dynamically interpolates case attributes into executable actions:

```yaml
id: brute_force_response
name: Brute Force & Credential Stuffing Containment
enabled: true
min_risk_score: 45
triggers:
  - type: alert_type
    alert_type: failed_login
    count: 5
    window_minutes: 10
actions:
  - type: notify
    channel: slack
    message: "Brute force attack detected against user {{user}} from IP {{source_ip}} (Case: {{case_id}})"
  - type: contain
    action: disable_user
    target: "{{user}}"
  - type: enrich
    source: virustotal
    query: "{{source_ip}}"
  - type: contain
    action: block_ip
    target: "{{source_ip}}"
```

The responder executes these actions safely in simulation mode, updating case status to `contained` and recording full execution parameters to the `response_actions` audit log.

<!-- SCREENSHOT: Automated SOAR Actions Audit -->
<!-- Replace with your screenshot: ![SOAR Audit Trail](docs/screenshots/soar_audit.png) -->
> *Figure 3.0: Immutable audit log tracking executed containment actions across identity, endpoint, and network perimeters.*

---

## 4. MITRE ATT&CK Framework Mapping

SentinelOps natively aligns with the MITRE ATT&CK Enterprise Matrix to give security leadership immediate insight into detection coverage:

| Tactic | Technique ID | Technique Name | Mapped Telemetry Event |
|---|---|---|---|
| **Credential Access** | T1110 | Brute Force | `failed_login` |
| **Credential Access** | T1003 | OS Credential Dumping | `credential_dumping` |
| **Execution** | T1204 | User Execution: Malicious File | `malware_detected` |
| **Execution** | T1059 | Command and Scripting Interpreter | `unusual_process` |
| **Privilege Escalation** | T1068 | Exploitation for Privilege Escalation | `privilege_escalation` |
| **Persistence** | T1547.001 | Registry Run Keys / Startup Folder | `registry_run_key` |
| **Persistence** | T1053 | Scheduled Task/Job | `persistence` |
| **Lateral Movement** | T1021 | Remote Services | `lateral_movement` |
| **Command and Control** | T1071 | Application Layer Protocol | `bad_ip_connection` |
| **Exfiltration** | T1048 | Exfiltration Over Alternative Protocol | `data_exfiltration` |

<!-- SCREENSHOT: MITRE ATT&CK Heatmap -->
<!-- Replace with your screenshot: ![MITRE Matrix Heatmap](docs/screenshots/mitre_coverage.png) -->
> *Figure 4.0: Tactical distribution and detection coverage mapped against the MITRE ATT&CK framework.*

---

## 5. Repository Structure

```
sentinelops-alert-triage/
├── data/
│   ├── generate_alerts.py         # Multi-stage attack chain & noise generator
│   └── alerts.jsonl               # 5,000+ synthetic telemetry records
├── src/
│   ├── __init__.py
│   ├── config.py                  # MITRE mappings, risk weights, and thresholds
│   ├── models.py                  # SQLAlchemy ORM schema (Alert, Case, ResponseAction)
│   ├── ingestor.py                # Normalization & MD5 deduplication engine
│   ├── correlator.py              # Sliding-window entity correlation engine
│   ├── risk_engine.py             # Hybrid risk scoring & anomaly detection
│   ├── playbook_engine.py         # Declarative YAML playbook parser & matcher
│   └── responder.py               # SOAR containment orchestration & audit logging
├── playbooks/
│   ├── brute_force.yml            # Credential stuffing response playbook
│   ├── malware_detection.yml      # Ransomware & EDR malware isolation playbook
│   ├── data_exfiltration.yml      # Exfiltration containment playbook
│   ├── privilege_escalation.yml   # Account suspension playbook
│   └── lateral_movement.yml       # Host quarantine playbook
├── dashboard/
│   └── app.py                     # Streamlit SOC operations command center
├── tests/
│   ├── test_ingestor.py           # Ingestor & deduplication unit tests
│   ├── test_correlator.py         # Temporal correlation & window boundary tests
│   ├── test_risk_engine.py        # Risk heuristics & anomaly detector tests
│   ├── test_playbook_engine.py    # Playbook trigger & variable resolution tests
│   └── test_responder.py          # Action execution & audit trail persistence tests
├── requirements.txt
├── setup.py
└── README.md
```

---

## 6. Installation & Quick Start

### 6.1 Prerequisites
- Python 3.10+
- Git

### 6.2 Setup Environment
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sentinelops-alert-triage.git
cd sentinelops-alert-triage

# Initialize virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install dependencies and local package
pip install -r requirements.txt
pip install -e .
```

### 6.3 Execute End-to-End Pipeline
```bash
# Step 1: Generate 5,000 synthetic attack & noise alerts
python data/generate_alerts.py --count 5000 --output data/alerts.jsonl

# Step 2: Ingest, Correlate, Score, and Auto-Respond via Python CLI
python -c "
from src.models import init_db
from src.ingestor import AlertIngestor
from src.correlator import AlertCorrelator
from src.risk_engine import RiskEngine
from src.responder import Responder

init_db()
print('[1/4] Ingesting telemetry...')
AlertIngestor().ingest_from_jsonl('data/alerts.jsonl')

print('[2/4] Correlating cases...')
AlertCorrelator().run_correlation()

print('[3/4] Training model & scoring risk...')
re = RiskEngine()
re.train_model()
re.score_all_cases()

print('[4/4] Executing automated SOAR playbooks...')
Responder().respond_to_all(min_risk=50.0)
print('[✓] Pipeline executed successfully.')
"
```

### 6.4 Launch Interactive SOC Console
```bash
streamlit run dashboard/app.py
```
Access the console at `http://localhost:8501`.

---

## 7. Verification & Automated Testing

SentinelOps maintains an isolated in-memory testing suite with zero external side effects:

```bash
python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

### Test Coverage Highlights
- **Ingestion**: Normalization of non-standard field aliases and validation of 5-minute MD5 deduplication windows.
- **Correlation**: Verification of cross-entity IP/User/Host clustering and sliding-window boundary isolation.
- **Risk Scoring**: Validation that multi-alert critical malware chains trigger >= 80 (Critical tier) and model serialization integrity.
- **Playbooks**: Exact trigger evaluation, window timing, and variable template interpolation.
- **Responder**: Audit log verification and mock containment state updates.

---

## 8. Alignment with Revolut SecOps Engineering

This project directly addresses the operational requirements outlined in Revolut's Information Security Operations profile:

| Revolut Focus Area | SentinelOps Implementation Evidence |
|---|---|
| **Security Platform Capabilities** | Engineered modular, production-ready micro-engine architecture for ingestion, correlation, and response. |
| **Threat Monitoring & Analysis** | 10-minute entity-pivot correlator transforms noisy raw logs into coherent incident cases with full chronological timelines. |
| **Incident Response & Vulnerability Containment** | Declarative YAML playbooks automate containment (identity locking, endpoint quarantine, network blocking). |
| **Data-Driven Risk Detection** | Hybrid scoring combining expert threat heuristics with multivariate anomaly detection on high-dimensional behavioral features. |
| **Software Engineering Standards** | PEP8-compliant Python, SQLAlchemy ORM persistence, comprehensive Pytest suite, and modular design. |

---

## 9. License

This project is licensed under the MIT License — designed for educational demonstration and portfolio evaluation.
