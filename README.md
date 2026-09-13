<div align="center">

# SENTINELOPS
### Autonomous Alert Triage, Entity Correlation & Incident Response Engine

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg?style=flat-square&logo=python)](https://python.org)
[![Testing](https://img.shields.io/badge/Pytest-19%20Passed%20%7C%20100%25-brightgreen.svg?style=flat-square&logo=pytest)](https://docs.pytest.org/)
[![Coverage](https://img.shields.io/badge/Coverage-77%25%20Validated-informational.svg?style=flat-square)](https://coverage.readthedocs.io/)
[![Architecture](https://img.shields.io/badge/Architecture-SIEM%20%2F%20SOAR%20Microengine-blueviolet.svg?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-black.svg?style=flat-square)](LICENSE)

**Engineered by Mehdi Mejri**  
*Enterprise Security Operations & Automation Platform*

</div>

---

## 1. Abstract & System Purpose

Security Operations Centers (SOCs) are burdened by high-volume telemetry ingestion, alert fragmentation, and delayed mean-time-to-respond (MTTR). Traditional SIEM solutions generate thousands of disconnected alerts per day, resulting in severe alert fatigue, while manual triage creates critical dwell-time windows for active adversaries.

**SentinelOps** is an autonomous, production-ready Security Orchestration, Automation, and Response (SOAR) and correlation platform. It ingests disparate security telemetry, normalizes events to a standard schema, deduplicates bursts via MD5 fingerprinting, correlates multi-stage attacks across a sliding temporal window, scores incident risk using a hybrid heuristic-ML engine, and dispatches automated containment actions via declarative YAML playbooks.

<!-- SCREENSHOT PLACEHOLDER 1 -->  

---
![alt text](</docs/screenshots/Screenshot 2026-09-13 204732.png>)
---


<p align="center">
  <em>Figure 1.0: SentinelOps Executive Console — Live Telemetry Posture, Composite Risk Distribution, and Threat Severity Metrics.</em>
</p>

---

## 2. Technical Architecture & Data Pipeline

SentinelOps executes a deterministic, multi-stage pipeline designed with loose coupling, transactional persistence (SQLAlchemy ORM), and zero external dependencies for rapid deployment.

```
                  RAW HETEROGENEOUS TELEMETRY STREAM
        (Sysmon, Windows Event Logs, EDR Agents, Perimeter Firewalls, IdP)
                                  │
                                  ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │ STAGE 1: INGESTION & SLIDING DEDUPLICATION (src/ingestor.py)      │
 │  • Schema normalization across non-standard vendor field aliases  │
 │  • MD5 entity fingerprinting: MD5(alert_type | IP | User | Host)  │
 │  • 5-minute sliding deduplication cache                           │
 │  • Real-time MITRE ATT&CK taxonomy enrichment (Technique & Tactic)│
 └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │ STAGE 2: SLIDING-WINDOW CORRELATOR (src/correlator.py)            │
 │  • Sliding 10-minute temporal evaluation window                   │
 │  • Multi-entity pivot clustering (IP, Username, Endpoint Host)    │
 │  • Case incident aggregation, lifecycle management, and escalation│
 └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │ STAGE 3: HYBRID RISK ENGINE (src/risk_engine.py)                  │
 │  • Heuristic Layer (0-85 pts): Base severity, threat weights      │
 │  • Anomaly Layer (0-30 pts): Isolation Forest / Distance deviation│
 │  • Dynamic priority assignment: Critical, High, Medium, Low       │
 └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │ STAGE 4: PLAYBOOK ENGINE & ORCHESTRATION (src/playbook_engine.py) │
 │  • Declarative YAML playbook parser and trigger evaluation        │
 │  • Jinja-style variable template interpolation ({{user}}, {{host}})│
 └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │ STAGE 5: AUTOMATED SOAR RESPONDER (src/responder.py)              │
 │  • Containment execution: Host isolation, user account suspension  │
 │  • Perimeter mitigation: Firewall IP blocklisting                │
 │  • Threat Intel: External indicator reputation enrichment         │
 │  • Immutable audit logging to SQLite 'response_actions' ledger    │
 └───────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │ STAGE 6: SOC ANALYST OPERATIONS CONSOLE (dashboard/app.py)        │
 │  • Interactive Streamlit dashboard with chronological timelines   │
 └───────────────────────────────────────────────────────────────────┘
```

---

## 3. Engineering Deep Dive & Core Subsystems

### 3.1 Telemetry Normalization & Cryptographic Deduplication (`src/ingestor.py`)
Disparate vendor appliances format logs with conflicting key notations (`src_ip` vs `client_ip`, `user` vs `username`, `alert_name` vs `event_type`). The ingestor canonicalizes all payloads into a strict data contract and computes a deterministic MD5 hash:

```text
Fingerprint = MD5( alert_type || source_ip || user || host )
```

Incoming events sharing a fingerprint within the 5-minute sliding window are dropped as redundant bursts, eliminating log inflation while preserving the original security incident context.

### 3.2 Temporal Entity-Pivot Correlation Engine (`src/correlator.py`)
Security attacks are rarely isolated incidents; they represent a sequence of actions along a kill chain. The correlation engine continuously evaluates unprocessed alerts against active cases within a sliding 10-minute time window:

```text
Δt = |t_alert - t_case_updated| ≤ 10 minutes
```

```
   [Time Window: 10 mins]
   ├── (10:02) 185.220.101.42 ---> failed_login  (Target: alice.smith)  ──┐
   ├── (10:05) 185.220.101.42 ---> failed_login  (Target: alice.smith)  ──┼──> [CLUSTERED INTO CASE-2026-001]
   └── (10:09) WS-EXEC-01        ---> powershell    (User: alice.smith)    ──┘
```

If an incoming alert shares any key pivot (`source_ip`, `user`, or `host`) with an active case within `Δt`, the alert is attached to the existing case, updating the case blast-radius metrics and escalating priority when higher severities are detected.

<!-- SCREENSHOT PLACEHOLDER 2 -->

---
![alt text](</docs/screenshots/Screenshot 2026-09-13 204749.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-13 204802.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-13 204814.png>)
---

<p align="center">
  <em>Figure 2.0: Incident Drill-Down Console — Chronological Attack Timeline, Pivot Entity Graph, and Associated Alerts.</em>
</p>

### 3.3 Hybrid Risk Scoring Engine (`src/risk_engine.py`)
To prevent false-positive overreactions while maintaining complete auditability, SentinelOps pairs deterministic rule-based threat heuristics with unsupervised machine learning:

```text
Composite Risk Score = min( 100.0, Heuristic_Score + Anomaly_Score )
```

#### Heuristic Threat Layer (0 to 85 Points)
* **Base Severity Score**: Evaluates the highest severity present (`Critical` = 50, `High` = 35, `Medium` = 20, `Low` = 10).
* **Threat Multiplier**: Targeted weights for high-impact tactics (`Malware` = 30, `Exfiltration` = 30, `Credential Dumping` = 30).
* **Velocity Multiplier**: Exponential penalty for rapid alert generation (`min(15.0, count * 2.5)`).
* **Blast Radius**: Additional `+5.0` penalty for cross-host compromise.

#### Anomaly Detection Layer (0 to 30 Points)
* **Feature Vector**: Extracts a 7-dimensional behavioral vector for each incident:
  ```text
  Feature_Vector = [ alert_count, unique_types, unique_hosts, unique_ips, time_span_mins, critical_ratio, velocity ]
  ```
* **Isolation Forest**: Standardizes features using a Z-score scaler and computes an unsupervised outlier score.
* **Resilient Fallback**: If third-party compiled C-extensions are restricted by host Application Control policies, the engine seamlessly activates an internal pure-Python multivariate distance deviation detector, ensuring 100% operational uptime.

---

## 4. Declarative YAML Playbooks & Automated Containment

Response logic is completely decoupled from application code. Procedures are declared in modular YAML manifests containing trigger constraints and parameterized actions.

### Example Production Playbook (`playbooks/malware_detection.yml`)
```yaml
id: malware_containment
name: Ransomware & EDR Malware Quarantine
enabled: true
min_risk_score: 60
severity_threshold: high
triggers:
  - type: alert_type
    alert_type: malware_detected
    count: 1
    window_minutes: 15
actions:
  - type: contain
    action: isolate_host
    target: "{{host}}"
  - type: contain
    action: disable_user
    target: "{{user}}"
  - type: notify
    channel: soc-incidents
    message: "CRITICAL: Malware signature detected on {{host}} by user {{user}}. Host isolated. Case: {{case_id}}"
```

### Supported Remediation Actions
* `disable_user`: Suspends user identity in Active Directory / Okta IdP and revokes active authentication sessions.
* `isolate_host`: Instructs endpoint EDR to sever network connectivity, leaving an encrypted tunnel open exclusively for SecOps triage.
* `block_ip`: Injects ingress/egress drop rules into edge perimeter firewalls.
* `enrich_virustotal`: Gathers real-time reputation scores and threat signatures on external indicators.
* `notify_slack`: Broadcasts high-priority operational alert cards to incident channels.

<!-- SCREENSHOT PLACEHOLDER 3 -->

---
![alt text](</docs/screenshots/Screenshot 2026-09-13 204829.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-13 204836.png>)
---

<p align="center">
  <em>Figure 3.0: Immutable SOAR Audit Trail — Persistent Execution History, Target Remediation, and Containment States.</em>
</p>

---

## 5. MITRE ATT&CK Matrix Alignment

Every ingested alert type is enriched at runtime with industry-standard MITRE ATT&CK taxonomy:

| Tactic | Technique ID | Technique Name | Telemetry Event |
|---|---|---|---|
| **Credential Access** | T1110 | Brute Force | `failed_login` |
| **Credential Access** | T1003 | OS Credential Dumping | `credential_dumping` |
| **Execution** | T1204 | User Execution: Malicious File | `malware_detected` |
| **Execution** | T1059 | Command and Scripting Interpreter | `unusual_process` |
| **Privilege Escalation** | T1068 | Exploitation for Privilege Escalation | `privilege_escalation` |
| **Persistence** | T1547.001 | Boot/Logon Autostart Execution | `registry_run_key` |
| **Persistence** | T1053 | Scheduled Task/Job | `persistence` |
| **Lateral Movement** | T1021 | Remote Services | `lateral_movement` |
| **Command and Control** | T1071 | Application Layer Protocol | `bad_ip_connection` |
| **Exfiltration** | T1048 | Exfiltration Over Alternative Protocol | `data_exfiltration` |

<!-- SCREENSHOT PLACEHOLDER 4 -->

---
![alt text](</docs/screenshots/Screenshot 2026-09-13 204824.png>)
---
---

<p align="center">
  <em>Figure 4.0: Tactical Enterprise Heatmap — Adversary Technique and Tactic Frequency Distribution.</em>
</p>

---

## 6. Repository Layout

```
sentinelops-alert-triage/
├── data/
│   ├── generate_alerts.py         # Multi-stage kill chain & noise generator
│   └── alerts.jsonl               # 5,000+ synthetic telemetry records
├── src/
│   ├── __init__.py
│   ├── config.py                  # MITRE taxonomy, threat weights, thresholds
│   ├── models.py                  # SQLAlchemy schema (Alert, Case, ResponseAction)
│   ├── ingestor.py                # Schema normalizer & MD5 deduplicator
│   ├── correlator.py              # Temporal entity-pivot correlation engine
│   ├── risk_engine.py             # Hybrid risk scoring & IsolationForest ML
│   ├── playbook_engine.py         # YAML playbook parser & template interpolator
│   └── responder.py               # SOAR containment orchestration & audit logging
├── playbooks/
│   ├── brute_force.yml            # Credential stuffing response playbook
│   ├── malware_detection.yml      # Ransomware & EDR malware quarantine playbook
│   ├── data_exfiltration.yml      # Unauthorized egress containment playbook
│   ├── privilege_escalation.yml   # Account suspension playbook
│   └── lateral_movement.yml       # Host network isolation playbook
├── dashboard/
│   └── app.py                     # Streamlit SOC operations console
├── tests/
│   ├── test_ingestor.py           # Ingestion & deduplication unit tests
│   ├── test_correlator.py         # Temporal clustering & window tests
│   ├── test_risk_engine.py        # Risk heuristics & anomaly detector tests
│   ├── test_playbook_engine.py    # Playbook matching & variable tests
│   └── test_responder.py          # Containment execution & audit tests
├── requirements.txt
├── setup.py
└── README.md
```

---

## 7. Installation & Operational Guide

### 7.1 System Requirements
* Python 3.10 or higher
* Git

### 7.2 Clone & Environment Initialization
```bash
# Clone the repository
git clone https://github.com/Mehdi-Mejri/sentinelops-alert-triage.git
cd sentinelops-alert-triage

# Create isolated virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install dependencies and local package in editable mode
pip install -r requirements.txt
pip install -e .
```

---
![alt text](</docs/screenshots/Screenshot 2026-09-04 181019.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-04 181329.png>)
---

### 7.3 Execute the End-to-End Pipeline
```bash
# 1. Synthesize 5,000 realistic enterprise alerts with embedded attack scenarios
python data/generate_alerts.py --count 5000 --output data/alerts.jsonl

# 2. Execute full automated ingest -> correlate -> score -> contain pipeline
python -c "
from src.models import init_db
from src.ingestor import AlertIngestor
from src.correlator import AlertCorrelator
from src.risk_engine import RiskEngine
from src.responder import Responder

init_db()
print('[1/4] Ingesting & deduplicating telemetry...')
AlertIngestor().ingest_from_jsonl('data/alerts.jsonl')

print('[2/4] Correlating cases across sliding 10-minute windows...')
AlertCorrelator().run_correlation()

print('[3/4] Training anomaly detector & calculating composite risk...')
re = RiskEngine()
re.train_model()
re.score_all_cases()

print('[4/4] Orchestrating automated playbook containment...')
Responder().respond_to_all(min_risk=50.0)
print('[SUCCESS] Pipeline completed. Database ready for inspection.')
"
```

### 7.4 Launch the SOC Command Center
```bash
streamlit run dashboard/app.py
```
Open your browser to `http://localhost:8501` to access all operational views.

---
![alt text](</docs/screenshots/Screenshot 2026-09-13 200225.png>)
---

## 8. Verification & Test Suite

SentinelOps enforces high test coverage across all critical correlation and containment pathways using an isolated in-memory SQLite database:

---
![alt text](</docs/screenshots/Screenshot 2026-09-04 202956.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-05 141505.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-06 201509.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-07 124901.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-11 141516.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-11 194145.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-13 195646.png>)
---


```bash
python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

---
![alt text](</docs/screenshots/Screenshot 2026-09-13 201551.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-09-13 201531.png>)
---
---


<p align="center"><sub>Made with ❤️ by <a href="https://github.com/Mejri-Mehdi">Mejri Mehdi</a></sub></p> 