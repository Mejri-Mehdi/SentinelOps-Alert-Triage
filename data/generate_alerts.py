"""Synthetic Security Alert Generator.

Simulates enterprise security telemetry with realistic attack scenarios:
- Brute force bursts
- Malware infection & C2 chains
- Lateral movement sequences
- Background enterprise noise
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path


# Entity Pools
ATTACKER_IPS = [
    "185.220.101.42",
    "194.26.29.112",
    "45.154.255.89",
    "193.142.59.81",
    "91.240.118.172",
]

INTERNAL_IPS = [f"10.0.{subnet}.{host}" for subnet in [1, 2, 5, 10] for host in range(10, 100)]

USERS = [
    "alice.smith",
    "bob.jones",
    "charlie.davis",
    "david.miller",
    "eve.johnson",
    "frank.wright",
    "grace.hopper",
    "admin",
    "svc_backup",
    "svc_deploy",
]

HOSTS = [
    "WS-EXEC-01",
    "WS-ENG-04",
    "WS-FIN-02",
    "WS-HR-07",
    "SRV-DC-01",
    "SRV-APP-02",
    "SRV-DB-01",
    "SRV-FILE-03",
]


def make_alert(
    timestamp: datetime,
    alert_type: str,
    severity: str,
    source_ip: str,
    user: str,
    host: str,
    description: str,
) -> dict:
    """Helper to construct a standardized alert record."""
    return {
        "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": timestamp.isoformat(),
        "severity": severity,
        "source_ip": source_ip,
        "user": user,
        "host": host,
        "alert_type": alert_type,
        "description": description,
    }


def generate_brute_force_scenario(base_time: datetime) -> list[dict]:
    """Simulates a rapid credential stuffing or brute force attack."""
    alerts = []
    attacker = random.choice(ATTACKER_IPS)
    target_user = random.choice(USERS[:6])
    target_host = random.choice(HOSTS)
    burst_count = random.randint(15, 30)

    for i in range(burst_count):
        t = base_time + timedelta(seconds=random.randint(2, 8) * i)
        alerts.append(
            make_alert(
                timestamp=t,
                alert_type="failed_login",
                severity="medium" if i < 10 else "high",
                source_ip=attacker,
                user=target_user,
                host=target_host,
                description=f"Multiple failed authentication attempts detected for user {target_user} from {attacker}",
            )
        )
    return alerts


def generate_malware_scenario(base_time: datetime) -> list[dict]:
    """Simulates multi-stage malware execution, persistence, C2, and exfiltration."""
    alerts = []
    victim_user = random.choice(USERS[:5])
    victim_host = random.choice(HOSTS[:4])
    c2_ip = random.choice(ATTACKER_IPS)
    internal_ip = random.choice(INTERNAL_IPS)

    # Step 1: User execution / suspicious process
    t1 = base_time
    alerts.append(
        make_alert(
            timestamp=t1,
            alert_type="unusual_process",
            severity="medium",
            source_ip=internal_ip,
            user=victim_user,
            host=victim_host,
            description=f"Suspicious PowerShell invocation with encoded command by {victim_user}",
        )
    )

    # Step 2: Malware detection on host
    t2 = t1 + timedelta(minutes=random.randint(1, 3))
    alerts.append(
        make_alert(
            timestamp=t2,
            alert_type="malware_detected",
            severity="critical",
            source_ip=internal_ip,
            user=victim_user,
            host=victim_host,
            description=f"EDR flagged known ransomware payload signature on {victim_host}",
        )
    )

    # Step 3: Persistence mechanism installed
    t3 = t2 + timedelta(minutes=random.randint(1, 4))
    alerts.append(
        make_alert(
            timestamp=t3,
            alert_type="registry_run_key",
            severity="high",
            source_ip=internal_ip,
            user=victim_user,
            host=victim_host,
            description=f"Suspicious Run key modified in registry under CurrentVersion\\Run on {victim_host}",
        )
    )

    # Step 4: C2 Communication
    t4 = t3 + timedelta(minutes=random.randint(2, 5))
    alerts.append(
        make_alert(
            timestamp=t4,
            alert_type="bad_ip_connection",
            severity="high",
            source_ip=c2_ip,
            user=victim_user,
            host=victim_host,
            description=f"Outbound connection attempt to known Command & Control IP {c2_ip}",
        )
    )

    # Step 5: Data Exfiltration
    t5 = t4 + timedelta(minutes=random.randint(3, 8))
    alerts.append(
        make_alert(
            timestamp=t5,
            alert_type="data_exfiltration",
            severity="critical",
            source_ip=c2_ip,
            user=victim_user,
            host=victim_host,
            description=f"Large volume (1.8 GB) encrypted egress transfer initiated to external destination {c2_ip}",
        )
    )

    return alerts


def generate_lateral_movement_scenario(base_time: datetime) -> list[dict]:
    """Simulates credential dumping and moving laterally across servers."""
    alerts = []
    comp_user = "admin"
    initial_host = "WS-ENG-04"
    server_targets = ["SRV-APP-02", "SRV-DC-01", "SRV-DB-01"]

    # Step 1: Credential dumping on first host
    t1 = base_time
    alerts.append(
        make_alert(
            timestamp=t1,
            alert_type="credential_dumping",
            severity="critical",
            source_ip=random.choice(INTERNAL_IPS),
            user=comp_user,
            host=initial_host,
            description=f"LSASS memory read access detected on {initial_host} indicative of Mimikatz activity",
        )
    )

    # Step 2: Privilege escalation
    t2 = t1 + timedelta(minutes=random.randint(2, 5))
    alerts.append(
        make_alert(
            timestamp=t2,
            alert_type="privilege_escalation",
            severity="high",
            source_ip=random.choice(INTERNAL_IPS),
            user=comp_user,
            host=initial_host,
            description=f"Privilege token impersonation detected elevation to SYSTEM on {initial_host}",
        )
    )

    # Step 3: Lateral hops to servers
    for idx, target in enumerate(server_targets):
        t_hop = t2 + timedelta(minutes=random.randint(3, 7) * (idx + 1))
        alerts.append(
            make_alert(
                timestamp=t_hop,
                alert_type="lateral_movement",
                severity="high",
                source_ip=random.choice(INTERNAL_IPS),
                user=comp_user,
                host=target,
                description=f"Remote administrative connection established via WinRM to {target} using compromised admin token",
            )
        )

    return alerts


def generate_background_noise(timestamp: datetime) -> dict:
    """Generates typical, non-correlated low-to-medium enterprise alerts."""
    noise_profiles = [
        ("failed_login", "low", "Single failed login attempt due to expired password"),
        ("unusual_process", "low", "Developer ran custom Python script from local directory"),
        ("bad_ip_connection", "medium", "Traffic to newly registered domain blocked by firewall"),
        ("persistence", "low", "System update scheduled task registered by Windows Update"),
    ]
    alert_type, severity, desc = random.choice(noise_profiles)

    return make_alert(
        timestamp=timestamp,
        alert_type=alert_type,
        severity=severity,
        source_ip=random.choice(INTERNAL_IPS + ATTACKER_IPS),
        user=random.choice(USERS),
        host=random.choice(HOSTS),
        description=desc,
    )


def generate_dataset(total_count: int, output_path: str):
    """Generates the full dataset with mixed scenarios and writes to JSONL."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    start_time = datetime.utcnow() - timedelta(days=2)
    alerts = []

    print(f"[*] Generating target {total_count} synthetic alerts...")

    # 1. Generate realistic attack chains
    num_scenarios = total_count // 50
    for _ in range(num_scenarios):
        scenario_time = start_time + timedelta(
            minutes=random.randint(0, 48 * 60)
        )
        choice = random.random()
        if choice < 0.45:
            alerts.extend(generate_brute_force_scenario(scenario_time))
        elif choice < 0.80:
            alerts.extend(generate_malware_scenario(scenario_time))
        else:
            alerts.extend(generate_lateral_movement_scenario(scenario_time))

    # 2. Fill the rest with background enterprise noise
    while len(alerts) < total_count:
        noise_time = start_time + timedelta(minutes=random.randint(0, 48 * 60))
        alerts.append(generate_background_noise(noise_time))

    # Sort all alerts chronologically (as they would arrive at the SIEM)
    alerts.sort(key=lambda a: a["timestamp"])

    # Write JSONL
    with open(path, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")

    print(f"[+] Successfully wrote {len(alerts)} alerts to {path}")

    # Display breakdown
    severities = {}
    types = {}
    for a in alerts:
        severities[a["severity"]] = severities.get(a["severity"], 0) + 1
        types[a["alert_type"]] = types.get(a["alert_type"], 0) + 1

    print("\n--- Telemetry Breakdown ---")
    print("Severity Distribution:")
    for sev, count in sorted(severities.items()):
        print(f"  {sev.upper():<10}: {count:>5} ({count/len(alerts)*100:.1f}%)")

    print("\nTop Alert Types:")
    for atype, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
        print(f"  {atype:<22}: {count:>5}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelOps Synthetic Telemetry Generator")
    parser.add_argument("--count", type=int, default=5000, help="Number of alerts to generate (default: 5000)")
    parser.add_argument("--output", type=str, default="data/alerts.jsonl", help="Output file path")
    args = parser.parse_args()

    generate_dataset(args.count, args.output)
