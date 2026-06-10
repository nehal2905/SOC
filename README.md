# Home SOC Lab

A self-contained, isolated virtual Security Operations Center (SOC) lab that simulates a corporate environment under coordinated attack and defense. Telemetry flows from an instrumented Windows victim through a log forwarder into a SIEM, where MITRE ATT&CK–mapped detections fire alerts and drive documented incident response.

## What This Lab Teaches

- End-to-end **attack → detect → respond** workflows across the kill chain
- **Sysmon** and Windows Event Log instrumentation on endpoints
- **Splunk** (primary) or **Wazuh** (alternative) for central ingestion, search, and alerting
- **Atomic Red Team** for reproducible adversary emulation
- **MITRE ATT&CK** as the common language for techniques, detections, and playbooks

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Host-Only Virtual Network (192.168.56.0/24)                 │
│                         Isolated from physical LAN                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐         SMB/WinRM/HTTP          ┌──────────────────────┐ │
│   │  Kali Linux  │ ─────── attack traffic ───────► │  Windows 10/11       │ │
│   │  (Attacker)  │         192.168.56.10           │  (Victim / Endpoint) │ │
│   │ 192.168.56.20│                                 │  192.168.56.10       │ │
│   └──────────────┘                                 │  • Sysmon            │ │
│                                                    │  • Win Event Log     │ │
│                                                    │  • Splunk UF / Wazuh │ │
│                                                    └──────────┬───────────┘ │
│                                                               │              │
│                                                    logs (9997/TCP or 1514)   │
│                                                               ▼              │
│                                                    ┌──────────────────────┐ │
│                                                    │  Splunk / Wazuh      │ │
│                                                    │  (SIEM)              │ │
│                                                    │  192.168.56.30       │ │
│                                                    │  • Index / rules     │ │
│                                                    │  • Dashboards        │ │
│                                                    │  • Alerts            │ │
│                                                    └──────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Victim** — Sysmon (process, network, file) + Windows Security/System/Application events
2. **Log forwarder** — Splunk Universal Forwarder (UF) or Wazuh agent → SIEM
3. **SIEM** — Parse, index, correlate; saved searches / rules evaluate continuously
4. **Detection** — Rules mapped to MITRE technique IDs; severity and context enriched
5. **Response** — Analyst follows `response/incident-response.md` per alert type

![Lab topology](architecture/lab-topology.png)

> Generate `lab-topology.png` from `architecture/lab-topology.mmd` — see `architecture/README.md`.

Full **attack → detect → respond** sequence: `architecture/attack-detect-respond-workflow.md`.

## Repository Layout

| Path | Purpose |
|------|---------|
| `architecture/` | Network and data-flow diagrams |
| `setup/` | VM, Sysmon, SIEM ingestion guides |
| `attacks/` | Per-stage attack playbooks (Atomic Red Team) |
| `detections/` | SPL/Wazuh rules + `attack-mapping.csv` |
| `response/` | Containment and remediation playbooks |
| `screenshots/` | Evidence: alerts, dashboards, raw logs |

## Quick Start

1. **Build the lab** — Follow `setup/01-vm-setup.md` (VirtualBox/VMware, host-only network).
2. **Instrument the victim** — Deploy `setup/02-sysmon-config.xml` and enable auditing per setup doc.
3. **Ingest logs** — Configure forwarding per `setup/03-siem-ingestion.md`.
4. **Baseline** — Run 24h with no attacks; tune false positives.
5. **Emulate** — Execute attacks in order under `attacks/` (one stage at a time).
6. **Validate detections** — Confirm rules in `detections/detection-rules.md` fire; capture screenshots.
7. **Respond** — Practice `response/incident-response.md` for each alert.

## Project Results

### Detections Implemented and Validated

| Category       | Detection ID | Status      |
| -------------- | ------------ | ----------- |
| Execution      | DET-EX-001   | ✅ Validated |
| Execution      | DET-EX-002   | ✅ Validated |
| Initial Access | DET-IA-001   | ✅ Validated |
| Persistence    | DET-PE-001   | ✅ Validated |
| Exfiltration   | DET-EXF-001  | ✅ Validated |

### SIEM Dashboard

The Home SOC Dashboard was created in Splunk and includes:

* Top Processes
* Security Event Distribution
* Recent Security Events
* Detection Alert Activity
* MITRE ATT&CK Coverage

### Alerting

Custom Splunk alerts were configured to trigger on validated detections and generate analyst-visible alerts for investigation and response.


## Attack → Detect → Respond (Summary)

| Stage | Attack (example) | Detection signal | Response |
|-------|------------------|------------------|----------|
| Initial Access | Phishing payload / malicious download | Sysmon 1 + 11; Win 4688 | Isolate host, block hash |
| Execution | PowerShell/cmd (T1059) | Suspicious parent-child (Sysmon 1) | Kill process tree |
| Persistence | Run key / scheduled task (T1547/T1053) | Registry/task create (Sysmon 12/13, 4698) | Remove persistence, scan |
| Privilege Escalation | UAC bypass / token abuse (T1548) | Privilege/token events (Sysmon 10, 4672) | Revoke session, patch |
| Exfiltration | Staged file upload (T1041) | Large outbound / unusual destination (Sysmon 3) | Block egress, scope data |

Full technique commands, SPL/Wazuh queries, and IR steps are in the linked folders and `detections/attack-mapping.csv`.

## SIEM Choice

| Component | Splunk (recommended) | Wazuh (open source) |
|-----------|----------------------|---------------------|
| Index | `wineventlog`, `sysmon` | `wazuh-alerts`, archives |
| Forwarder | Universal Forwarder 9997 | Wazuh agent 1514/1515 |
| Rules | Saved searches + `alert_action` | Custom rules XML / Sigma |

This repo ships **dual queries** (SPL + Wazuh) in `detections/detection-rules.md`.

## Dashboards (Splunk)

Import or recreate saved searches from `detections/detection-rules.md`, then build a simple **Home SOC** dashboard:

- Panel 1: Alerts in last 24h by `mitre_id`
- Panel 2: Top triggering hosts
- Panel 3: Sysmon Event ID volume timeline
- Panel 4: Real-time notable events table

Example base search for the notable panel:

```spl
index=wineventlog OR index=sysmon tag=attack_detected
| stats latest(_time) as time, latest(severity) as severity, values(mitre_id) as technique by rule_name, host
| sort - time
```

## Prerequisites

- 16 GB+ host RAM (32 GB recommended): 3 VMs (Kali, Windows, SIEM)
- VirtualBox 7+ or VMware Workstation
- Windows 10/11 evaluation ISO, Kali ISO, Splunk Enterprise trial or Wazuh OVA
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) cloned on Kali and victim (for `Invoke-AtomicTest`)

## Safety and Legal

- Run **only** on isolated host-only networks documented in setup.
- Do not point attack tools at production systems or the internet without authorization.
- Atomic tests modify the victim VM; use snapshots before each stage.

## What I Learned (template — fill after completing the lab)

After running the full chain, document:

1. **Telemetry gaps** — Which techniques had weak or no signal before tuning?
2. **False positives** — Which rules fired on benign admin activity? How did you tune them?
3. **Time to detect** — Wall-clock from attack command to first alert?
4. **Time to respond** — Steps that were manual vs. automatable?
5. **ATT&CK coverage** — Which tactics are well covered vs. blind spots in a home lab?
6. **SIEM skills** — SPL vs. Wazuh: which query language felt more maintainable for you?

Example entry:

> Running T1059.001 (PowerShell encoded command) produced Sysmon EID 1 with `-EncodedCommand` in CommandLine; our rule fired in ~45s. Initial Access via malicious ISO mount was noisier—we added a parent-process filter to reduce explorer.exe FPs.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Splunk Boss of the SOC](https://www.splunk.com/en_us/blog/security/boss-of-the-soc.html) (advanced practice)

## License

Educational use only. You are responsible for compliant use in your environment.
