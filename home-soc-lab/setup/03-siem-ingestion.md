# SIEM Log Ingestion

Route **Windows Security/System/Application** and **Microsoft-Windows-Sysmon/Operational** into Splunk or Wazuh.

## Log sources on the victim

| Source | Channel / Provider | Key Event IDs |
|--------|-------------------|---------------|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | 1, 3, 7, 10, 11, 12, 13, 22 |
| Security | `Security` | 4624, 4625, 4672, 4688, 4698, 4699, 7045 |
| PowerShell | `Microsoft-Windows-PowerShell/Operational` | 4103, 4104 |
| System | `System` | 7045 (service install) |

## Splunk Universal Forwarder (primary)

### 1. Install on Windows victim

Download UF from Splunk; install to `C:\Program Files\SplunkUniversalForwarder`.

Deployment server optional for home lab—use `inputs.conf` + `outputs.conf` locally.

### 2. `outputs.conf`

```ini
[tcpout]
defaultGroup = splunk_indexers

[tcpout:splunk_indexers]
server = 192.168.56.30:9997
```

### 3. `inputs.conf`

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = sysmon

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = wineventlog

[WinEventLog://System]
disabled = 0
index = wineventlog
```

### 4. Splunk indexer `props.conf` (SIEM node)

```ini
[WinEventLog://Security]
sourcetype = WinEventLog:Security

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

### 5. Verify ingestion

On SIEM:

```spl
index=sysmon earliest=-15m | stats count by EventCode
index=wineventlog EventCode=4688 earliest=-15m | head 20
```

Expected: Sysmon `EventCode=1` after any process start.

### 6. Field extraction (optional `transforms.conf`)

Map Sysmon XML to `CommandLine`, `ParentImage`, `Image`, `DestinationIp` via Splunk TA for Microsoft Sysmon or inline `FIELDALIAS`.

## Wazuh agent (alternative)

### 1. Install agent on Windows

```powershell
# Download Wazuh Windows agent MSI; point to manager 192.168.56.30
WAZUH_MANAGER="192.168.56.30" msiexec /i wazuh-agent-4.x.msi /qn
```

### 2. `ossec.conf` snippets (manager + agent)

Enable Sysmon log collection on agent:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 3. Verify

Wazuh dashboard → Agents → `WIN-VICTIM` → Log collection last event < 2 minutes.

## Index / retention (lab)

| Index | Retention | Notes |
|-------|-----------|-------|
| `sysmon` | 30 days | High volume; filter at forwarder if needed |
| `wineventlog` | 90 days | Security + PowerShell |

## Tagging for detections

Add `eventtype` or `tags` in saved searches:

```spl
| eval tag=if(match(CommandLine,"EncodedCommand"),"attack_detected",null())
```

For Wazuh, use rule `groups` → `attack_detected`.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| No Sysmon in SIEM | `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5` |
| UF not connecting | `netstat -an | findstr 9997`, Splunk `tcpdump` on 9997 |
| Wrong sourcetype | UF `inputs.conf` channel names exact match |
| Duplicate events | Only one forwarder; no Splunk + Wazuh same channel without routing |

Next: run attacks in `attacks/` and validate `detections/detection-rules.md`.
