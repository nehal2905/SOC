# Detection Rules

Each rule maps to MITRE ATT&CK IDs in `attack-mapping.csv`. Deploy as **Splunk saved searches** (scheduled, alert) or **Wazuh custom rules**.

Convention:

- `index=sysmon` / `index=wineventlog` — Splunk indexes from `setup/03-siem-ingestion.md`
- Severity: Low / Medium / High / Critical
- Tag alerts: `tag=attack_detected mitre_id=<ID>`

---

## Initial Access

### DET-IA-001 — Executable launched from Downloads

**MITRE:** T1204.002 | **Severity:** High

**Splunk SPL:**

```spl
index=sysmon EventCode=1
| where match(Image, "(?i)\\\\Downloads\\\\") OR match(CommandLine, "(?i)\\\\Downloads\\\\")
| where NOT match(Image, "(?i)\\\\(chrome|msedge|firefox)\\.exe")
| stats count earliest(_time) as first_seen latest(_time) as last_seen
    values(CommandLine) as CommandLine values(ParentImage) as ParentImage values(Hashes) as Hashes
    by host, Image, User
| eval rule_name="DET-IA-001", mitre_id="T1204.002", severity="High"
```

**Wazuh:**

```xml
<rule id="100001" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image">\\Downloads\\</field>
  <description>DET-IA-001: Process from Downloads folder</description>
  <group>attack_detected,mitre_T1204_002,</group>
</rule>
```

### DET-IA-002 — New file in Downloads followed by execution (15m window)

**MITRE:** T1566.001 / T1204 | **Severity:** Medium

**Splunk SPL:**

```spl
index=sysmon EventCode=11 TargetFilename="*\\Downloads\\*.exe"
| rename TargetFilename as dropped_file
| join type=inner host [
    search index=sysmon EventCode=1 earliest=-15m
    | where match(Image, ".*")
]
| where like(Image, "%".mvindex(split(dropped_file,"\\"),-1))
| table _time host User dropped_file Image CommandLine
| eval rule_name="DET-IA-002", mitre_id="T1566.001", severity="Medium"
```

---

## Execution

### DET-EX-001 — Encoded PowerShell command line

**MITRE:** T1059.001 | **Severity:** High

**Splunk SPL:**

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*FromBase64String*")
| table _time host User Image CommandLine ParentImage Hashes
| eval rule_name="DET-EX-001", mitre_id="T1059.001", severity="High"
```

**Wazuh:**

```xml
<rule id="100010" level="13">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.commandLine">-EncodedCommand|-enc </field>
  <field name="win.eventdata.image">\\powershell.exe|\\pwsh.exe</field>
  <description>DET-EX-001: Encoded PowerShell execution</description>
  <group>attack_detected,mitre_T1059_001,</group>
</rule>
```

### DET-EX-002 — Script interpreter spawned by Office

**MITRE:** T1059.001 | **Severity:** High

**Splunk SPL:**

```spl
index=sysmon EventCode=1
(Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe")
(ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\OUTLOOK.EXE")
| table _time host User ParentImage Image CommandLine
| eval rule_name="DET-EX-002", mitre_id="T1059.001", severity="High"
```

### DET-EX-003 — cmd.exe with suspicious download patterns

**MITRE:** T1059.003 | **Severity:** Medium

**Splunk SPL:**

```spl
index=sysmon EventCode=1 Image="*\\cmd.exe"
(CommandLine="*curl*" OR CommandLine="*certutil*" OR CommandLine="*bitsadmin*" OR CommandLine="*powershell*")
| stats latest(_time) as _time values(CommandLine) as CommandLine by host User
| eval rule_name="DET-EX-003", mitre_id="T1059.003", severity="Medium"
```

---

## Persistence

### DET-PE-001 — Registry Run key modification

**MITRE:** T1547.001 | **Severity:** High

**Splunk SPL:**

```spl
index=sysmon EventCode IN (12, 13)
(TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*")
| table _time host EventCode TargetObject Details Image User
| eval rule_name="DET-PE-001", mitre_id="T1547.001", severity="High"
```

**Wazuh:**

```xml
<rule id="100020" level="12">
  <if_sid>61615</if_sid>
  <field name="win.eventdata.targetObject">CurrentVersion\\Run</field>
  <description>DET-PE-001: Run key registry modification</description>
  <group>attack_detected,mitre_T1547_001,</group>
</rule>
```

### DET-PE-002 — Scheduled task created

**MITRE:** T1053.005 | **Severity:** High

**Splunk SPL:**

```spl
index=wineventlog EventCode=4698
| rex field=Message max_match=1 "Task Name:\s+(?<TaskName>[^\r\n]+)"
| table _time host TaskName Message
| eval rule_name="DET-PE-002", mitre_id="T1053.005", severity="High"
```

### DET-PE-003 — New Windows service installed

**MITRE:** T1543.003 | **Severity:** Critical

**Splunk SPL:**

```spl
(index=wineventlog EventCode=7045) OR (index=sysmon EventCode=1 Image="*\\services.exe")
| table _time host Message ServiceName Image CommandLine
| eval rule_name="DET-PE-003", mitre_id="T1543.003", severity="Critical"
```

---

## Privilege Escalation

### DET-PR-001 — Special privileges assigned (admin/SYSTEM)

**MITRE:** T1134 / T1078 | **Severity:** Critical

**Splunk SPL:**

```spl
index=wineventlog EventCode=4672
| search Message="*SeDebugPrivilege*" OR Message="*SeTcbPrivilege*"
| join type=left host User [ search index=sysmon EventCode=1 earliest=-5m
    | stats latest(Image) as Image latest(ParentImage) as ParentImage by host User ]
| table _time host User Message Image ParentImage
| eval rule_name="DET-PR-001", mitre_id="T1134.001", severity="Critical"
```

### DET-PR-002 — UAC bypass pattern (fodhelper / sdclt / eventvwr)

**MITRE:** T1548.002 | **Severity:** Critical

**Splunk SPL:**

```spl
index=sysmon EventCode=1
(Image="*\\fodhelper.exe" OR Image="*\\sdclt.exe" OR Image="*\\eventvwr.exe" OR CommandLine="*mscfile*")
| where ParentImage!="*\\explorer.exe" OR match(CommandLine, "(?i)registry|hkcu")
| table _time host User Image CommandLine ParentImage
| eval rule_name="DET-PR-002", mitre_id="T1548.002", severity="Critical"
```

### DET-PR-003 — Failed elevation attempt burst

**MITRE:** T1548 | **Severity:** Medium

**Splunk SPL:**

```spl
index=wineventlog EventCode=4625
| stats count by host TargetUserName IpAddress
| where count>=3
| eval rule_name="DET-PR-003", mitre_id="T1548", severity="Medium"
```

---

## Exfiltration

### DET-EXF-001 — Outbound connection to lab attacker subnet (high port)

**MITRE:** T1048.003 | **Severity:** High

**Splunk SPL:**

```spl
index=sysmon EventCode=3 Initiated=true
DestinationIp="192.168.56.20"
| stats sum(bytes_out) as total_bytes count by host Image User DestinationIp DestinationPort
| where total_bytes>100000 OR count>10
| eval rule_name="DET-EXF-001", mitre_id="T1048.003", severity="High"
```

> Note: `bytes_out` requires field alias from your TA; substitute with `count` threshold if unavailable.

**Wazuh:**

```xml
<rule id="100030" level="14">
  <if_sid>61609</if_sid>
  <field name="win.eventdata.destinationIp">192.168.56.20</field>
  <description>DET-EXF-001: Outbound connection to attacker IP</description>
  <group>attack_detected,mitre_T1048_003,</group>
</rule>
```

### DET-EXF-002 — PowerShell/curl outbound to non-SIEM IP

**MITRE:** T1041 | **Severity:** Critical

**Splunk SPL:**

```spl
index=sysmon EventCode=3 Initiated=true
(Image="*\\powershell.exe" OR Image="*\\curl.exe" OR Image="*\\certutil.exe")
NOT DestinationIp="192.168.56.30"
DestinationIp!="127.0.0.1"
| table _time host Image User DestinationIp DestinationPort
| eval rule_name="DET-EXF-002", mitre_id="T1041", severity="Critical"
```

### DET-EXF-003 — Staging file then network within 10 minutes

**MITRE:** T1020 / T1041 | **Severity:** High

**Splunk SPL:**

```spl
index=sysmon EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.7z" OR TargetFilename="*staging*")
| transaction host maxspan=10m
| where eventcount>1
| search *
| eval rule_name="DET-EXF-003", mitre_id="T1020", severity="High"
```

---

## Splunk alert configuration

For each saved search:

1. **Settings → Searches, reports, and alerts → New Alert**
2. Trigger: **Scheduled**, cron `*/5 * * * *` (lab) or real-time for demos
3. Trigger condition: **Number of Results** > 0
4. Action: email / webhook / log to `index=notable`
5. Add field: `| outputlookup append=t attack_notables.csv` (optional)

### Master correlation (dashboard feed)

```spl
| makeresults
| eval rules="DET-IA-001 DET-EX-001 DET-PE-001 DET-PR-001 DET-EXF-001"
| makemv rules
| mvexpand rules
| map search="search index=sysmon OR index=wineventlog $rules$ earliest=-24h"
```

Simpler approach: tag each saved search alert with `rule_name` and use:

```spl
index=_internal source=*scheduler* status=success savedsearch_name="DET-*"
| stats count by savedsearch_name
```

---

## Wazuh rule deployment

1. Add custom rules to `/var/ossec/etc/rules/local_rules.xml` on manager.
2. `systemctl restart wazuh-manager`
3. Map `groups` → `attack_detected` for dashboard filters.

---

## Tuning checklist

- [ ] Baseline 24h: note FPs from Windows Update, Defender
- [ ] Exclude `Image=C:\Windows\System32\svchost.exe` children where appropriate
- [ ] Restrict `DestinationIp=192.168.56.20` to lab attacker only
- [ ] Document threshold changes in README "What I learned"
