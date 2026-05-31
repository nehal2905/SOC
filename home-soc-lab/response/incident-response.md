# Incident Response Playbook

Operational steps for the Home SOC lab. Align with NIST phases: **Prepare → Detect → Analyze → Contain → Eradicate → Recover → Lessons Learned**.

Assume single victim `WIN-VICTIM` (192.168.56.10), SIEM at 192.168.56.30, attacker at 192.168.56.20.

---

## Global procedures

### Severity matrix

| Severity | SLA (lab) | Example rules |
|----------|-----------|---------------|
| Critical | Immediate | DET-PE-003, DET-PR-002, DET-EXF-002 |
| High | 15 min | DET-EX-001, DET-PE-001, DET-EXF-001 |
| Medium | 1 hr | DET-IA-002, DET-EX-003, DET-PR-003 |
| Low | Next business day | Informational baselines |

### Evidence preservation

```powershell
# On victim (admin) — before containment changes
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\IR\sysmon.evtx
wevtutil epl Security C:\IR\security.evtx
Copy-Item C:\ProgramData\SplunkUniversalForwarder\var\log\splunk\* C:\IR\ -Recurse -ErrorAction SilentlyContinue
```

Copy `C:\IR\` to SIEM or host via read-only share; screenshot dashboards in `screenshots/`.

### Network isolation (host-only lab)

**VirtualBox:** disable victim adapter or change to disconnected NIC.

**Windows (soft isolate):**

```powershell
Set-NetFirewallProfile -All -Enabled True
New-NetFirewallRule -DisplayName "IR-Block-All-Outbound" -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName "IR-Allow-SIEM" -Direction Outbound -RemoteAddress 192.168.56.30 -Action Allow
```

**Hard isolate:** VM snapshot revert only after evidence export.

---

## Initial Access

**Triggers:** DET-IA-001, DET-IA-002  
**MITRE:** T1204.002, T1566.001

### Detect

- Confirm Sysmon EID 1/11 and Security 4688 in SIEM.
- Identify file path, hash (`Hashes` field), parent process, user.

### Contain

1. Isolate host (see above).
2. Block attacker IP on victim firewall:

```powershell
New-NetFirewallRule -DisplayName "Block-Kali" -Direction Outbound -RemoteAddress 192.168.56.20 -Action Block
```

3. Disable compromised account session:

```powershell
query user
logoff <SESSION_ID>
```

### Eradicate

1. Delete malicious file from `Downloads` / `Temp`.
2. Block hash in Windows Defender (lab):

```powershell
Add-MpPreference -ExclusionPath C:\IR  # only if scanning IR folder
Remove-MpThreat -ThreatID <id>  # if detected
```

3. Search for secondary payloads:

```spl
index=sysmon host=WIN-VICTIM EventCode=1 earliest=-7d
| stats count by Image
| sort - count
```

### Recover

- Restore VM snapshot `clean-golden` if integrity unknown.
- Re-enable network; monitor DET-IA-* for 24h.

### Lessons learned

Document initial vector (email sim vs. download) and time-to-detect.

---

## Execution

**Triggers:** DET-EX-001, DET-EX-002, DET-EX-003  
**MITRE:** T1059.001, T1059.003, T1059.007

### Detect

- Extract `CommandLine`, `ParentImage`, `User`, process GUID from Sysmon.

### Contain

1. Kill process tree by PID:

```powershell
# Replace <PID> from Sysmon ProcessId
Stop-Process -Id <PID> -Force
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq <PID> } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

2. Optional: disable PowerShell for standard users (GPO/registry lab only).

### Eradicate

- Clear `%TEMP%` and suspicious `.ps1` / `.bat`.
- Review PowerShell 4104 script blocks in SIEM.

### Recover

- Validate no residual `powershell -enc` in Run keys or Tasks.
- Re-run execution Atomic test; confirm detection still fires (regression test).

---

## Persistence

**Triggers:** DET-PE-001, DET-PE-002, DET-PE-003  
**MITRE:** T1547.001, T1053.005, T1543.003

### Detect

- Registry: Sysmon 12/13 `TargetObject`.
- Tasks: Security 4698.
- Services: System 7045.

### Contain

- Isolate host if service persistence is unknown malicious code.

### Eradicate

```powershell
# Run key
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabPersist" -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Scheduled task
schtasks /query /fo LIST /v | findstr /i "SOCLab"
schtasks /delete /tn "SOCLabTask" /f

# Service (replace name)
sc.exe stop "BadServiceName"
sc.exe delete "BadServiceName"
```

Audit:

```powershell
Get-ScheduledTask | Where-Object State -eq Ready
Get-CimInstance Win32_Service | Where-Object StartMode -eq 'Auto'
```

### Recover

- Reboot victim; confirm no persistence in Sysmon/4698.
- Snapshot post-eradication: `post-ir-clean`.

---

## Privilege Escalation

**Triggers:** DET-PR-001, DET-PR-002, DET-PR-003  
**MITRE:** T1548.002, T1134.001, T1548

### Detect

- Correlate 4672 with preceding process creation.
- Identify account that gained privileges.

### Contain

1. Force logoff admin sessions:

```powershell
logoff <ID> /server:WIN-VICTIM
```

2. Disable `labadmin` until review:

```powershell
Disable-LocalUser -Name "labadmin"
```

3. Isolate host.

### Eradicate

- Remove UAC bypass artifacts (registry keys per Atomic cleanup).
- Patch: ensure Windows fully updated (lab snapshot note).

### Recover

- Re-enable `labadmin` with new password.
- Enforce UAC: **Always notify** in lab GPO.

---

## Exfiltration

**Triggers:** DET-EXF-001, DET-EXF-002, DET-EXF-003  
**MITRE:** T1041, T1048.003, T1020

### Detect

- Sysmon EID 3: `DestinationIp`, `DestinationPort`, `Image`.
- Identify staging files (Sysmon 11).

### Contain

1. Block egress (firewall rules above).
2. Block attacker IP and port 8080/8443.
3. Preserve staging file copies to `C:\IR\`.

### Eradicate

- Delete staging data:

```powershell
Remove-Item C:\Users\labuser\Documents\staging.txt -Force -ErrorAction SilentlyContinue
```

- On Kali: delete received files in `/tmp/exfil`.

### Recover

- Assess **scope**: what data left the host (lab: fake SSN file only).
- Rotate `labuser` password; review shares.
- Restore from golden snapshot if real sensitive data ever used (never in lab).

### Lessons learned

Record bytes transferred (if available) and whether DET-EXF-001 threshold needs tuning.

---

## Post-incident report template

```markdown
## Incident summary
- ID: IR-YYYY-MM-DD-01
- Stage: [Initial Access | Execution | ...]
- MITRE: [Txxxx]
- Detection rule: [DET-xxx]
- Host: WIN-VICTIM
- Start / detect / contain times:

## Timeline
| UTC | Event |
|-----|-------|
|     | Atomic test executed |
|     | First SIEM alert |

## Actions taken
- [ ] Isolate
- [ ] Eradicate
- [ ] Recover
- [ ] Detection tuned

## Recommendations
-
```

---

## Automation hooks (optional stretch goals)

| Action | Tool |
|--------|------|
| Isolate VM | VirtualBox CLI `VBoxManage controlvm WIN-VICTIM poweroff` |
| Kill PID | Splunk Adaptive Response / webhook to PowerShell remoting |
| Create ticket | Email alert → parse `rule_name` |

Not required for lab completion; document in README if implemented.
