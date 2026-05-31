# Privilege Escalation

Attempt to obtain higher privileges (admin/SYSTEM) via UAC bypass patterns, token manipulation, or abuse of elevation paths.

## MITRE mapping

| Technique | ID | Atomic test |
|-----------|-----|-------------|
| Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | T1548.002 |
| Access Token Manipulation | T1134 | T1134.001 |
| Exploitation for Privilege Escalation | T1068 | — (out of scope for safe lab) |

## Atomic Red Team (victim)

```powershell
cd C:\AtomicRedTeam\atomics

# T1548.002 — UAC bypass (fodhelper / eventvwr patterns — lab VM only)
Invoke-AtomicTest T1548.002 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1548.002 -TestNumbers 1

# T1134.001 — Token impersonation (requires admin)
Invoke-AtomicTest T1134.001 -TestNumbers 1
```

## Manual (safe lab)

```powershell
# Run as labuser — failed elevation still logs 4625/4673
Start-Process powershell.exe -Verb RunAs -ArgumentList "-c whoami"

# Successful admin logon (use labadmin once)
runas /user:labadmin cmd.exe
```

## Expected telemetry

| Log source | Event ID | Evidence |
|------------|----------|----------|
| Security | 4672 | Special privileges assigned to new logon |
| Security | 4624 | Logon Type 2/10 elevation |
| Sysmon | 1 | Processes under high-integrity paths |
| Sysmon | 10 | ProcessAccess to protected processes (advanced) |

## Detection

- **DET-PR-001** — New logon with privileged groups (4672 + 4688)
- **DET-PR-002** — UAC bypass registry/command patterns (fodhelper, sdclt)
- **DET-PR-003** — Sensitive privilege SeDebugEnabled assigned

## Response pointer

`response/incident-response.md` → **Privilege Escalation**

## Notes

- Run UAC bypass tests only on **snapshotted** VMs.
- Many Atomic tests require specific Windows builds; document failures in README "What I learned."

## Screenshot checklist

- [ ] Event 4672 correlated with suspicious parent process
- [ ] Alert DET-PR-001
