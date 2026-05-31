# Execution

Run adversary commands and scripts after foothold. Focus: **PowerShell**, **cmd**, suspicious **parent-child** chains.

## MITRE mapping

| Technique | ID | Atomic test |
|-----------|-----|-------------|
| PowerShell | T1059.001 | T1059.001 |
| Windows Command Shell | T1059.003 | T1059.003 |
| JavaScript | T1059.007 | T1059.007 |

## Atomic Red Team (victim)

```powershell
cd C:\AtomicRedTeam\atomics

# T1059.001 — Encoded PowerShell (high signal)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# T1059.003 — cmd executing whoami
Invoke-AtomicTest T1059.003 -TestNumbers 1

# T1059.001 — Suspicious execution policy bypass
Invoke-AtomicTest T1059.001 -TestNumbers 2
```

## Manual commands (reproducible)

```powershell
# Encoded command (matches DET-EX-001)
powershell.exe -NoProfile -EncodedCommand dwByaW50ICdIZWxsbyBTT0Mn

# Parent-child: Word → PowerShell (simulate)
# Start-Process winword.exe (if installed) then:
Start-Process powershell.exe -ArgumentList "-nop -w hidden -c whoami"
```

## Expected telemetry

| Log source | Event ID | Evidence |
|------------|----------|----------|
| Sysmon | 1 | `powershell.exe` with `-EncodedCommand` |
| PowerShell | 4104 | Script block logging (if enabled) |
| Security | 4688 | Process creation audit |
| Sysmon | 1 | ParentImage ≠ expected for child |

## Detection

- **DET-EX-001** — Encoded PowerShell command line
- **DET-EX-002** — Office/productivity app spawning script interpreter
- **DET-EX-003** — cmd.exe with download/cradle patterns

## Response pointer

`response/incident-response.md` → **Execution**

## Validation query (Splunk)

```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*EncodedCommand*"
| table _time host User CommandLine ParentImage
```

## Screenshot checklist

- [ ] Alert DET-EX-001 fired
- [ ] Full CommandLine in notable event
