# Persistence

Maintain access across reboots via **registry run keys** and **scheduled tasks**.

## MITRE mapping

| Technique | ID | Atomic test |
|-----------|-----|-------------|
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | T1547.001 |
| Scheduled Task/Job: Scheduled Task | T1053.005 | T1053.005 |
| Create or Modify System Process: Windows Service | T1543.003 | T1543.003 |

## Atomic Red Team (victim — requires elevation for some tests)

```powershell
cd C:\AtomicRedTeam\atomics

# T1547.001 — Registry Run key
Invoke-AtomicTest T1547.001 -TestNumbers 1

# T1053.005 — Scheduled task
Invoke-AtomicTest T1053.005 -TestNumbers 1

# T1543.003 — Service (admin)
Invoke-AtomicTest T1543.003 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1543.003 -TestNumbers 1
```

## Manual (lab-friendly)

```powershell
# Run key (HKCU — no admin required)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SOCLabPersist" -Value "C:\Windows\System32\calc.exe" -PropertyType String -Force

# Scheduled task
schtasks /create /tn "SOCLabTask" /tr "calc.exe" /sc onlogon /ru labuser /f
```

## Expected telemetry

| Log source | Event ID | Evidence |
|------------|----------|----------|
| Sysmon | 12, 13 | RegistryEvent Run key |
| Security | 4698 | Scheduled task created |
| Sysmon | 1 | `schtasks.exe` or `reg.exe` |
| System | 7045 | New service (T1543) |

## Detection

- **DET-PE-001** — Run/RunOnce registry modification
- **DET-PE-002** — New scheduled task creation
- **DET-PE-003** — New Windows service installed

## Response pointer

`response/incident-response.md` → **Persistence**

## Cleanup (after lab)

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SOCLabPersist" -ErrorAction SilentlyContinue
schtasks /delete /tn "SOCLabTask" /f
```

## Screenshot checklist

- [ ] Sysmon RegistryEvent target `CurrentVersion\Run`
- [ ] Security 4698 in SIEM
