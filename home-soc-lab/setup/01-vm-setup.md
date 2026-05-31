# VM and Network Setup

Build three VMs on a **host-only** virtual network so attack traffic and malware samples never touch your home LAN.

## Topology

| VM | Role | Suggested RAM | Disk | IP (static) |
|----|------|---------------|------|-------------|
| `soc-win-victim` | Windows 10/11 endpoint | 4–8 GB | 60 GB | 192.168.56.10 |
| `soc-kali-attacker` | Kali Linux | 2–4 GB | 40 GB | 192.168.56.20 |
| `soc-siem` | Splunk Enterprise or Wazuh | 8–12 GB | 80 GB | 192.168.56.30 |

Hostname examples: `WIN-VICTIM`, `KALI-ATTACK`, `SIEM-01`.

## VirtualBox (recommended)

### 1. Create host-only network

1. **File → Host Network Manager → Create**
2. Adapter: `192.168.56.1/24`, DHCP optional (disable if using static IPs only)
3. Note adapter name, e.g. `VirtualBox Host-Only Ethernet Adapter`

### 2. Per-VM network adapter

- **Adapter 1**: Host-only → select the adapter above
- **Do not** enable NAT or Bridged on the victim/attacker for lab traffic (SIEM may use NAT *only* for package updates if you accept split routing—prefer offline ISOs for strict isolation)

### 3. Promiscuous mode

Set to **Allow VMs** on attacker adapter if you plan packet capture exercises (optional).

## VMware Workstation

1. **Edit → Virtual Network Editor → Add Network** (VMnet2)
2. Type: **Host-only**, subnet `192.168.56.0`, mask `255.255.255.0`
3. Assign each VM to VMnet2; disable "Connect at power on" for unused adapters

## Windows victim (`soc-win-victim`)

1. Install Windows 10/11 Pro (evaluation ISO).
2. Set static IP:
   - IP: `192.168.56.10`
   - Mask: `255.255.255.0`
   - Gateway: *(none for strict isolation)* or `192.168.56.1` if host-only gateway required
   - DNS: `192.168.56.30` or disable DNS
3. Rename computer: `WIN-VICTIM`
4. Create lab users:
   - `labuser` (standard) — primary victim persona
   - `labadmin` (local admin) — for privilege escalation demos
5. Enable PowerShell logging (Group Policy or registry):

```powershell
# Run as Administrator
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
```

6. Enable advanced audit policy (Command Prompt as Admin):

```cmd
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
```

7. Windows Firewall: allow inbound from `192.168.56.0/24` only for WinRM/SMB lab scenarios, or disable for pure client simulation.

8. **Snapshot**: `clean-golden` after updates and before Sysmon.

## Kali attacker (`soc-kali-attacker`)

1. Install Kali Linux (latest rolling or stable).
2. Static IP: `192.168.56.20/24`
3. Install tooling:

```bash
sudo apt update && sudo apt install -y git python3-pip impacket-scripts
git clone https://github.com/redcanaryco/atomic-red-team.git ~/atomic-red-team
```

4. Clone for offline Atomic tests on Windows (optional): copy `atomics/` to victim via host-only SMB share.

5. Verify connectivity:

```bash
ping -c 3 192.168.56.10
nmap -sV 192.168.56.10
```

## SIEM (`soc-siem`)

### Splunk Enterprise (trial)

1. Install Splunk Enterprise on Ubuntu 22.04 or Windows Server VM.
2. Static IP: `192.168.56.30`
3. Create indexes:

```spl
# Splunk Web → Settings → Indexes
# wineventlog, sysmon — 5GB each for lab
```

4. Open firewall port **9997** (ingestion) from `192.168.56.10` only.

### Wazuh (alternative)

1. Deploy [Wazuh OVA](https://documentation.wazuh.com/current/quickstart.html) or single-node Docker on `192.168.56.30`.
2. Register Windows agent from victim; verify agent connected in Wazuh dashboard.

## DNS and isolation checklist

- [ ] No bridged adapter on victim/attacker
- [ ] Host cannot route victim traffic to internet (verify: victim has no default gateway or blocked)
- [ ] Snapshots before each attack stage
- [ ] Shared folders disabled between host and victim (or read-only)
- [ ] Time sync: all VMs same timezone (NTP on host-only optional)

## Validation

From Kali:

```bash
curl -k https://192.168.56.30:8000  # Splunk Web (if enabled)
nc -zv 192.168.56.30 9997            # Splunk receiving
```

From Windows (after forwarder install):

```powershell
Test-NetConnection -ComputerName 192.168.56.30 -Port 9997
```

Proceed to `02-sysmon-config.xml` deployment and `03-siem-ingestion.md`.
