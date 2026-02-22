# APT Lateral Movement Investigation Lab

![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Domain](https://img.shields.io/badge/Domain-homelab.local-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-9%20Techniques-red)

A home lab simulating a full APT attack chain from initial foothold to 
domain compromise, with blue team detection using Splunk. Built on Proxmox 
with Active Directory, Windows 10, and Kali Linux.

> **Author:** Karishan  
> **Domain:** homelab.local  
> **Duration:** 4 days  
> **Total Attack Events Detected:** 109

---

## Lab Overview

![Dashboard](screenshots/splunk-dashboard-overview.png) 

---

## Objective

Simulate how a real APT group moves through a corporate Active Directory 
environment — starting as a low-privileged HR user and escalating to full 
Domain Admin. Every attack phase is paired with Splunk detection rules 
mapped to MITRE ATT&CK.

**Skills demonstrated:**
- Active Directory attacks and privilege escalation
- Kerberos abuse — Kerberoasting and Golden Ticket
- Credential dumping — NTDS.dit extraction via Backup Operators
- Pass-the-Hash lateral movement
- Blue team detection with Splunk
- MITRE ATT&CK mapping and log analysis

---

## Lab Environment

| Machine | Role | IP | OS |
|---------|------|----|----|
| HL-DC01 | Domain Controller | 192.168.0.104 | Windows Server 2022 |
| HL-WS01 | Victim Workstation | 192.168.0.105 | Windows 10 22H2 |
| Kali | Attacker Machine | 192.168.0.103 | Kali Linux |
| Ubuntu | Splunk SIEM | 192.168.0.135 | Ubuntu 24.04 |

**Domain:** `homelab.local`  
**Hypervisor:** Proxmox VE  
**SIEM:** Splunk Enterprise

---

## Active Directory Structure
```
homelab.local
│
├── OU=Admins
│     └── da_admin          🔴 Domain Admin
│
├── OU=HR
│     └── brown             🟢 Initial Access Target
│
├── OU=IT
│     └── johnson           🟡 Lateral Movement Pivot
│
├── OU=Service Accounts
│     └── svc_backup        🔵 Kerberoast Target
│
└── OU=Workstations
      └── HL-WS01
```

---

## Attack Chain
```
Phase 2 — Initial Foothold
Kali → Meterpreter on HL-WS01 as brown (HR User)
         ↓
Phase 3 — Credential Harvesting
Kerberoast svc_backup → crack hash → Summer2024!
Secretsdump via johnson (IT User) → SAM + cached creds
         ↓
Phase 4 — Lateral Movement & Domain Compromise
svc_backup + Backup_Operators → diskshadow → NTDS.dit
Extract da_admin NTLM hash → Pass-the-Hash to DC01
         ↓
Phase 5 — Persistence
Forge Golden Ticket using krbtgt hash
Permanent domain access — survives password resets
         ↓
Phase 6 — Data Exfiltration
Access HR_Share + IT_Share as Domain Admin
Stage and exfiltrate sensitive files
         ↓
Phase 7 — Detection & Investigation
Splunk detection rules for every phase
109 confirmed attack events detected
MITRE ATT&CK mapped across 5 tactics
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Events Detected |
|-----------|-----|----------------|
| Remote Services WinRM | T1021.006 | 84 |
| Valid Domain Accounts | T1078.002 | 49 |
| Kerberoasting | T1558.003 | 29 |
| Non-Standard Port | T1571 | 16 |
| Pass-the-Hash | T1550.002 | 7 |
| User Execution | T1204 | ✅ |
| NTDS Dump | T1003.003 | ✅ |
| LSASS Memory | T1003.001 | ✅ |
| Golden Ticket | T1558.001 | ✅ |

![MITRE Coverage](screenshots/mitre-tactic-coverage.png)

---

## Key Detections

| Detection | EventID | Confidence |
|-----------|---------|------------|
| Kerberoasting | 4769 + RC4 0x17 | High |
| Pass-the-Hash | 4624 LogonType 3 | High |
| NTDS Dump | Sysmon EID 1 diskshadow | High |
| Credential Dump | Sysmon EID 10 lsass | Medium |
| Golden Ticket | 4768 no pre-auth | Low |
| Lateral Movement | 4624 + 4672 chain | High |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Metasploit / msfvenom | Payload generation + reverse shell |
| Impacket GetUserSPNs | Kerberoasting |
| Impacket secretsdump | Credential dumping |
| Hashcat | Offline hash cracking |
| Evil-WinRM | WinRM shell via hash |
| CrackMapExec | SMB enumeration |
| Impacket ticketer | Golden Ticket forging |
| Sysmon | Deep Windows telemetry |
| Splunk | Log collection + detection |

---

## Repository Structure
```
apt-lateral-movement-lab/
│
├── README.md
├── screenshots/              ← Lab + Splunk screenshots
│
├── attack-playbook/
│   ├── phase2-initial-foothold.md
│   ├── phase3-credential-harvesting.md
│   ├── phase4-lateral-movement.md
│   ├── phase5-golden-ticket.md
│   └── phase6-exfiltration.md
│
├── detection/
│   ├── splunk-queries.md
│   ├── alert-rules.md
│   └── mitre-attack-mapping.md
│
├── diagrams/
│   └── network-diagram.md
│
├── docs/
│   └── lab-setup.md
│
└── report/
    └── apt-investigation-report.md
```

---

## Disclaimer

This project is built for **educational purposes only** in an isolated home 
lab environment. All techniques demonstrated should only be used in 
environments you own or have explicit written permission to test.

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Impacket](https://github.com/fortra/impacket)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742)