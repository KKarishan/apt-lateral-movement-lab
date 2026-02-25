# Network & Attack Diagrams

> **Author:** Karishan  
> **Domain:** homelab.local  
> **Hypervisor:** Proxmox VE

---

## Lab Network Topology

![Proxmox Topology](../apt-lateral-movement-lab/screenshots/proxmox-topology.png)

### Proxmox Host

    Windows Server 2022
        Hostname: HL-DC01
        IP Address: 192.168.0.104
        Domain: homelab.local

    Windows 10
        Hostname: HL-WS01
        IP Address: 192.168.0.105

---

## Active Directory Privilege Hierarchy

![AD Privilege Hierarchy](../apt-lateral-movement-lab/screenshots/ad-privilege-hierarchy.png)


1. Create OUs
   1. Admins
   2. HR
   3. IT
   4. Service Accounts
   5. Groups
2. Create all user accounts
    | User | Description | Notes |
    |------|-------------|-------|
    | da_admin | Domain admin |
    | brown | standard HR user | Lateral movement pivot |
    | johnson | IT user | 
    | tempuser | another IT user |
    | svc_backup | service account | Kerberoast target |

3. Create groups and assign members

    | Groups | Members|
    |--------|--------|
    | HR_Users | brown |
    | IT_Users | johnson, tempuser |
    | Workstation_Local_Admins | johnson, svc_backup |
    | Backup_Operators | svc_backup | 
    | Domain Admins | da_admins |

> Note: Set SPN on svc_backup to make it Kerberoastable.

4. Create file shares on HL-DC01
   | Folder Name | Path | Users | Access |
   |-------------|------|-------|--------|
   | HR_Share | C:\Shares\HR | da_admin | Full access |
   |    |   |  HR_Users | Change access |
   |    |   | IT_Users | Read access |
   | IT_Share | C:\Shares\IT | da_admin | Full access |
   |    |   |  IT_Users | Change access |
   |    |   | HR_Users | Read access |

5. Add some dummy files to make exfil realistic
   | Folder Name | Files |
   |-------------|-------|
   | HR_Share | passwords.txt |
   |  | fake_payroll.xlsx | 
   | IT_Share | server_config.docx |   
   |  | backup_config.ps1 |   

---

## Full Attack Flow

![Full Attack Flow](../apt-lateral-movement-lab/screenshots/full-attack-flow.png)

---

## Logging & Detection Architecture

![Log & detection Architecture](../apt-lateral-movement-lab/screenshots/log-detect-architecture.png)

---

## Detection Coverage Map
```
Attack Step               Detection Method          EventID      Confidence
───────────────────────   ──────────────────────    ─────────    ──────────
Payload execution    ───► Process creation          Sysmon 1     HIGH
Reverse shell        ───► Network connection        Sysmon 3     HIGH
Kerberoasting        ───► TGS + RC4 encryption      4769         HIGH
LSASS access         ───► Process access            Sysmon 10    MEDIUM
PTH logon            ───► Network logon Type 3      4624         HIGH
NTDS dump            ───► diskshadow execution      Sysmon 1     HIGH
DA privilege         ───► Special privileges        4672         HIGH
Golden Ticket        ───► TGT request               4768         MEDIUM
Data staging         ───► File creation             EID 11       HIGH
```

---

## Port Reference

| Port | Protocol | Usage | Detection |
|------|----------|-------|-----------|
| 4444 | TCP | Meterpreter C2 | Sysmon EID 3 |
| 5985 | TCP | WinRM / Evil-WinRM | WinRM Operational Log |
| 9997 | TCP | Splunk forwarder | — |
| 445 | TCP | SMB share access | EID 5140 |
| 88 | TCP/UDP | Kerberos | EID 4768, 4769 |
| 389 | TCP | LDAP enumeration | — |
| 636 | TCP | LDAPS | — |



