# Zerologon Lab

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/zerologon/](https://cyberdefenders.org/blueteam-ctf-challenges/zerologon/)

Suggested tools: EZ Tools, Event Log Explorer, KAPE, Event Viewer, NTFS Log Tracker, CyberChef

Tactics: Lateral Movement

# Scenario

Your role as a Tier 2 SOC Analyst at EliteSystems Corp is put to the test following an alert from the Tier 1 team about a confirmed phishing email leading to a potential network wide intrusion. With disk data already triaged and ready for analysis, you must uncover the extent of this intrusion and identify the compromised assets within the network.

![image.png](image.png)

# Questions

Q1- Analyzing the attack chain requires identifying the file that initiated the payload execution. Which shortcut file was generated after executing the payload-containing file extracted from the ZIP archive?

Answer: `documents.lnk`

Reason: MFTECmd parsing of `FIN-PC`'s `$MFT` shows `documents.zip.lnk` created at `2024-01-01 20:00:24 UTC` in `.\Users\esmith\AppData\Roaming\Microsoft\Windows\Recent`, marking when the ZIP archive was opened. The archive was extracted to `.\Users\esmith\Downloads\documents\max`, and execution of the payload created `documents.lnk` at `2024-01-01 20:00:37 UTC` (MFT entry `35111`, parent path `.\Users\esmith\Downloads\documents`), a shortcut file generated as a side effect of running the extracted payload.

```bash
.\MFTECmd.exe -f 'C:\Users\Administrator\Desktop\Start Here\Artifacts\FIN-PC\$MFT' --csv 'C:\Users\Administrator\Desktop\Start Here' --dr
```

![image.png](image%201.png)

Q2- It’s essential to gather as much information as possible about the attack. Can you identify the malicious script inside the ZIP Archive?

Answer: `eyewear.bat`

Reason: From the same `FIN-PC` `$MFT` listing, `.\Users\esmith\Downloads\documents\max` contains both `easygoing.exe` and `eyewear.bat`, both created at `2024-01-01 20:00:37 UTC` (MFT entries `35108` and `35109`). The `.bat` extension identifies `eyewear.bat` as the malicious script component delivered alongside the executable payload.

Q3- By identifying the C2 IP address, we can gather clues about the attacker, such as their possible location, identity, or affiliation, and understand their motives. Can you identify the C2 IP address?

Answer: `42.63.200.142`

Reason: Sysmon Event ID 3 (network connection) logs on `FIN-PC` show `C:\Users\esmith\AppData\Local\Temp\easygoing.exe` (ProcessGuid `{9ba2f8d1-19f4-6593-5301-000000000d00}`) repeatedly connecting from `192.168.202.197` out to `42.63.200.142:80` over TCP. Beaconing runs from `2024-01-02 07:19:02 PM UTC` (first observed connection) through at least `2024-01-02 10:02:24 PM UTC` (last observed connection in the filtered set), at a roughly 30-second interval, tagged by Sysmon with `technique_id=T1036, technique_name=Masquerading`.

![image.png](image%202.png)

Q4- A key step in an attacker's strategy is reconnaissance. What command was used to gather and export data about the domain's computers?

Answer: `Get-ADComputer -Filter * -Properties * | Export-CSV "C:\Users\esmith\Appdata\Local\Temp\ADComputers.csv" -NoTypeInformation`

Reason: Sysmon Event ID 1 (process creation) on `FIN-PC` at `2024-01-02 19:50:32.133 UTC` shows `powershell.exe` (ProcessGuid `{9ba2f8d1-6908-6594-7802-000000000d00}`) launched by `easygoing.exe` (ParentProcessGuid `{9ba2f8d1-19f4-6593-5301-000000000d00}`, the same C2 process anchored in Q3), with command line `powershell -nop -exec bypass -EncodedCommand <base64>`, tagged `technique_id=T1059.001, technique_name=PowerShell`. Decoding the Base64 payload as UTF-16LE recovers `Get-ADComputer -Filter * -Properties * | Export-CSV "C:\Users\esmith\Appdata\Local\Temp\ADComputers.csv" -NoTypeInformation`, an AD reconnaissance command enumerating all domain computer objects and exporting them to CSV.

```bash
$ echo 'RwBlAHQALQBBAEQAQwBvAG0AcAB1AHQAZQByACAALQBGAGkAbAB0AGUAcgAgACoAIAAtAFAAcgBvAHAAZQByAHQAaQBlAHMAIAAqACAAfAAgAEUAeABwAG8AcgB0AC0AQwBTAFYAIAAiAEMAOgBcAFUAcwBlAHIAcwBcAGUAcwBtAGkAdABoAFwAQQBwAHAAZABhAHQAYQBcAEwAbwBjAGEAbABcAFQAZQBtAHAAXABBAEQAQwBvAG0AcAB1AHQAZQByAHMALgBjAHMAdgAiACAALQBOAG8AVAB5AHAAZQBJAG4AZgBvAHIAbQBhAHQAaQBvAG4A' | base64 -d 
Get-ADComputer -Filter * -Properties * | Export-CSV "C:\Users\esmith\Appdata\Local\Temp\ADComputers.csv" -NoTypeInformation
```

![image.png](image%203.png)

Q5- With escalated privileges, an attacker can typically do more damage. What command did the attacker use to attempt privilege escalation?

Answer: `echo ddb867670d7 > \\.\pipe\308808`

Reason: Sysmon Event ID 1 (process creation) on `FIN-PC` at `2024-01-02 21:12:44.910 UTC` shows `cmd.exe` (ProcessGuid `{9ba2f8d1-7c4c-6594-bb02-000000000d00}`) launched by `rundll32.exe` (ProcessGuid `{9ba2f8d1-7c4c-6594-ba02-000000000d00}`), both running as `NT AUTHORITY\SYSTEM`, tagged `technique_id=T1059.003, technique_name=Windows Command Shell`. The command line was `C:\Windows\system32\cmd.exe /c echo ddb867670d7 > \\.\pipe\308808`, writing a randomly generated token into a named pipe while executing under SYSTEM context.

```bash
The following information was included with the event:
technique_id=T1059.003,technique_name=Windows Command Shell
2024-01-02 21:12:44.910
{9ba2f8d1-7c4c-6594-bb02-000000000d00}
1184
C:\Windows\System32\cmd.exe
10.0.19041.746 (WinBuild.160101.0800)
Windows Command Processor
Microsoft® Windows® Operating System
Microsoft Corporation
Cmd.Exe
C:\Windows\system32\cmd.exe /c echo ddb867670d7 > \\.\pipe\308808
C:\Windows\system32\
NT AUTHORITY\SYSTEM
{9ba2f8d1-7c4c-6594-c5ff-8c0000000000}
0x8cffc5
0
System
SHA1=F1EFB0FDDC156E4C61C5F78A54700E4E7984D55D,MD5=8A2122E8162DBEF04694B9C3E0B6CDEE,SHA256=B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450,IMPHASH=272245E2988E1E430500B852C4FB5E18
{9ba2f8d1-7c4c-6594-ba02-000000000d00}
1020
C:\Windows\System32\rundll32.exe
C:\Windows\system32\rundll32.exe
NT AUTHORITY\SYSTEM
```

## Named Pipe Impersonation Using SCM

A named pipe is a private two-way channel between processes. An attacker who already has local Administrator rights sets up a listener on one, then tricks a `SYSTEM`-level process into connecting to it. Once `SYSTEM` connects, the attacker's code borrows ("impersonates") that connection's `SYSTEM` identity and spawns its own process running as `SYSTEM`.

**Objective:** Escalate from local Administrator to full `SYSTEM`.

**Recon & Setup:** Confirms existing local admin rights (`whoami /priv` / group membership). This is not an exploit against an unprivileged account; admin is a prerequisite. Attacker prepares a pipe listener (`\\.\pipe\<name>`) coded to call `ImpersonateNamedPipeClient` on connect.

**Exploitation Chain:**

- Create a service via `sc.exe create` (or `OpenSCManager`/`CreateService`) pointing at a one-liner such as `cmd.exe /c echo ... > \\.\pipe\<name>`
- Start the service (`sc.exe start`)
- The Service Control Manager (SCM), which runs as `SYSTEM`, launches the binary, so SYSTEM is the one connecting to the attacker's pipe
- The listener calls `ImpersonateNamedPipeClient` to capture the `SYSTEM` token, then `DuplicateTokenEx`/`CreateProcessWithTokenW` to spawn a new `SYSTEM` process

**Key Pivot/Insight:** The attacker never attacks `SYSTEM` directly. The pivot chases a standing design fact: local admins can create/start services, and the SCM that runs them is `SYSTEM`. Privilege (admin) → mechanism (SCM) → identity (`SYSTEM` token).

**Root Cause:** Microsoft does not treat local Administrator-to-`SYSTEM` as a security boundary; an admin can already load drivers, read LSASS, and reconfigure services arbitrarily. This technique is one convenient, automatable path to a `SYSTEM` token among several equally valid ones, which is why it isn't something Microsoft patches.

**Offensive Tooling & Payloads:** Metasploit `getsystem` (named-pipe-impersonation technique), PsExec-style service installs, Cobalt Strike `elevate`. Manual equivalent: `sc.exe create` + `cmd.exe /c echo ... > \\.\pipe\<name>`.

**Detection & Hardening:** The admin→`SYSTEM` gap itself can't be closed, only limited and watched.

- Minimize standing local admin (least privilege, JIT/PAM elevation) — this is the real control point
- Service creation telemetry: Event ID `7045` (System log) and `4697` (Security log)
- Application control (AppLocker/WDAC) to block unsigned or unexpected service binaries
- Sysmon EID `17`/`18` (pipe create/connect) correlated with EID `1` (process creation); pipe names matching known tool conventions (random strings, patterns like `MSSE-####-server`) are a strong signal

**Lessons for Future Engagements:** Treat local admin compromise as equivalent to full host compromise in both red and blue reporting. The differentiator isn't preventing this pivot, it's catching it fast through service-creation plus pipe telemetry correlation.

Q6- We need to assess the severity of the breach. Was the attacker able to compromise any user account? Can you provide the password of the user account the attacker compromised?

Answer: `MYpassword123#`

Reason: Sysmon Event ID 1 (process creation) on `FIN-PC` at `2024-01-02 21:28:43.938 UTC` shows `cmd.exe` (ProcessGuid `{9ba2f8d1-800b-6594-c002-000000000d00}`) launched by `rundll32.exe` (ProcessGuid `{9ba2f8d1-77e1-6594-aa02-000000000d00}`, PID `2956`), both running as `NT AUTHORITY\SYSTEM`, tagged `technique_id=T1059.003, technique_name=Windows Command Shell`. 

The `ParentProcessGuid` matches the same `rundll32.exe` instance already tied to the SYSTEM-escalation lineage (Q5), confirming this action ran within that same elevated session. The command line was `wmic /node:192.168.202.126 /user:FileShareService /password:MYpassword123# logicaldisk get caption,description,drivetype,providername,volumename`, authenticating remotely as the `FileShareService` account using the password `MYpassword123#` to enumerate logical disks on `192.168.202.126`.

```bash
The following information was included with the event:
technique_id=T1059.003,technique_name=Windows Command Shell
2024-01-02 21:28:43.938
{9ba2f8d1-800b-6594-c002-000000000d00}
1080
C:\Windows\System32\cmd.exe
10.0.19041.746 (WinBuild.160101.0800)
Windows Command Processor
Microsoft® Windows® Operating System
Microsoft Corporation
Cmd.Exe
C:\Windows\system32\cmd.exe /C wmic /node:192.168.202.126 /user:FileShareService /password:MYpassword123# logicaldisk get caption,description,drivetype,providername,volumename
C:\Windows\system32\
NT AUTHORITY\SYSTEM
{9ba2f8d1-7c4c-6594-c5ff-8c0000000000}
0x8cffc5
0
System
SHA1=F1EFB0FDDC156E4C61C5F78A54700E4E7984D55D,MD5=8A2122E8162DBEF04694B9C3E0B6CDEE,SHA256=B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450,IMPHASH=272245E2988E1E430500B852C4FB5E18
{9ba2f8d1-77e1-6594-aa02-000000000d00}
2956
C:\Windows\System32\rundll32.exe
C:\Windows\System32\rundll32.exe
NT AUTHORITY\SYSTEM
```

Q7- To ensure complete eradication, identifying and removing persistence mechanisms is essential to ensure the attacker can no longer access the compromised system. What's the command used by the attacker to achieve persistence?

Answer: `cmd.exe /C schtasks /create /tn "ChromeUpdater" /tr "powershell -File 'C:\Users\esmith\AppData\Local\ChromeUpdater\ChromeUpdate.ps1'" /sc onlogon /ru System`

Reason: Sysmon Event ID 1 (process creation) on `FIN-PC` at `2024-01-02 21:35:06.488 UTC` shows `cmd.exe` (ProcessGuid `{9ba2f8d1-818a-6594-c602-000000000d00}`) launched by the same `rundll32.exe` (ProcessGuid `{9ba2f8d1-77e1-6594-aa02-000000000d00}`, PID `2956`) tied to the SYSTEM-escalation lineage, running as `NT AUTHORITY\SYSTEM`, tagged `technique_id=T1059.003, technique_name=Windows Command Shell`. The command line was `schtasks /create /tn "ChromeUpdater" /tr "powershell -File 'C:\Users\esmith\AppData\Local\ChromeUpdater\ChromeUpdate.ps1'" /sc onlogon /ru System`, creating a scheduled task disguised as `ChromeUpdater` that runs a PowerShell script at every logon with SYSTEM privileges.

```bash
The following information was included with the event:
technique_id=T1059.003,technique_name=Windows Command Shell
2024-01-02 21:35:06.488
{9ba2f8d1-818a-6594-c602-000000000d00}
4496
C:\Windows\System32\cmd.exe
10.0.19041.746 (WinBuild.160101.0800)
Windows Command Processor
Microsoft® Windows® Operating System
Microsoft Corporation
Cmd.Exe
C:\Windows\system32\cmd.exe /C schtasks /create /tn "ChromeUpdater" /tr "powershell -File 'C:\Users\esmith\AppData\Local\ChromeUpdater\ChromeUpdate.ps1'" /sc onlogon /ru System
C:\Users\esmith\AppData\Local\ChromeUpdater\
NT AUTHORITY\SYSTEM
{9ba2f8d1-7c4c-6594-c5ff-8c0000000000}
0x8cffc5
0
System
SHA1=F1EFB0FDDC156E4C61C5F78A54700E4E7984D55D,MD5=8A2122E8162DBEF04694B9C3E0B6CDEE,SHA256=B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450,IMPHASH=272245E2988E1E430500B852C4FB5E18
{9ba2f8d1-77e1-6594-aa02-000000000d00}
2956
C:\Windows\System32\rundll32.exe
C:\Windows\System32\rundll32.exe
NT AUTHORITY\SYSTEM
```

Q8- Identifying the targeted data for exfiltration allows the organization to understand the potential impact of the breach and the data's confidentiality level. What's the full path of the folder whose data was targeted by the PowerShell script?

Answer: `C:\Users`

Reason: Sysmon Event ID 11 (FileCreate) on `FIN-PC` at `2024-01-02 21:59:08.415 UTC` shows `rundll32.exe` (ProcessGuid `{9ba2f8d1-77e1-6594-aa02-000000000d00}`, PID `2956`) — the same `SYSTEM`-escalation lineage process — writing `localdisk.ps1` to `C:\Users\administrator\AppData\Local\Temp\`. The script's recovered contents enumerate every directory under `C:\Users\`, compress each into its own ZIP archive via `Compress-Archive`, and stage the output in `C:\Data`, consistent with staging user profile data for exfiltration.

```bash
The following information was included with the event:
technique_id=T1059.001,technique_name=PowerShell
2024-01-02 21:59:08.415
{9ba2f8d1-77e1-6594-aa02-000000000d00}
2956
C:\Windows\System32\rundll32.exe
C:\Users\administrator\AppData\Local\Temp\localdisk.ps1
2024-01-02 21:59:08.415
NT AUTHORITY\SYSTEM

# PS1 script contents
$destinationPath = "C:\Data"

if (-not (Test-Path -Path $destinationPath)) {
    New-Item -ItemType Directory -Path $destinationPath
}

$directories = Get-ChildItem -Path "C:\Users\" -Directory

foreach ($dir in $directories) {
    $zipFileName = "$($dir.Name).zip"
    $zipFilePath = Join-Path $destinationPath $zipFileName
    Compress-Archive -Path $dir.FullName -DestinationPath $zipFilePath
    Write-Host "Compressed $($dir.FullName) to $zipFilePath"
}

Write-Host "All folders in C:\Users\ have been compressed."

```

Q9- To understand the spread of the intrusion and discover possible lateral movement attempts. What is the name of the malicious service installed remotely on `FileServer`?

Answer: `075b12b`

Reason: Security log Event ID `7045` (Service Control Manager) on `FileServer.elitesystems.local` at `2024-01-02 21:09:55 UTC` records a service installation under SID `S-1-5-21-1454730794-1276634269-3791626178-1104`. The service `075b12b` points to `\\FILESERVER\ADMIN$\075b12b.exe`, configured as a demand-start user-mode service running under the `LocalSystem` account — the same `ADMIN$`/SCM service-install pattern used earlier on `FIN-PC` (`a962278.exe`) for SYSTEM-level execution, now confirmed as the lateral-movement mechanism onto `FileServer`.

```bash
Type :		Information
Date :		1/2/2024
Time :		9:09:55 PM
Event :		7045
Source :		Service Control Manager
Category :	None
User :		\S-1-5-21-1454730794-1276634269-3791626178-1104
Computer :	FileServer.elitesystems.local
Description:
A service was installed in the system.

Service Name:  075b12b
Service File Name:  \\FILESERVER\ADMIN$\075b12b.exe
Service Type:  user mode service
Service Start Type:  demand start
Service Account:  LocalSystem
```

Q10- Credential dumping can significantly expand the breach's impact, giving attackers access to numerous systems and data. Can you identify the process name that dumped credentials?

Answer: `rundll32.exe`

Reason: Sysmon Event ID 10 (ProcessAccess) on `FileServer` at `2024-01-02 21:11:01.450 UTC` shows `rundll32.exe` (ProcessGuid `{f590a53f-7be4-6594-b306-000000000700}`, PID `5800`) opening a handle to `lsass.exe` (ProcessGuid `{f590a53f-3a09-6594-0c00-000000000700}`, PID `628`) with `GrantedAccess 0x1010` (`PROCESS_QUERY_LIMITED_INFORMATION` + `PROCESS_VM_READ`), tagged `technique_id=T1003, technique_name=Credential Dumping`. The call stack terminates in an `UNKNOWN` frame not backed by any loaded module, consistent with reflectively-loaded credential-dumping code running inside `rundll32.exe`, both processes running as `NT AUTHORITY\SYSTEM`.

```bash
The following information was included with the event:
technique_id=T1003,technique_name=Credential Dumping
2024-01-02 21:11:01.450
{f590a53f-7be4-6594-b306-000000000700}
5800
6328
C:\Windows\system32\rundll32.exe
{f590a53f-3a09-6594-0c00-000000000700}
628
C:\Windows\system32\lsass.exe
0x1010
C:\Windows\SYSTEM32\ntdll.dll+9fc24|C:\Windows\System32\KERNELBASE.dll+20d0e|UNKNOWN(0000017A3B54E3C4)
NT AUTHORITY\SYSTEM
NT AUTHORITY\SYSTEM
```

Q11- Attackers usually install software on a target system to maintain long-term access, move laterally, access other systems, and expand their reach. What remote access software did the attacker install on one of the machines?

Answer: AnyDesk

Reason: Sysmon Event ID 1 (process creation) on `FileServer` at `2024-01-02 21:18:47.186 UTC` shows `cmd.exe` (ProcessGuid `{f590a53f-7db7-6594-b506-000000000700}`) launched by `rundll32.exe` (ProcessGuid `{f590a53f-7ba8-6594-af06-000000000700}`, PID `1284`) — the same `{f590a53f-...}` lineage as the LSASS credential-dumping event (Q10) — running from `C:\Users\FileShareService\Downloads\` as `NT AUTHORITY\SYSTEM`. 

The command line was `cmd.exe /C start anydesk.exe --install "C:\Program Files (x86)\AnyDesk" --start-with-win --create-desktop-icon`, tagged `technique_id=T1059.003, technique_name=Windows Command Shell`. Security log Event ID `7045` confirms the install completed at `21:18:51 UTC`, registering an auto-start `AnyDesk Service` (`C:\Program Files (x86)\AnyDesk\AnyDesk.exe --service`) under the `LocalSystem` account, giving the attacker persistent remote-access capability on `FileServer`.

```bash
The following information was included with the event:
technique_id=T1059.003,technique_name=Windows Command Shell
2024-01-02 21:18:47.186
{f590a53f-7db7-6594-b506-000000000700}
1080
C:\Windows\SysWOW64\cmd.exe
10.0.17763.592 (WinBuild.160101.0800)
Windows Command Processor
Microsoft® Windows® Operating System
Microsoft Corporation
Cmd.Exe
C:\Windows\system32\cmd.exe /C start anydesk.exe --install  "C:\Program Files (x86)\AnyDesk" --start-with-win --create-desktop-icon
C:\Users\FileShareService\Downloads\
NT AUTHORITY\SYSTEM
{f590a53f-3a09-6594-e703-000000000000}
0x3e7
0
System
SHA1=E2EAD0993B917E1828A658ADA0B87E01D5B8424F,MD5=C43699F84A68608E7E57C43B7761BBB8,SHA256=2EDB180274A51C83DDF8414D99E90315A9047B18C51DFD070326214D4DA59651,IMPHASH=392B4D61B1D1DADC1F06444DF258188A
{f590a53f-7ba8-6594-af06-000000000700}
1284
C:\Windows\SysWOW64\rundll32.exe
C:\Windows\System32\rundll32.exe
NT AUTHORITY\SYSTEM

Type :		Information
Date :		1/2/2024
Time :		9:18:51 PM
Event :		7045
Source :		Service Control Manager
Category :	None
User :		\SYSTEM
Computer :	FileServer.elitesystems.local
Description:
A service was installed in the system.

Service Name:  AnyDesk Service
Service File Name:  "C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service
Service Type:  user mode service
Service Start Type:  auto start
Service Account:  LocalSystem
```

Q12- What password did the attacker set for the installed software?

Answer: `Qwerty123!@#_!`

Reason: Sysmon Event ID 1 (process creation) on `FileServer` at `2024-01-02 21:21:42.639 UTC` shows `cmd.exe` (ProcessGuid `{f590a53f-7e66-6594-c506-000000000700}`) launched by the same `rundll32.exe` (ProcessGuid `{f590a53f-7ba8-6594-af06-000000000700}`, PID `1284`) lineage from the AnyDesk install (Q11), running from `C:\Program Files (x86)\AnyDesk\` as `NT AUTHORITY\SYSTEM`. The command line was `cmd.exe /C echo Qwerty123!@#_! | AnyDesk.exe --set-password`, tagged `technique_id=T1059.003, technique_name=Windows Command Shell`, setting the AnyDesk unattended-access password to `Qwerty123!@#_!` to secure remote-access persistence.

```bash
The following information was included with the event:
technique_id=T1059.003,technique_name=Windows Command Shell
2024-01-02 21:21:42.639
{f590a53f-7e66-6594-c506-000000000700}
6080
C:\Windows\SysWOW64\cmd.exe
10.0.17763.592 (WinBuild.160101.0800)
Windows Command Processor
Microsoft® Windows® Operating System
Microsoft Corporation
Cmd.Exe
C:\Windows\system32\cmd.exe /C echo Qwerty123!@#_! | AnyDesk.exe --set-password
C:\Program Files (x86)\AnyDesk\
NT AUTHORITY\SYSTEM
{f590a53f-3a09-6594-e703-000000000000}
0x3e7
0
System
SHA1=E2EAD0993B917E1828A658ADA0B87E01D5B8424F,MD5=C43699F84A68608E7E57C43B7761BBB8,SHA256=2EDB180274A51C83DDF8414D99E90315A9047B18C51DFD070326214D4DA59651,IMPHASH=392B4D61B1D1DADC1F06444DF258188A
{f590a53f-7ba8-6594-af06-000000000700}
1284
C:\Windows\SysWOW64\rundll32.exe
C:\Windows\System32\rundll32.exe
NT AUTHORITY\SYSTEM
```

Q13- Attackers often enable RDP for more control. What command was used by the attacker to enable RDP?

Answer: `reg  add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0` 

Reason: Sysmon Event ID 1 (process creation) on `DC01` at `2024-01-02 20:29:34.468 UTC` shows `reg.exe` (ProcessGuid `{20b65a2c-722e-6594-8e01-000000000800}`) launched by `cmd.exe` (ProcessGuid `{20b65a2c-722e-6594-8c01-000000000800}`, PID `5860`), both running under `ELITESYSTEMS\dlee` at `High` integrity, tagged `technique_id=T1083, technique_name=File and Directory Discovery`. The parent command line was `cmd.exe /Q /c reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0 1> \\127.0.0.1\ADMIN$\__1704190945.703671 2>&1`, setting `fDenyTSConnections` to `0` to enable Remote Desktop. The output-redirection to a timestamped file under `\\127.0.0.1\ADMIN$\` is a signature pattern of Impacket's `wmiexec.py`, and the compromised account here is `dlee`, distinct from `esmith` and `FileShareService` seen on the earlier hosts.

```bash
The following information was included with the event:
technique_id=T1083,technique_name=File and Directory Discovery
2024-01-02 20:29:34.468
{20b65a2c-722e-6594-8e01-000000000800}
5704
C:\Windows\System32\reg.exe
10.0.17763.1 (WinBuild.160101.0800)
Registry Console Tool
Microsoft® Windows® Operating System
Microsoft Corporation
reg.exe
reg  add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0 
C:\
ELITESYSTEMS\dlee
{20b65a2c-7082-6594-fcfa-3f0000000000}
0x3ffafc
0
High
SHA1=429DF8371B437209D79DC97978C33157D1A71C4B,MD5=8A93ACAC33151793F8D52000071C0B06,SHA256=19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF,IMPHASH=BE482BE427FE212CFEF2CDA0E61F19AC
{20b65a2c-722e-6594-8c01-000000000800}
5860
C:\Windows\System32\cmd.exe
cmd.exe /Q /c reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0 1> \\127.0.0.1\ADMIN$\__1704190945.703671 2>&1
ELITESYSTEMS\dlee
```

# Attack Chain

| Time (UTC) | Stage | Detail | MITRE |
| --- | --- | --- | --- |
| `2024-01-01 20:00:24` | Initial Access | `documents.zip.lnk` created in Recent folder on `FIN-PC` (user `esmith`) after opening phishing-delivered ZIP | `T1566.001` |
| `2024-01-01 20:00:37` | Execution | `easygoing.exe` and `eyewear.bat` extracted and executed from `.\Downloads\documents\max`; `documents.lnk` created as execution side-effect | `T1204.002` |
| `2024-01-02 19:19:02` – `22:02:24` | Command and Control | `easygoing.exe` (Cobalt Strike Beacon) beacons to `42[.]63[.]200[.]142:80` over TCP, ~30s interval | `T1071.001` |
| `2024-01-02 19:50:32` | Discovery | Encoded PowerShell via fork-and-run `rundll32.exe`: `Get-ADComputer -Filter * -Properties * Export-CSV ADComputers.csv` | `T1059.001`, `T1018` |
| `2024-01-02 20:29:34` | Lateral Movement | `reg add fDenyTSConnections /d 0` on `DC01` (account `dlee`), enabling RDP, output redirected via `wmiexec`-style `ADMIN$` pattern | `T1021.001` |
| `2024-01-02 20:53:52` | Privilege Escalation | `a962278.exe` pushed to `\\127.0.0.1\ADMIN$\` and run as `NT AUTHORITY\SYSTEM` via SCM service install on `FIN-PC` | `T1543.003` |
| `2024-01-02 21:09:55` | Lateral Movement | Service `075b12b` installed via `\\FILESERVER\ADMIN$\075b12b.exe` (Event ID `7045`) | `T1021.002` |
| `2024-01-02 21:11:01` | Credential Access | `rundll32.exe` opens `lsass.exe` with `PROCESS_VM_READ`, unbacked call stack, on `FileServer` | `T1003.001` |
| `2024-01-02 21:12:44` | Privilege Escalation | Named-pipe impersonation verification: `cmd.exe /c echo ddb867670d7 > \\.\pipe\308808` as `SYSTEM` on `FIN-PC` | `T1134` |
| `2024-01-02 21:18:47` – `21:18:51` | Persistence | `AnyDesk.exe --install` run, `AnyDesk Service` installed (`LocalSystem`, auto-start) on `FileServer` | `T1219` |
| `2024-01-02 21:21:42` | Persistence | AnyDesk unattended-access password set to `Qwerty123!@#_!` | `T1219` |
| `2024-01-02 21:28:43` | Credential Access | `wmic /node:192.168.202.126 /user:FileShareService /password:MYpassword123#` — stolen credential reuse | `T1078` |
| `2024-01-02 21:35:06` | Persistence | `schtasks /create /tn "ChromeUpdater" ... /sc onlogon /ru System` on `FIN-PC` | `T1053.005` |
| `2024-01-02 21:59:08` | Collection | `localdisk.ps1` dropped on `FIN-PC`, compresses all `C:\Users\` directories to `C:\Data` | `T1560`, `T1005` |

## Attack Tree

```bash
[Stage 1 — Initial Access, FIN-PC]
└── Phishing email (lure: "Meleena Thomas" copyright claim) → esmith@elitesystemscorp[.]xyz
    └── documents.zip downloaded/opened ← documents.zip.lnk
        └── Extracted to .\Downloads\documents\max
            ├── easygoing.exe (Cobalt Strike Beacon) ← execution
            │   └── documents.lnk ← side-effect artifact
            └── eyewear.bat (malicious script)

[Stage 2 — C2 & Discovery, FIN-PC]
└── easygoing.exe beacons → 42[.]63[.]200[.]142:80 (TCP, ~30s interval)
    └── fork-and-run rundll32.exe (sacrificial process)
        └── powershell -EncodedCommand → Get-ADComputer (AD recon)
            └── output via named pipe postex_3e52

[Stage 3 — Privilege Escalation, FIN-PC]
└── a962278.exe pushed to \127.0.0.1\ADMIN$\ → SCM service install → SYSTEM
    └── rundll32.exe (SYSTEM) chain
        └── cmd.exe → echo ddb867670d7 > \.\pipe\308808 ← impersonation verification
            ├── schtasks /create "ChromeUpdater" ← persistence
            └── localdisk.ps1 → Compress-Archive C:\Users* → C:\Data ← collection

[Stage 4 — Lateral Movement, DC01]
└── dlee session → wmiexec-style ADMIN$ execution
    └── reg add fDenyTSConnections=0 ← RDP enabled

[Stage 5 — Lateral Movement, FileServer]
└── wmic /node:192.168.202.126 /user:FileShareService /password:MYpassword123#
    └── Service 075b12b installed via \FILESERVER\ADMIN$\ ← SYSTEM foothold
        └── rundll32.exe → lsass.exe (PROCESS_VM_READ) ← credential dumping
            └── AnyDesk.exe --install ← persistence
                └── AnyDesk --set-password Qwerty123!@#_! ← persistence secured
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Delivery | Lure | Fake copyright-infringement phishing email from "Meleena Thomas" |
|  | Archive | `documents.zip` |
| Dropped File | Payload | `easygoing.exe` |
|  | Script | `eyewear.bat` |
|  | Shortcut | `documents.lnk` |
| Network | C2 IP | `42[.]63[.]200[.]142` |
|  | C2 Port | `80` |
| Discovery | Command | `Get-ADComputer -Filter * -Properties * |
| Privilege Escalation | Dropped File | `a962278.exe` |
|  | Named Pipe | `\\.\pipe\308808` |
|  | Verification Command | `echo ddb867670d7 > \\.\pipe\308808` |
| Lateral Movement | Host | `DC01` (`reg add fDenyTSConnections=0`, account `dlee`) |
|  | Service | `075b12b` (`\\FILESERVER\ADMIN$\075b12b.exe`) |
| Credential Access | Technique | LSASS memory read, `rundll32.exe` → `lsass.exe` |
|  | Stolen Credential | `FileShareService` : `MYpassword123#` |
| Persistence | Scheduled Task | `ChromeUpdater` (`onlogon`, `ru System`) |
|  | Remote Access Tool | AnyDesk (`AnyDesk Service`, `LocalSystem`, auto-start) |
|  | AnyDesk Password | `Qwerty123!@#_!` |
| Collection | Script | `localdisk.ps1` (compresses `C:\Users\*` to `C:\Data`) |
| Compromised Accounts | User | `esmith` |
|  | User | `FileShareService` |
|  | User | `dlee` |

# Lab Insights

- **Fork-and-run leaves a traceable skeleton, not a disguise:** Every privileged action in this intrusion — recon, privesc verification, persistence, collection — ran inside a chain of `rundll32.exe` sacrificial processes spawned by the same Beacon ProcessGuid lineage. The technique is meant to make actions look like generic system activity, but because Sysmon preserves `ParentProcessGuid` across every hop, the entire operator session stays linkable end-to-end once you anchor on the first compromised GUID, rather than evading detection outright.
- **Admin-to-SYSTEM is a mechanism problem, not a vulnerability:** Both the `FIN-PC` and `FileServer` privilege escalations used the same `ADMIN$`/SCM service-install pattern to convert existing local admin rights into unrestricted SYSTEM access. Since Microsoft doesn't treat that boundary as a security boundary, this step was never going to be blocked — it was only ever going to be *caught*, via Event ID `7045` and Sysmon pipe/process correlation.
- **Credential reuse compounds host-to-host:** A single harvested credential (`FileShareService`) was reused across hosts for both discovery (`wmic`) and lateral movement into `FileServer`, while a completely separate account (`dlee`) was independently leveraged on `DC01`. The breach's reach tracks the number of distinct identities compromised at least as much as the number of hosts touched.
- **Legitimate tooling as the final persistence layer:** The attacker's last confirmed action was installing AnyDesk, a signed, legitimate remote-access product, as a SYSTEM-level auto-start service. Commercial RMM/remote-access software blends into normal administrative traffic far better than a custom implant, making it a durable fallback access path even if the original Beacon and scheduled task are both remediated.