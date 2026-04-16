# Maranhao Lab

![image.png](image.png)

# Table of Contents

- [Context](#context)
- [Scenario](#scenario)
- [Initial Access](#initial-access)
- [Execution](#execution)
- [Persistence](#persistence)
- [Defense Evasion](#defense-evasion)
- [Discovery](#discovery)
- [Credential Access](#credential-access)
- [Collection](#collection)
  * [Named Pipes](#named-pipes)
- [Command and Control](#command-and-control)

# Context

**Lab link**: [https://cyberdefenders.org/blueteam-ctf-challenges/maranhao/](https://cyberdefenders.org/blueteam-ctf-challenges/maranhao/)

**Suggested tools**: Event Log Explorer, DB Browser for SQLite, Registry Explorer, EvtxECmd, FTK Imager, PECmd

**Tactics**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Collection

# Scenario

A gaming enthusiast in a known organization has downloaded what they believed to be a free mod launcher for a popular survival game. The file which downloaded contained a ZIP archive with an installer that looked like a standard game setup package.

Eager to try it, the gamer downloaded the file and executed the installer. Unbeknownst to him, the program silently dropped hidden files into a directory. One of these files was configured to persist through registry keys, ensuring it would relaunch every time the system started.

Within a short time, unusual activity triggered alerts on the Security Operations Center's (SOC) in GOAT Company's monitoring dashboard. The gamer's machine was observed making outbound requests to a malicious domain and a suspicious external IP address. Endpoint logs also showed evidence of process injection, suggesting credential theft. The Security Operations Center (SOC) quickly isolated the machine and saved a full disk image for your analysis.

# Initial Access

Q1- Analysts identified an external object that acted as the patient-zero delivery mechanism. Which remote resource URL initiated the chain of compromise by providing the archive disguised as a legitimate game utility?

**Answer**: hxxps://drive.usercontent.google.com/uc?id=1mIxhfZXmcUT2mbKNuahsRI4S_rzVUFKW&export=download

**Explanation**: Mount the AD1 in FTK Imager, export Edge’s `History`, then open it in DB Browser for SQLite. There’s a single download entry, and `tab_url` identifies the source URL that started the compromise.

![image.png](image%201.png)

![image.png](image%202.png)

Q2- In reconstructing the timeline of compromise, which precise timestamp correlates to the adversary's delivery vector entering the victim environment as a ZIP file?

**Answer**: 2025-09-17 10:10

**Explanation**: This timestamp comes from the `start_time` field in the prior DB Browser output. Use a tool like DCode to convert Chromium timestamps to UTC.

![image.png](image%203.png)

Q3- The ZIP archive's decompression exposed a loader binary that masqueraded as a legitimate launcher. What was the executable responsible for initializing this staged intrusion?

**Answer**: `Fnafdoomlauncher.exe`

**Explanation**: Sysmon Event ID 11 (FileCreate) shows the executable being created immediately after the archive was decompressed.

![image.png](image%204.png)

# Execution

Q4- Adversaries often alter installer behavior to remain invisible during deployment. Which installer flag was leveraged to suppress user-facing prompts during execution of the trojanized setup?

**Answer**: `/VERYSILENT`

**Explanation**: `/VERYSILENT` is a built-in Inno Setup switch (not a custom flag) used to suppress installer UI prompts.

![image.png](image%205.png)

Q5- Forensic correlation across endpoints requires file-level fingerprinting. What SHA1 hash uniquely represents the dropper binary that initiated further payload deployment?

**Answer**: FCB94C06FA80CE277B47E545B3805AB38BB6ACF4

**Explanation**: It’s the same dropper from the prior question. The SHA1 comes from Sysmon Event ID 29 (`FileExecutableDetected`) for that binary.

![image.png](image%206.png)

Q6- Post-installation, the secondary payload did not remain in temporary directories but was staged in a user-space program folder. Identify the exact directory path used for this execution pivot.

**Answer**: `C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\`

**Explanation**: The dropper first extracts to a `.tmp` directory, then stages the second payload in this path for execution.

![image.png](image%207.png)

```bash
# Process flow
Fnafdoomlauncher.exe /VERYSILENT
        │
        ▼
Inno Setup extracts to is-TMCD1.tmp\
        │
        ▼
Fnafdoomlauncher.tmp runs (the real dropper logic)
        │
        ├─► Drops updater.exe to AppData\Local\Programs\Microsoft Updater\
        │
        └─► Opens updater.exe with PROCESS_ALL_ACCESS (0x1fffff)
                │
                └─► Likely injects code or hollow/resumes it to execute
```

Q7- During execution, the secondary component was invoked with a victim-tagging token for C2 identification. What globally unique string was provided as the argument?

**Answer**: e90de8b2-eb79-4614-94f8-308f0f81573b

**Explanation**: This GUID is passed on the command line as a unique victim ID so the C2 can identify which host is checking in.

![image.png](image%208.png)

# Persistence

Q8- What was the complete file path of the binary embedded within the persistence mechanism to guarantee re-execution after reboot?

**Answer**: `C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\updater.exe`

**Explanation**: This is the same path for the second payload indicated in the previous question.

Q9- Temporal analysis of registry modifications showed the exact moment persistence was locked in. What is the date and time this key entry was created?

**Answer**: 2025-09-17 10:13

**Explanation**: Check Sysmon Event ID 13 (Registry value set) early in the logs; it records when the persistence entry was created.

![image.png](image%209.png)

# Defense Evasion

Q10- Post-installation, the adversary concealed its artifacts at the file-system level. Which native Windows utility and attribute combination was used to render both files and directories hidden and system-protected?

**Answer**: `attrib +h +s`

**Explanation**: `attrib` is a native Windows utility for setting file attributes. Sysmon shows the attacker applying Hidden + System to multiple artifacts in the directory, including:

- `updater.exe`
- `infoprocess.exe`
- `crypto.key`
- `settings.key`

![image.png](image%2010.png)

# Discovery

Q11- Investigators observed the malware pulling system-level metadata that revealed the installed edition of Windows (e.g., "Microsoft Windows 10 Pro"). This information could later be used by the attacker to determine compatibility with payload execution. Which exact query facilitated this operating system enumeration?

**Answer**: `wmic os get Caption`

**Explanation**: This command appears in Sysmon Event ID 1 (`ProcessCreate`). It returns the installed Windows edition (the `Caption` field).

![image.png](image%2011.png)

```
C:\> wmic os get Caption
Caption
Microsoft Windows 10 Home
```

Q12- To assess whether the compromised system had sufficient processing resources or was running in a sandbox with emulated hardware, the malware issued a command to extract the processor's vendor and model string. What specific query enabled this reconnaissance?

**Answer**: `wmic cpu get Name`

**Explanation**: Like the prior WMI query, this is host fingerprinting and is visible in the same process creation activity.

![image.png](image%2012.png)

Q13- As part of its environment fingerprinting, the malware attempted to identify graphics hardware to help distinguish between a physical workstation and a low-resource virtual machine. Which query would return the video controller model?

**Answer**: `wmic path win32_VideoController get Name`

**Explanation**: Another WMI-based fingerprinting query used to collect hardware details (GPU model).

Q14- The malware generated a unique victim identifier that would remain stable across reboots and reinstalls by retrieving a machine's hardware UUID. Which WMI command was responsible for collecting this globally unique identifier?

**Answer**: `wmic csproduct get UUID`

**Explanation**: This WMI query retrieves the machine’s hardware UUID from BIOS/UEFI. Because it’s stable across reboots and OS reinstalls, it’s a reliable identifier for host fingerprinting.

![image.png](image%2013.png)

Q15- During host triage, analysts identified a query that enumerated logical drives along with their free space and size. This could help an attacker determine whether the host was worth further exploitation (e.g., data exfiltration feasibility). Which WMI command produced this disk inventory?

**Answer**: `wmic logicaldisk get Caption,FreeSpace,Size,Description /format:list`

**Explanation**: Another WMIC inventory query observed alongside the other host-fingerprinting commands.

![image.png](image%2014.png)

```
C:\> wmic logicaldisk get Caption,FreeSpace,Size,Description /format:list

Caption=C:
Description=Local Fixed Disk
FreeSpace=288907137024
Size=1003942309888
```

Q16- Unlike transient licensing tokens stored in tokens.dat, the malware pursued a static registry artifact used as a backup for Windows activation. Identify the precise registry entry (hive, key path, and value) that serves as a fallback product key reference.

**Answer**: `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\BackupProductKeyDefault`

**Explanation**: This registry value can be abused as a durable “fallback” Windows product key reference. Attackers/activation tools may set `...SoftwareProtectionPlatform\BackupProductKeyDefault` and use a scheduled task to periodically re-apply the activation state via the Software Protection Platform service (`sppsvc`), restoring it even after partial remediation.

![image.png](image%2015.png)

```bash
C:\> powershell.exe -c "Get-ItemProperty -Path \"HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\" -Name \"BackupProductKeyDefault\"" #Attacker reading the current backup product key to use it for persistence mechanisms
```

# Credential Access

Q17- Attackers often terminate browsers before attempting to steal session data, cookies, or inject a malicious browser extension. What is the command that was used to forcibly terminate all browser processes?

**Answer**: `taskkill /F /IM msedge.exe`

**Explanation**: Locate `taskkill` in Sysmon process-creation events to find the exact command line.

![image.png](image%2016.png)

# Collection

Q18- After injection, the malware established an interprocess channel for credential theft. What named pipe was created to ferry stolen browser data?

**Answer**: `ChromeDecryptIPC_e7e223c5-50d5-40ae-8513-64c9962789c2`

**Explanation**: `infoprocess.exe` (masquerading as an updater under `Microsoft Updater` in the user’s AppData) created the named pipe `\ChromeDecryptIPC_e7e223c5-50d5-40ae-8513-64c9962789c2` at 10:13 under the `Levi` context. The `ChromeDecryptIPC` prefix strongly implies IPC used to move decrypted browser data, and the appended GUID makes the pipe name unique per infection to avoid collisions and simple signatures.

To link the processes involved, correlate Sysmon Event ID 17 (PipeCreated) with Event ID 18 (PipeConnected). The lab may not include both, but for context:

- **Event 17 (`PipeCreated`)** gives you the **server side** — the process that created the pipe:

```bash
EventID: 17
Image: C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\infoprocess.exe
PipeName: \ChromeDecryptIPC_e7e223c5-50d5-40ae-8513-64c9962789c2
```

- **Event 18 (`PipeConnected`)** gives you the **client side** — the process that connected to it:

```bash
EventID: 18
Image: C:\Program Files\Google\Chrome\Application\chrome.exe
PipeName: \ChromeDecryptIPC_e7e223c5-50d5-40ae-8513-64c9962789c2
```

## Named Pipes

Named pipes exist on both platforms but with differences.

**What they are:** A named pipe is a kernel-managed communication channel with a human-readable name that processes can reference to send and receive data. It behaves like a file you read/write to, but data flows between processes rather than to disk.

**Why not just "call each other directly":** Processes can't access each other's memory — the OS enforces strict memory isolation. So they need a **kernel-mediated mechanism** to pass data. Options include:

| Mechanism | Use case |
| --- | --- |
| Named pipes | Streaming data between processes |
| Sockets | Network communication |
| Shared memory | High speed, same machine only |
| Message queues | Async messaging |

**OS Differences:**

| Aspect | Windows | Linux |
| --- | --- | --- |
| Namespace | `\\.\pipe\name` | `/tmp/mypipe` or anywhere in filesystem |
| Created with | `CreateNamedPipe()` | `mkfifo()` |
| Network support | Yes, via SMB | No, local only |
| Permissions | ACLs + impersonation | Standard Unix file permissions |
| Directionality | Bidirectional | Unidirectional (need two for both directions) |

**Key difference:** Windows named pipes support impersonation, so a server can adopt the security token of a connecting client which Linux pipes don't natively support. This is the property most relevant to Windows privilege escalation abuse. On Linux, attackers more commonly use Unix domain sockets when they need bidirectional, permission-aware IPC.

# Command and Control

Q19- To enrich host discovery with geolocation data, the malware beaconed to an external resolver. Which service endpoint did it query?

**Answer**: ip-api.com

**Explanation**: Sysmon Event ID 22 (`DNSQuery`) shows the malware requesting this geolocation service domain.

![image.png](image%2017.png)

Q20- Blocking by domain is insufficient; analysts confirmed the resolved address of the geolocation API. Which single IP must be blacklisted?

**Answer**: 208.95.112.1

**Explanation**: This IP is the DNS resolution for the geolocation service domain in the prior question.

```bash
C:\> nslookup 208.95.112.1
Name:    ip-api.com
Address:  208.95.112.1
```

Q21- During network traffic analysis, the malware's outbound request did not resolve to a direct host but instead terminated at Cloudflare's edge network, a common tactic to conceal attacker infrastructure. Which two IP addresses were returned as part of this resolution?

**Answer**: 172.67.144.96, 104.21.71.100

**Explanation**: Sysmon Event ID 22 (DNSQuery) shows `updater.exe` querying `api.maranhaogang.fun`, which resolved to `172.67.144.96` and `104.21.71.100` (Cloudflare). This suggests the attacker proxied C2 behind Cloudflare (CDN hiding/domain fronting), obscuring the origin and making the traffic appear to terminate at Cloudflare.

![image.png](image%2018.png)
