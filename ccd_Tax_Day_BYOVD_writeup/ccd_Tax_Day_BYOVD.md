# Tax Day - BYOVD Lab

<p align="center">
  <img src="image.png" alt="image.png">
</p>

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Initial Access](#initial-access)
- [Persistence](#persistence)
- [Discovery](#discovery)
- [Credential Access](#credential-access)
- [Stealth and Defense Impairment](#stealth-and-defense-impairment)
  * [Windows PE Header Breakdown](#windows-pe-header-breakdown)
  * [Bring Your Own Vulnerable Driver BYOVD](#bring-your-own-vulnerable-driver-byovd)
    + [PPL Bypass Mechanism in BYOVD Kernel Kill](#ppl-bypass-mechanism-in-byovd-kernel-kill)
- [Credential Access](#credential-access-1)
- [Attack Chain](#attack-chain)
  * [Text Tree](#text-tree)
- [Artifacts](#artifacts)
- [Lab Insights](#lab-insights)

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/tax-day-byovd/](https://cyberdefenders.org/blueteam-ctf-challenges/tax-day-byovd/)

Suggested tools: DB Browser for SQLite, Timeline Explorer, Windows Event Viewer, PECmd

Tactics: Resource Development, Persistence, Privilege Escalation, Defense Evasion, Command and Control

# Scenario

Every year around tax season, accountants are buried in forms, filings, and contractor paperwork. Attackers know this. They count on the urgency, the routine, the muscle memory of downloading one more document. This time it worked.

The machine has been imaged and the evidence is in front of you — start digging.

# Initial Access

**Q1**- While searching and downloading tax forms, `kjones` certainly downloaded a file that doesn't fit what he was looking for. What is the name of that file?

Answer: `form_w9.msi`

Reason: User `kjones` downloaded `form_w9.msi` from `hxxp://bringetax[.]com/` while browsing for tax forms, observed via DB Browser for SQLite. The file is an 8.5MB Windows Installer package disguised as a routine document, served with Multipurpose Internet Mail Extensions (MIME) type `application/x-msi`. The domain and filename both exploit tax-season urgency, a pattern consistent with phishing or malicious-download pretexting rather than a legitimate Internal Revenue Service (IRS) or contractor form site. This activity maps to MITRE ATT&CK technique T1566.002 (Phishing: Spearphishing Link) for the initial delivery vector, with subsequent execution of the `.msi` file falling under T1204.002 (User Execution: Malicious File).

![image.png](image%201.png)

**Q2**- What time was that file downloaded?

Answer: `2026-04-30 18:10`

Reason: Using a tool like `DCode`, the `end_time` value `13422046217841750` (Chromium/WebKit epoch format, microseconds since `1601-01-01 00:00:00 UTC`) converts to `2026-04-30 18:10:17 UTC`, marking the moment `form_w9.msi` finished downloading. This anchors the start of the attack timeline (T0) for subsequent event correlation across the host.

![image.png](image%202.png)

**Q3**- What domain was that file downloaded from?

Answer: `bringetax.com`

Reason: The file was pulled from `hxxp://bringetax[.]com/`, a domain crafted to look tax-form-adjacent but not an official Internal Revenue Service (IRS) or payroll/contractor platform. This is consistent with a purpose-registered phishing or malware-delivery domain timed to tax season.

![image.png](image%203.png)

**Q4**- At some point `kjones` opened the files he downloaded, which triggered the execution of the rogue file. When exactly did that happen?

Answer: `2026-04-30 18:14`

Reason: `explorer.exe` (PID `5860`) spawned `msiexec.exe` at `2026-04-30 18:14:53.543`, four minutes after the download completed. This timing is consistent with `kjones` double-clicking `form_w9.msi` from the Downloads folder to trigger installation. This behavior maps to MITRE ATT&CK technique T1204.002 (User Execution: Malicious File), with `msiexec.exe` acting as the execution vector for whatever payload the Microsoft Installer (MSI) package drops. The `explorer.exe` to `msiexec.exe` parent-child relationship is the expected process lineage for a user-initiated install and lines up with the download-to-execution gap observed in the timeline.

Process lineage: `{c73af8d8-9c1d-69f3-6606-000000005400}`

![image.png](image%204.png)

# Persistence

**Q5**- The execution of that file immediately triggered a chain of events leading to the installation of a remote management tool. A new service was registered on the system shortly after. What is the name of that service?

Answer: `AteraAgent`

Reason: After the SYSTEM-context `msiexec.exe /V` spawned from `services.exe`, Sysmon Event ID 11 (`FileCreate`) on that same ProcessGuid shows it writing `C:\Program Files\ATERA Networks\AteraAgent\Agent\AteraAgent.exe` at `2026-04-30 18:15:27.797`, followed by registration of the `AteraAgent` service. This is a legitimate remote monitoring and management (RMM) tool being abused here to give the attacker persistent, living-off-the-land remote access that blends in with normal IT tooling. Windows System log Event ID 7045 (Service Control Manager) on `WKSTN-01.maromalix.corp` at `2026-04-30 18:15:47 UTC` records the `AteraAgent` service installation, with binary path `C:\Program Files\ATERA Networks\AteraAgent\Agent\AteraAgent.exe`, configured for auto-start under the `LocalSystem` account. This is the authoritative service-creation event and lands roughly 20 seconds after the Sysmon Event ID 11 (`FileCreate`) of the same binary, giving two-source corroboration between file-write and service-registration for the writeup.

Process lineage from the installer execution: `{c73af8d8-9c1e-69f3-6706-000000005400}`

![image.png](image%205.png)

![image.png](image%206.png)

**Q6**- The same installation also deployed a second remote access tool. What is the service name registered for this second tool?

Answer: `Splashtop® Remote Service`

Reason: The same elevated `msiexec.exe` (PID `7140`, ProcessGuid `{c73af8d8-9c1e-69f3-6706-000000005400}`) that dropped `AteraAgent` also deployed `Splashtop`. Sysmon Event ID 11 (`FileCreate`) shows `BdEpSDK.exe` written at `18:18:00.169`, followed by Event ID 7045 at `18:18:23` registering the Splashtop Remote Service (binary `SRService.exe`, auto-start, `LocalSystem`). Two legitimate RMM tools deployed from a single malicious installer chain is a strong redundancy or fallback pattern: if one RMM channel gets detected and killed, the attacker retains the other as a backup foothold.

![image.png](image%207.png)

![image.png](image%208.png)

# Discovery

**Q7**- After gaining access, the attacker started discovery activity through the RMM. There is a specific process belonging to the RMM agent that acted as the parent to all subsequent attacker commands on the system. What is the name of that process?

Answer: `AgentPackageRunCommandInteractive.exe`

Reason: The attacker used Atera's built-in "run command" feature: `AgentPackageRunCommandInteractive.exe` (PID `9324`) launched `cmd.exe` (PID `6944`) as `SYSTEM`, which then became the parent process for all subsequent discovery commands, including the `reg.exe` registry queries. This confirms the remote monitoring and management (RMM) tool was not just a persistence mechanism but the active command and control (C2) channel the attacker was typing commands through in real time. This maps to MITRE ATT&CK technique T1059.003 (Command and Scripting Interpreter: Windows Command Shell), with `AgentPackageRunCommandInteractive.exe` serving as the C2 proxy that translated attacker input into the local shell session.

```bash
# Process lineage
AteraAgent (RMM service, SYSTEM)
    └── AgentPackageRunCommandInteractive.exe (PID 9324)  ← Atera "run command" module, attacker-issued
        └── cmd.exe (PID 6944)  ← ProcessGuid {c73af8d8-adc8-69f3-b20a-000000005400}
            ├── reg.exe (ProcessGuid {c73af8d8-adce-69f3-b60a-000000005400})  ← reg query HKLM\...\Lsa DisableRestrictedAdmin
            └── reg.exe (ProcessGuid {c73af8d8-ade1-69f3-b90a-000000005400})  ← second reg query
```

![image.png](image%209.png)

![image.png](image%2010.png)

**Q8**- The attacker queried registry keys to check the current state of the system before making any changes. What was the first registry key they queried?

Answer: `HKLM\System\CurrentControlSet\Control\Lsa`

Reason: The attacker's first discovery action through the Atera remote monitoring and management (RMM) shell was querying `HKLM\System\CurrentControlSet\Control\Lsa` at `2026-04-30 19:30:22.077 UTC` (shown above) to check whether Restricted Admin Mode was disabled. This is reconnaissance to determine whether pass-the-hash (PtH) Remote Desktop Protocol (RDP) access would be viable later in the intrusion, before taking any further action on the host. Checking `Restricted Admin Mode` status before acting is a deliberate sequencing choice: this setting, when enabled, allows RDP authentication with just the NTLM hash rather than the plaintext password, so confirming its state first tells the attacker whether PtH is a viable lateral movement path without needing to capture credentials in plaintext.

# Credential Access

**Q9**- The attacker then attempted to dump LSASS to steal credentials but was immediately blocked by Defender. When did Defender first detect this attempt?

Answer: `2026-04-30T19:32`

Reason: Defender's Antimalware Scan Interface (AMSI) provider caught a PowerShell-based LSASS dumping attempt in-memory before it could execute, flagging it as `HackTool:PowerShell/Lsassdump.A` at High severity. The detection occurred under `NT AUTHORITY\SYSTEM` through `powershell.exe`, spawned from the same remote monitoring and management (RMM)-driven `cmd.exe` shell used for the earlier discovery activity. This was caught at the script content level via AMSI, not through post-execution behavioral detection. The attacker's obfuscation was not sufficient to slip the actual PowerShell logic past AMSI's scan, even though the process itself launched successfully. This detection maps to MITRE ATT&CK technique T1003.001 (OS Credential Dumping: LSASS Memory).

![image.png](image%2011.png)

# Stealth and Defense Impairment

**Q10**- Failing to dump LSASS, the attacker tried to stop Defender directly but was also blocked. What exact command did the attacker run to attempt this?

Answer: `sc.exe stop WinDefend`

Reason: After the AMSI-blocked LSASS dump attempt a minute earlier, the attacker pivoted to a direct approach: attempting to stop the `WinDefend` service outright via `sc.exe`. Defender's tamper-protection feature caught this as a command-line-level detection (Detection Source: System, not AMSI this time). This means Defender flagged the attempt to disable itself through a specific tamper-protection signature rather than scanning executed script content. This action maps to MITRE ATT&CK technique T1562.001 (Impair Defenses: Disable or Modify Tools), with the failed outcome demonstrating tamper protection functioning as designed against a user-mode service-stop attempt.

![image.png](image%2012.png)

**Q11**- With both attempts blocked, the attacker launched an interactive PowerShell session and dropped two files into the system. What are the names of those two files?

Answer: `HWAuidoOs2Ec.sys`, `kd.exe`

Reason: A malicious PowerShell session, launched after both the LSASS dumping and Defender-stop attempts were blocked, dropped two files into `C:\Users\kjones\AppData\Roaming\`: `HWAuidoOs2Ec.sys`, a misspelled-name file posing as an audio driver and serving as the vulnerable kernel driver for the upcoming Bring Your Own Vulnerable Driver (BYOVD) stage, and `kd.exe`, named to mimic Microsoft's legitimate Kernel Debugger tool but serving as the loader or controller for that driver. Both files were written by the same `powershell.exe` process (ProcessGuid `{c73af8d8-ae45-69f3-d20a-000000005400}`), which traces back through `cmd.exe` to the `AgentPackageRunCommandInteractive.exe` remote monitoring and management (RMM) channel used throughout the intrusion. This drop maps to MITRE ATT&CK technique T1588.002 (Obtain Capability: Tool) for staging the vulnerable driver and loader ahead of exploitation.

```bash
# Lineage
AteraAgent (RMM service, SYSTEM)
    └── AgentPackageRunCommandInteractive.exe (PID 11968)  ← Atera "run command" module, attacker-issued
        └── cmd.exe (PID 8560)  ← ProcessGuid {c73af8d8-ae45-69f3-d00a-000000005400}
            └── cmd.exe /c powershell
                └── powershell.exe (PID 7316)  ← ProcessGuid {c73af8d8-ae45-69f3-d20a-000000005400}
                    ├── FileCreate: HWAuidoOs2Ec.sys  ← 19:35:13.232, vulnerable driver (BYOVD)
                    └── FileCreate: kd.exe  ← 19:35:20.233, driver loader/controller
```

![image.png](image%2013.png)

**Q12**- The attacker then registered one of those dropped files as a kernel service. What name did the attacker give to that service?

Answer: `HwAudio`

Reason:  `HwAudio` was registered as a `type= kernel` service pointing at the dropped driver via `sc.exe` at `19:35:32.600`. This is the literal Bring Your Own Vulnerable Driver (BYOVD) driver-load step: `sc.exe create HwAudio type= kernel binPath= C:\Users\kjones\AppData\Roaming\HWAuidoOs2Ec.sys`, spawned by the same `powershell.exe` session that dropped the files. Creating the service with `type= kernel` instructs the Service Control Manager to load the `.sys` file as a kernel-mode driver rather than a normal user-mode service. This is the exact mechanism that places the attacker's vulnerable driver into kernel space.

![image.png](image%2014.png)

**Q13**- One of the two dropped files was an executable designed to kill Windows Defender. When was it executed for the first time?

Answer: `2026-04-30 19:35`

Reason: `kd.exe`, the Defender-killing tool, was first observed executing at `2026-04-30 19:35:51.740`, not through a direct process-creation log but inferred from a Sysmon Event ID 10 (`ProcessAccess`) event showing `powershell.exe` (PID `7316`) opening a full-access handle (`0x1fffff`) into `kd.exe` (PID `8924`, ProcessGuid `{c73af8d8-af17-69f3-100b-000000005400}`). No Event ID 1 exists anywhere in the log for `kd.exe`'s own launch, which is notable given that the `HwAudio` kernel driver had been registered moments earlier. One plausible explanation is that the vulnerable driver was used to blind Sysmon's process-creation visibility for this specific execution, though that remains a hypothesis pending static-analysis confirmation of the driver's capabilities rather than a confirmed finding.

![image.png](image%2015.png)

**Q14**- Load that executable in IDA. What is the process name this executable targets?

Answer: `MsMpEng.exe`

Reason: `kd.exe`, the dropped Defender-killing executable, was loaded into IDA Pro for static analysis. In `main`, a hardcoded string constant `"MsMpEng.exe"` (auto-labeled `aMsmpengExe` by IDA) is passed into a custom `GetPidByName` function, which enumerates running processes via `CreateToolhelp32Snapshot`/`Process32First`/`Process32Next` and compares each entry's name against that target using `strcmp`. This confirms the tool was purpose-built to locate and terminate Microsoft Defender's core service process. The hardcoded string approach (`"MsMpEng.exe"` compared via `strcmp`) confirms this is a purpose-built tool targeting a single, specific process rather than a general-purpose process killer, consistent with a BYOVD toolkit built or acquired specifically for this kind of Defender-bypass operation.

![image.png](image%2016.png)

![image.png](image%2017.png)

```nasm
.rdata:000000014000B029                                         ; DATA XREF: __gcc_register_frame+4C↑o
.rdata:000000014000B041                 align 10h
.rdata:000000014000B050 aMsmpengExe     db 'MsMpEng.exe',0      ; DATA XREF: main+D↑o
.rdata:000000014000B05C                 align 20h
.rdata:000000014000B060 ; const char Buffer[]
```

## Windows PE Header Breakdown

Every Windows executable, `.exe`, `.dll`, and `.sys` files included, follows the Portable Executable (PE) format, a structured file layout defined by Microsoft that both the operating system loader and static analysis tools like IDA Pro rely on to correctly map a file's contents into memory. When a compiler and linker build a binary, they don't just dump raw machine code into a file, they organize the output into named sections, each carrying its own memory protection attributes (read, write, execute) that the Windows loader enforces at runtime via page-level permissions. This section-based structure is why a forensic analyst reverse-engineering a tool like `kd.exe` can reliably predict where to look for specific content: code lives in one place, strings in another, and imported function references in a third, regardless of which specific binary is being examined.

The core sections an analyst encounters:

- `.text`, the actual executable machine code. This section is marked read and execute, but not writable, which is where functions like `main` or `GetPidByName` physically exist as disassembled instructions.
- `.rdata`, read-only initialized data: string literals, constant variables, and frequently the Import Directory Table or Import Address Table (IAT) metadata, though this placement is compiler-dependent since some linkers fold `.idata` directly into `.rdata`.
- `.idata`, import data proper: the names and addresses of external functions the binary pulls from other Dynamic Link Libraries (DLLs), such as the `DeviceIoControl` reference examined earlier. As noted, some linkers merge this into `.rdata` instead of keeping it as a separate section, which is a linker or compiler choice rather than a strict Portable Executable (PE) format requirement.
- `.data`, read-write initialized data: global or static variables that start with a defined value and can change during execution.
- `.bss`, uninitialized global or static variables, zeroed at load time; on Windows this is frequently folded into `.data` rather than kept separate.
- `.rsrc`, resources: icons, version information, embedded manifests, and dialog templates.
- `.reloc`, the base relocation table, used when a binary cannot load at its preferred base address, supporting Address Space Layout Randomization (ASLR).
- `.pdata`, exception handling data, specific to x64 binaries, used for structured exception handling and stack unwind information.

**Why It Matters for Forensic Analysis**

Understanding section boundaries lets an analyst reason about intent rather than just content. A string like `"[+] Connected to Huawei Driver (Ring 0 access)."` sitting in `.rdata` is expected and unremarkable in isolation, but a `.text` section full of unresolved `??` bytes, as encountered in the earlier IDA session, is a signal worth investigating rather than dismissing, since executable code should be fully present and disassemblable in a file loaded directly from disk. Section attributes also matter for malware behavior: legitimate code should never need to write into `.text` at runtime, so a process observed modifying its own or another process's `.text` section is a strong indicator of self-modifying code, process hollowing, or shellcode injection, since it violates the expected read/execute-only permission model.

**Relevance to Detection and MITRE ATT&CK Mapping**

Anomalies in Portable Executable (PE) section structure are a recognized detection surface. Packed or obfuscated malware frequently shows abnormal section characteristics, unusually high entropy in a section that should be low-entropy code, a `.text` section with an executable-and-writable permission combination that legitimate compilers rarely produce, or a mismatch between a section's declared `VirtualSize` and its on-disk `SizeOfRawData`, the exact condition that can produce the `??` gaps seen in the earlier IDA screenshot. This maps to MITRE ATT&CK technique T1027 (Obfuscated Files or Information), since manipulating section structure, packing, or padding is a common technique to evade static analysis and signature-based detection.

**Q15**- Continue your analysis in IDA. The executable communicates with the loaded driver by sending it a specific control code. What is the IOCTL code passed to `DeviceIoControl`?

Answer: `0x2248DC`

Reason: Continuing static analysis of `kd.exe` in IDA Pro, tracing forward from `main`: the tool first calls `GetPidByName("MsMpEng.exe")`, which enumerates running processes via `CreateToolhelp32Snapshot`/`Process32First`/`Process32Next` and matches by `strcmp` to resolve Defender's process ID (PID). It then opens a handle to the vulnerable driver via `CreateFileA`. That handle is passed into `DeviceIoControl` at `main+14F`, where the control code is loaded immediately beforehand (`mov edx, 2248DCh ; dwIoControlCode`), sending the resolved PID into the driver to trigger kernel-privileged termination.

Status strings recovered from `.rdata` narrate the same flow: `"[+] Connected to Huawei Driver (Ring 0 access)."`, `"[>] Sending IOCTL to terminate target..."`, `"[***] SUCCESS: %s (PID %lu) has been terminated."`. These strings confirm the driver is represented internally as Huawei-signed and abused purely as a Ring 0 (kernel privilege level) process-kill primitive against Defender.

This chain maps to MITRE ATT&CK technique T1068 (Exploitation for Privilege Escalation) for the Bring Your Own Vulnerable Driver (BYOVD) mechanism itself, and T1562.001 (Impair Defenses: Disable or Modify Tools) for the resulting termination of `MsMpEng.exe`. Together with the earlier failed `sc.exe`-based stop attempt, this confirms the attacker escalated from a blocked user-mode defense-evasion technique to a successful kernel-mode one once the vulnerable driver was staged.

Static analysis flow (IDA Pro, `kd.exe`):

1. `GetPidByName("MsMpEng.exe")` uses `CreateToolhelp32Snapshot` + `Process32First`/`Process32Next` + `strcmp` to resolve the target PID.
2. `CreateFileA` opens a handle to the driver device (`hDevice`).
3. `DeviceIoControl(hDevice, dwIoControlCode=0x2248DC, InBuffer=<PID>, ...)` sends the kill Input/Output Control (IOCTL).
4. The driver (`HWAuidoOs2Ec.sys`), Huawei-signed per binary strings, terminates `MsMpEng.exe` at kernel privilege.

![image.png](image%2018.png)

## Bring Your Own Vulnerable Driver BYOVD

Bring Your Own Vulnerable Driver (BYOVD) is a technique where an attacker who has already gained administrative or SYSTEM-level access on a host brings a legitimately signed, but exploitable, kernel driver onto the machine and loads it deliberately. Windows requires kernel-mode drivers to be signed by a trusted certificate authority, and the operating system's kernel-mode code signing enforcement will refuse to load an unsigned or tampered driver. Rather than trying to forge a signature or exploit the signing chain itself, the attacker sidesteps this entirely by using a driver that is genuinely, validly signed by a legitimate hardware vendor, but that also happens to expose a dangerous capability through its Input/Output Control (IOCTL) interface, most commonly arbitrary process termination, arbitrary memory read/write, or arbitrary kernel object manipulation.

In the `kd.exe`/`HWAuidoOs2Ec.sys` case just documented, the flow was: register the vulnerable driver as a kernel-type service via `sc.exe create ... type= kernel`, which causes the Service Control Manager to load it into kernel space; open a handle to the driver's device object via `CreateFileA`; then call `DeviceIoControl` with a specific control code that the driver interprets as a command, in this case, terminate the process whose PID is passed in the input buffer. Because the driver itself is signed and was never modified, Windows has no reason to distrust it. The vulnerability isn't in how the driver got there, it's in what the driver was designed (or accidentally left) to allow any caller to do once loaded.

**Why It Evades Detection**

BYOVD is effective specifically because it inverts the usual trust model defenders rely on. Endpoint detection tools, Microsoft Defender included, generally treat "signed driver" as a strong positive trust signal, and kernel-mode code is inherently more privileged and less visible to user-mode security agents than the processes those agents are trying to protect. A security product running in user mode or even as a protected process cannot reliably stop a malicious action that originates from kernel space, since kernel code runs at a higher privilege ring than the defender itself. This is precisely why the attacker in this case pivoted to BYOVD only after two user-mode evasion attempts failed: the AMSI-blocked PowerShell LSASS dump and the tamper-protection-blocked `sc.exe stop WinDefend` were both caught because they operated within layers Defender actively monitors. The kernel driver's IOCTL-based kill primitive bypasses that layer entirely, since from the operating system's perspective, a trusted, signed kernel driver requested the termination, not an unprivileged or flagged user-mode process.

Additionally, because the vulnerable driver is a real, legitimately distributed file rather than custom attacker tooling, static file-reputation and hash-based detection often have nothing to flag: the file itself isn't malware, its capability is simply being misused by the loader/controller executable (`kd.exe` here) that drives it.

**Detection Methods**

Detection for BYOVD centers on behavioral and contextual signals rather than static file reputation, since the driver itself will typically pass signature checks:

- **Service creation with `type= kernel`** targeting a binary path outside the standard driver store (`C:\Windows\System32\drivers\`), especially in user-writable locations like `AppData\Roaming`, is a strong anomaly signal. Sysmon Event ID 13 (registry value set) or Windows Event ID 7045 (Service Control Manager) with a `ServiceType` of kernel driver and an unusual `ImagePath` should be treated as high-priority.
- **Known-vulnerable driver hash/name blocklists.** Microsoft maintains a vulnerable driver blocklist (`DriverSiPolicy.p7b`), and tools like LOLDrivers track publicly known abusable drivers by hash and name. Comparing loaded driver hashes against this list catches known BYOVD tools even when the loader executable is novel.
- **Process handles opened to driver device objects followed immediately by `DeviceIoControl` calls from unusual parent processes.** A `powershell.exe`spawned executable calling `CreateFileA` against a device path and then `DeviceIoControl` shortly after is atypical for legitimate driver interaction outside of vendor management tools.
- **Correlating the kernel-service registration timestamp against subsequent unexplained process terminations**, particularly of security products, is often the clearest confirmation, exactly the pattern used in this writeup: `HwAudio` service creation, followed by `kd.exe` execution inferred via ProcessAccess rather than ProcessCreate, followed by Defender's termination.

**Mitigations**

- Enable and enforce Microsoft's vulnerable driver blocklist, which is on by default on modern Windows builds with Hypervisor-protected Code Integrity (HVCI) or Smart App Control enabled, but can be explicitly verified and enforced via policy.
- Restrict which accounts can load kernel drivers or create kernel-type services; this generally requires SYSTEM or local Administrator rights, so tightly scoping administrative access reduces the attack surface for BYOVD to occur at all.
- Deploy Attack Surface Reduction (ASR) rules and Endpoint Detection and Response (EDR) tooling that specifically monitor for kernel-mode service registration events combined with anomalous binary locations.
- Enable Windows Defender Application Control (WDAC) or similar allowlisting to restrict which drivers, even signed ones, are permitted to load on the host.

**MITRE ATT&CK Mapping**

- T1068 (Exploitation for Privilege Escalation): the core BYOVD mechanism, leveraging the driver's kernel-privileged IOCTL interface.
- T1543.003 (Create or Modify System Process: Windows Service): the `sc.exe create ... type= kernel` registration step.
- T1562.001 (Impair Defenses: Disable or Modify Tools): the resulting termination of the security product.
- T1036 (Masquerading): applicable when the driver or loader uses a misleading name, as seen with `HWAuidoOs2Ec.sys` and `kd.exe`.

### PPL Bypass Mechanism in BYOVD Kernel Kill

Protected Process Light (PPL) is what makes `MsMpEng.exe` resistant to termination even from a SYSTEM-context user-mode caller. PPL enforcement works by checking the *calling* process's own signature and protection level against the target's before permitting an action like `TerminateProcess`, which is precisely why the earlier `sc.exe stop WinDefend` attempt failed: `sc.exe`, even running as SYSTEM, is still a user-mode caller subject to that check, and its protection level didn't meet the bar required to touch a PPL-protected target.

A kernel-mode driver is not a "caller" in the sense PPL enforcement was designed to evaluate, it operates as part of the kernel itself, one privilege ring below where PPL checks are actually enforced. This lets a vulnerable driver defeat PPL through one of two primitives:

- **Arbitrary kernel memory read/write.** The driver locates the target process's `EPROCESS` structure, the kernel's internal representation of the process, and directly patches its `SignatureLevel`/`Protection` field. Once that field is cleared, the process is no longer marked protected, and a normal termination call succeeds where it previously would have been blocked.
- **Direct kernel-mode termination.** The driver's IOCTL wraps a kernel API like `ZwTerminateProcess` or `PsTerminateProcess`, called from kernel context. Because the request originates from Ring 0 rather than a user-mode caller, it bypasses the PPL access-control check entirely rather than needing to strip protection first.

Either path produces the same outcome: a protection model designed to stop user-mode callers, including SYSTEM-level ones, has no equivalent enforcement against a caller already operating inside the kernel. This is the specific mechanistic reason the `HwAudio` driver's `DeviceIoControl` call succeeded against `MsMpEng.exe` after the user-mode `sc.exe` attempt was blocked by tamper protection.

# Credential Access

**Q16**- With Defender neutralized, the attacker successfully dumped LSASS. When was the dump file created on disk?

Answer: `2026-04-30 19:36`

Reason: `kd.exe`'s kernel-level termination of `MsMpEng.exe` cleared the way for the attacker to dump LSASS unopposed. `rundll32.exe` (PID `4648`) invoked the `comsvcs.dll` `MiniDump` export against `lsass.exe` (PID `684`), first opening a full-access handle at `19:36:06.371` (Event ID 10), then writing the resulting memory dump to `C:\Users\kjones\AppData\Roaming\lsass.dmp` at `19:36:06.283` (Event ID 11). Both events share the same `rundll32.exe` ProcessGuid, giving source-to-output corroboration for the exact dump file and its disk location. This maps to MITRE ATT&CK technique T1003.001 (OS Credential Dumping: LSASS Memory), using the `comsvcs.dll` `MiniDump` export as a living-off-the-land alternative to a dedicated credential-dumping tool, notable since this succeeded where the earlier AMSI-flagged PowerShell-based LSASS dump attempt failed, confirming Defender's termination was the enabling step for this second attempt.

![image.png](image%2019.png)

![image.png](image%2020.png)

# Attack Chain

| Time (UTC) | Stage | Detail | MITRE |
| --- | --- | --- | --- |
| `2026-04-30 18:10` | Initial Access | `kjones` downloads `form_w9.msi` from `hxxp://bringetax[.]com/` while searching for tax forms | T1204, T1566 |
| `2026-04-30 18:14:53` | Execution | `explorer.exe` spawns `msiexec.exe` to install `form_w9.msi` | T1204 |
| `2026-04-30 18:14:54` | Execution | Elevated `msiexec.exe /V` spawned SYSTEM-context from `services.exe` | T1218 |
| `2026-04-30 18:15:27` | Persistence | `AteraAgent.exe` dropped to `Program Files\ATERA Networks\...` | T1105 |
| `2026-04-30 18:15:47` | Persistence | `AteraAgent` service registered (auto-start, `LocalSystem`) | T1543.003 |
| `2026-04-30 18:18:00` | Persistence | `BdEpSDK.exe` (Splashtop) dropped | T1105 |
| `2026-04-30 18:18:23` | Persistence | Splashtop® Remote Service registered (auto-start, `LocalSystem`) | T1543.003 |
| `2026-04-30 19:30:16` | Command and Control | `AgentPackageRunCommandInteractive.exe` (Atera) spawns `cmd.exe`, attacker's interactive C2 shell | T1059.003 |
| `2026-04-30 19:3x` | Discovery | `reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin` | T1012 |
| `2026-04-30 19:32:21` | Execution | `cmd.exe /c powershell` spawns interactive PowerShell session | T1059.001 |
| `2026-04-30 19:32:38` | Credential Access (blocked) | AMSI/Defender blocks PowerShell LSASS dump attempt (`HackTool:PowerShell/Lsassdump.A`) | T1003.001 |
| `2026-04-30 19:33:43` | Defense Evasion (blocked) | `sc.exe stop WinDefend` blocked by Defender tamper protection | T1562.001 |
| `2026-04-30 19:35:13` | Defense Evasion | `HWAuidoOs2Ec.sys` (vulnerable Huawei-signed driver) dropped to `AppData\Roaming` | T1588.002 |
| `2026-04-30 19:35:20` | Defense Evasion | `kd.exe` (driver controller/loader) dropped to `AppData\Roaming` | T1105 |
| `2026-04-30 19:35:32` | Privilege Escalation | `sc create HwAudio type= kernel binPath= HWAuidoOs2Ec.sys`, vulnerable driver loaded to kernel | T1543.003 |
| `2026-04-30 19:35:51` | Defense Evasion | `kd.exe` executes: resolves `MsMpEng.exe` PID, sends IOCTL `0x2248DC` to `HwAudio` driver, terminates Defender at Ring 0 | T1068, T1562.001 |
| `2026-04-30 19:36:06` | Credential Access | `rundll32.exe comsvcs.dll,MiniDump` dumps `lsass.exe` to `lsass.dmp`, unopposed post-Defender-kill | T1003.001 |

## Text Tree

```bash
[+] form_w9.msi delivered via bringetax[.]com  ← attacker → kjones (18:10)
    └── explorer.exe → msiexec.exe (user execution, 18:14:53)
        └── msiexec.exe /V (SYSTEM, via services.exe)
            ├── [Stage 1 — Persistence: Dual RMM Deployment]
            │   ├── AteraAgent.exe dropped → AteraAgent service (18:15)
            │   └── BdEpSDK.exe (Splashtop) dropped → Splashtop® Remote Service (18:18)
            │
            └── [Stage 2 — C2 via RMM]
                └── AgentPackageRunCommandInteractive.exe (19:30:16)
                    └── cmd.exe
                        ├── reg.exe query Lsa\DisableRestrictedAdmin  ← discovery (19:3x)
                        └── cmd.exe /c powershell (19:32:21)
                            ├── [Stage 3 — Failed Evasion]
                            │   ├── LSASS dump attempt  ✗ blocked by AMSI (19:32:38)
                            │   └── sc stop WinDefend  ✗ blocked, tamper protection (19:33:43)
                            │
                            └── [Stage 4 — BYOVD]
                                ├── HWAuidoOs2Ec.sys dropped (19:35:13)  ← vulnerable Huawei driver
                                ├── kd.exe dropped (19:35:20)  ← driver controller
                                ├── sc create HwAudio type=kernel (19:35:32)  ← driver loaded to Ring 0
                                └── kd.exe executes (19:35:51)
                                    └── IOCTL 0x2248DC → HwAudio driver
                                        └── MsMpEng.exe terminated at kernel level  ← Defender killed
                                            └── [Stage 5 — Credential Access, unopposed]
                                                └── rundll32.exe comsvcs.dll,MiniDump (19:36:06)
                                                    └── lsass.dmp written to AppData\Roaming
```

# Artifacts

**Network Indicators**

| Type | Value |
| --- | --- |
| Malicious download domain | `hxxp://bringetax[.]com/` |

**Host Indicators**

| Type | Value |
| --- | --- |
| Initial lure file | `C:\Users\kjones\Downloads\form_w9.msi` |
| Legitimate RMM #1 (abused) | `C:\Program Files\ATERA Networks\AteraAgent\Agent\AteraAgent.exe` |
| Legitimate RMM #1 service | `AteraAgent` |
| Legitimate RMM #2 (abused) | `C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRService.exe` |
| Legitimate RMM #2 service | Splashtop® Remote Service |
| RMM C2 module | `AgentPackageRunCommandInteractive.exe` |
| Vulnerable driver (BYOVD) | `C:\Users\kjones\AppData\Roaming\HWAuidoOs2Ec.sys` |
| Kernel service name | `HwAudio` |
| Driver controller/loader | `C:\Users\kjones\AppData\Roaming\kd.exe` |
| LSASS dump output | `C:\Users\kjones\AppData\Roaming\lsass.dmp` |

**File Hashes**

| Type | Value |
| --- | --- |
| `form_w9.msi` SHA256 | `D53E90AF814F61E09BFF87A883A3B0DCB7DCF883F17A2425A62A2D4B5A9407FB` |

**Detection Events**

| Type | Value |
| --- | --- |
| Defender detection #1 | `HackTool:PowerShell/Lsassdump.A` (AMSI, High severity) |
| Defender detection #2 | `Trojan:Win32/MpTamperSrvDisableAV.D` (System, Severe) |

**BYOVD Parameters**

| Type | Value |
| --- | --- |
| Driver vendor (claimed) | Huawei |
| Target process | `MsMpEng.exe` |
| IOCTL code | `0x2248DC` |
| Kernel service type | `type= kernel` |

# Lab Insights

- Living-off-the-land isn't just binaries anymore — it's whole platforms. The redundant Atera + Splashtop deployment shows attackers increasingly weaponizing entire legitimate categories of software (RMM tools) rather than individual LOLBins. Both are signed, both are IT-department-normal, and running two in parallel isn't overkill — it's insurance against a single detection killing the whole foothold. Defenders who allowlist "known-good" RMM vendors by name are handing attackers a blind spot by design.
- Detection succeeded exactly where it was supposed to, and failed exactly where it was designed not to reach. AMSI caught the PowerShell LSASS dump; tamper protection caught the sc stop WinDefend attempt — both textbook wins for user-mode/script-level defenses. But neither has any visibility into kernel space, which is precisely why BYOVD exists as a technique class: it doesn't need to be stealthy against AMSI or tamper protection, it needs to operate one privilege ring below where those controls live at all. Two blocked attempts weren't a failure of the attack chain — they were reconnaissance for which door was actually unlocked.
- A valid signature answers a different question than "is this safe." The entire BYOVD stage worked because Windows' signing check validates publisher identity, not code safety — a distinction that doesn't map cleanly onto how most people intuitively think about "trusted" software. The vulnerable driver never needed to evade anything; it just needed to already be legitimate, and its vulnerability did the rest.
- Static telemetry gaps are themselves evidence, not just inconvenience. The missing EID 1 for kd.exe's launch wasn't a logging failure to shrug off — once correlated against the kernel driver load that preceded it, the absence of an expected event became a data point suggesting Sysmon visibility was being manipulated at the kernel level. Treating gaps as signal rather than noise is what separates a full reconstruction from a partial one.
- Process lineage tools (ProcessGuid, text trees) pay for themselves most on the longest chains. This lab's chain ran RMM service → agent module → cmd → powershell → dropped files → kernel service → driver → LSASS dump — six-plus hops deep. Anywhere along that chain, relying on PID or timestamp proximity instead of ProcessGuid would have produced a plausible-looking but wrong lineage; the discipline of confirming each hop is what made the eventual gap (the missing kd.exe EID 1) visible as an anomaly instead of getting lost in general log noise.