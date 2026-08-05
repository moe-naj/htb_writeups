# Base

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Tasks](#tasks)
- [User Flag Walkthrough](#user-flag-walkthrough)
- [Root Flag Walkthrough](#root-flag-walkthrough)
- [Attack Chain](#attack-chain)
  * [Attack Tree](#attack-tree)
- [Artifacts](#artifacts)
- [Lab Insights](#lab-insights)

<p align="center">
  <img src="image.png" alt="image.png" width="300">
</p>

# Context

Lab link: [https://app.hackthebox.com/machines/Base](https://app.hackthebox.com/machines/Base)

Suggested tools: `nmap`, `curl`, `gobuster`, Burp Suite, `strings`, `nc`, `ssh`, `sudo`

# Scenario

Base is a very easy Linux machine that focuses on exploiting PHP misconfigurations and insecure coding practices. A vulnerable web application with a listable login folder reveals a swap file containing the PHP code for the web-app. A brief analysis of the code reveals a comparison vulnerability in the login function which allows authentication bypass. With authorized access to the web-app, a reverse shell can be uploaded to grant initial access to the host machine. Then, the web application configuration files can be examined to find a plaintext password allowing SSH access to a more privileged user. Finally, privilege escalation can be achieved abusing misconfigured `sudo` permissions on the `find` binary.

# Tasks

Q1- Which two TCP ports are open on the remote host?

Answer: 22, 80

Reason: A TCP port scan of the target host 10.129.95.184 identified exactly two open ports: `22/tcp`, running OpenSSH `7.6p1` on Ubuntu Linux, and `80/tcp`, running Apache httpd `2.4.29` on Ubuntu, serving a web application titled "Welcome to Base." All remaining 998 scanned ports were closed. This limited attack surface confines initial access vectors to the web application on port 80 and SSH authentication on port 22.

```bash
nmap -sC -sV 10.129.95.184 -vv

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome to Base
```

Q2- What is the relative path on the webserver for the login page?

Answer: `/login/login.php`

Reason: Browsing to the target's homepage and inspecting the rendered navigation links revealed that the "Login" menu item points to a relative path of `/login/login.php`, confirmed both by grepping the raw HTML response for the string "login" and by directly navigating to the page in a browser, which rendered a standard username/password login form under the `BASE` site branding. This establishes the login application's location on the webserver and sets up the next step: enumerating the `/login/` directory itself for additional exposed files (such as editor swap files) that may leak the underlying PHP source.

![image.png](image%201.png)

Q3- How many files are present in the '/login' directory?

Answer: 3

Reason: Directory listing was enabled on the `/login/` directory, which exposed exactly three files: `config.php`, `login.php`, and `login.php.swp`. The presence of a `.swp` file is significant, as this is a Vim swap file automatically created while a source file is being edited; if left behind after the edit completes, it can be retrieved and often reconstructed to recover the original source code, exposing the application's internal logic (including authentication code in `login.php`) to an unauthenticated attacker.

```bash
$ curl -s http://10.129.95.184/login/ | grep -iEo '<a href="[^"]+\.[^"]+">' | cut -d '"' -f2
config.php
login.php
login.php.swp
```

Q4- What is the file extension of a swap file?

Answer: `.swp`

Reason: The recovered file `login.php.swp` carries the `.swp` extension, the standard artifact Vim generates while a file is open for editing to support crash recovery. Its presence in the publicly listable `/login/` directory confirms that the `login.php` source was edited directly on the production webserver at some point, and the swap file was never cleaned up after the session ended abnormally, leaving the file recoverable by an unauthenticated attacker via a simple HTTP request.

Q5- Which PHP function is being used in the backend code to compare the user submitted username and password to the valid username and password?

Answer: `strcmp()`

Reason: Recovering readable strings from the leaked `login.php.swp` swap file revealed that the authentication logic validates submitted credentials using PHP's `strcmp()` function, comparing both `$username` against `$_POST['username']` and `$password` against `$_POST['password']`, with a successful login redirecting to `/upload.php` and setting `$_SESSION['user_id'] = 1`. This is significant because PHP's `strcmp()` is not designed for security-sensitive comparisons — when given a non-string (such as an array) instead of a string for either argument, it returns `NULL` rather than throwing a type error in PHP versions prior to 8, and `NULL == 0` evaluates to true under loose comparison, meaning an attacker who submits an array-typed `username`/`password` parameter can force the check to falsely succeed without knowing any valid credentials.

```bash
$ strings login.php.swp | grep -i strcmp -C 5
            print("<script>alert('Wrong Username or Password')</script>");
        } else {
            header("Location: /upload.php");
            $_SESSION['user_id'] = 1;
        if (strcmp($password, $_POST['password']) == 0) {
    if (strcmp($username, $_POST['username']) == 0) {
    require('config.php');
if (!empty($_POST['username']) && !empty($_POST['password'])) {
session_start();
<?php
```

Q6- In which directory are the uploaded files stored?

Answer: `/_uploaded`

Reason: Directory brute-forcing the webroot with `gobuster` against the `big.txt` wordlist revealed a directory named `_uploaded`, returning HTTP `301` and redirecting to `/_uploaded/`, alongside standard entries like `assets` and blocked `.htaccess`/`.htpasswd` files (both `403`). Since the leaked source code showed a successful login bypass redirecting to `/upload.php`, this discovered `/_uploaded` directory is almost certainly where files submitted through that upload functionality are written and later served back, making it the logical target for hosting a malicious payload (e.g. a PHP reverse shell) once authentication is bypassed.

```bash
$ gobuster dir -u http://10.129.95.184/ -w /usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.184/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 278]
.htpasswd            (Status: 403) [Size: 278]
_uploaded            (Status: 301) [Size: 318] [--> http://10.129.95.184/_uploaded/]
assets               (Status: 301) [Size: 315] [--> http://10.129.95.184/assets/]
...
```

Q7- Which user exists on the remote host with a home directory?

Answer: `john`

Reason: The `/home/` directory on the target host contains a single user directory, `john`, discovered after obtaining a shell as `www-data` (the Apache service account) and confirming the hostname as `base`.

Q8- What is the password for the user present on the system?

Answer: `thisisagoodpassword`

Reason: Reading the application's configuration file, `config.php`, located in `/var/www/html/login/`, revealed hardcoded credentials in plaintext: a username of `admin` and a password of `thisisagoodpassword`. Since this same password is reused for the local system user `john`, it enables direct SSH access to that account, escalating from the low-privilege `www-data` web shell to a full interactive session as a named user on the host.

```bash
www-data@base:/var/www/html/login$ cat config.php

<?php
$username = "admin";
$password = "thisisagoodpassword";
```

# User Flag Walkthrough

1- Authentication bypass via PHP loose comparison: The leaked `login.php.swp` source revealed that both the username and password were validated using PHP's `strcmp()` function under a loose `== 0` comparison. Intercepting the login `POST` request in Burp Suite and modifying the body to send `password` as an array (`password[]=''`) rather than a string caused `strcmp()` to receive a non-string argument, returning `NULL`; since `NULL == 0` evaluates true in PHP's loose comparison, the check passed without any valid credentials, granting authenticated access to the application as `admin`.

2- Reverse shell upload: With authenticated access to the file upload functionality, a PHP reverse shell payload was uploaded, landing in the previously discovered `/_uploaded/` directory. Requesting the uploaded file's path via the browser (or `curl`) while a local `netcat` listener was active triggered the payload's execution on the target, returning an interactive connection as the low-privileged web service account `www-data`.

3- Configuration file credential discovery: From the `www-data` shell, reading the application's configuration file at `/var/www/html/login/config.php` exposed hardcoded, plaintext credentials: username `admin` and password `thisisagoodpassword`. Enumerating `/home/` showed a single local system user, `john`, and the leaked password was found to be reused for that account.

4- SSH access as john: Using the recovered password against the local user `john` over SSH granted a full interactive shell as that user, escalating from the restricted web-service context to a named user account on the host.

5- User flag capture: Reading `user.txt` from `john`'s home directory returned the flag, completing the user-level objective of the engagement.

```bash
POST /login/login.php HTTP/1.1
Host: 10.129.95.184
Content-Type: application/x-www-form-urlencoded

username=admin&password[]=''

- -- upload malicious PHP reverse shell via authenticated upload form ---

$ curl http://10.129.95.184/_uploaded/<shell>.php
--- netcat listener catches connection ---

www-data@base:/var/www/html/login$ cat config.php
<?php
$username = "admin";
$password = "thisisagoodpassword";

www-data@base:/$ ls /home/
john

$ ssh john@10.129.95.184
Password: thisisagoodpassword

john@base:~$ cat user.txt
[REDACTED]
```

![image.png](image%202.png)

![image.png](image%203.png)

Q10- What is the full path to the command that the user `john` can run as user `root` on the remote host?

Answer: `/usr/bin/find`

Reason: Running `sudo -l` as the user `john` revealed a sudo permission entry allowing `john` to execute `/usr/bin/find` as `root` with no other restrictions. Since `find` supports an `-exec` flag that can invoke arbitrary commands, this misconfiguration is a well-known privilege escalation vector — `find` can be used to spawn a root-owned shell directly, without needing to know the root password.

```bash
john@base:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on base:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on base:
    (root : root) /usr/bin/find
```

Q11- What action can the find command use to execute commands?

Answer: `exec`

Reason: The `find` command supports an `-exec` action, which executes an arbitrary command against each matched file, optionally substituting the matched filename via `{}`. Since `john` was permitted to run `/usr/bin/find` as `root` via `sudo` with no argument restrictions, this action can be abused to spawn an interactive shell running with root privileges rather than operating on any actual file.

# Root Flag Walkthrough

1- Sudo privilege enumeration: Running `sudo -l` as `john` revealed that `john` could execute `/usr/bin/find` as `root` with no further restrictions, and `find`'s `-exec` action was identified as the abusable primitive for privilege escalation.

2- Root shell via find -exec: Leveraging the passwordless `sudo` permission, `sudo find . -exec /bin/sh ; -quit` was executed, invoking `find` on the current directory and using its `-exec` action to spawn `/bin/sh` as `root` for the first matched entry, then immediately exiting the `find` traversal via `-quit` — dropping straight into a root-owned interactive shell.

3- Root flag capture: Confirming privileges with `whoami` returned `root`. Navigating to `/root` and listing its contents showed `root.txt` (not `flag.txt`), and reading it returned the final flag, completing full compromise of the host.

```bash
john@base:~$ sudo find . -exec /bin/sh \; -quit
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
[REDACTED]
```

# Attack Chain

| Stage | Detail | MITRE |
| --- | --- | --- |
| Reconnaissance | `nmap -sC -sV` against `10.129.95.184` identifies `22/tcp` (OpenSSH) and `80/tcp` (Apache) open | T1595.001 |
| Discovery | Directory listing enabled on `/login/` exposes `config.php`, `login.php`, `login.php.swp` | T1083 |
| Collection | Recovery of `login.php.swp` (Vim swap file) discloses full PHP authentication source code | T1213 |
| Initial Access | `strcmp()` type-juggling bypass — Burp Suite used to send `password[]` as an array, forcing a false-positive loose comparison (`NULL == 0`) | T1190 |
| Execution | Authenticated upload of a PHP reverse shell to `/_uploaded/`, triggered via HTTP request, yielding a shell as `www-data` | T1505.003 |
| Credential Access | `config.php` read from web shell, exposing hardcoded plaintext credentials (`admin` / `thisisagoodpassword`) | T1552.001 |
| Lateral Movement | SSH login as local user `john` using the reused web-app password | T1021.004 |
| Privilege Escalation (Discovery) | `sudo -l` reveals passwordless `sudo` rights on `/usr/bin/find` | T1069.001 |
| Privilege Escalation | `sudo find . -exec /bin/sh ; -quit` spawns an interactive root shell via GTFOBins-style sudo abuse | T1548.003 |
| Objective Complete | `root.txt` read from `/root/`, confirming full host compromise | T1005 |

## Attack Tree

```bash
HTB Base (10.129.95.184)
│
├── 80/tcp -- Apache 2.4.29, custom PHP web app
│   └── directory listing enabled on /login/
│       └── login.php.swp recovered (leaked source code)
│           └── strcmp() type-juggling auth bypass (Burp: password[]='')
│               └── authenticated file upload -> /_uploaded/
│                   └── PHP reverse shell triggered via HTTP
│                       └── shell as www-data
│                           │
│                           ├── config.php read -> admin:thisisagoodpassword
│                           │   └── password reused for local user john
│                           │       └── SSH as john
│                           │           │
│                           │           ├── /home/john/user.txt
│                           │           │   └── [USER FLAG] 
│                           │           │
│                           │           └── sudo -l -> (root) /usr/bin/find, NOPASSWD
│                           │               └── sudo find . -exec /bin/sh \; -quit
│                           │                   └── shell as root
│                           │                       └── /root/root.txt
│                           │                           └── [ROOT FLAG] 
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Hosts / Network | Target IP | `10.129.95.184` |
|  | Attacker `tun0` IP | `10.10.15.0/23` |
|  | Open ports | `22/tcp` (SSH), `80/tcp` (HTTP) |
|  | Hostname | `base` |
| Web Application | Login page | `/login/login.php` |
|  | Listable directory | `/login/` |
|  | Leaked source file | `login.php.swp` |
|  | Config file | `config.php` |
|  | Upload directory | `/_uploaded/` |
| Credential Access | Discovered credentials | `admin` : `thisisagoodpassword` |
|  | Credential source | `/var/www/html/login/config.php` |
|  | Reused for local account | `john` |
| Vulnerability | Auth bypass mechanism | `strcmp()` loose comparison / type juggling (`password[]=''`) |
|  | Privilege escalation vector | Passwordless `sudo` on `/usr/bin/find` (`-exec`) |
| Access | Initial shell | `www-data` (via uploaded PHP reverse shell) |
|  | Privileged shell | `john` (via SSH, reused password) |
|  | Root shell | `root` (via `sudo find . -exec /bin/sh ; -quit`) |
| Tools | Recon | `nmap`, `gobuster` |
|  | Exploitation | Burp Suite (request interception/modification), custom PHP reverse shell payload |
|  | Access | `ssh`, `curl` |

# Lab Insights

1. Leftover editor artifacts are rarely inert leftovers — they're often a direct pipeline from "code was edited here" to "attacker gets the source." Vim's crash-recovery mechanism is designed to survive abnormal session termination, which is exactly the failure mode most likely on a production server (dropped SSH session, killed process) rather than a controlled dev environment; the swap file recovered here, `login.php.swp`, handed over the entire authentication logic for free, collapsing the intended black-box trust boundary between "what the server exposes" and "what an attacker can see" without a single exploit being run. (T1213)
2. Loose/type-juggling comparisons are a systemic risk in dynamically typed languages, not a one-off bug — any comparison operator that coerces types before comparing (PHP's `==`, `strcmp()` against non-strings, similar patterns in JavaScript) creates a class of authentication bypass where the attacker's goal shifts from "guess the secret" to "find an input type the developer didn't anticipate." Here, submitting `password` as an array rather than a string turned a strict-looking equality check into an unconditional pass, illustrating that input type, not just input value, is part of an application's attack surface. (T1190)
3. A single misconfigured `sudo` rule collapses the entire privilege boundary it was meant to enforce, because very few binaries are truly "safe" to run as root unrestricted — utilities like `find`, `vim`, `less`, or `awk` retain general-purpose command execution features (here, `find`'s `exec` action) that have nothing to do with their intended narrow use case. Granting passwordless root access to such a binary is functionally equivalent to granting root shell access outright, which is why GTFOBins-style abuse of allow-listed `sudo` commands remains one of the most common Linux privilege escalation vectors in real environments, not just CTF boxes. (T1548.003)