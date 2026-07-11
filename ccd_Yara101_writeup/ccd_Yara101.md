# Yara101 Lab

# Table of Contents
- [Context](#context)
- [Scenario](#scenario)
- [Questions](#questions)
- [Lab Insights](#lab-insights)

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/yara101/](https://cyberdefenders.org/blueteam-ctf-challenges/yara101/)

Suggested tools: Stringsifter, Strings, ilspy, Yara

Tactics: Detection Engineering

# Scenario

Recent intelligence reports have raised alarms about advanced variants of known malware strains on critical infrastructures in the Middle East. Gleanings from underground forums suggest these enhanced variants might result from collaboration between multiple threat actor groups.

As a Detection Engineer, your task is to analyze the provided malware samples, identify the unique characteristics of these samples, and create YARA rules to detect all potential variants. Your findings will be important in safeguarding regional assets and understanding the depth of this evolving cyber threat.

# Questions

Q1- As you begin your analysis of the malware samples, understanding the category of the malware will provide insight into its potential behavior and threat. What category does the first malware belong to?

Answer: Ransomware

Reason: The first malware sample was provisionally categorized as ransomware following a strings scan of the executable, which revealed a ransom note embedded directly in the binary at static analysis time. The extracted text included the lines `All your important files are encrypted!` and `RESTORE YOU DATA POSIBLE ONLY BUYING private key from us.` The broken English phrasing is consistent with ransom notes historically attributed to non-native English speaking threat actors.

```bash
ubuntu@ip-172-31-21-12:~/Desktop/Start here/Artifacts/Level_1$ strings sample_1 | grep -i "encrypted\|restore\|private key"
All your important files are encrypted!
Any attempts to restore your files with the thrid-party software will be fatal for your files!
RESTORE YOU DATA POSIBLE ONLY BUYING private key from us.
 # Do not rename encrypted files.
%ld files encrypted; speed %ld files/sec
All your files are encrypted by LockBit
for more information see Restore-My-Files.txt that is located in every encrypted folder
```

Q2- After encrypting the victim's files, the ransomware leaves behind a `.txt` note directing victims to a payment link, usually accessible via the Tor browser. What is this link?

Answer: `hxxp://lockbitks2tvnmwk.onion/`

Reason: The ransom note discovered during static analysis (dated `2026-07-10`, no additional timestamped event since this is a standalone binary artifact) also identified the sample as LockBit and directed victims to a Tor payment portal at `hxxp://lockbitks2tvnmwk[.]onion/`, surfaced by grepping the strings output around the `.onion` keyword. This confirms the note's claimed branding.

Q3- Having pinpointed a unique Indicator of Compromise (IOC) from the malware strains, developing a YARA rule for detection is crucial. Once you've crafted your rule, refer to the README.txt file on your lab machine for instructions on verifying its effectiveness. What's the level 1 flag?

Answer: `yara_level_1_completed_4de1e9160`

Reason: After crafting a YARA rule targeting the unique LockBit ransom note strings and onion address identified in Q1/Q2 (`2026-07-10` static analysis of `sample_1`), running it against the lab's verification harness per the on-host `README.txt` instructions confirmed successful detection and returned the Level 1 completion.

```c
rule LockBit_Ransomware_Sample1
{
    meta:
        description = "Detects LockBit ransomware variant based on ransom note strings and Tor payment link"
        source = "sample_1 static strings analysis"
        date = "2026-07-10"

    strings:
        $lockbit_url = "http://lockbitks2tvnmwk.onion/"

    condition:
        $lockbit_url
}
```

Q4- Moving forward with your analysis, you turn your attention to the second malware family. What category do these samples fall under?

Answer: Stealer

Reason: The second malware family was categorized as a stealer, confirmed via a strings scan of `sample_1` in `Level_2` (`2026-07-10` static analysis) that revealed a full set of `.NET` auto-property backing fields: `ScanPasswords`, `ScanWallets`, `ScannedCookie`, `Autofills`, `FtpConnections`, and `RecoursiveFileGrabber`. The `k__BackingField` naming pattern indicates this is a managed C#/`.NET` binary whose class properties map directly to credential and data harvesting functionality, covering passwords, cookies, autofill data, FTP (File Transfer Protocol) connections, and cryptocurrency wallets. This is consistent with infostealer behavior rather than encryption or destructive payloads.

```bash
ubuntu@ip-172-31-21-12:~/Desktop/Start here/Artifacts/Level_2$ strings sample_1 | grep -iE "wallet|password|cookie|autofill|ftp|grabber"
get_ScanFTP
set_ScanFTP
<ScanFTP>k__BackingField
<Password>k__BackingField
<Cookies>k__BackingField
<Autofills>k__BackingField
<FtpConnections>k__BackingField
<ScannedWallets>k__BackingField
<ScanWallets>k__BackingField
get_Password
set_Password
ScannedCookie
AllWalletsRule
Autofill
RecoursiveFileGrabber
ScanPasswords
get_Cookies
set_Cookies
get_Autofills
set_Autofills
get_FtpConnections
set_FtpConnections
get_ScannedWallets
set_ScannedWallets
get_ScanWallets
set_ScanWallets
AutofillT
ScannedCookieT
Name	Autofills
Cookies
Password
ScanFTP
ScanWallets
FtpConnections
ScannedWallets
```

Q5- To determine the potential damage and intent of the malware, it's crucial to understand the data it targets. From your analysis of the 1st sample of this malware family, which application related to FTP connections has its credentials targeted for theft by the malware?

Answer: FileZilla

Reason: Continued analysis of `sample_1` identified FileZilla as the FTP client whose stored credentials are targeted, a `strings` `grep` around the "`zilla`" keyword surfaced the literal string FileZilla.

```bash
ubuntu@ip-172-31-21-12:~/Desktop/Start here/Artifacts/Level_2$ strings sample_1 | grep -i "zilla" -C 2
pbIV
value__
FileZilla
sdi845sa
cbData
```

Q6- As part of your ongoing analysis, search for the application name (identified in the previous step) within the strings of the other malware samples. What is the sample name that does not contain this application name?

Answer: `sample_2`

Reason: Grepping "`zilla`" across all Level_2 stealer samples showed `sample_3` and `sample_4` both contain the FileZilla string, but `sample_2` returned no match, indicating this variant either lacks FTP-credential-harvesting functionality entirely or targets FTP clients through a different code path/string that doesn't reference the "FileZilla" name directly.

Q7- Continuing with your investigation, you turn to the last unidentified malware sample. This family is reputed for targeting browser extensions, especially those linked to cryptocurrencies. What is the Base64 encoded string within the sample that contains the names of these extensions?

Answer: (see base64 string below)

```bash
# Identify base64 via RegEx
$ strings sample | grep -oE "[A-Za-z0-9+/]{20,}={0,2}" | awk 'length($0) % 4 == 0'

ZmZuYmVsZmRvZWlvaGVua2ppYm5tYWRqaWVoamhhamJ8WW9yb2lXYWxsZXQKaWJuZWpkZmptbWtwY25scGVia2xtbmtvZW9paG9mZWN8VHJvbmxpbmsKamJkYW9jbmVpaWlubWpiamxnYWxoY2VsZ2Jlam1uaWR8TmlmdHlXYWxsZXQKbmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm58TWV0YW1hc2sKYWZiY2JqcGJwZmFkbGttaG1jbGhrZWVvZG1hbWNmbGN8TWF0aFdhbGxldApobmZhbmtub2NmZW9mYmRkZ2Npam5taG5mbmtkbmFhZHxDb2luYmFzZQpmaGJvaGltYWVsYm9ocGpiYmxkY25nY25hcG5kb2RqcHxCaW5hbmNlQ2hhaW4Kb2RiZnBlZWloZGtiaWhtb3BrYmptb29uZmFubGJmY2x8QnJhdmVXYWxsZXQKaHBnbGZoZ2ZuaGJncGpkZW5qZ21kZ29laWFwcGFmbG58R3VhcmRhV2FsbGV0CmJsbmllaWlmZmJvaWxsa25qbmVwb2dqaGtnbm9hcGFjfEVxdWFsV2FsbGV0CmNqZWxmcGxwbGViZGpqZW5sbHBqY2JsbWprZmNmZm5lfEpheHh4TGliZXJ0eQpmaWhrYWtmb2JrbWtqb2pwY2hwZmdjbWhmam5tbmZwaXxCaXRBcHBXYWxsZXQKa25jY2hkaWdvYmdoZW5iYmFkZG9qam5uYW9nZnBwZmp8aVdhbGxldAphbWttamptbWZsZGRvZ21ocGpsb2ltaXBib2ZuZmppaHxXb21iYXQKZmhpbGFoZWltZ2xpZ25kZGtqZ29ma2NiZ2VraGVuYmh8QXRvbWljV2FsbGV0Cm5sYm1ubmlqY25sZWdrampwY2ZqY2xtY2ZnZ2ZlZmRtfE1ld0N4Cm5hbmptZGtuaGtpbmlmbmtnZGNnZ2NmbmhkYWFtbW1qfEd1aWxkV2FsbGV0Cm5rZGRnbmNkamdqZmNkZGFtZmdjbWZubGhjY25pbWlnfFNhdHVybldhbGxldApmbmpobWtoaG1rYmpra2FibmRjbm5vZ2Fnb2dibmVlY3xSb25pbldhbGxldAphaWlmYm5iZm9icG1lZWtpcGhlZWlqaW1kcG5scGdwcHxUZXJyYVN0YXRpb24KZm5uZWdwaGxvYmpkcGtoZWNhcGtpampka2djamhraWJ8SGFybW9ueVdhbGxldAphZWFjaGtubWVmcGhlcGNjaW9uYm9vaGNrb25vZWVtZ3xDb2luOThXYWxsZXQKY2dlZW9kcGZhZ2pjZWVmaWVmbG1kZnBocGxrZW5sZmt8VG9uQ3J5c3RhbApwZGFkamtma2djYWZnYmNlaW1jcGJrYWxuZm5lcGJua3xLYXJkaWFDaGFpbgpiZm5hZWxtb21laW1obHBtZ2puam9waGhwa2tvbGpwYXxQaGFudG9tCmZoaWxhaGVpbWdsaWduZGRramdvZmtjYmdla2hlbmJofE94eWdlbgptZ2Zma2ZiaWRpaGpwb2FvbWFqbGJnY2hkZGxpY2dwbnxQYWxpV2FsbGV0CmFvZGtrYWduYWRjYm9iZnBnZ2ZuamVvbmdlbWpiamNhfEJvbHRYCmtwZm9wa2VsbWFwY29pcGVtZmVuZG1kY2dobmVnaW1ufExpcXVhbGl0eVdhbGxldApobWVvYm5mbmZjbWRrZGNtbGJsZ2FnbWZwZmJvaWVhZnxYZGVmaVdhbGxldApscGZjYmprbmlqcGVlaWxsaWZua2lrZ25jaWtnZmhkb3xOYW1pV2FsbGV0CmRuZ21sYmxjb2Rmb2JwZHBlY2FhZGdmYmNnZ2ZqZm5tfE1haWFyRGVGaVdhbGxldApiaGdob2FtYXBjZHBib2hwaGlnb29vYWRkaW5wa2JhaXxBdXRoZW50aWNhdG9y

ffnbelfdoeiohenkjibnmadjiehjhajb|YoroiWallet
ibnejdfjmmkpcnlpebklmnkoeoihofec|Tronlink
jbdaocneiiinmjbjlgalhcelgbejmnid|NiftyWallet
nkbihfbeogaeaoehlefnkodbefgpgknn|Metamask
afbcbjpbpfadlkmhmclhkeeodmamcflc|MathWallet
hnfanknocfeofbddgcijnmhnfnkdnaad|Coinbase
fhbohimaelbohpjbbldcngcnapndodjp|BinanceChain
odbfpeeihdkbihmopkbjmoonfanlbfcl|BraveWallet
hpglfhgfnhbgpjdenjgmdgoeiappafln|GuardaWallet
blnieiiffboillknjnepogjhkgnoapac|EqualWallet
cjelfplplebdjjenllpjcblmjkfcffne|JaxxxLiberty
fihkakfobkmkjojpchpfgcmhfjnmnfpi|BitAppWallet
kncchdigobghenbbaddojjnnaogfppfj|iWallet
amkmjjmmflddogmhpjloimipbofnfjih|Wombat
fhilaheimglignddkjgofkcbgekhenbh|AtomicWallet
nlbmnnijcnlegkjjpcfjclmcfggfefdm|MewCx
nanjmdknhkinifnkgdcggcfnhdaammmj|GuildWallet
nkddgncdjgjfcddamfgcmfnlhccnimig|SaturnWallet
fnjhmkhhmkbjkkabndcnnogagogbneec|RoninWallet
aiifbnbfobpmeekipheeijimdpnlpgpp|TerraStation
fnnegphlobjdpkhecapkijjdkgcjhkib|HarmonyWallet
aeachknmefphepccionboohckonoeemg|Coin98Wallet
cgeeodpfagjceefieflmdfphplkenlfk|TonCrystal
pdadjkfkgcafgbceimcpbkalnfnepbnk|KardiaChain
bfnaelmomeimhlpmgjnjophhpkkoljpa|Phantom
fhilaheimglignddkjgofkcbgekhenbh|Oxygen
mgffkfbidihjpoaomajlbgchddlicgpn|PaliWallet
aodkkagnadcbobfpggfnjeongemjbjca|BoltX
kpfopkelmapcoipemfendmdcghnegimn|LiqualityWallet
hmeobnfnfcmdkdcmlblgagmfpfboieaf|XdefiWallet
lpfcbjknijpeeillifnkikgncikgfhdo|NamiWallet
dngmlblcodfobpdpecaadgfbcggfjfnm|MaiarDeFiWallet
bhghoamapcdpbohphigoooaddinpkbai|Authenticator
```

Reason: Static analysis of the final unidentified sample (`Level_2`, `2026-07-10`) revealed a `Base64`-encoded string embedded in the binary that decodes to a newline-separated, pipe-delimited list mapping approximately 30 Chrome and Edge browser extension IDs to their corresponding cryptocurrency wallet names, including `YoroiWallet`, `TronLink`, `MetaMask`, and `Coinbase`, among others. This mapping list identifies the sample as a stealer variant purpose-built to enumerate installed crypto wallet browser extensions on infected hosts. Confirming exfiltration of the harvested wallet data as opposed to enumeration alone requires further analysis of the sample's network or file input/output (I/O) behavior.

Q8- With the insights you've gathered from the malware samples, craft a comprehensive YARA rule that can detect all four samples. Utilize the strings and string offsets condition in YARA rules. After formulating your rule, consult the README.txt file on your lab machine to validate its precision and reliability. Upon successful verification, what's the level 2 flag you obtained?

Reason: `yara_level_2_completed_f17312f7d`

Answer: Crafting a YARA rule targeting "`Software\\Valve\\Steam`" combined with the Login Data string (common to this stealer family's data-harvesting targets across all four samples) as a `wide fullword` string match successfully scanned the lab's file corpus (2026-07-10) and matched exactly 4 out of 4178 files, corresponding precisely to the four stealer samples analyzed, confirming the rule's precision and returning the Level 2 completion flag.

```c
rule Stealer
{
    meta:
        description = "Detects Stealer Malware"
        source = "Static strings analysis"
        date = "2026-07-10"

    strings:
        $str = "Software\\Valve\\SteamLogin Data" wide fullword
    condition:
        $str
}
```

# Lab Insights

- Plaintext strings are a triage superpower against unhardened malware. Neither the ransomware nor the stealer samples employed packing or string obfuscation, meaning a single strings | grep pass was sufficient to identify malware category, family (LockBit), C2/payment infrastructure (the .onion address), and even full IOC target lists (FileZilla, Steam, wallet extensions) — a reminder that static string analysis should always be the first move before reaching for disassemblers, since many commodity/leaked-builder malware families skip obfuscation entirely.
- .NET/managed binaries leak their own architecture through compiler metadata. The k__BackingField naming convention on the stealer samples effectively handed over the malware's internal design (ScanPasswords, ScanWallets, RecoursiveFileGrabber) without any decompilation — a pattern worth remembering: strings output on managed-code malware (C#/.NET, Java) tends to be far more semantically legible than native C/C++ binaries, because compiler-generated property/class names double as functional documentation.
- Effective YARA IOCs favor uniqueness and structure over generic keywords. Early rule drafts using words like "encrypted" risked false positives; the winning approach — pairing a registry-path fragment (Software\\Valve\\Steam) with a wide fullword modifier — worked because it captured a structurally unique, unlikely-to-collide string rather than a broad thematic term, reinforcing that rule quality comes from specificity and correct encoding modifiers (wide, fullword, nocase, base64) matched to how the string actually appears in memory/disk, not just from adding more strings to an N of them condition.
