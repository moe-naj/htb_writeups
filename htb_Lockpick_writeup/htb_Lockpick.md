# Lockpick

![image.png](image.png)

# Context

Lab link: [https://app.hackthebox.com/sherlocks/Lockpick](https://app.hackthebox.com/sherlocks/Lockpick)

Suggested tools: IDA, Ghidra, `jq`, `xlsx2csv`, `xmllint`, `python`, `grep`

# Scenario

Forela needs your help! A whole portion of our UNIX servers have been hit with what we think is ransomware. We are refusing to pay the attackers and need you to find a way to recover the files provided.

**Warning**

This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments.

Once the Sherlock zip has been unzipped, you will find a `DANGER.txt` file. Please read this to proceed.

## XOR Decryption Script

The sample was loaded into IDA with Hex-Rays to recover the encryption routine. The decompiled logic showed a simple repeating-key XOR over each file's bytes, with the key hardcoded in the binary as `bhUlIshutrea98liOp` (19 bytes). This was reimplemented in `decrypt.py`, XORing each `.24bes` file byte-for-byte against the repeating key (`data[i] ^ key[i % key_len]`) and stripping the `.24bes` suffix to recover the original filename and content. All six encrypted files decrypted cleanly into valid formats (SQL, JSON, CSV, XML, XLSX), confirming the key and algorithm were correct.

```python
"""
Decrypt files encrypted with a repeating-key XOR scheme.

Change these for a new target:
- key:     the XOR key (bytes)
- folder:  directory that holds the encrypted files
- out_dir: where to write the recovered files
- the endswith(".24bes") check and the [:-6] slice
  (adjust if the encrypted extension is different)
"""

import os

key = b"bhUlIshutrea98liOp"          # encryption key
key_len = len(key)
folder = "forela-criticaldata"       # folder containing the .24bes files
out_dir = "decrypted"                # where recovered files will be written

os.makedirs(out_dir, exist_ok=True)  # create output dir if it doesn't exist

for name in os.listdir(folder):
    if not name.endswith(".24bes"):  # skip anything that isn't encrypted
        continue

    path = os.path.join(folder, name)
    with open(path, "rb") as f:
        data = f.read()              # read the whole encrypted file

    # XOR every byte with the repeating key
    decrypted = bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

    out_name = name[:-6]             # remove the ".24bes" extension
    out_path = os.path.join(out_dir, out_name)
    with open(out_path, "wb") as f:
        f.write(decrypted)           # write the recovered file

    print(f"decrypted {name} -> {out_path}")
```

# Questions

Q1- Please confirm the encryption key string utilised for the encryption of the files provided?

Answer: `bhUlIshutrea98liOp`

Reason: Recovered directly from the decompiled Hex-Rays output of the ransomware binary, where the XOR key is hardcoded as a byte string used in the encryption loop.

Q2- We have recently received an email from `wbevansn1@cocolog-nifty.com` demanding to know the first and last name we have him registered as. Please confirm the first and last name of this applicant.

Answer: `Walden Bevans`

Reason: `grep` on the decrypted `forela_uk_applicants.sql` for `wbevansn1@cocolog-nifty.com` returned the record `(830,'Walden','Bevans','wbevansn1@cocolog-nifty.com', ...)`.

Q3- What is the MAC address and serial number of the laptop assigned to Hart Manifould?

Answer: `E8-16-DF-E7-52-48`, `1316262`

Reason: `grep` on the decrypted `it_assets.xml` for the record where `assigned_to` is `Hart Manifould` returned `asset_id 501`, a `laptop` with `MAC E8-16-DF-E7-52-48` and `serial_number 1316262`.

Q4- What is the email address of the attacker?

Answer: `bes24@protonmail.com`

Reason: Each `_note.txt` ransom note dropped alongside the encrypted files states contact address `bes24@protonmail.com` for payment negotiation.

Q5- Please confirm the email address of the person with the highest profit percentage in a single trade alongside the profit percentage.

Answer: `fmosedale17a@bizjournals.com`, `142303.1996053929628411706675436`

Reason: Parsed the decrypted `trading-firebase_bkup.json` with `jq`, computed profit percentage per trade record, and sorted to find the maximum value, which belonged to `fmosedale17a@bizjournals.com`.

Q6- Please confirm the IP address for Karylin O'Hederscoll detailed in the Sales Forecast log.

Answer: `8.254.104.208`

Reason: `grep` on the decrypted `sales_forecast.xlsx` log content for `Karylin O'Hederscoll` returned the associated access IP `8.254.104.208`.

Q7- Which of the following file extensions is not targeted by the malware? `.txt`, `.sql`, `.ppt`, `.pdf`, `.docx`, `.xlsx`, `.csv`, `.json`, `.xml`

Answer: `.ppt`

Reason: Comparing the set of encrypted file extensions present in `forela-criticaldata` against the candidate list showed `.sql`, `.xlsx`, `.csv`, `.json`, and `.xml` were all targeted and encrypted, while `.ppt` had no corresponding `.24bes` file.

Q8- Please confirm the MD5 hash of the applicants DB.

Answer: `f3894af4f1ffa42b3a379dddba384405`

Reason: `md5sum` on the decrypted `forela_uk_applicants.sql` produced this hash, confirming the file decrypted without corruption.

Q9- Please confirm the MD5 hash of the trading backup.

Answer: `87baa3a12068c471c3320b7f41235669`

Reason: `md5sum` on the decrypted `trading-firebase_bkup.json` produced this hash, confirming the file decrypted without corruption.

Q10- Please confirm the MD5 hash of the complaints file.

Answer: `c3f05980d9bd945446f8a21bafdbf4e7`

Reason: `md5sum` on the decrypted `complaints.csv` produced this hash, confirming the file decrypted without corruption.

# Artifacts

| Category | Type | Value |
| --- | --- | --- |
| Encryption | Algorithm | Repeating-key XOR |
|  | Key | `bhUlIshutrea98liOp` |
|  | Encrypted extension | `.24bes` |
| Dropped File | Decryptor (self-written) | `decrypt.py` |
|  | Ransom note | `<filename>.24bes_note.txt` |
| Host Indicators | Encrypted file | `forela_uk_applicants.sql.24bes` |
|  | Encrypted file | `trading-firebase_bkup.json.24bes` |
|  | Encrypted file | `complaints.csv.24bes` |
|  | Encrypted file | `it_assets.xml.24bes` |
|  | Encrypted file | `sales_forecast.xlsx.24bes` |
|  | Encrypted file | `customer-feedback.json.24bes` |
| Network | Attacker contact | `bes24@protonmail.com` |
| Integrity | MD5 (applicants DB) | `f3894af4f1ffa42b3a379dddba384405` |
|  | MD5 (trading backup) | `87baa3a12068c471c3320b7f41235669` |
|  | MD5 (complaints) | `c3f05980d9bd945446f8a21bafdbf4e7` |

# Lab Insights

- **Static RE beats brute force on symmetric crypto:** the entire recovery hinged on one Hex-Rays pass to pull a hardcoded XOR key out of the binary rather than attempting any cryptanalysis. When ransomware uses a reversible, non-randomized cipher, the fastest path is always "find the key in the sample," not "attack the ciphertext."
- **File format validity is a free integrity check:** once decrypted, every file opened as a clean SQL dump, XLSX workbook, or well-formed XML/JSON without any corruption. Correct magic bytes and parseable structure across all six files was itself strong confirmation the key and offset logic were right, before a single hash was computed.
- **Post-decryption work was data mining, not forensics:** after the key was recovered, the remaining tasks reduced to `grep`, `jq`, and spreadsheet lookups across the newly readable files. This lab's actual difficulty was entirely front-loaded into the one RE step; everything downstream was plain data analysis.