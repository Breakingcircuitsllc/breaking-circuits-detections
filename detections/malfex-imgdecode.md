# MALFEX imgdecode (native Windows DLL loader) — IOCs and starter detections

Campaign: MALFEX's October 2026 evolution. After Checkmarx (Oct 5) and
CloudSEK disclosed the JavaScript stealer-chain packages (Oct 7), the operator
replaced each removed package within ~2 days — `imgbundle` (decrypt role),
`runhelper` (FFI run role) — then moved the loader into a compiled Windows
DLL: `imgdecode` 1.0.3, published Oct 11 under the new publisher handle
`malfexteste8`. A nine-line `index.js` calls `require('imgdecode')`, which
loads `prebuilds/win32-x64/imgdecode.node`. From v1.0.1 the addon's N-API
init function runs the loader: checks for an interactive console
(`GetConsoleMode` — fails on pipes/files, so CI and sandboxes are skipped),
downloads encrypted shellcode from GitHub, AES-256-CBC-decrypts it (key =
SHA-256 of passphrase `nif-runtime-2027`, first 16 response bytes = IV), and
injects it into a suspended `dllhost.exe` (VirtualAllocEx → WriteProcessMemory
→ VirtualProtectEx → CreateRemoteThread; in-process fallback via
VirtualAlloc/RtlMoveMemory/VirtualProtect/CreateThread). No install script —
install-script blockers do not stop it, and `binding.gyp` is absent even
though registry metadata lists `node-gyp rebuild`.
Scope: ~929 downloads Sept 30–Oct 12 per SafeDep (still present on npm at the
time of the Oct 17 flag); no public GitHub project declares it as a
dependency, so exposure is concentrated in private consumers.
Primary source: SafeDep research, Oct 13, 2026
(https://safedep.io/malfex-imgdecode-npm-native-addon-loader/); corroborated
by The Hacker News, Oct 16–17. Campaign background from Checkmarx/CloudSEK
(Oct 5–7), whose own IOC list contains the stage-2 downloader hash
`2f268ca7…` — high-confidence campaign linkage.

Confirmed vs. inferred (SafeDep's own caveats, don't blur them):
- CONFIRMED: the package, publisher, addon mechanics, console check, payload
  URL, passphrase, all file hashes, persistence entries, and the recovered
  stage-3 sample.
- INFERENCE: `banner.jpg` (the native loader's actual payload) was never
  recovered — the `cavecrew` GitHub account was 404 at analysis time. The link
  from the loader to the stage-2 Go downloader and the `movinlike` stealer is
  inferred from the sibling carrier `banner.png`, the shared repo, and the
  shared encryption key. The SafeDep-analyzed stage-3 build (`8d50cb1b…`) is a
  different build than the one in the Checkmarx report (`c9c374af…`).
- The three DLL builds share one PDB path, which is what the YARA rule keys on.

Cross-campaign note: this is the same Portuguese-speaking operator style seen
in the Oct 8 TraderTraitor-linked Terraform campaign (decoy `.woff` payloads)
and the same npm-vector targeting of AI-dev machines as the Shai-Hulud
tensorlake variant and GhostAction. Operator cadence: disclosure/removal →
replacement package within ~2 days, under a fresh publisher handle.

ATT&CK mapping: T1105 (Ingress Tool Transfer), T1055.002 (Process Injection:
Portable Executable Injection), T1055.001 (DLL injection, in-process fallback),
T1027 (Obfuscated Files or Information: AES-256-CBC + XOR 0x37 strings),
T1547.001 (Registry Run Keys/Startup Folder), T1053.005 (Scheduled Task),
T1071.001 (Web Protocols), T1005 (Data from Local System), T1552.001
(Credentials in Files), T1555 (Credentials from Password Stores).

## Indicators of compromise

```
# imgdecode.node DLL builds (SafeDep; all three share the same PDB path)
d7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714   # imgdecode.node 1.0.0
54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85   # imgdecode.node 1.0.1
a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1   # imgdecode.node 1.0.2, 1.0.3 (same file)

# Related campaign files
4f4f7d64139bde6d458a061c7fb7dd247f70f60a1ab47d87fd3634656586c106   # banner.png (archived JS-stage carrier)
2f268ca76ab27971d8b16bd4ded26e1f9cd3d4460b894af2d4bdf89f0ab7ec4b   # stage-2 Go downloader (in Checkmarx IOC list)
8d50cb1ba0c2a16a673a2d08a8fb5c45bd8755c95c30ded98a84c74bfe52c9e6   # stage-3 setup.exe, "movinlike" stealer+RAT (different build than Checkmarx's c9c374af…)

# npm packages (defanged)
imgdecode 1.0.0–1.0.3            # still live at time of Oct 17 flag
imgbundle 1.0.0–1.0.2            # removed — decrypt role
runhelper 1.0.0                  # removed — FFI run role (koffi)
cdn-img-fetch, img-to-native, native-runner   # removed — original chain (Sep 26)

# Publishers
malfexteste8                     # new sixth handle, registered for imgdecode
trelicas.flexionar_4q@icloud[.]com

# Payload delivery (defanged)
hxxps://raw.githubusercontent[.]com/cavecrew/proj/main/banner.jpg   # shellcode, AES-256-CBC
hxxps://raw.githubusercontent[.]com/cavecrew/proj/main/banner.png   # sibling JS-stage carrier
nif-runtime-2027                 # AES key passphrase (key = SHA-256(passphrase); IV = first 16 response bytes)
malfexteam2027                   # earlier passphrase used by img-to-native (Checkmarx/CloudSEK)

# Stage 3 download + C2 (defanged)
hxxp://104.234.65[.]75:700/setup.exe        # stage-2 → stage-3 download
104.234.65[.]75:7007 /about/sendRouter      # stealer upload API
104.234.65[.]75:7007 /about/discord         # discord data path
ws://104.234.65[.]75:7007/agent             # RAT WebSocket
MALFEX-89BEE69BB61967AF1C3B07C9             # stealer license key (in stage-3 config)

# Persistence + staging paths
%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe   # persistence copy
MicrosoftEdgeUpdateService       # Run key value AND scheduled task name
%TEMP%\svc_update.exe            # stage-3 file name

# Build artifact (present in all three DLL builds; YARA anchor)
C:\Users\Administrator\Desktop\npm\imgdecode\build\Release\imgdecode.pdb

# Package internals
prebuilds/win32-x64/imgdecode.node   # addon path inside the tarball (no binding.gyp present)

# Decoded DLL internals (runtime-resolved; not plaintext in the binary — strings are XOR 0x37 encoded)
# CreateProcessW, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx,
# CreateRemoteThread, ResumeThread, TerminateProcess, GetSystemDirectoryW, CloseHandle, Sleep
# Imports: WinINet, bcrypt.dll (CNG), kernel32 GetConsoleMode/VirtualProtect/TerminateProcess
# Injection target: %SystemRoot%\System32\dllhost.exe (suspended, no window, no console)
```

Notes:
- The operator rotates packages AND publisher handles within days of
  takedowns. Weight the behavioral rules (2–4) over hashes and package names.
- The loader executes only when stdout is an interactive console —
  sandboxed/detonated copies may do nothing, so absence of activity in a
  sandbox is not evidence of benignity. Legitimate `node.exe` never spawns
  `dllhost.exe` without `/Processid:`.
- SafeDep searched public code and lockfiles: no public project declares
  `imgdecode`. Check private repos and CI caches — `npm`/`deps.dev` download
  counts include registry mirrors and scanners.
- The earlier campaign passphrase `malfexteam2027` (from Checkmarx/CloudSEK)
  is a second decrypt-string to hunt for in samples.

## Sigma rules

### 1. Known MALFEX imgdecode campaign files by hash

```yaml
title: MALFEX imgdecode Campaign Known File Hashes
id: 68e9330e-6afa-4baf-8291-c790ea65bcf3
status: test
description: Detects a file matching one of the 6 MALFEX SHA-256 hashes published by SafeDep (Oct 13, 2026): three imgdecode.node DLL builds, the archived banner.png carrier, the stage-2 Go downloader, and the stage-3 movinlike stealer.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
author: Rumi, from SafeDep reporting
date: 2026-10-17
tags:
    - attack.t1105
    - attack.t1055
logsource:
    category: file_event
detection:
    selection:
        SHA256:
            - 'd7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714'
            - '54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85'
            - 'a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1'
            - '4f4f7d64139bde6d458a061c7fb7dd247f70f60a1ab47d87fd3634656586c106'
            - '2f268ca76ab27971d8b16bd4ded26e1f9cd3d4460b894af2d4bdf89f0ab7ec4b'
            - '8d50cb1ba0c2a16a673a2d08a8fb5c45bd8755c95c30ded98a84c74bfe52c9e6'
    condition: selection
falsepositives:
    - None expected; hash-based
level: critical
```

### 2. Behavioral core — node.exe spawning dllhost.exe without /Processid

The strongest single signal (SafeDep's own detection guidance). Legitimate
COM hosting always passes `/Processid:`; MALFEX's injection target does not.

```yaml
title: Node.js Spawning COM Host Without ProcessId Argument
id: 5add45af-72cc-4364-92fe-eff7adc61c9c
status: experimental
description: Detects node.exe as the parent of dllhost.exe with no /Processid: argument — the MALFEX imgdecode injection pattern (suspended dllhost.exe, no window). Confirmed by SafeDep as the distinctive detection signal for this loader.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
author: Rumi
date: 2026-10-17
tags:
    - attack.t1055.002
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\node.exe'
            - '\bun.exe'
    selection_child:
        Image|endswith: '\dllhost.exe'
    filter_legitimate:
        CommandLine|contains: '/Processid:'
    condition: selection_parent and selection_child and not filter_legitimate
falsepositives:
    - Rare; legitimate COM activation always carries /Processid:. Verify hits against the imgdecode hashes
level: high
```

### 3. Node.js loading the imgdecode native addon

```yaml
title: Node.js Loading MALFEX imgdecode Native Addon
id: 8404c3ba-5c15-4969-b669-e6074427ce6f
status: experimental
description: Detects node.exe loading imgdecode.node — the MALFEX native-addon loader. The loader runs in the N-API module init function, so no install script or build step is required; image-load is the earliest observable.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
author: Rumi
date: 2026-10-17
tags:
    - attack.t1105
    - attack.t1055
logsource:
    category: image_load
    product: windows
detection:
    selection_image:
        ImageLoaded|endswith: 'imgdecode.node'
    selection_process:
        Image|endswith: '\node.exe'
    condition: selection_image and selection_process
falsepositives:
    - None expected while the name is campaign-specific; generalized addon-load rules for prebuilds/ DLLs in npm packages are a separate hunt
level: high
```

Fleet sweep (Windows dev boxes): search for `prebuilds\win32-x64\imgdecode.node`
under `node_modules`, or `grep -r "imgdecode" package-lock.json`.

### 4. Egress to MALFEX payload and command infrastructure

```yaml
title: Outbound Connection to MALFEX imgdecode Infrastructure
id: e987e096-95bb-4724-b679-b55012379521
status: experimental
description: Detects outbound traffic to the MALFEX imgdecode shellcode URL (GitHub raw via node.exe) or to the stage/C2 IP 104.234.65.75 on port 700 (stage download) or 7007 (stealer upload API, RAT WebSocket).
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
author: Rumi
date: 2026-10-17
tags:
    - attack.t1105
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_shellcode_url:
        c-uri|contains: '/cavecrew/proj/main/banner.jpg'
    selection_github_process:
        c-uri|contains: 'raw.githubusercontent.com'
        Image|endswith: '\node.exe'
    selection_stage_ip:
        dst_ip: '104.234.65.75'
    condition: selection_shellcode_url or (selection_github_process) or selection_stage_ip
falsepositives:
    - Legitimate node.exe traffic to raw.githubusercontent.com (common in dev tooling); confirm against the banner.jpg URI or the stage IP before treating as a hit
level: high
```

### 5. EdgeUpdate persistence artifacts

```yaml
title: MALFEX EdgeUpdate Persistence Artifacts
id: e3a16943-8f62-4d6e-a817-71a13e30fbd0
status: experimental
description: Detects the MALFEX stage-3 persistence chain: a copy named MicrosoftEdgeUpdate.exe under %APPDATA%\Microsoft\EdgeUpdate, a Run key value named MicrosoftEdgeUpdateService, or a scheduled task of the same name.
references:
    - https://safedep.io/malfex-imgdecode-npm-native-addon-loader/
author: Rumi
date: 2026-10-17
tags:
    - attack.t1547.001
    - attack.t1053.005
logsource:
    category: file_event
    product: windows
detection:
    selection_copy:
        TargetFilename|contains: '\AppData\Roaming\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe'
    selection_taskname:
        TaskName|contains: 'MicrosoftEdgeUpdateService'
    condition: selection_copy or selection_taskname
falsepositives:
    - Legitimate Microsoft Edge updater paths look similar; the MALFEX copy lives under the user %APPDATA% tree with a scheduled task bearing the service name — review hits against genuine Edge update installs
level: high
```

## YARA rule — imgdecode native loader

Keys on what all three DLL builds share and legitimate addons lack: the
operator's build PDB path, PE/Node-API shape, and the injection-oriented
import set (WinINet + CNG crypto + GetConsoleMode). Payload strings are
XOR-0x37 encoded in the binary, so this rule does not rely on them.
(SafeDep ships its own `malfex_imgdecode.yar` in the write-up; treat this as
a companion and validate both against your corpus.)

```yara
rule Malfex_Imgdecode_Native_Loader {
    meta:
        description = "MALFEX imgdecode npm native-addon loader (Oct 2026) - MSVC Node.js DLL with injection imports"
        author = "Rumi, from SafeDep reporting"
        date = "2026-10-17"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash_v1_0_0 = "d7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714"
        hash_v1_0_1 = "54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85"
        hash_v1_0_2_1_0_3 = "a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1"
    strings:
        // Present in all three builds per SafeDep
        $pdb = "C:\\Users\\Administrator\\Desktop\\npm\\imgdecode\\build\\Release\\imgdecode.pdb" ascii
        // Node-API module registration
        $napi = "napi_register_module_v1" ascii
        // Console check that lets it dodge CI and sandboxes
        $console = "GetConsoleMode" ascii
        // Crypto + networking imports used for payload fetch and decrypt
        $wininet = "wininet.dll" ascii nocase
        $bcrypt = "bcrypt.dll" ascii nocase
    condition:
        uint16(0) == 0x5A4D
        and $pdb
        and $napi
        and $console
        and 1 of ($wininet, $bcrypt)
}
```

## Response notes

1. **Isolate and take memory before reboot.** The native loader runs its
   shellcode in memory inside a suspended `dllhost.exe`; SafeDep's explicit
   guidance is to collect memory before powering down.
2. **Hunt the loader's trail:** `node_modules` copies of `imgdecode` (grep
   lockfiles for the name), `node.exe` children named `dllhost.exe`, the
   persistence entries above, and `%TEMP%\svc_update.exe`.
3. **Treat `banner.jpg` stage-2 linkage as inferred, stage-3 as confirmed
   present.** If stage-3 ran, it's a full stealer+RAT: rotate browser
   passwords, session cookies, Discord tokens, cloud/SSH/npm/GitHub tokens,
   and crypto wallets — from a clean device, after containment. Move wallet
   funds if seed phrases were on the box.
4. **Don't trust local logs alone.** The recovered stage-3 sample has
   Security/Sysmon EVTX tampering capability (it recalculates checksums) and
   deletes PowerShell history — compare against external logs.
5. **Dead-man's-switch instinct check:** SafeDep does not report a revocation
   trap for MALFEX (unlike the Shai-Hulud tensorlake variant) — standard
   revoke-after-containment applies here, not the inverted playbook.
6. **Feed the next replacement into this pack.** The operator ships a
   replacement package ~2 days after each takedown; the behavioral rules
   (node→dllhost without `/Processid:`, WinINet+crypto addon imports, console
   check) survive package-name and publisher-handle rotation. New publisher
   handles remain the earliest campaign signal.
