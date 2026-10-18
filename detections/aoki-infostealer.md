# Aoki (Aokigahara) infostealer — IOCs and starter detections

Campaign/targeting: first observed early 2026; AI coding-assistant credential
targeting is a recent addition, reported Oct 15, 2026. Steals credentials and
session files for Claude/Claude Code, OpenAI Codex, Cursor, Codeium, Gemini,
JetBrains AI Assistant, Kiro and GitHub Copilot — plus AWS creds, browser data,
crypto wallets, password managers, messaging/gaming/VPN/FTP clients. Pure
collector: posts to a `/gate` C&C endpoint, no backdoor command set.
Source: Symantec Threat Hunter Team (primary, Oct 15, 2026). Symantec detects
the family as `Infostealer.Aoki`. No attributed actor; financial motive.

ATT&CK mapping (Threadlinqs TL-2026-3606): T1005, T1119 (Collection); T1071.001
(C2 web protocols); T1518.001 (Security Software Discovery); T1528, T1539,
T1552.001, T1552.002, T1555.003, T1555.005 (Credential Access); T1583.001
(Acquire Infrastructure: Domains).

Note on Threadlinqs: their 26 IOCs / 9 Sigma-SPL-KQL rules are gated behind a
free account and could not be pulled here. The IOC set below is the full
published Symantec set (17 hashes, 3 domains); older-sample IP/port-8080
details were not published. The Sigma rules below are original, built from
Symantec's credential-path list and the remediation guidance.

## Indicators of compromise

```
# Infostealer.Aoki SHA-256 samples (17, from Symantec)
752c8e64af60960b85cf00e4bd34eb459e24b7939464f718ec18494df43b4b69
bf037920d39b85572ec7e53b51f09c28198c2c0afbc7c7d6cf639b1f047caebf
0adc8e83b2416c275b1283916d70568faddeb6d718eb45f9addfb0938db245b3
6655b89b9885483d459c73f2a52e3cec121de5c5956172a8676a0f4c2de94999
780bbdbb119befd4eb16e0c2ec0c64e7bedc1b53ce4f85804aea091a6e3af519
2fb80e2221bd304e7cd5ac04169e71807ad92d19836f1aaf7885295cb90b2d94
73dbac0907e8a092cd978f2787ab1994946f5da1e08f2bdbd05ea52e80cdb896
07bc2e3a1d14743cc44f1dc4c78d15d0f2b458b39fb48422b13df40fc662ba21
c533570fd7cd7eaf5478317b03ea5750d03797aa4d11ebd96555b6cb708c63f2
6350dfee6975a9b159c5a57a3e97f757b0b02fd2dc708016fa6d7270e720c865
36af3acc78058023cdcf9307bc15be640be9425de97e574fdaf42d03d308725b
039240551f88b0064b2615dffdc1321b1e7c58e3f617ac138a65a6d59400b331
0e38bd3c30a4ca08641240ce95b5b6ba593e131213ca1b2a28da4e0385fcabc4
3b4547f0d7549274f366cd9568b3d302c1e80e1b89359da681beb47260ec7975
b590235493487c51f7050b341c9b2450e4f6daf0cecae271c
e374f9ff5094f728528efa566c3de1b7fea7d95f497242a01fffa6c70b5eb768
f779314b1a5a0b297fd4e2a5f9c1e40d387b3e7c401d42324b556a70f813840e

# C2 domains (newer samples, HTTPS, /gate endpoint)
dobeqnesmot.cc
hjazfioe.surf
neihite.cc

# C2 URLs (POST of collected data)
https://dobeqnesmot.cc/gate
https://hjazfioe.surf/gate
https://neihite.cc/gate
```

Notes:
- Older samples used raw IPs over unencrypted HTTP port 8080; the IPs were not
  published. Hunt for port-8080 plaintext HTTP egress alongside the domain rules.
- Aoki is actively developed — expect new hashes. Weight the behavioral rule
  below more heavily over time.

## AI credential stores targeted (Windows paths)

- `%USERPROFILE%\.claude.json`
- `%APPDATA%\Claude\` (Claude Desktop cookies)
- `%USERPROFILE%\.codex\config.toml`, `%USERPROFILE%\.codex\auth.json`
- `%APPDATA%\Cursor\`, `%USERPROFILE%\.cursor\` (Cursor local state DB caches chat/code)
- `%USERPROFILE%\.kiro\`, `%APPDATA%\Kiro\`
- `%USERPROFILE%\.windsurf\`, `%APPDATA%\Windsurf\`, `%USERPROFILE%\.zed\`
- `%APPDATA%\JetBrains\` (AI Assistant), `%USERPROFILE%\.vscode\` extensions (Copilot)
- ChatGPT/Gemini session cookies (browser profile stores), `.env` files, AWS creds

## Sigma rules

### 1. Known Aoki sample on disk or executing

```yaml
title: Infostealer.Aoki Known Sample Hash
id: cad2b4a8-2cc8-4fc4-ac24-fb167ee5caf7
status: test
description: Detects a file or process image matching one of the 17 Infostealer.Aoki SHA-256 hashes published by Symantec, Oct 2026.
references:
    - https://www.security.com/threat-intelligence/aoki-infostealer-ai-targeting
    - https://intel.threadlinqs.com/threat/TL-2026-3606
author: Rumi, from Symantec Threat Hunter reporting
date: 2026-10-15
tags:
    - attack.t1005
logsource:
    category: file_event
detection:
    selection:
        SHA256:
            - '752c8e64af60960b85cf00e4bd34eb459e24b7939464f718ec18494df43b4b69'
            - 'bf037920d39b85572ec7e53b51f09c28198c2c0afbc7c7d6cf639b1f047caebf'
            - '0adc8e83b2416c275b1283916d70568faddeb6d718eb45f9addfb0938db245b3'
            - '6655b89b9885483d459c73f2a52e3cec121de5c5956172a8676a0f4c2de94999'
            - '780bbdbb119befd4eb16e0c2ec0c64e7bedc1b53ce4f85804aea091a6e3af519'
            - '2fb80e2221bd304e7cd5ac04169e71807ad92d19836f1aaf7885295cb90b2d94'
            - '73dbac0907e8a092cd978f2787ab1994946f5da1e08f2bdbd05ea52e80cdb896'
            - '07bc2e3a1d14743cc44f1dc4c78d15d0f2b458b39fb48422b13df40fc662ba21'
            - 'c533570fd7cd7eaf5478317b03ea5750d03797aa4d11ebd96555b6cb708c63f2'
            - '6350dfee6975a9b159c5a57a3e97f757b0b02fd2dc708016fa6d7270e720c865'
            - '36af3acc78058023cdcf9307bc15be640be9425de97e574fdaf42d03d308725b'
            - '039240551f88b0064b2615dffdc1321b1e7c58e3f617ac138a65a6d59400b331'
            - '0e38bd3c30a4ca08641240ce95b5b6ba593e131213ca1b2a28da4e0385fcabc4'
            - '3b4547f0d7549274f366cd9568b3d302c1e80e1b89359da681beb47260ec7975'
            - 'b590235493487c51f7050b341c9b2450e4f6daf0cecae271c'
            - 'e374f9ff5094f728528efa566c3de1b7fea7d95f497242a01fffa6c70b5eb768'
            - 'f779314b1a5a0b297fd4e2a5f9c1e40d387b3e7c401d42324b556a70f813840e'
    condition: selection
falsepositives:
    - None expected; hash-based
level: critical
```

### 2. DNS or connection to Aoki C2 infrastructure

```yaml
title: DNS Query or Connection to Infostealer.Aoki C2
id: 58ff5e69-b712-44a9-9082-abc05a1a9f9e
status: test
description: Detects DNS resolution or outbound connections toward the three Aoki C2 domains; newer samples exfiltrate to HTTPS /gate on these domains. Pair with a hunt for plaintext HTTP egress on port 8080 (older samples).
references:
    - https://www.security.com/threat-intelligence/aoki-infostealer-ai-targeting
author: Rumi, from Symantec Threat Hunter reporting
date: 2026-10-15
tags:
    - attack.t1071.001
    - attack.t1583.001
logsource:
    category: dns_query
detection:
    selection_apex:
        Query:
            - 'dobeqnesmot.cc'
            - 'hjazfioe.surf'
            - 'neihite.cc'
    selection_subdomain:
        Query|endswith:
            - '.dobeqnesmot.cc'
            - '.hjazfioe.surf'
            - '.neihite.cc'
    condition: selection_apex or selection_subdomain
falsepositives:
    - Domains may be reassigned after takedown; re-validate before blocking long-term
level: high
```

### 3. Behavioral — suspicious access to AI coding-assistant credential stores

Catches the behavior, not the campaign: any process other than the assistants
themselves (and your backup/sync tooling) reading credential/config/session
files of AI coding assistants. This is the durable signal — it survives hash
rotation and domain changes, and generalizes to Aoki-like stealers (tensorlake
variant, GhostAction aftermath, Djinn) hunting the same stores.

```yaml
title: Suspicious Read of AI Coding Assistant Credential Files
id: d9b4d54c-b2cf-48df-8fb4-0051b3d3e45f
status: experimental
description: Hunt rule for non-assistant processes reading credential or session files of AI coding assistants (Claude/Codex/Cursor/Kiro/Copilot and related). Based on the credential stores Aoki (Infostealer.Aoki) targets per Symantec, Oct 2026.
references:
    - https://www.security.com/threat-intelligence/aoki-infostealer-ai-targeting
author: Rumi
date: 2026-10-15
tags:
    - attack.t1552.001
    - attack.t1539
    - attack.t1005
logsource:
    category: file_access
    product: windows
detection:
    selection_credential_files:
        TargetFilename|contains:
            - '\.claude.json'
            - '\.codex\'
            - '\.cursor\'
            - '\.kiro\'
            - '\.windsurf\'
            - '\.zed\'
            - 'AppData\Roaming\Claude'
            - 'AppData\Roaming\Cursor'
    selection_assistant_processes:
        Image|contains:
            - 'claude.exe'
            - 'cursor.exe'
            - 'code.exe'
            - 'windsurf.exe'
            - 'zed.exe'
            - 'jetbrains'
    filter_backup_sync:
        Image|contains:
            - 'veeam'
            - 'Carbonite'
            - 'CrashPlan'
    condition: selection_credential_files and not selection_assistant_processes and not filter_backup_sync
falsepositives:
    - Legitimate AI-assistant updaters, installers, or enterprise backup agents not in the filter lists; tune Image filters to your fleet before enabling alerting
level: medium
```

## Response notes

On a confirmed hit: isolate, then revoke-and-rotate AI assistant API keys,
OAuth tokens and session cookies (Claude, Codex, Cursor, Gemini, JetBrains AI,
Kiro, Copilot) plus AWS creds — stolen tokens let attackers act under a
legitimate identity and API quota. Review provider usage/billing logs for
unexpected consumption (LLMjacking). Symantec notes no persistence mechanism
was observed, but re-image rather than trust cleanup on an infostealer box.
