# UNC7017 (AOMEI ephemeral supply-chain compromise) — IOCs and starter detections

Campaign: UNC7017 — newly named by Google Threat Intelligence Group / Mandiant
(disclosed Oct 16–17, 2026). Between April and July 2026 the actor tampered
with AOMEI Technology's update infrastructure (AOMEI Backupper, and possibly
AnyViewer, which shares the update flow) in brief 5–10 minute windows: unsigned
`down_html.ini` / `Notifycfg.ini` on AOMEI origin servers were rewritten to
redirect clients to an attacker ZIP, then reverted. Confirmed windows: May 28
05:40–05:50 UTC (10 min), July 16 08:33–08:39 UTC (6 min), July 20 10:35–10:40
UTC (5 min). GTIG calls this the first supply-chain compromise it has seen
using windows this short — point-in-time vendor checks return clean files, so
do not dismiss endpoint detections on a live URL check.

Kill chain: tampered `down_html.ini` redirects to `upgrade-now.zip` →
CROSSROAD downloader (`upgrade-now.exe`) runs from the AOMEI `html/` dir,
validates environment, downloads `component.zip`/`en.zip` → establishes
scheduled-task persistence → SHINYROAD modular backdoor delivered via DLL
search-order hijacking of the signed Radmin binary (`FamItrfc.exe`) loading
unsigned `BlkScrDl.dll`, which stages `csvc\RuntimeComponent.dll` (embedded
PocketPy VM, C2 8.218.65.184:443). July 20 wave also coerced WebDAV NTLM auth
to `8.210.84.56` via a 1x1-pixel popup (`file://8.210.84.56/DavWWWRoot/...`)
— credential theft with no code execution. Later stage: ADAPTAGENT (Adaptix C2
client) masquerading as Nitro PDF tools, persistence via `\NitroRuntime`.

Victimology: opportunistic — whoever polled during a window. Confirmed in IT
services, telecommunications, higher education across 11 countries (Australia,
Brazil, India, Pakistan, Portugal, Singapore, South Africa, Spain, Switzerland,
Türkiye, United States); GTIG says the true scope is likely broader. AOMEI took
server-side corrective action July 29, 2026 — this does NOT disinfect endpoints
already compromised.

Attribution: nation and sponsorship unknown. UNC7017 is the GTIG-tracked
cluster for the AOMEI campaign only — it is NOT attributed to the Oct 15
ConnectWise Cloud Backup credential compromise (that actor is still unknown;
one secondary outlet conflated the two stories — treat as separate).

Primary source: GTIG/Mandiant, "Investigating Ephemeral Supply Chain
Tampering", Oct 2026
(https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering).
Collaborating research: ManageEngine Threat Analysis Lab (METAL).

ATT&CK mapping: T1195.002 (Supply Chain Compromise: Compromise Software Supply
Chain), T1574.001 (Hijack Execution Flow: DLL), T1053.005 (Scheduled Task),
T1559.001 (COM), T1059.001 (PowerShell), T1059.006 (Python), T1036.005
(Masquerading), T1480 (Execution Guardrails), T1187 (Forced Authentication /
NTLM coercion), T1608.001 (Stage Capabilities), T1583.001/.006 (Acquire
Infrastructure).

## Indicators of compromise

```
# CROSSROAD downloader (upgrade-now.exe, SHA-256)
11e576df44e9c9eef72b9f5b699291bcdb200a19130778ec231e5b0987b913ad   # May 20 wave
9a58e8f49edf5644e5728f74cf36f560d3d486fa51db4db69d927963c7aca450   # July 16 wave
b360b6db0c2b668317edc1504a7c39ef047f0d925c8f113b521f6724c157ae21   # July 20 wave

# CROSSROAD archives (upgrade-now.zip, SHA-256)
6670ab3f0434a42f33416f8354150b1701e7615f3cfa2f1635e54f8df0f6eec7   # May 20
9ed503c6a9a3a493fb859401e9ed469eed77ab9927341964d6dbfbfa6255aeba   # July 20

# SHINYROAD package and components (SHA-256)
d167bc898e856da8a4003cb4dfc7de55fea109eee3cd64fc8999710314109464   # component.zip / en.zip
8fbaa74b27dc1e89abfc694e834378746f0ad37a688098c5f8f511410157c8b8   # RuntimeComponent.dll (PocketPy engine)
5837bc26a73cfb46ffd466cf889f03ce2f6a48f1f3fd42ec8be22189d51cab1e   # BlkScrDl.dll (malicious)
4c0a75e0f62ddc0bb350c224fe996f3b2ab08dcb0d288231c61ffe9406c7045b   # config.zip
4b4d25b3501519476f9a62a88a781e4f446f669280eb5e98c6b96eb6d3743431   # metadata.dat (ChaCha20 payload)

# ADAPTAGENT / Nitro masquerade (SHA-256)
14b31918075e6130b9123158743db0a81e2d7bfcf6d39731ee7d9200a98cd591   # NitroPromotion.exe
8c8090aca8ddb1cf968d2b810457e0cfce97c03cd721f70d2eca7f37f2681fc4   # Eztwain4.dll (ADAPTAGENT)
7b252be444dee2fb2a57043a823dc5b5e1fae970aea91ee2c8339aa70329969d   # abe.exe (secondary payload)

# Tampered AOMEI config files (SHA-256) — endpoint caches in %PROGRAMFILES(X86)%\AOMEI\*\Tmphtml\
924ad92d89dde577d5858b2ebc5703a485467842d78e98b75019b2e2e0ac3fe6   # down_html.ini, July 16 window
d2f9ef2429312667f0512504b6a19ba4a9cc5514f1b2933923dd42f75a1c5934   # Notifycfg.ini, July 16 window
286e0d8c7bdfaa7c251a3e8f0f2fefbe25c67586c0149d39b1095c89dc6023c8   # Notifycfg.ini, July 20 WebDAV version
f2a7d0a4c8613a9cdd31ede6131b27040c0571ca97970b245a710191806d7ac4   # down_html.ini, July 20 window

# Network (defang before sharing)
8.210.84.56        # WebDAV NTLM target; Adaptix C2 (also :6800 beacons)
8.218.65.184       # SHINYROAD C2 (historical; ports 41397 and 443)
47.239.60.117      # secondary infrastructure
96.126.191.98      # allowlist IP in attacker's whitelist.ini (June 22) — context, not actor infra
promotion.storage-data.com    # stage-2 dropper staging
aomei.storage-data.com        # stage-3 payload staging
storage-data.com              # actor domain
serv.oss-cn-hongkong.aliyuncs.com   # Alibaba OSS, April/May staging

# Host artifacts (strongest behavioral indicators)
\RadminComponentRuntime        # scheduled task -> %LOCALAPPDATA%\Radmin\FamItrfc.exe --runtimechk (every 3h)
\NitroRuntime                 # scheduled task -> hidden powershell launching NitroPromotion.exe
%LOCALAPPDATA%\Radmin\BlkScrDl.dll            # unsigned, sideloaded by signed FamItrfc.exe
%LOCALAPPDATA%\Radmin\csvc\RuntimeComponent.dll
%LOCALAPPDATA%\Nitro Pro\Eztwain4.dll         # ADAPTAGENT, sideloaded by Nitro masquerade
Local\963d3c60-d406-4ad6-aa1e-dc8e45061ccf    # SHINYROAD shared memory section
Global\{F9E6E3C0-E11A-4F85-9944-AF4AD6E05883} # CROSSROAD mutex
"Radmin Component runtime checkable."         # RadminComponentRuntime task description
"AOMEI Update Compent"                       # PE version-info typo in CROSSROAD
Anyviewer-loader/1.0 / Anyviewer-ipcheck/1.0 # CROSSROAD user-agents (geo check)
```

## Sigma rules

### Rule 1 — UNC7017 persistence: RadminComponentRuntime / NitroRuntime scheduled tasks
```yaml
title: UNC7017 Scheduled Task Persistence (RadminComponentRuntime / NitroRuntime)
id: unc7017-scheduled-task-persistence
status: experimental
description: >
  Detects creation or execution of the scheduled tasks UNC7017 used for
  persistence: \RadminComponentRuntime (SHINYROAD via signed Radmin) and
  \NitroRuntime (ADAPTAGENT / Adaptix C2). Task names are campaign-specific;
  legitimate Radmin or Nitro installs do not create these.
author: Rumi (threat-actor watch)
date: 2026-10-18
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  product: windows
detection:
  selection_task:
    TaskName|contains:
      - 'RadminComponentRuntime'
      - 'NitroRuntime'
  selection_cmdline:
    CommandLine|contains:
      - '--runtimechk'
      - 'NitroPromotion.exe'
  condition: selection_task or selection_cmdline
level: high
```

### Rule 2 — FamItrfc.exe executing with --runtimechk from a Radmin profile path
```yaml
title: UNC7017 SHINYROAD Execution via Radmin --runtimechk
id: unc7017-radmin-runtimechk
status: experimental
description: >
  CROSSROAD registers a scheduled task that runs
  %LOCALAPPDATA%\Radmin\FamItrfc.exe --runtimechk every 3 hours; the signed
  Radmin binary then search-order-hijacks the unsigned BlkScrDl.dll. The
  --runtimechk argument is the actor's, not Radmin's.
author: Rumi (threat-actor watch)
date: 2026-10-18
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1574.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\FamItrfc.exe'
    CommandLine|contains: '--runtimechk'
  filter_localappdata:
    Image|contains: '\AppData\Local\Radmin\'
  condition: selection and filter_localappdata
level: high
```

### Rule 3 — Unsigned BlkScrDl.dll / RuntimeComponent.dll in the Radmin profile path
```yaml
title: UNC7017 SHINYROAD DLL Sideloading Artifacts
id: unc7017-shinyroad-dll-artifacts
status: experimental
description: >
  Detects the SHINYROAD loader DLLs in %LOCALAPPDATA%\Radmin\: unsigned
  BlkScrDl.dll (sideloaded by signed FamItrfc.exe) and
  csvc\RuntimeComponent.dll (embedded PocketPy VM). Legitimate Radmin ships
  neither file.
author: Rumi (threat-actor watch)
date: 2026-10-18
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
tags:
  - attack.defense_evasion
  - attack.t1574.001
  - attack.t1036.005
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|contains:
      - '\AppData\Local\Radmin\BlkScrDl.dll'
      - '\AppData\Local\Radmin\csvc\RuntimeComponent.dll'
      - '\AppData\Local\Nitro Pro\Eztwain4.dll'
  condition: selection
level: high
```

### Rule 4 — Outbound to UNC7017 staging infrastructure
```yaml
title: UNC7017 Staging and C2 Network Indicators
id: unc7017-network-indicators
status: experimental
description: >
  Outbound connections to UNC7017 staging domains and C2 IPs, or AOMEI
  updater processes reaching non-vendor update infrastructure. Infrastructure
  rotated across waves (Alibaba OSS -> storage-data.com -> GCS bucket), so
  weight this below the behavioral rules.
author: Rumi (threat-actor watch)
date: 2026-10-18
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
tags:
  - attack.command_and_control
logsource:
  category: network_connection
  product: windows
detection:
  selection_domains:
    DestinationHostname|endswith:
      - 'storage-data.com'
  selection_ips:
    DestinationIp:
      - '8.210.84.56'
      - '8.218.65.184'
      - '47.239.60.117'
  selection_ua:
    UserAgent|contains:
      - 'Anyviewer-loader/1.0'
      - 'Anyviewer-ipcheck/1.0'
  condition: selection_domains or selection_ips or selection_ua
level: medium
```

## YARA

Mandiant published four production YARA rules with the report
(`G_APT_Downloader_CROSSROAD_1`, `G_APT_Backdoor_SHINYROAD_1`,
`G_APT_Backdoor_SHINYROAD_2`, `G_APT_Launcher_ADAPTAGENT_1`) — use those as
the comprehensive set rather than duplicating them here. One compact
behavioral rule for environments that want a single fast triage signature:

```yara
rule UNC7017_Persistence_Artifacts
{
    meta:
        author = "Rumi (threat-actor watch)"
        date = "2026-10-18"
        desc = "UNC7017 scheduled-task / shared-memory / mutex artifacts (AOMEI campaign)"
        ref = "https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering"
    strings:
        $task1 = "RadminComponentRuntime" ascii wide
        $task2 = "Radmin Component runtime checkable." ascii wide
        $task3 = "NitroRuntime" ascii wide
        $shm   = "963d3c60-d406-4ad6-aa1e-dc8e45061ccf" ascii wide
        $mutex = "F9E6E3C0-E11A-4F85-9944-AF4AD6E05883" ascii wide
        $typo  = "AOMEI Update Compent" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of them
}
```

## Hunt notes

- The triage trap is the campaign's defining feature: tampering lasted 5–10
  minutes per window, so live checks of AOMEI's update URLs return clean files.
  Preserve endpoint-cached configs in `%PROGRAMFILES(X86)%\AOMEI\*\Tmphtml\`
  and review proxy/firewall telemetry at the alert's exact second — do not
  validate against the live vendor server.
- Hunt window: April–July 2026 (CROSSROAD samples in the wild from late
  April; AOMEI fixed servers July 29 — endpoints compromised earlier stay
  compromised).
- If any box runs AOMEI Backupper ≥ 8.3.0 or AnyViewer: check for the two
  scheduled tasks, `%LOCALAPPDATA%\Radmin\` contents, and unsigned
  `upgrade-now.exe` drops in AOMEI `Tmphtml\` / `html\` dirs.
- UNC7017 = AOMEI campaign only. The Oct 15 ConnectWise Cloud Backup
  credential compromise (173 M365 tenants) remains unattributed — do not merge
  the two in reporting.
