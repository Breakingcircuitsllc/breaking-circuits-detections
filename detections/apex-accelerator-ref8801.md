# Apex Accelerator (REF8801) — IOCs and starter detections

Campaign: Elastic Security Labs' Oct 12, 2026 report "Auditing the auditor:
Unmasking Apex Accelerator," tracked as REF8801. A fake Web3 accelerator
("Apex Arena") that spent months manufacturing legitimacy (fake reviews,
TOKEN2049 presence, takedown Luma event page, $124M-raised claims) to lure
crypto startup founders with free Claude/Gemini credits, coding tools, and
security audits. The delivered npm packages — malicious from the moment of
publication, not a supply-chain compromise — drop cross-platform infostealers
and backdoors, and (novelly) hijack the victim's AI coding agent: a
repackaged Oh My Pi agent whose model traffic is rerouted through
attacker-controlled infrastructure while an attacker-controlled MCP server
is registered in the victim's agent configuration.

This campaign was flagged to the watch on Oct 14, 2026 (09:23 EDT). This pack
is the backfill that was never built then — it belongs in the public
detections set alongside the other flag-to-pack outputs. Per dugganusa's
follow-on research (Oct 17–18), the operation stopped shipping when npm
acted (@apexacc/cli deprecated Oct 13, @apexacc/audit removed from the
registry), but two predecessor packages were STILL INSTALLABLE with no
deprecation notice as of Oct 18 morning: `@apexfdn/copilot-mcp` and
`@apexscore/cli`. Deprecation does not stop installs — all 122 versions of
`@apexacc/cli` still resolve, so a pinned version or old lockfile keeps
pulling it. Hunt value is historical-compromise and current exposure.

Attribution caveat: operator is UNNAMED. Russian-language comments in the
macOS verifier source ("Проверяем AI агентов по env переменным") do not
establish nationality or attribution — Elastic's own caveat. No named actor
here; this is a campaign/intrusion-set pack, not an actor attribution.

Primary sources: Elastic Security Labs (Oct 12, 2026)
(https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages)
· dugganusa evolution analysis (Oct 17)
(https://www.dugganusa.com/post/one-operation-three-npm-accounts-four-mutations-how-the-apex-accelerator-malware-evolved-before-e)
· dugganusa still-installable follow-up (Oct 18)
(https://www.dugganusa.com/post/ten-malicious-npm-packages-we-filed-are-still-installable-mini-shai-hulud-has-been-quiet-for-ten-da)
· SafeDep predecessor report (@copilot-mcp/apex re-publish after takedown)
· Jamf (CloudSyncD family background).

ATT&CK mapping (Elastic maps v19; verify IDs against your version):
T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain),
T1566 (Phishing — the accelerator lure), T1059.001 (PowerShell), T1548.002
(Bypass User Account Control), T1055 (Process Injection — shellcode via
EnumPageFilesW callback), T1005 (Data from Local System), T1115 (Clipboard),
T1113 (Screen Capture), T1539 (Steal Web Session Cookie), T1041
(Exfiltration Over C2 Channel), T1105 (Ingress Tool Transfer), T1071.001
(Web Protocols), T1552 (Unsecured Credentials — AI-client config stores).

## Indicators of compromise

```
# npm packages — the four known names (dugganusa, Oct 17-18)
# @apexacc/cli deprecated Oct 13 but ALL 122 versions still resolve
# @apexacc/audit removed from registry
# @apexfdn/copilot-mcp and @apexscore/cli STILL INSTALLABLE as of Oct 18 AM
@apexacc/cli
@apexacc/audit
@apexfdn/copilot-mcp
@apexscore/cli

# npm user / GitHub org (do not auto-block the GitHub org name alone;
# use it to scope package provenance)
apexaccelerator (npm user)
apexaccs (GitHub: apexaccs/copilot, apexaccs/audit-mcp)

# Verification / bootstrap C2 (both platforms)
vrf.apexaccs[.]org           # POST /api/v1/vrf with {"p":"win32"} or {"p":"darwin"}

# Hijacked AI-agent infrastructure
arena.apexaccs[.]org        # onboarding, attacker LLM API, remote MCP server
arena.apexaccs[.]org/api/llm/v1/chat/completions   # intercepted OpenRouter-labeled traffic
arena.apexaccs[.]org/api/copilot/mcp               # attacker MCP server URL
token.apexaccs[.]org        # in-person invitation site
arena.apexfdn[.]xyz         # earlier onboarding portal (SafeDep)
verify.apexfdn[.]xyz        # macOS installer script + CloudSyncD tarball
apexaccs[.]org             # accelerator home page

# macOS CloudSyncD C2
ccmihr[.]com                # POST /macos/jquery.js, ChaCha-encrypted+Base64

# Windows delivery chain
0auth-chromium[.]com        # serves PowerShell delivery script (APIService)
ehegisnightmare[.]icu       # hosts bludness.exe and exegis.exe/install.exe

# Earlier script-download hosts (rotate through history when hunting)
arenapex[.]cloud
cloudmain365duo[.]top       # XOR-encoded in bootstrap history
fdn4apex[.]com              # XOR+Base64-encoded in later revisions
main.router-apex[.]com      # /updater.sh (earlier macOS Rust verifier)
update.apex-arena-router[.]com  # /loader.sh (--run-verify path)

# Telegram exfil (Windows stealer; bot tokens XOR 0xAA in binary)
# Bot 7245263938 -> chat -1002808379519 (startup notification)
# Bot 8298433231 -> chat -1004302192071 (zip exfil)

# SHA-256 — from Elastic's observables table (Oct 12, 2026)
985829083f3937df6c82419216f7697afae0caac8efca6257a756066fe2c0abb  # apex-windows-x64.exe
5ee7145061f05779f7f6f9b72e216713d17d53e183a92f408bfbbc44f2bfb95d  # apex-audit-windows-x64.exe
42a760b15fea7c9af718ee45386c1c3ea1bec9e30c95d16c287bcc8b2efdc72e  # apex-darwin-arm64
127ae4cad80b6605157ca2a1feada8a235e16aacc5d2119337a98115a4e13274  # apex-verify-darwin
20f0a401676292d4ae34932e61f34afa97bcfc47ee517cda2afeb7222264a193  # apex-audit-darwin-arm64
a50cdb508d13884630945a98eea0615b866d938eb0a16c5d958e6c8c181a6df8  # apex-audit-verify-darwin
68f5a00eafa8ecebf5d93328e0fec23b24d6f91808c8384db002946a13656c71  # installer (CloudSyncD)
ee8cd9aba420f1b26b5d43e5bcdd6025a277b4946bb5daf76ab45c0e5f7ecd0b  # exegis.exe (2nd-stage loader)
ed5cb4af1d2cb067b8d23783ebf05d70278728462ba4f1bf29da0a3a41efc35e  # enc_loader.exe (encrypted 3rd stage)
```

Notes:
- The Dropbox path `dropbox[.]com/scl/fi/tbxu5vgr9l1vuw3s7rw7v/VisualStudioSetup.exe`
  is a VALIDLY SIGNED Microsoft VS2022 installer used as a front — hunt the
  Dropbox download path in context, never the installer hash alone.
- dugganusa's download counts (@apexfdn/copilot-mcp 6,105; @apexscore/cli
  6,736 through Oct 16) are UPPER BOUNDS (mirrors + automated installs
  included), not victim counts.
- `%APPDATA%\.cobra` is an infection MARKER shared by the first-stage loader
  and the native stealer. Its presence SUPPRESSES the native stage but does
  NOT prove the stealer completed — hunt it as evidence of exposure, not of
  successful exfiltration.
- The stealer collects AI-client configs into archive folders under
  `Network Protocol Clients/MCP/`.

## Sigma rules

### 1. Apex verification C2 contact (both platforms)

```yaml
title: REF8801 Apex Accelerator Verification C2
id: 1774c8ff-c098-4ee9-96f6-21dc80248c27
status: test
description: Detects DNS or proxy requests to vrf.apexaccs[.]org, the bootstrap verification endpoint used by both @apexacc/cli and @apexacc/audit on Windows and macOS (POST /api/v1/vrf with {"p":"win32"} or {"p":"darwin"}) — Elastic Security Labs, REF8801, Oct 12, 2026.
references:
    - https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
author: Rumi, from Elastic Security Labs reporting
date: 2026-10-19
tags:
    - attack.t1071.001
    - attack.t1105
logsource:
    category: dns
detection:
    selection:
        query|contains: 'vrf.apexaccs.org'
    condition: selection
falsepositives:
    - None expected for this exact domain
level: high
```

### 2. Attacker-controlled MCP server registration (the agent-hijack)

```yaml
title: Attacker MCP Server Registered in AI Agent Config
id: 5b36e2ea-ae04-4b36-a127-631c9045a320
status: experimental
description: Detects the REF8801 attacker-controlled MCP server URL (arena.apexaccs[.]org/api/copilot/mcp) appearing in agent MCP configuration files such as ~/.apex/agent/mcp.json (created/replaced by the @apexacc/cli bootstrap as "apex-copilot"), or the intercepted OpenRouter-labeled LLM endpoint (arena.apexaccs[.]org/api/llm/v1/chat/completions). Map the field names to your EDR/file-integrity or proxy schema. Eight remote tool definitions (apex_score, apex_code_review, ...) ride on this server.
references:
    - https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
author: Rumi
date: 2026-10-19
tags:
    - attack.t1195.002
logsource:
    category: file_event
detection:
    selection_file:
        TargetFilename|contains:
            - '\.apex\agent\mcp.json'
            - '.apex/agent/mcp.json'
    selection_url:
        Url|contains: 'arena.apexaccs.org/api/copilot/mcp'
    selection_llm:
        Url|contains: 'arena.apexaccs.org/api/llm/v1/chat/completions'
    condition: (selection_file and selection_url) or selection_llm
falsepositives:
    - Low — these URLs are operator-controlled; tune TargetFilename if your fleet legitimately uses apex-named directories
level: critical
```

### 3. Windows VBS/PS1 launcher chain

```yaml
title: REF8801 Windows Launcher Chain via VBS Dropper
id: 0a58a3ea-7cd4-4e08-8b71-c9b4803cded2
status: test
description: Detects the REF8801 Windows bootstrap pattern: a _apex_run.vbs or _audit_run.vbs script in %TEMP% (WScript.Shell.Run wrapper) launching powershell -NoProfile -ExecutionPolicy Bypass against _apex_run.ps1 / _audit_run.ps1, written by the npm launchers' verification bootstrap (Elastic, Oct 12, 2026).
references:
    - https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
author: Rumi
date: 2026-10-19
tags:
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_vbs:
        ParentImage|endswith: '\wscript.exe'
        CommandLine|contains:
            - '_apex_run.vbs'
            - '_audit_run.vbs'
    selection_ps1:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '_apex_run.ps1'
            - '_audit_run.ps1'
    condition: selection_vbs or selection_ps1
falsepositives:
    - None expected — these filenames are campaign-specific
level: high
```

### 4. npm installs of the Apex package set

```yaml
title: Apex Accelerator Malicious npm Package Install
id: 3ea2a861-9ab8-437e-9866-b7b638d70ae7
status: test
description: Detects installs of any of the four REF8801 npm packages. @apexacc/cli was deprecated Oct 13, 2026 but ALL 122 versions still resolve; @apexacc/audit was removed; @apexfdn/copilot-mcp and @apexscore/cli were still installable with no deprecation notice as of Oct 18, 2026 (dugganusa). A pinned version or stale lockfile keeps pulling the deprecated one.
references:
    - https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
    - https://www.dugganusa.com/post/ten-malicious-npm-packages-we-filed-are-still-installable-mini-shai-hulud-has-been-quiet-for-ten-da
author: Rumi
date: 2026-10-19
tags:
    - attack.t1195.002
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '@apexacc/cli'
            - '@apexacc/audit'
            - '@apexfdn/copilot-mcp'
            - '@apexscore/cli'
    condition: selection
falsepositives:
    - None — these are known-malicious package names; treat every hit as exposure
level: critical
```

### 5. CloudSyncD macOS artifacts

```yaml
title: REF8801 CloudSyncD macOS Artifacts
id: fe4bd417-d599-4aff-8712-1397c9f87ddc
status: experimental
description: Detects CloudSyncD macOS artifacts from REF8801: the ~/.local/share/cloudsync/ install directory, the phished-password store ~/.config/cloudsync/data.json, or the gate's C2 ccmihr[.]com (POST /macos/jquery.js). The first stage validates the phished password via /usr/bin/dscl /Local/Default -authonly and shows a decoy "Shared library version mismatch" error.
references:
    - https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
author: Rumi
date: 2026-10-19
tags:
    - attack.t1552
    - attack.t1071.001
logsource:
    category: file_event
    product: macos
detection:
    selection_dir:
        TargetFilename|contains: '.local/share/cloudsync/'
    selection_pwstore:
        TargetFilename|endswith: '.config/cloudsync/data.json'
    selection_c2:
        query|contains: 'ccmihr.com'
    condition: selection_dir or selection_pwstore or selection_c2
falsepositives:
    - Legitimate software does not use the cloudsync path or ccmihr.com
level: high
```

### 6. Stealer infection marker and loader filenames

```yaml
title: REF8801 Windows Stealer Marker and Loader Files
id: bebff3c1-278e-46af-97e2-d8532a30fa60
status: test
description: Detects the REF8801 Windows chain's file artifacts: the %APPDATA%\.cobra infection marker (shared by first-stage loader and native stealer — evidence of exposure, not proof of completed exfil), and the loader filenames exegis.exe / updater_loader.exe in %TEMP%. (Elastic, Oct 12, 2026.)
references:
    - https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
author: Rumi
date: 2026-10-19
tags:
    - attack.t1105
logsource:
    category: file_event
    product: windows
detection:
    selection_marker:
        TargetFilename|endswith: '\.cobra'
    selection_loaders:
        TargetFilename|contains:
            - '\exegis.exe'
            - '\updater_loader.exe'
    condition: selection_marker or selection_loaders
falsepositives:
    - Low — \.cobra and these loader names are campaign-specific
level: medium
```

## YARA rule — triage for REF8801 loader/stealer captures

Triage use only. Keys on the Golang loader's block-shuffle LCG constants
(0xF7A874C6B9DE43D5, 0xE0ED02C1BBE35BB7, inverse 0xF40FBF0EDD42DD7D), the
Chrome app-bound unwrap constants, and the operator's Telegram bot IDs /
C2 domains. For sorting suspected captures, not for alerting.

```yara
rule REF8801_ApexAccelerator_Triage {
    meta:
        description = "Apex Accelerator / REF8801 loader and stealer indicators (Oct 2026) - triage only"
        author = "Rumi, from Elastic Security Labs reporting"
        date = "2026-10-19"
        reference = "https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages"
        status = "experimental - triage, do not alert"
    strings:
        $c2_vrf = "vrf.apexaccs.org" ascii
        $c2_arena = "arena.apexaccs.org" ascii
        $c2_ccmihr = "ccmihr.com" ascii
        $c2_chromium = "0auth-chromium.com" ascii
        $c2_ehegis = "ehegisnightmare.icu" ascii
        $mcp_url = "/api/copilot/mcp" ascii
        $llm_url = "/api/llm/v1/chat/completions" ascii
        $tg1 = "7245263938" ascii
        $tg2 = "8298433231" ascii
        $cobra = ".cobra" ascii
        $ps1a = "_apex_run.ps1" ascii
        $ps1b = "_audit_run.ps1" ascii
        // Golang loader block-shuffle LCG constants (little-endian)
        $lcg_a = { D5 C6 B9 DE 43 5D F7 A8 }
        $lcg_c = { B7 BB 35 BB C1 02 ED E0 }
        $lcg_ai = { 7D D4 42 ED 0E BF 0F F4 }
        // Chrome app-bound unwrap AES-GCM constant (prefix)
        $chrome_k = "B31C6E241AC846728DA9C1FAC4936651CFFB944D1" ascii
    condition:
        filesize < 50MB
        and 2 of ($c2_*)
        and (1 of ($lcg_*) or $chrome_k or 1 of ($tg*))
}
```

## Response notes

1. **The agent itself is compromised, not just the host:** if `@apexacc/cli`
   was run, the victim's AI coding agent sent prompts, conversation history,
   code snippets, and tool outputs to `arena.apexaccs[.]org`, and an
   attacker-controlled MCP server (`apex-copilot`) was registered in
   `~/.apex/agent/mcp.json`. Remove the entry, audit `mcp.json` files in
   Claude Desktop / Cursor / Windsurf for `apex-audit` or `apex-copilot`,
   and ROTATE every secret that passed through the agent — the operator
   had read access to all of it.
2. **Audit the supply chain, not just the host:** grep lockfiles and CI for
   all four scoped packages. `@apexacc/cli`'s 122 versions still resolve
   despite deprecation — pinning or a stale lockfile re-pulls malware.
   `@apexfdn/copilot-mcp` and `@apexscore/cli` were still installable as
   of Oct 18; check npm's current status before assuming removal.
3. **macOS:** the phished password is stored in
   `~/.config/cloudsync/data.json` — change it from a CLEAN device, then
   remove `~/.local/share/cloudsync/` and sweep for the `installer`
   binary.
4. **Windows:** hunt `%APPDATA%\.cobra` (exposure marker), `%TEMP%\
   exegis.exe`, `%TEMP%\updater_loader.exe`, `_apex_run.vbs/.ps1`;
   remove the Defender exclusion for `%USERPROFILE%\.apex-audit` and
   re-check Smart App Control policy state (`VerifiedAndReputablePolicyState`).
5. **Browser creds:** the stealer defeats Chrome's app-bound encryption via
   lsass/winlogon token duplication — treat saved passwords, cookies, and
   session tokens as compromised, not just copied.
6. **Standard revoke-after-containment applies.** No dead-man's-switch
   reported for this campaign (that was the Shai-Hulud tensorlake variant —
   do not conflate). But Telegram exfil means collected data already left:
   scope the response as a data-breach, not just a malware cleanup.
