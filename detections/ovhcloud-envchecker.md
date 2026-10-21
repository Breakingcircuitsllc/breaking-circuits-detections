# OVHcloud CLI `envchecker` (GitHub release-asset hijack) — IOCs and starter detections

Campaign: supply-chain compromise of the OVHcloud CLI, disclosed Oct 19, 2026
by OVHcloud founder Octave Klaba and detailed in OVHcloud's official security
incident advisory (Oct 20, 2026). Between 14:47 and 16:21 UTC+2 on Oct 19 —
a 94-minute window — the attacker replaced already-published GitHub release
assets for v0.11.0 through v0.15.0 with locally built malicious binaries.
No source code, tags, CI/CD pipelines, or Docker images were touched: GitHub's
release immutability option was DISABLED on the repository, so an account
with the right permissions could clobber existing release blobs with no CI
checks — `gh release upload --clobber` semantics. OVHcloud has since enabled
immutability. Clean: v0.10.0 and the newly published v0.16.0 (signed tags).
Customer-detected: a hash check failed and was reported publicly (GitHub
issue #300). Approximately 250 downloads occurred during the window —
downloads ≠ executions ≠ successful exfils.

Root cause — the part that matters for developer tooling: per OVHcloud's
advisory, the GitHub keys were stolen a full year earlier, via a malicious
VS Code extension (`color-picker-universal 2.8.91`) installed on the
developer's PERSONAL Mac in October 2025. The account had been visibly
burned since at least March 2026 (OpenSourceMalware: four personal repos
rewritten 2026-03-05, three with a hidden `preinstall.js` loader decoding a
stage-2 via a Solana memo dead drop — a known GlassWorm indicator), and
nobody connected it to OVHcloud. Patient, credential-first supply chain:
a year from key theft to release-asset replacement.

Malware: `envchecker` secret stealer inside the tampered CLI binaries.
On execution it enumerates credential files, archives them into a temp
directory `envchecker-[0-9]{9,10}`, resolves the exfil destination via
Solana RPC (dynamic C2 dead drop, same tradecraft as Shai-Hulud's Ethereum
contract), and uploads the archive over TLS. CEO's words: the binary's job
is to "retrieve secrets from the disk"; his guidance is the only correct
posture — treat ALL secrets on any machine that ran an affected binary as
compromised and rotate everything, not just the OVHcloud tokens.

Primary sources: OVHcloud official advisory, "ovhcloud-cli security
incident - October 19th, 2026" (Oct 20, 2026); Octave Klaba on X;
OpenSourceMalware analysis; BleepingComputer; SecurityWeek. Write-up
synthesis (attack flow, targeted-file tables) via dev.to/anoymask and
sh3llc0d3, both citing the OVHcloud advisory.

Confirmed vs. inferred (don't blur them):
- CONFIRMED: the 94-minute window, the affected versions (v0.11.0–v0.15.0),
  the disabled immutability, ~250 downloads, the envchecker temp-dir
  pattern, the credential-file target list, the exfil IP and staging
  domain, the Solana RPC lookup, the malicious-extension root cause
  (per OVHcloud's own advisory), v0.16.0 clean with immutability enabled.
- INFERENCE: the exact count of successful executions/exfiltrations was
  not disclosed. The GlassWorm attribution rests on the Solana memo dead
  drop and the March 2026 preinstall.js loader — a campaign label, not a
  named actor.

No sample hashes have been published (OpenSourceMalware had not recovered
the final payload at disclosure; none in OVHcloud's advisory). There is no
binary-signature layer here — this pack is the behavioral layer: the
envchecker directory, the credential-file sweep, and the exfil network
artifacts. Add hashes if/when a sample surfaces.

Cross-campaign notes: the AI coding-assistant history targeting makes this
the fourth AI-tooling-targeting development in October (Aoki infostealer
Oct 15, tensorlake Shai-Hulud variant Oct 8, REF8801 agent-hijack). The
mutable-release-asset trick is the same trust boundary the UNC7017 AOMEI
campaign abused (ephemeral server-side tampering, Jul 2026) — never
validate a release asset against the live vendor record; pin digests.

ATT&CK mapping: T1195.002 (Supply Chain Compromise: Compromise Software
Supply Chain — release asset replacement), T1204.002 (Malicious File),
T1005 (Data from Local System), T1552.001 (Credentials in Files),
T1555 (Credentials from Password Stores), T1041 (Exfiltration Over C2
Channel), T1071.001 (Web Protocols), T1608.003 (Install Digital
Certificate — abusing Solana RPC as dynamic C2), T1552.006 (Group Policy
Preferences — .netrc/git config sweeps, analogous).

## Indicators of compromise

```
# Network (defang before sharing)
45.32.148[.]174          # exfil destination, :443 TLS (per OVHcloud advisory)
api.cloud-analytics-telemetry[.]com   # staging domain disguised as cloud
                         # telemetry provider, /v1/telemetry endpoint
                         # (per sh3llc0d3 binary analysis)
# Solana RPC endpoints consulted for dynamic exfil destination (any public
# Solana RPC; destination wallet not published)

# Host artifacts (strongest behavioral indicators)
envchecker-[0-9]{9,10}   # temp directory created by the stealer; archive of
                         # collected secrets staged here before upload
~/.ovh/ovh.conf          # OVHcloud API credentials
~/.aws/credentials       # AWS access keys (+ AWS_SECRET_ACCESS_KEY env)
~/.azure/azureProfile.json  # Azure/Entra profiles (+ MS token cache)
~/.kube/config           # Kubernetes client certs / bearer tokens
~/.ssh/id_rsa            # OpenSSH private keys
~/.ssh/id_ed25519
~/.netrc                 # machine credentials
~/.gitconfig / git config# repo credentials/helpers
~/.env files             # generic secret files
Docker, Kubernetes, Terraform, npm settings

# AI coding-assistant histories and session data (fourth October instance
# of AI-tooling targeting; pasted secrets in histories are the prize)
VS Code, Cursor, Claude, Continue histories/session databases

# Initial access (root cause, per OVHcloud advisory)
color-picker-universal 2.8.91   # malicious VS Code extension; GlassWorm-linked
```

## Sigma rules

```yaml
title: OVHcloud envchecker stealer staging directory
id: 7f2a1c90-ovh-envchecker-staging
status: experimental
description: Detects creation of the envchecker temp directory the tampered
  OVHcloud CLI (v0.11.0-v0.15.0, Oct 19 2026) uses to stage stolen secrets.
  The CLI binary appearing to function while this directory exists is the
  tell. Rotate every secret on the host, not just OVHcloud tokens.
author: Breaking Circuits threat-intel watch
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|re: '.*envchecker-\d{9,10}.*'
  condition: selection
level: critical
```

```yaml
title: Tampered OVHcloud CLI exfiltration to known IP
id: 7f2a1c91-ovh-exfil-ip
status: experimental
description: Outbound TLS from the ovhcloud process to the published exfil
  destination 45.32.148.174:443. Destinations can rotate via the Solana
  RPC lookup — also hunt ovhcloud-process traffic to Solana RPC endpoints.
author: Breaking Circuits threat-intel watch
logsource:
  category: network_connection
detection:
  selection:
    Image|contains: 'ovhcloud'
    DestinationIp: '45.32.148.174'
    DestinationPort: 443
  condition: selection
level: critical
```

```yaml
title: Tampered OVHcloud CLI telemetry staging domain
id: 7f2a1c92-ovh-staging-domain
status: experimental
description: The stealer POSTs archives to api.cloud-analytics-telemetry.com
  disguised as a cloud telemetry provider. Block and hunt DNS/proxy logs.
author: Breaking Circuits threat-intel watch
logsource:
  category: dns
detection:
  selection:
    QueryName|contains: 'api.cloud-analytics-telemetry.com'
  condition: selection
level: high
```

```yaml
title: CLI process sweeping credential files
id: 7f2a1c93-ovh-cred-sweep
status: experimental
description: The ovhcloud binary has no legitimate reason to read SSH keys,
  cloud CLI configs, .netrc, or kubeconfig. File reads across several of
  these from one CLI process is the collection phase.
author: Breaking Circuits threat-intel watch
logsource:
  category: file_access
detection:
  selection_img:
    Image|contains: 'ovhcloud'
  selection_files:
    TargetFilename|contains:
      - '.ssh/id_rsa'
      - '.ssh/id_ed25519'
      - '.aws/credentials'
      - '.azure/azureProfile.json'
      - '.kube/config'
      - '.ovh/ovh.conf'
      - '.netrc'
  condition: selection_img and selection_files
level: high
```

```yaml
title: CLI process reading AI assistant histories
id: 7f2a1c94-ovh-ai-history
status: experimental
description: The stealer collects AI coding-assistant databases and
  histories (VS Code, Cursor, Claude, Continue) — pasted secrets in
  histories are the prize. Fourth October instance of AI-tooling
  targeting after Aoki, the tensorlake Shai-Hulud variant, and REF8801.
author: Breaking Circuits threat-intel watch
logsource:
  category: file_access
detection:
  selection_img:
    Image|contains: 'ovhcloud'
  selection_histories:
    TargetFilename|contains:
      - 'Code/User/workspaceStorage'
      - 'Cursor/User/workspaceStorage'
      - '.claude'
      - '.continue'
  condition: selection_img and selection_histories
level: high
```

## Response notes

- **Rotate everything.** Per Klaba: treat all secrets on an affected
  machine as compromised — cloud keys, SSH keys, npm/GitHub tokens,
  .env contents, and anything pasted into AI assistant chats. Deleting
  the binary is not remediation.
- **Scope check:** only binaries downloaded Oct 19, 14:47–16:21 UTC+2
  (v0.11.0–v0.15.0) are affected, but execution can happen after the
  window — check install timestamps, not just download dates.
  Upgrade path: v0.16.0 with immutable releases enabled.
- **Hunt for the entry, not just the stealer:** the same developer's
  personal Mac hosted a GlassWorm-linked malicious extension for a year.
  Any team member running `color-picker-universal 2.8.91` (or who
  installed extensions from outside the verified publisher set) should
  be treated as potentially key-compromised — GitHub PATs and npm
  tokens issued from that machine are suspect.
- **Maintainer lesson:** enable GitHub release immutability and
  signature/provenance attestation; verify release assets against pinned
  digests, never against the live vendor record.
