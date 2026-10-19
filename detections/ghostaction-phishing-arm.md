# GhostAction access-refresh phishing arm (my-github[.]com) — IOCs and starter detections

Campaign: OpenSourceMalware's Oct 19, 2026 reporting on an access-refresh arm
of the GhostAction operation. The operator registered the lookalike domain
`my-github[.]com` on Oct 9 (resolving to `193.32.204[.]199` — the same server
IP as the stage-2 stealer), then used it to phish an open-source maintainer:
an email from `noreply@my-github[.]com` impersonating a GitHub security alert
("new login from Moscow, Russia") → a reverse proxy harvesting the
maintainer's password AND 2FA code in real time → injected JavaScript silently
authorizing an OAuth app with `repo`, `workflow`, and `read:org` scopes. Per
OSM, the `workflow` scope is what lets the operator push the next batch of
malicious workflow files — this is how compromised access gets refreshed
after victims clean up stage 1.

Attribution caveat: OSM has NOT yet tied this kit to the 94-repo stage-2
cluster. Treat as access-refresh infrastructure (possibly copycat), not
confirmed same-operator usage. The OAuth client ID below was previously
documented in OSM's Oct 11 phishing-kit write-up; the Oct 19 report confirms
it in active phishing use.

Primary sources: OpenSourceMalware deep-dive (Oct 16, 2026)
(https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file)
· The Hacker News
(http://thehackernews.com/2026/10/ghostaction-attackers-plant-credential.html).

ATT&CK mapping: T1566.002 (Phishing: Spearphishing Link), T1550.001
(Application Access Token), T1078 (Valid Accounts).

## Indicators of compromise

```
# Lookalike domain (registered Oct 9, 2026; defang before sharing)
my-github[.]com

# Phishing sender
noreply@my-github[.]com

# Server (shared with the stage-2 stealer infrastructure)
193.32.204[.]199

# Malicious OAuth application — revoke if seen in authorized apps
Ov23ctrqCqZ79UaYKwyq

# OAuth scopes requested by the kit
repo, workflow, read:org

# Lure text (impersonated GitHub security alert)
"new login from Moscow, Russia"
```

Notes:
- The reverse proxy harvests password AND 2FA code in real time
  (adversary-in-the-middle). TOTP/SMS codes do not survive this kit;
  phishing-resistant MFA (WebAuthn/hardware keys) does.
- Once authorized, the OAuth app inherits the victim's permissions. The
  `workflow` scope lets the operator push malicious `.github/workflows`
  files to every repo the victim can write to — the refresh payoff.
- Domain registered Oct 9: sweep historical DNS/proxy logs back to Oct 9,
  not just Oct 19.

## Sigma rules

### 1. Lookalike GitHub domain in DNS or proxy logs

```yaml
title: Lookalike GitHub Domain my-github.com
id: a1f3c7e2-9b4d-4e8f-a2c5-7d9f1b3e6a04
status: test
description: Detects DNS lookups or proxy requests for my-github[.]com, the lookalike domain registered Oct 9, 2026 for GhostAction's access-refresh phishing arm (OpenSourceMalware, Oct 19, 2026).
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi, from OpenSourceMalware reporting
date: 2026-10-19
tags:
    - attack.t1566.002
logsource:
    category: dns
detection:
    selection:
        query|contains: 'my-github.com'
    condition: selection
falsepositives:
    - None expected for this exact domain; do not broaden to generic lookalikes without tuning
level: high
```

Hunt variant (not an alert): generalize to eTLD+1 values containing
`github` that are not `github.com` / `*.github.com` / `*.githubusercontent.com`,
to catch the next registration.

### 2. Malicious OAuth app authorization in GitHub audit log

```yaml
title: GhostAction Phishing OAuth App Authorized
id: b2e48d1f-5c7a-4b9e-9d3f-2a8c6e4b1f07
status: experimental
description: Detects authorization of the GhostAction phishing OAuth app (client ID Ov23ctrqCqZ79UaYKwyq, documented by OpenSourceMalware Oct 11 and confirmed in active phishing Oct 19, 2026), or any OAuth app granted the repo+workflow scope combination from an unfamiliar source. Map the field names to your GitHub audit-log schema before alerting.
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi
date: 2026-10-19
tags:
    - attack.t1550.001
    - attack.t1078
logsource:
    category: application
    product: github
    service: audit_log
detection:
    selection_client_id:
        oauth_client_id: 'Ov23ctrqCqZ79UaYKwyq'
    selection_scope_combo:
        granted_scopes|contains:
            - 'repo'
            - 'workflow'
    filter_known:
        oauth_client_id:
            - '<your known internal client IDs>'
    condition: selection_client_id or (selection_scope_combo and not filter_known)
falsepositives:
    - Legitimate CI/automation apps legitimately granted repo+workflow scopes; allowlist known client IDs
level: critical
```

### 3. Fake GitHub security-alert email

```yaml
title: Phishing Email Impersonating GitHub Security Alert
id: c3f59e2a-6d8b-4c9f-a4e1-9b7d3f2e8a15
status: experimental
description: Detects emails from the GhostAction phishing sender, or GitHub "new login" lures arriving from any non-github.com sender domain (OpenSourceMalware, Oct 19, 2026).
references:
    - https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file
author: Rumi
date: 2026-10-19
tags:
    - attack.t1566.002
logsource:
    category: email
detection:
    selection_sender:
        sender|endswith: 'my-github.com'
    selection_lure:
        subject|contains: 'new login from'
        sender|endswith:
            - 'github.com'
    condition: selection_sender or (selection_lure and not sender|endswith)
falsepositives:
    - Legitimate GitHub security alerts match selection_lure's subject but are excluded by the sender filter
level: high
```

Note: the `not sender|endswith` construction above is pseudo-logic — express
as your email pipeline's negation for "sender domain is not github.com".

### 4. Shared infrastructure (cross-reference)

Egress to `193.32.204[.]199:8080` is already covered by rule 4 of the
GhostAction stage-2 pack (`ghostaction-stage2.md`) — same server IP, same
port. Don't duplicate it; the phishing arm reuses the stealer's
infrastructure.

## YARA rule — triage for suspected phishing-kit files

Triage use only: matches files carrying the kit's published strings
(domain, OAuth client ID, scope combination). For sorting suspected
phishing-kit captures, not for alerting.

```yara
rule GhostAction_PhishingKit_Triage {
    meta:
        description = "GhostAction access-refresh phishing kit indicators (Oct 2026) - triage only"
        author = "Rumi, from OpenSourceMalware reporting"
        date = "2026-10-19"
        reference = "https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file"
        status = "experimental - triage, do not alert"
    strings:
        $domain1 = "my-github.com" ascii
        $domain2 = "noreply@my-github.com" ascii
        $client = "Ov23ctrqCqZ79UaYKwyq" ascii
        $scope1 = "read:org" ascii
        $scope2 = "\"workflow\"" ascii
        $scope3 = "'workflow'" ascii
        $lure = "Moscow" ascii
    condition:
        filesize < 1MB
        and ($domain1 or $domain2 or $client)
        and 1 of ($scope*)
}
```

## Response notes

1. **Revoke the OAuth grant first, from a clean device:** GitHub Settings →
   Applications → Authorized OAuth Apps → revoke `Ov23ctrqCqZ79UaYKwyq`.
   Then revoke all sessions, PATs, SSH and deploy keys, and rotate. Cleaning
   the inbox doesn't revoke the grant.
2. **Hunt the refresh payoff:** check every repo the victim could write to
   for `.github/workflows` files added after the authorization timestamp —
   that's what the `workflow` scope bought the operator.
3. **Report and block:** registrar abuse and GitHub for `my-github[.]com`,
   Safe Browsing submission, block at DNS/proxy, and sweep historical logs
   back to Oct 9 (registration date).
4. **Durable defense:** move maintainers to phishing-resistant MFA
   (WebAuthn/hardware keys). This kit harvests TOTP codes in real time.
5. **Scope caveat:** kit not confirmed tied to the 94-repo stage-2 cluster —
   scope the response to the phished account and its writable repos, but
   treat any repo it could write to as potentially refreshed.
