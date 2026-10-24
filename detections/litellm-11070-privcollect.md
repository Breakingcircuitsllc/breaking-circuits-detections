# LiteLLM 1.107.0 `privcollect` (PyPI startup-hook supply-chain compromise) — IOCs and starter detections

Campaign: PyPI supply-chain compromise of LiteLLM 1.107.0, disclosed Oct 21,
2026. Upwind's research team reported it first: all seven 1.107.0 wheels on
PyPI contain three injected files (`cook.pth`, `cook.py`,
`sitecustomize.py`) that are ABSENT from the `v1.107.0` git tag — a
build/publish-side injection, not a source-commit change. Socket's AI
scanner flagged all seven wheels within 7 minutes of publication
(publication 11:39:51 UTC, alerts 11:46:30 UTC); Socket and
OpenSourceMalware (OSM) both published full static analyses the same day.
The wheels install a credential stealer ("privcollect") and a persistent
hourly remote-Python loader, both triggered by normal Python startup —
no LiteLLM import required. The same payload reached container users:
`ghcr.io/berriai/litellm` tags `v1.107.0`, `latest`, `main-latest`,
`main-stable` all resolved to the same image index at ~13:14 UTC, so
floating-tag deployments received it without pinning 1.107.0. Upwind also
reports affected `litellm-database` and `litellm-non_root` GHCR images and
`litellm/litellm` on Docker Hub (Socket: direct file verification only in
the main amd64 image; the others share the recorded malicious source
revision).

## Update — Oct 23, 2026: the attack chain is confirmed (Socket + LiteLLM)

Socket's attack timeline and LiteLLM's own attack-chain writeup (both
Oct 23) replace the guesswork about initial access. The attacker held
**push access to `BerriAI/litellm` from Oct 10, 2026 — 11 days before**
the malicious 1.107.0 release. On Oct 10 and again Oct 12, two
secret-stealing GitHub Actions workflows (`.github/workflows/cache.yml`,
commit subject "ci: bump cache config", on short-lived branches
`ci-tmp-a351cc` and `ci-tmp-be33e9`, pushed and deleted the same day) ran
successfully and exfiltrated organization and environment CI secrets to
webhook.site endpoints (full URLs in the IOC list below). Root cause,
per LiteLLM: an **Agent Platform master key accidentally committed to a
public repository in May 2026 and never revoked**, used to pull a GitHub
org owner's token. LiteLLM's audit logs tie the GH_TOKEN stolen on
Oct 10 to the approval of the Oct 21 malicious release — this
**supersedes the Oct 22 suspected vector** (stolen GitHub CLI tokens via
exposed deployment logs, below, now marked superseded). Secrets drained
during the 11 days include the GitHub App private key, the org GH_TOKEN,
ANTHROPIC_API_KEY, OPENAI_API_KEY, AWS_BEARER_TOKEN_BEDROCK, Linear
session cookies, and DATABASE_URLs. Attacker IPs: 69.48.229.143
(Oct 10), 199.91.221.39 (Oct 21). Workflow commits:
b69bc36fd4e23b23ea09f4ce63a92b07258f5044,
1a6e3c1e41f1b5c8eeaeeb2ae94bcd95390fa891. ATT&CK additions: T1528 (Steal
Application Access Token), T1195.002 already mapped below. **Hunt your
own orgs:** search Actions history and the audit log for `cache.yml`,
`ci-tmp-*` branches, and `webhook.site` anywhere in workflow files —
the pre-release CI theft, not the wheel, is where the org-wide damage
happened. Separately (Oct 23): the loader's GitHub pointer account
`letters9813` has been **removed** (profile and `domain.txt` both 404),
so surviving loaders can no longer fetch a new C2 domain; the
`privcollect` stealer itself is unchanged and still exfiltrates at
interpreter startup. Still ahead: LiteLLM's embargoed fix for a second,
separate vulnerability ships publicly with disclosure on **Oct 27**.

Delivery path (the strongest build-system evidence): the Linux amd64
image's attached build provenance records the PRIVATE
`BerriAI/project-releaser` workflow, run `39587059944`, and a dispatch
input explicitly naming the hyphenated lookalike owner `Berri-AI`
(`https://github.com/Berri-AI/litellm`; legit is `BerriAI/litellm`).
The malicious build ran 10:51:23–11:06:31 UTC Oct 21. The recorded source
revision (`20535d8fa11f786a6c24df7488a0e449ed5f09ad`) contains
`cook/purelib/{cook.pth,cook.py,sitecustomize.py}`, byte-identical to the
wheel. Packaging trail: a commit at 09:48:21 UTC added `data = "cook"` to
the Maturin config (`[tool.maturin]`, manifest
`litellm-rust/crates/python-bridge/Cargo.toml`), supplying the data
directory with the startup payloads; a commit at 10:46:29 UTC added
`COPY cook ./cook` to the backend, gateway, and migrations Dockerfiles.
The tagged release's `pyproject.toml` LACKS the `data = "cook"` setting —
tag review alone misses this packaging change.

Execution: `cook.pth` is a 12-byte file containing `import cook`; Python
executes `.pth` import lines during site initialization. The imported
`cook.py` is a single obfuscated statement:
`exec(zlib.decompress(base64.b64decode("...")))`. `sitecustomize.py` —
auto-imported at interpreter startup — carries the same 1,237-line
collector variant plus the persistent loader. Trigger caution from Socket:
starting Python or pip in an affected environment to inspect or repair the
install RE-EXECUTES the payload; downloading or unzipping the wheel as data
does not. The `cook.py` variant spawns its collector in a daemon thread and
creates `/tmp/.pc_once_72129118c59f5636c0bb` after a successful upload
(suppresses repeat collection); it sets `PRIVCOLLECT_ACTIVE=1` so child
processes don't double-collect. A short-lived interpreter can exit before
the collector thread finishes, and an absent marker file does NOT clear a
host (failed uploads, tmp cleanup, container replacement).

Exfil: AES-256-CBC (random 256-bit key + 128-bit IV) over the JSON
collection, RSA-4096 OAEP wrap of the AES key, gzip-compressed tar with
`hdr.json` (metadata), `data.bin` (IV + ciphertext), `key.bin`
(RSA-wrapped key). POST to plain HTTP
`http://www.litellm.dev/healthcheck` with `Content-Type:
application/octet-stream`, an obsolete IE-style User-Agent
(`Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64;
Trident/7.0)`), `X-SHA256: <sha256 of body>`, and the fixed header
`X-Token: XWiA8gZNa7NcX2XRoAEb`; up to 4 attempts with 120s timeouts and
exponential backoff. Plain-HTTP means proxies/firewalls may see the path
and custom headers despite the encrypted body. Domain: apex `litellm.dev`
registered Oct 13, 2026 — one week before the release (per Upwind); the
legit project domain is `litellm.ai`. The HTTPS site at `www.litellm.dev`
appears to host an OPERATOR PANEL with victim information (OSM, analysis
ongoing).

Loader: `sitecustomize.py` locks `/tmp/remote_code_loader.lock`
(non-blocking), forks a daemon (setsid, fds 0–2 → /dev/null, chdir `/`),
then loops forever: fetch
`https://raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt`,
take the first line matching domain-or-`localhost` (optionally with port),
resolve it, GET `http://{domain}/codepy`, `compile()` it, `exec()` with
`__name__ == '__main__'` in a thread-pool worker, sleep 3,600s. NO
signature or hash verification. `domain.txt` has been EMPTY since
2026-10-20 09:15 UTC (per Upwind; OSM did not independently verify
history) — the loader is dormant until the operator commits a new domain.
(Update Oct 23, 2026: the `letters9813` account has been removed from
GitHub and the pointer file 404s with it — the re-arm path is dead; see
the attack-chain update at the top of this pack.)
Earlier pointer contents were `localhost:18909` and `test[.]test[.]com:18909`.

What it steals ("privcollect", 16 modules, each behind its own error
handler): browser logins/cookies/history (Chromium family + Firefox,
DPAPI/AES-GCM-aware); SSH/GPG/TLS/Let's Encrypt private keys; shell,
Python, Node, DB-client, Vim, PowerShell, command histories; AWS, Azure,
GCP, Kubernetes, Docker, GitHub CLI, rclone, Heroku, `.netrc`; npm, PyPI,
pip, Yarn, Maven, Gradle, Composer, RubyGems, Cargo configs; `.env` files;
K8s service-account tokens; GitLab Runner, Jenkins, Vault, Terraform,
Packer secrets; ALL env vars plus other Linux processes' `/proc/*/environ`;
cloud instance metadata (AWS EC2/ECS, GCP, Azure); and AI dev-tool configs
(Codex `~/.codex/auth.json`, Claude `~/.claude/.credentials.json`,
Gemini `~/.gemini/oauth_creds.json`, Cursor `~/.cursor/mcp.json`, Copilot,
VS Code, Windsurf, Kiro, Zed, Continue, OpenCode, Hugging Face, Qwen, Amp,
Factory, Trae, Ollama, Amazon Q). With `DATABASE_URL` set, a Prisma child
process runs `SELECT "credential_name", "credential_values" FROM
"LiteLLM_CredentialsTable" LIMIT 500` and `SELECT "model_name",
"litellm_params" FROM "LiteLLM_ProxyModelTable" LIMIT 500` — explicit
targeting of the proxy's own stored upstream provider keys.

Primary sources: Upwind public investigation (Oct 21, 2026); Socket blog
"LiteLLM PyPI Package and Docker Images Compromised" (Oct 21, 2026);
OpenSourceMalware analysis "LiteLLM 1.107.0 PyPI Wheel Contains a
Credential Stealer and Persistent Python Backdoor" (Oct 21, 2026, by
c0a15726-c5b1-4b0d-85e6-fe15553df9e2). Attack-chain update sources
(Oct 23, 2026): Socket, "LiteLLM attack timeline"
(socket.dev/blog/litellm-attack-timeline); LiteLLM, "Security Incident
Oct 21 2026 — Attack Chain" (docs.litellm.ai/blog).

Confirmed vs. inferred (don't blur them):
- CONFIRMED: all seven 1.107.0 wheels affected (Upwind); the three
  injected files and their SHA-256s; the RECORD manifest hashes match
  (Upwind verified); the payload is absent from the git tag; the
  12-byte `cook.pth`; the base64+zlib+exec wrapper; the 1,237-line
  collector decoded from both embedded blobs (decoded SHA-256s in OSM);
  the marker file and `PRIVCOLLECT_ACTIVE`; the exfil URL, headers,
  X-Token value, AES/RSA scheme, tar layout; the lock file path, the
  GitHub pointer repo, `/codepy` fetch loop, 3,600s interval; apex domain
  registration Oct 13, 2026; the provenance-recorded lookalike source
  owner `Berri-AI`, run 39587059944, build window 10:51–11:06 UTC,
  `data = "cook"` packaging commit and `COPY cook` Docker commits; PyPI
  publication 11:39:51 UTC with Socket alerts at 11:46:30 UTC; PyPI pulled
  the release by 13:23 UTC Oct 21 (~2h exposure); malicious Docker images
  served 11:46–14:20 UTC (SafeDep timeline).
- INFERENCE: how the build environment or publishing credential was
  compromised was UNKNOWN until Oct 23 — the attack-chain update at the
  top of this pack now answers it (May 2026 master-key commit → org-owner
  token → Oct 10 push access). The provenance public run URL 404s and job
  logs are private — the recorded inputs are evidence of what the workflow
  RECORDED, not proof of trustworthy authorization (Socket's caveat).
  Oct 22 suspect (LiteLLM, via Oliver Jensen — explicitly UNCONFIRMED at
  the time, and SUPERSEDED Oct 23 by the confirmed chain above):
  the malicious actions ran through three engineers' GitHub accounts via
  stolen GitHub CLI OAuth tokens — one account triggered the
  project-releaser run, another approved it; Jensen suspects the tokens
  leaked through logs of an internet-exposed internal deployment. All
  involved tokens revoked, org reduced to one unaffected user, trusted
  registry links to the GitHub org removed. THN's Oct 22 root-cause note
  (Oct 19 widened release permissions; org-owner token disabling branch
  protection, force-push) may describe the same window — LiteLLM's
  Oct 23 attack-chain writeup is now the authoritative account. OSM
  explicitly does NOT attribute to TeamPCP or any actor, despite the
  March 2026 TeamPCP Trivy-token compromise that hit LiteLLM 1.82.7/1.82.8
  with the same startup-hook technique — second PyPI compromise of
  LiteLLM in 2026, infrastructure differs. As of Oct 22, 2026, no public
  attribution to any named actor. OSM did not probe the panel or
  the collection endpoint; no IP/hosting attribution for `litellm.dev`
  should be asserted from these reports. Exposure scope is bounded by
  download counts PyPI has not published.
- PARTIAL: Upwind reports affected `litellm-database`/`litellm-non_root`
  GHCR and Docker Hub images from the shared malicious revision; Socket
  verified file contents only in the main amd64 image.

Cross-campaign notes: this is the FIFTH AI-tooling-targeting development
in October (tensorlake Shai-Hulud variant Oct 8, Aoki Oct 15, REF8801,
OVHcloud Oct 19) — and the second supply-chain hit on an AI gateway this
year after March's TeamPCP LiteLLM compromise. The `.pth` + `sitecustomize`
startup-hook technique is now a repeated packaging-stage tradecraft (same
technique class as the March TeamPCP LiteLLM wheels). The `data = "cook"`
Maturin setting is the packaging analog of the OVHcloud disabled-release-
immutability gap: the trust boundary is the build config, not the source
tag. The dynamic `domain.txt` GitHub dead drop is the same mutable-
pointer tradecraft as Shai-Hulud's Ethereum contract and OVHcloud's Solana
RPC lookup.

ATT&CK mapping: T1195.002 (Supply Chain Compromise: Compromise Software
Supply Chain — tampered wheel + container images), T1134.002 (Create
Process with Token — forked/setsid daemon), T1036 (Masquerading —
`healthcheck` endpoint, operator panel), T1005 (Data from Local System),
T1552.001 (Credentials in Files), T1555 (Credentials from Password
Stores), T1552.007 (Container API — K8s service-account tokens),
T1078 (Valid Accounts — stolen cloud sessions), T1041 (Exfiltration Over
C2 Channel), T1071.001 (Web Protocols), T1571 (Non-Standard Port — `:18909`
historical pointer), T1059.006 (Python — remote `compile`/`exec`),
T1053.003 (Scheduled Task/Job — hourly polling loop; cron semantics via
sleep), T1083 (File and Directory Discovery), T1113 (Screen Capture —
n/a; included to distinguish: no screen capture here), T1497 (Virtual
Machine/Sandbox Evasion — PRIVCOLLECT_ACTIVE and marker-file logic).

## Indicators of compromise

```
# Build / package (prevention layer — pin, don't float)
litellm==1.107.0                     # ALL wheels affected; do NOT use
litellm-1.107.0.data/purelib/cook.pth
litellm-1.107.0.data/purelib/cook.py
litellm-1.107.0.data/purelib/sitecustomize.py
data = "cook"                        # Maturin config added 09:48:21 UTC Oct 21
COPY cook ./cook                      # added to backend/gateway/migrations Dockerfiles
Berri-AI/litellm                      # hyphenated lookalike source owner in
                                     # BerriAI/project-releaser run 39587059944
20535d8fa11f786a6c24df7488a0e449ed5f09ad   # recorded source revision
# Container tags that resolved to the same image index (~13:14 UTC Oct 21):
ghcr.io/berriai/litellm:v1.107.0 / :latest / :main-latest / :main-stable

# File hashes (analyzed macOS x86-64 wheel; three payload files, Upwind+OSM)
7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d  # litellm-1.107.0-cp310-abi3-macosx_10_12_x86_64.whl (38,106,866 bytes)
7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb  # cook.pth
9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25  # cook.py
34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa  # sitecustomize.py
20a59e5a285799e7cf7fa16cfba1c1414f1e84a8459e14207cfd4e998c2cd24b  # sitecustomize.py decoded collector
6ea3d8ef6cf73a72d8df24f663b7a31ce67494eeb9b0d707b93484e66675d2df  # cook.py decoded collector

# Host artifacts (detection layer)
import cook                            # entire contents of cook.pth (12 bytes)
/tmp/.pc_once_72129118c59f5636c0bb    # post-upload marker (cook.py variant)
PRIVCOLLECT_ACTIVE=1                   # env var suppressing duplicate collection
/tmp/remote_code_loader.lock           # non-blocking lock of the loader daemon
# top-level site-packages entry points installed by the wheel:
<any site-packages>/cook.pth ; <any site-packages>/cook.py ; <any site-packages>/sitecustomize.py
# NOTE: sitecustomize.py exists legitimately in some environments — the
# detection rule pairs it with the co-located cook.* files.

# Network (defang before sharing; plain-HTTP — sensors see path + headers)
http://www[.]litellm[.]dev/healthcheck   # encrypted bundle receiver (POST)
X-Token: XWiA8gZNa7NcX2XRoAEb            # fixed exfil header
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)  # UA on exfil POSTs
X-SHA256: <sha256 of encrypted tar body> # per-request body checksum header
litellm[.]dev                             # apex registered 2026-10-13 (legit: litellm.ai)
https://raw[.]githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt
                                         # mutable pointer; EMPTY since Oct 20 09:15 UTC
http://{domain}/codepy                    # unsigned remote-Python fetch (dormant until pointer set)
# historical pointer contents (not confirmed operational C2): localhost:18909, test[.]test[.]com:18909

# Attacker post-exfil infrastructure (Wiz, Oct 22): from these two IPs the
# operator validated stolen AWS instance-role creds ~4.5h post-exfil —
# sts:GetCallerIdentity → bedrock:ListFoundationModels/ListModels
# (LLMjacking pattern), plus IAM enumeration (ListRoles, ListUsers,
# ListAccessKeys) in a few environments
168.100.8[.]57 ; 165.227.201[.]8

# Attack-chain infrastructure (Socket timeline + LiteLLM writeup, Oct 23)
69.48.229[.]143        # attacker IP — Oct 10 CI-secret theft
199.91.221[.]39        # attacker IP — Oct 21 release activity
webhook[.]site/65a42464-3cfa-4b02-a18c-17a6d7b86f37   # CI exfil endpoint (Oct 10 run)
webhook[.]site/4da03473-a3e7-4dc2-a087-9c564b4208e1   # CI exfil endpoint (Oct 12 run)
.github/workflows/cache.yml   # secret-stealing workflow ("ci: bump cache config")
ci-tmp-a351cc ; ci-tmp-be33e9  # short-lived branches that carried it (deleted same day)
b69bc36fd4e23b23ea09f4ce63a92b07258f5044   # workflow commit
1a6e3c1e41f1b5c8eeaeeb2ae94bcd95390fa891   # workflow commit

# AI dev-tool configs targeted (overlap with OVHcloud/Aoki hunting)
/.codex/auth.json  / .claude/.credentials.json  / .gemini/oauth_creds.json  / .cursor/mcp.json
+ Copilot, Windsurf, Kiro, Zed, Continue, OpenCode, Hugging Face, Qwen, Amp, Factory, Trae, Ollama, Amazon Q
```

## YARA rules

```yara
rule Litellm_11070_PrivCollect_Payload
{
    meta:
        description = "LiteLLM 1.107.0 startup-hook payload: cook.py / sitecustomize.py collector or loader"
        campaign = "LiteLLM 1.107.0 PyPI supply-chain compromise, 2026-10-21"
        reference = "Upwind investigation; Socket blog 2026-10-21; OpenSourceMalware analysis 2026-10-21"
        author = "Breaking Circuits threat-intel watch"
        date = "2026-10-21"
    strings:
        $pc1 = "privcollect"
        $pc2 = "PC_MODULES"
        $pc3 = "PRIVCOLLECT_ACTIVE"
        $pc4 = "www.litellm.dev"
        $pc5 = "XWiA8gZNa7NcX2XRoAEb"
        $pc6 = "letters9813"
        $pc7 = ".pc_once_72129118c59f5636c0bb"
        $pc8 = "remote_code_loader.lock"
        $exec_zlib_b64 = /exec\s*\(\s*zlib\.decompress\s*\(\s*base64\.b64decode\s*\(/ nocase
    condition:
        // obfuscated wrapper: base64+zlib+exec alone is the startup-hook tell
        $exec_zlib_b64 or
        // decoded collector / loader needs at least two family markers
        2 of ($pc1, $pc2, $pc3, $pc4, $pc5, $pc6, $pc7, $pc8)
}

rule Litellm_11070_CookPth_Hook
{
    meta:
        description = "12-byte cook.pth startup hook installed by the trojanized LiteLLM 1.107.0 wheels"
        campaign = "LiteLLM 1.107.0 PyPI supply-chain compromise, 2026-10-21"
        author = "Breaking Circuits threat-intel watch"
        date = "2026-10-21"
    strings:
        $pth = "import cook"
    condition:
        // a 12-byte .pth file is the malicious form; co-located cook.py is the corroboration
        filesize < 64 and $pth
}
```

## Sigma rules

```yaml
title: Trojanized LiteLLM wheel startup-hook files installed
id: 7f2a1c95-litellm-cookpth
status: experimental
description: Detects installation of the 1.107.0 startup-hook payloads —
  cook.pth / cook.py / sitecustomize.py landed at site-packages top level
  by the trojanized wheels. Any Python start afterwards executes them.
  Rebuilding the environment from a reviewed artifact is the fix; the
  files survive package removal of litellm/ alone.
author: Breaking Circuits threat-intel watch
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '\site-packages\cook.pth'
      - '\site-packages\cook.py'
  condition: selection
level: critical
falsepositives:
  - An internal package literally named 'cook' installing these files is
    unlikely but check before alerting.
```

```yaml
title: LiteLLM privcollect exfiltration to www.litellm.dev
id: 7f2a1c96-litellm-exfil
status: experimental
description: The stealer POSTs its encrypted bundle over plain HTTP to
  /healthcheck on www.litellm.dev with a fixed X-Token header. The plain
  HTTP means the path and custom headers are visible to network sensors
  even though the body is AES-encrypted.
author: Breaking Circuits threat-intel watch
logsource:
  category: proxy
detection:
  selection:
    c-uri|endswith: '/healthcheck'
    c-uri-host: 'www.litellm.dev'
  selection_headers:
    c-useragent: 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)'
  condition: selection or selection_headers
level: critical
```

```yaml
title: LiteLLM privcollect loader lock file
id: 7f2a1c97-litellm-loader-lock
status: experimental
description: The sitecustomize.py persistent loader takes a non-blocking
  lock on /tmp/remote_code_loader.lock, then forks a detached hourly
  remote-Python fetcher. The lock plus a python process whose cwd is '/'
  with stdio to /dev/null is the resident tell.
author: Breaking Circuits threat-intel watch
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename: '/tmp/remote_code_loader.lock'
    Image|endswith: '/python3'
  condition: selection
level: high
```

```yaml
title: LiteLLM loader mutable-pointer access
id: 7f2a1c98-litellm-pointer
status: experimental
description: The loader's hourly check fetches domain.txt from the
  letters9813/pythonclient-test GitHub repo, then (once a domain is set)
  GETs /codepy from an attacker-supplied host. Any hit means the dormant
  loader is still alive — block and hunt.
author: Breaking Circuits threat-intel watch
logsource:
  category: dns
detection:
  selection:
    QueryName|contains:
      - 'raw.githubusercontent.com'
  selection_repo:
    c-uri|contains: 'letters9813/pythonclient-test'
  condition: selection and selection_repo
level: high
```

```yaml
title: Python sweeping AI dev-tool credentials at startup
id: 7f2a1c99-litellm-ai-sweep
status: experimental
description: The privcollect collector reads AI dev-tool auth files
  (Codex, Claude, Gemini, Cursor, Copilot, Windsurf, Kiro, Zed,
  Continue, OpenCode, HF, Qwen, Amp, Factory, Trae, Ollama, Amazon Q).
  No legitimate Python startup path reads across several of these at
  once; this is the collection phase. Fifth AI-tooling-targeting
  development in October 2026 (tensorlake Shai-Hulud variant, Aoki,
  REF8801, OVHcloud).
author: Breaking Circuits threat-intel watch
logsource:
  category: file_access
detection:
  selection_proc:
    Image|endswith:
      - '/python3'
      - '/python3.10'
      - '/python3.11'
      - '/python3.12'
  selection_files:
    TargetFilename|contains:
      - '.codex/auth.json'
      - '.claude/.credentials.json'
      - '.gemini/oauth_creds.json'
      - '.cursor/mcp.json'
  condition: selection_proc and selection_files
level: high
```

```yaml
title: Secret-stealing GitHub Actions workflow file (cache.yml)
id: 7f2a1c96-litellm-cacheyml
status: experimental
description: Detects creation of .github/workflows/cache.yml — the filename
  used twice (Oct 10 and Oct 12, 2026) for the secret-stealing workflows
  that drained the BerriAI/litellm org's CI secrets to webhook.site ahead
  of the trojanized 1.107.0 release. Legitimate cache workflows exist:
  the discriminator is any webhook.site / request-capture URL in the
  workflow content — inspect the file on hit.
author: Breaking Circuits threat-intel watch
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
      - '\.github\workflows\cache.yml'
      - '/.github/workflows/cache.yml'
  condition: selection
level: high
```

## Response notes

- **Rotate everything, then rebuild.** Any Python that started after the
  1.107.0 install is a suspected exposure: cloud keys, provider API keys
  (the LiteLLM proxy's OWN stored upstream keys are a named target),
  GitHub/npm tokens, SSH/GPG keys, browser sessions, and every AI
  dev-tool session on the host. Revoke and replace from a clean
  environment before remediation of the affected host.
- **Do not triage with the affected Python.** Starting its python/pip to
  inspect or repair the install re-executes the payload (Socket). Inspect
  wheels as data; rebuild environments from a reviewed artifact.
- **Don't trust the absence of the marker file.** `/tmp/.pc_once_*` only
  appears after a successful upload; failed uploads, tmp cleanup, and
  container replacement all erase it. Check wheel provenance and install
  timestamps instead.
- **Kill the loader separately.** Removing the wheel/site-packages
  artifacts does not stop an already-forked `/codepy` poller; check for
  the lock file, the detached python process (cwd `/`, stdio →
  `/dev/null`), and the GitHub pointer's current contents before
  declaring clean.
- **Pin wheels AND images.** Block `litellm==1.107.0` (pin
  `1.106.2` per Upwind; unverified earlier artifacts are not certified
  clean); pin container DIGESTS, not floating tags — `latest` resolved to
  the compromised index.
- **Maintainer lesson:** the compromise lives in the packaging config
  (`data = "cook"`), not the tagged source. Review build-config diffs
  and verify release provenance against the expected source owner
  (`BerriAI`, not `Berri-AI`); enable immutable releases and
  signed/provenance attestation.
