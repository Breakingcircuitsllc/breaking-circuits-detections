# Breaking Circuits — Detections

Public Sigma and YARA detections from the Breaking Circuits threat-intel watch:
same-day tracking of supply-chain attacks, malicious packages, and actors going
after developer and AI tooling. Written from primary-source research
(vendor reports, GTIG/Mandiant, Socket, Huntress, and others), tested against
the published indicators, and free to use.

**Brought to you by Breaking Circuits — home of [BC Automations](https://bcautomations.online) and Vibe Scan, the plain-English safety scan for vibe-coded apps.**

## Detection packs

| Pack | Campaign | Strongest hunt |
|---|---|---|
| [Apex Accelerator / REF8801](detections/apex-accelerator-ref8801.md) | Fake Web3 accelerator (Elastic, Oct 2026): malicious-from-publish npm packages drop cross-platform stealers and hijack the victim's AI coding agent — rerouted OpenRouter-labeled traffic + attacker-controlled MCP server. | `~/.apex/agent/mcp.json` pointing at `arena.apexaccs.org`; `vrf.apexaccs[.]org` verification C2 |
| [UNC7017 / AOMEI](detections/unc7017-aomei.md) | Newly named actor (GTIG/Mandiant, Oct 2026). Ephemeral 5–10-minute tampering of AOMEI Backupper update servers, Apr–Jul 2026 — CROSSROAD downloader → SHINYROAD backdoor via signed-Radmin DLL sideloading. | Scheduled task `\RadminComponentRuntime`; `FamItrfc.exe --runtimechk` |
| [GhostAction stage 2](detections/ghostaction-stage2.md) | Fake-font credential stealer planted in 94 GitHub repos (Oct 2026), launched by a VS Code `tasks.json` folderOpen task disguised as a font file. | Node.js executing a `.woff2` file — never legitimate |
| [GhostAction phishing arm](detections/ghostaction-phishing-arm.md) | Access-refresh phishing via lookalike domain `my-github[.]com` (Oct 2026): fake GitHub security alert → reverse proxy harvesting password + 2FA → silent OAuth app authorization (`repo`, `workflow`, `read:org`). | OAuth client ID `Ov23ctrqCqZ79UaYKwyq`; the `my-github.com` domain |
| [MALFEX `imgdecode`](detections/malfex-imgdecode.md) | npm package whose native DLL side-loads encrypted shellcode from a GitHub-hosted image; ends in the "movinlike" stealer+RAT. MALFEX active since Aug 2023. | `node.exe` spawning `dllhost.exe` with no `/Processid:` |
| [Aoki infostealer](detections/aoki-infostealer.md) | Latest Aoki (Aokigahara) builds targeting AI developer credential stores — Claude, ChatGPT, Codex, Copilot, Cursor, Gemini, JetBrains AI, Kiro — plus AWS creds. | Access to `~/.claude.json`, Codex `config.toml`, AI-tool cookie stores |

Each pack contains the full published IOC set, Sigma rules, YARA where it
earns its keep, ATT&CK mapping, and response notes (including the traps:
revoke before cleanup, never trust a live vendor-server check against
ephemeral tampering, don't trust local logs after stage-3 tampering).

## Using these

- Sigma rules are in the packs as YAML blocks — copy them into your Sigma
  pipeline and convert with `sigma convert` for your backend.
- YARA rules are provided for triage and hunting; validate in your
  environment before alerting on them.
- Indicators are sourced from the cited primary reports. Hashes and IPs go
  stale — treat the behavioral rules as the durable layer.

## Contributing

Corrections, additional indicators, and conversion-tested rule variants are
welcome via issues and pull requests. If you run one of these rules and hit
something real, we'd like to hear about it.

## License

Detection rules in this repository are released for defensive use. Campaign
write-ups summarize and cite the original researchers — all credit for the
underlying discovery belongs to them.
