# Changelog

All notable changes to `umbra-blue` are documented here. Versions follow [Semantic Versioning](https://semver.org/), where breaking changes mean skill renames, removals, or category restructures.

## [Unreleased]

### Added

- **Blue Team Mapper links.** Every skill now links to its page in the [Blue Team Mapper](https://umbrasec-labs.github.io/BlueTeamMapper/), which shows the skill's techniques and any UMBRASEC rules for them. For techniques in the mapper matrix, the page also shows the matrix rows, the response flow chains, and the reader's own coverage. The link appears in a new Mapper column in the README skill index and in `COVERAGE.md`, and as a `mapper` URL field on each skill in `claude-skills.json`. `tools/build_manifest.py` generates all three from one base URL.

### Changed

- **Re-synced four upstream sigma-pack rule fixes.** `tools/sync_rules.py` refreshed every inlined copy, and the skill prose that described the old logic now matches. `metabase-reset-password-sqli.yml` escapes the `/*` comment marker, which Sigma read as a wildcard that matched any query string containing a slash ([umbrasec.dev issue #3](https://github.com/umbrasec-labs/umbrasec.dev/issues/3)), and adds percent-encoded markers for access logs that keep the query string encoded (`detect-metabase-sqli`, `monitor-external-attack-surface`). `litellm-proxy-spawns-shell.yml` adds versioned `python3.9` to `python3.14` parents and `busybox`, `nc.openbsd`, `nc.traditional` and `netcat` children (`detect-litellm-command-injection`). `litellm-stealer-exfil.yml` matches `cs-host` logged with a port or a trailing dot, so the `c-uri` selection is now only for proxies that log the full URL (`detect-litellm-command-injection`, `detect-data-exfiltration`). `kerberoasting-spn-fanout.yml` gains a `falsepositives` section for scanners, monitoring accounts and busy legitimate accounts (`detect-kerberoasting`).

### Planned

- Promote Tier 2 skills to Tier 1 as UMBRASEC writeups and sigma-pack rules land
- Claude Code plugin marketplace packaging

## [0.1.0] - 2026-10-23

### Added

- **Full mirror of claude-red.** 77 defensive skills answer all 78 claude-red offensive skills across the same 23 category folders. Two claude-red course skills share a counterpart with their sibling skill.
- **Tier 1, sourced (10 skills).** `detect-kerberoasting`, `detect-oauth-consent-phishing`, `detect-litellm-command-injection`, `detect-metabase-sqli`, `detect-ncentral-post-exploitation`, `detect-data-exfiltration`, `detect-supply-chain-compromise`, `monitor-external-attack-surface`, `defend-llm-top-10`, and `defend-ai-agents`. Each is built from a published UMBRASEC writeup or tool. Where a skill inlines a detection, it is reused byte for byte from the UMBRASEC sigma-pack.
- **Tier 2, methodology (67 skills).** Defender's method, log sources, hunt, and hardening for every remaining claude-red skill, with a banner stating that no bespoke UMBRASEC rule ships yet.
- **Tooling.** `tools/build_manifest.py` generates `claude-skills.json`, `COVERAGE.md`, `MINDMAP.md`, and the README index from `tools/pairs.json`. `tools/validate.py` enforces the library rules. `tools/sync_rules.py` refreshes inlined rules from the sigma-pack. CI runs the validator against the live sigma-pack and fails on stale generated files.
- **Installer.** `install.sh` flattens the category tree into the one-folder-per-skill layout Claude Code discovers, with category and tier filters, collision protection, and uninstall.

### Quality

- Every skill passed an adversarial technical review before release. 110 findings were raised and 107 fixed, including wrong integrity-level SIDs, a miscited advisory, and incorrect Sysmon, NPS, GitHub audit-log, and D3FEND identifiers. The other 3 are logic issues in upstream sigma-pack rules, tracked for a fix in the sigma-pack and a re-sync here.
- Every description fits the 1,024-character Agent Skills limit, and every skill uses only the `name` and `description` frontmatter keys.
