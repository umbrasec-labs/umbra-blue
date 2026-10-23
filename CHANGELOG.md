# Changelog

All notable changes to `umbra-blue` are documented here. Versions follow [Semantic Versioning](https://semver.org/), where breaking changes mean skill renames, removals, or category restructures.

## [Unreleased]

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
