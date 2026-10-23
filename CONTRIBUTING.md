# Contributing to umbra-blue

Thanks for contributing. This guide covers the skill format, the tier rules, and how changes are checked, so the library stays coherent and trustworthy as it grows.

## Quick Rules

1. **Defensive only.** Explain a technique only as far as a defender needs to detect or mitigate it. No exploit code, payloads, bypass code, or attacker how-to.
2. **Never invent a rule or a citation.** This is the one rule no tier may break.
3. **Ship the tier honestly.** Tier 1 ships a sourced, tuned rule. Tier 2 carries the methodology banner and no rule code blocks.
4. **Map precisely.** Real log sources, event IDs, table names, and fields, plus the MITRE ATT&CK technique and a D3FEND countermeasure where one maps.
5. **Always include tuning and false positives,** and an honest limitations section.
6. **Plain hyphens only.** No em-dashes or en-dashes anywhere. The validator rejects them.

Read [PRINCIPLES.md](PRINCIPLES.md) for the full rules.

---

## Skill Format

A skill lives at:

```
Skills/<category>/<skill-name>/SKILL.md
```

The category matches the claude-red category of the offensive skill it answers. The folder name **must** match the `name:` field.

### Frontmatter

Use exactly these two keys. Claude.ai upload rejects any other key.

```yaml
---
name: detect-example
description: "One paragraph, at most 1,024 characters, no angle brackets. Lead with the threat and use case, give the ATT&CK IDs and log sources, then end with 'Use when ...' trigger phrases."
---
```

- `name`: lowercase letters, digits, and single hyphens, at most 64 characters, and never the words `claude` or `anthropic`.
- `description`: this is what Claude matches against. Put the key use case first.

### Body

Start from a template:

- [`templates/SKILL-tier1.md`](templates/SKILL-tier1.md) for a sourced skill with an inlined rule.
- [`templates/SKILL-tier2.md`](templates/SKILL-tier2.md) for a methodology skill.

Tier 1 rule blocks are reused from the UMBRASEC sigma-pack. The first line inside each fenced block is a comment naming the file and the words `canonical copy`, and every other line is byte-identical to the sigma-pack file:

````markdown
```yaml
# kerberoasting-rc4-service-ticket.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: Kerberoasting - RC4 Service Ticket Requested
...
```
````

---

## Adding or Changing a Skill

1. Create or edit `Skills/<category>/<skill-name>/SKILL.md`.
2. Add or update its pairing in [`tools/pairs.json`](tools/pairs.json). Every skill must answer at least one claude-red skill.
3. Regenerate the index files:
   ```bash
   python3 tools/build_manifest.py
   ```
   This rewrites `claude-skills.json`, `COVERAGE.md`, `MINDMAP.md`, and the badges, category table, and skill index in `README.md`. Do not edit those by hand.
4. Validate:
   ```bash
   python3 tools/validate.py
   python3 tools/validate.py --sigma-pack ../umbrasec.dev/tools/sigma-pack   # if you touched a Tier 1 rule
   ```
5. Note the change in [CHANGELOG.md](CHANGELOG.md).

CI runs the validator against the live sigma-pack and fails if any generated file is stale.

## When a sigma-pack Rule Changes

Tier 1 copies must stay byte-identical to the canonical rule. Refresh them all at once:

```bash
python3 tools/sync_rules.py --sigma-pack ../umbrasec.dev/tools/sigma-pack
python3 tools/validate.py --sigma-pack ../umbrasec.dev/tools/sigma-pack
```

Fixes to a rule's logic belong in the sigma-pack first, then get synced here.

## Promoting Tier 2 to Tier 1

Publish the UMBRASEC writeup and add the tuned rule to the sigma-pack, then rebuild the skill from the Tier 1 template, inline the rule, cite the writeup, remove the Tier 2 banner, and regenerate.

## Review Process

Pull requests are reviewed for technical accuracy, tier honesty, defensive scope, precise mapping, and attribution. Expect one round of review.

## What We Won't Accept

- Offensive content: exploit code, payloads, bypasses, or step-by-step attack instructions
- Fabricated rules, invented citations, or a Tier 2 skill presented as Tier 1
- Real victim infrastructure, real credentials, or personal data in examples
- Content under licenses incompatible with MIT

## Questions

Open an issue before a large change so the direction can be confirmed. For security-sensitive reports, see [SECURITY.md](SECURITY.md).
