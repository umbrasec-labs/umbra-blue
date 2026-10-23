---
name: detect-example
description: "Trigger paragraph: state the threat, the technique and ATT&CK ID, the log source, what the skill gives (defensive method and hardening), and the phrases a user would type. Use when detecting, hunting, or hardening against <threat>."
---

# <Threat> - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

<!--
  Tier 2 rules (see ../PRINCIPLES.md):
  - Ship NO inline rule code block. Describe detection logic in prose, and point to
    public rule sources (SigmaHQ, vendor docs, D3FEND) by URL. Never fabricate a rule
    or claim UMBRASEC authored one.
  - Real methodology only, not filler. Name real log sources, event IDs, and fields.
  - Map to the actual ATT&CK technique and a D3FEND countermeasure.
  - Framework table only where you can ground the codes in the guide; else omit it.
  - No em-dashes or en-dashes. Delete these comments and <placeholders> before shipping.
-->

## What it looks like, defender view

Two or three sentences on how the attack presents in telemetry, so a defender knows what to catch. No offensive how-to.

## Log sources and signals

- The exact logs, tables, event IDs, and fields that carry the signal.
- What normal looks like, so the anomaly is legible.

## Detection approach

Describe what to alert on, in prose. Point to public, maintained rules rather than inventing one, for example the relevant SigmaHQ rule directory or a vendor analytic, by URL. State plainly that a tuned UMBRASEC rule is not yet shipped for this threat.

## Threat hunt

A hypothesis-driven hunt as explicit steps or a query sketch.

## Hardening

Shrink the attack surface. Map to a framework where it grounds cleanly.

| Control | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| <control> | <mapping or -> | <mapping or -> | <mapping or -> |

## Honest limitations

What this approach does not catch, and why.

## ATT&CK and D3FEND

- MITRE ATT&CK: <Txxxx> <name>
- MITRE D3FEND: <countermeasure, if one maps>
- Public rule sources: <SigmaHQ / vendor URLs>
