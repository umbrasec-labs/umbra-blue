---
name: detect-example
description: "One-paragraph trigger block. State the threat, the technique, the ATT&CK ID, the log source, and the concrete words a user would type that should load this skill. Example: Detection methodology for <threat> (MITRE ATT&CK <Txxxx>). Covers <what it ships: Sigma rule / KQL query / hunt>, keyed off <event ID / log source>, with tuning and false-positive notes. Use when investigating <symptom>, writing detections for <technique>, hunting for <behaviour>, or reviewing alerts about <threat>."
---

# <Threat> - Detection and Response

<!--
  House style: lead with the defender's TL;DR, require the log source, ship the rule
  inline, then tune, hunt, mitigate, state limits, map, and cite. Keep it defensive.
  Delete these comments and every <placeholder> before shipping. See ../PRINCIPLES.md.
-->

## TL;DR for defenders

Two or three sentences: what to turn on, which event or field gives the attack away, and which rule below is the high-precision one. A reader who stops here should still know what to do Monday.

## Log sources required

- The exact log, where it is generated, and the audit policy or configuration that makes the event appear.
- Any collection gap that becomes a blind spot, stated plainly.

## Detection

Ship the rule inline. One fenced block per rule, highest precision first.

```yaml
# <rule-name>.yml  (canonical copy: tools/sigma-pack/rules/<path>)
title: <title>
status: experimental
# ... full Sigma/KQL body ...
```

## Tuning and false positives

- Baseline first in report-only mode. State the starting thresholds and that they are dials, not gospel.
- List the benign activity that trips each rule and how to allowlist it.

## Threat hunt

A hypothesis-driven hunt for the low-and-slow case the alert rules miss, as explicit steps or a query.

## Mitigation

Shrink the attack surface, not just detect it. Map each control to a framework where it helps.

| Control | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| <control> | <mapping> | <mapping> | <mapping> |

## Honest limitations

What this does not catch, and why. Every detection has blind spots - name them.

## ATT&CK and references

- MITRE ATT&CK: <Txxxx> <name>
- UMBRASEC writeup: https://umbrasec.dev/research/<slug>.html
- <primary sources: vendor advisories, CVE, RFCs>
