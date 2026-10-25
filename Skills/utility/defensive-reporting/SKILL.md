---
name: defensive-reporting
description: "Detection and incident reporting methodology where every claim is tied to a primary source, plus detection of anti-forensic activity that attacks that evidence: log clearing and tampering (MITRE ATT&CK T1070, T1685.005, T1070.006), disabling event logging (T1685.001), and stored-data manipulation (T1565.001). Keys off Windows Security Event IDs 1102, 4719, 1100 and System 104, Sysmon Event ID 2 and process creation, and Linux auditd/journald. Gives a report structure that survives scrutiny, an evidence-hygiene and chain-of-custody checklist, source-tracing discipline, tamper-signal detection logic, a hunt for destroyed telemetry, and hardening mapped to ISO 27001 and NIST CSF 2.0. Use when writing an incident or detection report, preparing a SOC deliverable for an auditor or regulator, building an IR report template, tracing an alert claim to its log source, or hunting for cleared or tampered logs after an intrusion."
---

# Detection and Incident Reporting - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

A report is only as strong as the evidence under it, and an attacker who has read your playbook attacks that evidence before you can write it. Two disciplines, one skill. First, the reporting discipline: every finding in an incident or detection report points to a specific log source, event ID, timestamp, and immutable artifact, so a reader can retrace it without taking your word for anything. Second, the detection discipline: watch for the anti-forensic moves that break that chain, above all **Windows Security Event ID 1102** (audit log cleared), **System Event ID 104** (an event log cleared), **4719** (audit policy changed), **1100** (event logging service shut down), and Sysmon **Event ID 2** (file creation time changed, the timestomp signal). A report that says "logs show X" without a retraceable pointer, and a log pipeline that cannot prove it was not tampered with, both fail the same test.

## What it looks like, defender view

In telemetry, evidence tampering is loud if you are watching the right channel and silent if you are not. A cleared Security log leaves exactly one record: Event **1102**, written by the act of clearing, naming the account and logon session that did it (correlate the logon ID to process-creation events for the process). Clearing via `wevtutil cl`, `Clear-EventLog`, or the Event Viewer GUI produces **104** in the System log per channel cleared. Turning auditing off before acting shows as **4719** (audit policy changed) or **1100/1108** around the logging service. Timestomping, where an attacker backdates a dropped file to blend with the OS, shows as Sysmon **Event ID 2** (FileCreateTime changed) when the new time predates the file's real arrival. On Linux the equivalents are `auditd` records for writes to `/var/log`, truncation of `utmp`/`wtmp`/`btmp`, and gaps or rotation anomalies in `journald`. In the report itself, the defender view of a weak deliverable is a claim with no anchor: a severity with no scoring vector, a "we observed" with no event ID or timestamp, a screenshot with no hash and no chain-of-custody line. This skill is defensive and ships no tooling for clearing logs, forging timestamps, or defeating audit; it explains those acts only far enough to catch them and to document what they destroyed.

## Log sources and signals

The reporting half of this skill does not key off one log; it keys off all of them, because the discipline is that every asserted fact names the source it came from. The detection half keys off a small, high-value set:

- **Windows Security, Event ID 1102** - "The audit log was cleared." Carries `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, and `SubjectLogonId`; it does not name the clearing process, so join the `SubjectLogonId` to 4688 or Sysmon Event ID 1 to find it. Benign causes are near zero outside of deliberate administrative cleanup, which should be change-ticketed.
- **Windows System, Event ID 104** - an event log file was cleared, one per channel. Pairs with 1102 for the Security channel.
- **Windows Security, Event ID 4719** - "System audit policy was changed." An attacker disabling a subcategory before acting shows here.
- **Windows Security, Event ID 1100 / 1108** - the event logging service shut down, or a channel failed to process an event. A sudden 1100 outside a planned reboot is a gap you must account for.
- **Sysmon Event ID 2** - FileCreateTime changed. The core timestomp signal (T1070.006). Compare the logged creation time against the record's own write time and against first-seen in EDR.
- **Sysmon Event ID 1 / Security 4688** - process creation. Surfaces the tools of tampering: `wevtutil.exe`, `fsutil usn deletejournal`, `vssadmin delete shadows`, `PowerShell Clear-EventLog`, `auditpol /clear`.
- **Linux `auditd`** - watch rules on `/var/log`, `/etc/audit`, and the audit binaries; `journald` sequence-number gaps; truncated `wtmp`/`btmp`.
- **The evidence artifacts a report cites** - packet captures, memory images, disk images, log exports, screenshots. Each needs a cryptographic hash (SHA-256), a capture timestamp in UTC, and a custody record. Normal looks like a continuous, hash-anchored, time-synchronised record; the anomaly is any break in it.

What normal looks like: Security logs roll by size, not by sudden emptiness; 1102 appears only against a change ticket; file creation times move forward, never backward relative to first-seen.

## Detection approach

Alert on the tamper signals, not on the absence of logs, because absence is exactly what the attacker is buying. The highest-precision rule is a single Event **1102** or **104** that does not line up with an approved maintenance window: treat every unscheduled log-clear as an incident until proven otherwise, since a legitimate clear is rare and always planned. Next, alert on **4719** and **1100** that cluster with other suspicious activity on the same host and logon session, which is the "turn off the camera first" pattern. For timestomping, alert on Sysmon **Event ID 2** where the new FileCreateTime is older than the file's first-seen time in EDR or older than its own MFT record change. Cross-correlate process-creation events for the known tamper binaries listed above with the logon session that generated them.

Point to public, maintained rules rather than inventing one. SigmaHQ carries community rules for these signals in its Windows built-in sets, for example the security and system channel directories under [github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin) (log-cleared and audit-policy-change detections live there; Sysmon Event ID 2 timestomp rules live under `rules/windows/file/file_change`), and process-creation rules for `wevtutil`, `fsutil`, and `vssadmin` under the `process_creation` directory. MITRE ATT&CK's own detection notes for [T1070](https://attack.mitre.org/techniques/T1070/), [T1685.005](https://attack.mitre.org/techniques/T1685/005/) and [T1685.001](https://attack.mitre.org/techniques/T1685/001/) name the same data sources. A tuned UMBRASEC rule is **not** yet shipped for this threat; use the public sources above and baseline them against your own maintenance activity before enforcing.

For the reporting discipline there is no rule to run, only a gate to apply: no claim ships without a source pointer. Build the gate into the template itself (see below) so a reviewer can reject any finding whose evidence line is empty.

## Report structure that survives scrutiny

One finding, one retraceable claim. Each detection or incident finding carries, at minimum:

1. **Claim** - what you assert happened, in one sentence.
2. **Source** - the exact log source, table, or artifact: for example "Windows Security 4769 on DC01", "Sysmon EID 1 on WKS-204", "pcap `capture-007.pcap` SHA-256 `ab12...`".
3. **Timestamp** - UTC, from a time-synchronised source; note the clock source if it is not NTP-disciplined.
4. **Observation** - the raw field values that support the claim, quoted, redacted of secrets and PII per the global handling rules.
5. **Confidence and gaps** - what the evidence proves, what it does not, and which log you wish you had.
6. **Severity** - scored with a stated method (CVSS vector, or your SOC's incident-severity matrix) so the number is reproducible, never asserted bare.

The executive summary is written last and reads in ninety seconds: business impact in plain language, counts by severity, and the handful of strategic actions. Translate every bit of jargon for that audience. The technical body is where the sourcing discipline lives; the summary inherits its credibility from the body, not the other way round.

## Threat hunt

Hunt for the evidence that is missing, which is harder than hunting for evidence that is present.

1. **Clear-log sweep.** Over a long window, list every Event **1102** and **104** across all hosts. Join each to the change-management record. Any clear with no matching ticket is a lead. Rank by host criticality and by what else happened on that host in the surrounding hour.
2. **Silence detection.** For each host, compute the gap between consecutive Security-log event sequence numbers or timestamps. A gap far larger than that host's baseline, especially one bracketed by a **1100** then a resumption, flags a blackout the attacker may have engineered. `journald` sequence gaps and `wtmp` truncation are the Linux equivalents.
3. **Timestomp retro-hunt.** Pull Sysmon **Event ID 2** where the new `CreationUtcTime` is earlier than `PreviousCreationUtcTime` (the file was backdated), then triage the files by path (system directories are the blending targets) and by EDR first-seen.
4. **Report-integrity hunt.** For a sample of past incident findings, retrace each claim to its cited source. Any claim you cannot retrace is a process failure to fix before the next audit, and a sign your retention or sourcing discipline has a hole.

## Hardening

Shrink the attacker's ability to destroy the record, and make the record provable after the fact. The control codes below are grounded in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html), which maps the SOC build-out to ISO 27001:2022 and NIST CSF 2.0; the Essential Eight column is marked where the Eight deliberately does not reach incident reporting and evidence handling, as the guide notes.

| Control | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| Forward logs off-host to a write-once/WORM or append-only store so a local clear cannot destroy the record | - (beyond E8) | A.8.15 Logging | DE.CM |
| Written incident response and evidence-handling plan, including chain of custody and hashing | - (beyond E8) | A.5.24-5.26 Incident management; A.5.28 Collection of evidence | RS.MA; RC.RP Recovery |
| Defined reporting obligations and authorities contacts, so notification is timely and defensible | - (beyond E8) | A.5.5 Contact with authorities; A.6.8 Information security event reporting | RS.CO Communications |
| Tabletop the report workflow and feed lessons back into the template | - (beyond E8) | A.5.27 Learning from information security incidents | ID.IM Improvement |
| Restrict who can clear logs or change audit policy, and alert on every use of that right | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 |

Enforce NTP so timestamps across sources agree; a report whose clocks disagree cannot order events. Keep retention long enough that the hunt above can run; a 1102 is useless if the window it sits in has already rotated away.

## Honest limitations

An attacker who disables auditing cleanly before acting may leave no 1102, only a 4719 or a silent gap, and the quietest ones tamper upstream of the host, at the collector or the SIEM, where your host rules never see it. Forwarding logs off-host defeats a local clear but not an attacker who owns the log pipeline itself, which is why write-once storage and out-of-band integrity checks matter. Timestomp detection depends on having a second, independent time source (EDR first-seen, MFT) to contradict the forged one; without it the backdated file looks native. On the reporting side, the source-tracing gate catches unsourced claims but cannot catch a correctly-cited source that was itself tampered with before you collected it, which is the whole reason the integrity controls above sit alongside the discipline. None of this is a verdict engine: it lays out evidence and gaps so a human makes the call.

## ATT&CK and D3FEND

This is a cross-cutting detection-and-reporting skill rather than a single-technique detection, so it maps to the anti-forensic techniques that attack the evidence a report depends on, and to the logging that makes reports retraceable.

- MITRE ATT&CK: [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/); [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/); [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006/); [T1685.001 Disable or Modify Tools: Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/); [T1565.001 Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/).
- MITRE D3FEND: no single D3FEND countermeasure covers "evidence-backed reporting" as a discipline; the closest mapped countermeasures against the techniques above are in D3FEND's Detect tactic (platform and file monitoring). See the inferred countermeasures on the D3FEND technique pages at [d3fend.mitre.org](https://d3fend.mitre.org/) for T1070, T1070.001 and T1562.002 (D3FEND has not yet mapped the ATT&CK v19 IDs, so it still files T1685.005 under the revoked T1070.001 and T1685.001 under the revoked T1562.002) rather than treating a specific code as authored here.
- Public rule sources: [SigmaHQ Windows built-in rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin) (log-cleared, audit-policy-change), [SigmaHQ file_change rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/file/file_change) (timestomp) and `process_creation` rules for `wevtutil`/`fsutil`/`vssadmin`; MITRE ATT&CK detection notes for [T1070](https://attack.mitre.org/techniques/T1070/), [T1685.005](https://attack.mitre.org/techniques/T1685/005/) and [T1685.001](https://attack.mitre.org/techniques/T1685/001/).

**Scope note.** This is a defensive skill. It explains anti-forensic techniques only to the depth needed to detect them and to document what they destroyed, and it ships no tooling for clearing logs, forging timestamps, or defeating audit. UMBRASEC publishes defense, not offense.
