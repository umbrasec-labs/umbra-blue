---
name: detect-anti-forensics
description: "Detection and hunt methodology for anti-forensic indicator removal on Windows endpoints: audit-log clearing (MITRE ATT&CK T1685.005), timestomping (T1070.006), and file wiping or artifact deletion (T1070.004), the last two under the T1070 Indicator Removal parent, with the adjacent Defense Impairment signal T1685.001 Disable or Modify Windows Event Log. It keys off Windows Security event 1102, System event 104, Security 1100 and 4719, Sysmon event 2 (file creation time changed) and events 23 and 26 (file delete), plus process-creation and PowerShell logging. The skill gives defenders the real event IDs and fields, a forensic-grade MFT and USN hunt for timestomping, hardening that moves evidence off the host, and links to public SigmaHQ and MITRE rule sources. Use when triaging an Event ID 1102 alert, investigating a cleared Security log, hunting for timestomped files, chasing suspected log tampering or wevtutil cl / Clear-EventLog activity, or hardening log retention so a local wipe does not destroy evidence."
---

# Anti-Forensics (Indicator Removal) - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

An intruder who already has administrative rights will try to erase their trail: clear the Windows event logs, backdate file timestamps so tooling blends into the OS install, and wipe the files they dropped. Clearing the **Security** log writes **Event ID 1102** and clearing any other channel writes **System Event ID 104**, so both are high-signal and rare in healthy operation. Timestomping shows up in **Sysmon Event ID 2** and, more reliably, in the NTFS Master File Table when `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps disagree. The single most valuable control is not a rule at all: forward logs off the host in near real time, so a local clear leaves the evidence intact on the collector. These are late-stage detections. By the time they fire the attacker usually owns the box, so treat any hit as an active-intrusion lead, not noise.

## What it looks like, defender view

A Security log that ends abruptly, then resumes, with a lone 1102 at the seam. A host that simply stops forwarding events while its neighbours keep talking. A binary in `C:\Windows\System32` or a user temp path whose creation time matches the OS install to the second but whose `$FILE_NAME` record or USN journal entry says it arrived last Tuesday. A short burst of `wevtutil`, `Clear-EventLog`, `fsutil usn deletejournal`, or `cipher /w` in process telemetry, often minutes before a log goes quiet. None of these is benign-by-default on a production server.

## Log sources and signals

- **Security 1102** "The audit log was cleared." Security channel only. Fields: `SubjectUserName`, `SubjectDomainName`, `SubjectUserSid`, `SubjectLogonId`. Pivot on `SubjectLogonId` to the session that did it. Most shops watch only this one.
- **System 104** "The event log file was cleared" (provider `Microsoft-Windows-Eventlog`). Fires when **Application, System, or any non-Security channel** is cleared. Fields include the clearing user and `Channel`. If you alert on 1102 alone you miss a clear of every other log.
- **Security 1100** "The event logging service has shut down." Stopping the service before tampering means 1102 may never be written. Treat an unexpected 1100 on a server as suspicious.
- **Security 4719** "System audit policy was changed." Turning auditing off (T1685.001) silences future events without clearing anything.
- **Sysmon Event ID 2** "A process changed a file creation time." Fields: `Image`, `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime`. This is the direct timestomp signal, but its scope is narrow: creation time only, `$STANDARD_INFORMATION` only, via the `SetFileTime` API, and it needs an explicit include in the Sysmon config. It is noisy by default (installers, browsers, archive extraction, Office).
- **Sysmon Event ID 23 / 26** "File Delete archived / File Delete detected." The artifact-wipe signal. Both require explicit Sysmon config and 23 needs an archive directory with space. Native `Security 4660 / 4663` only fire where a SACL exists on the path.
- **Process creation** (Sysmon 1, or Security 4688 with command-line auditing enabled) and **PowerShell script-block logging 4104** carry the acts themselves: `wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, `fsutil usn deletejournal`, `cipher /w`, and sdelete-style secure-delete tools.
- **Linux** (T1685.006 / T1070.003), one note: an auditd watch `-w /var/log -p wa` and watches on `~/.bash_history`, `/var/log/wtmp` and `/var/log/btmp`, plus syscall rules for `utimensat` / `utimes`, catch log truncation, history clearing, and timestamp changes.

What normal looks like: 1102 and 104 appear during deliberate reimaging and decommissioning, so baseline those windows. Sysmon 2 is routine for software installs, which is why the timestomp signal is better confirmed in the MFT than alerted on from event 2 alone.

## Detection approach

Alert outright on **Security 1102** and **System 104**. Neither is produced by normal log rollover or retention; a cleared log is an explicit action. Suppress the known maintenance windows (imaging, decommission) by host and time, and send everything else to triage with the clearing account attached. Pair this with a **collector-side gap detector**: a host that was forwarding 4624 / 4688 volume and goes silent has either died or been silenced, and 1100 just before the silence confirms tampering even when 1102 never gets written. For timestomping, use Sysmon 2 as a lead and confirm in the MFT (see the hunt); for wiping, watch the process-creation and PowerShell commands above. A tuned UMBRASEC rule is not yet shipped for this threat, so lean on maintained public rules:

- **SigmaHQ** (github.com/SigmaHQ/sigma): `rules/windows/builtin/security` and `rules/windows/builtin/system` for the 1102 / 104 / 1100 / 4719 clears, `rules/windows/process_creation` for `wevtutil` and friends, `rules/windows/file/file_change` for timestomp, `rules/windows/file/file_delete` for wiping, and `rules/linux/auditd` for the Linux equivalents.
- **MITRE CAR** analytic CAR-2016-04-002 "User Activity from Clearing Event Logs."
- **Elastic detection-rules** (github.com/elastic/detection-rules) and **Splunk Security Content** (research.splunk.com) both ship maintained "Windows Event Log Cleared" analytics.
- **MITRE ATT&CK** technique pages for T1685.005, T1070.004 and T1070.006 carry the current detection and mitigation guidance.

## Threat hunt

Hypothesis: an intruder cleared logs or backdated a dropped file on a specific host. No fenced rules here; this is a procedure.

1. Over a 90-day window, list every **Security 1102** and **System 104** across all hosts, join the clearing account, and subtract the known imaging and decommission windows. Anything left is a lead; rank by host sensitivity.
2. For each lead host, pull the minutes **before** each clear from process-creation and PowerShell 4104 and look for `wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, or an unexpected **1100**. A clear preceded by a service stop is a strong tamper pattern.
3. Run the gap detector: for each host, compare expected daily volume of 4624 / 4688 against actual, and flag hosts that fell silent. Check whether **1102 survives on the WEF collector** even though the local log is gone; that gap is itself the finding.
4. Timestomp confirmation, offline from a disk image: compare `$STANDARD_INFORMATION` against `$FILE_NAME` timestamps in the MFT. A file whose SI creation time is earlier than its FN creation time, or whose sub-second precision is zeroed (a classic manual-timestomp artifact), is suspect. Cross-check against the `$Extend\$UsnJrnl:$J` USN journal, which records a creation or basic-info change at the real time, and against Prefetch and Amcache, which carry execution times that contradict a backdated binary.
5. For suspected wiping, reconcile Sysmon 23 / 26 and `$UsnJrnl` delete records against what should still be on disk, and recover from the forwarded logs and backups rather than the wiped host.

## Hardening

Shrink the attacker's ability to destroy evidence, and make the evidence survive the host. Mappings follow the control codes in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Forward logs off-host in near real time (WEF / syslog / SIEM) | A local clear no longer destroys the record; 1102 itself survives on the collector | ML2/ML3 event-log requirements | A.8.15 Logging | DE.CM Continuous monitoring |
| Restrict who can clear logs and who is local admin | `SeSecurityPrivilege` and admin reduction limit who can clear the Security log or stop the service | Restrict administrative privileges (ML2+) | A.8.16 Monitoring activities | DE.AE Adverse events |
| Deploy Sysmon and EDR with file-time and file-delete telemetry | Produces the Sysmon 2 / 23 / 26 and behavioural signals the detections need | - | A.8.16 Monitoring activities | DE.CM; DE.AE |
| Immutable retention and evidence handling | Write-once or legal-hold storage preserves logs for the investigation after a wipe | - | A.5.28 Collection of evidence; A.5.24 Incident response planning | RS.MA Incident management |

## Honest limitations

Per-record tampering (editing or selectively deleting individual `.evtx` records) never writes a 1102. Stopping the EventLog service first means 1102 may never exist, which is why the gap detector and the forwarded copy matter more than the single event. Sysmon 2 sees only creation-time changes through `SetFileTime`; it misses modified / accessed changes, `$FILE_NAME` edits, PowerShell `Set-ItemProperty` on `LastWriteTime`, and raw MFT writes, so the MFT comparison is the real proof. Events 23 / 26 need a Sysmon config most environments do not deploy. And the premise of the whole technique is that the attacker is already privileged, so these are detections of late-stage activity, not of initial access. State what the evidence shows and what it does not; the detection advises, the defender decides whether an intrusion is live.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/), [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/), [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006/), [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004/); adjacent [T1685.001 Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/).
- ATT&CK mitigations: M1029 Remote Data Storage (forward and store logs off the host) and M1022 Restrict File and Directory Permissions.
- MITRE D3FEND: the Detect tactic answers Indicator Removal; the per-technique countermeasure list is at [d3fend.mitre.org/offensive-technique/attack/T1070.001](https://d3fend.mitre.org/offensive-technique/attack/T1070.001/) (D3FEND has not yet mapped the ATT&CK v19 IDs, so it still files T1685.005 under this revoked ID). The defensive move that matters most here is moving the log off the host and analysing it where the attacker cannot reach it; specific D3-xxx identifiers are not asserted here because they were not verified against the live knowledge graph.
- Public rule sources: SigmaHQ (github.com/SigmaHQ/sigma), MITRE CAR CAR-2016-04-002, Elastic detection-rules, Splunk Security Content.

**Scope note.** This is a defensive skill. It explains anti-forensic indicator removal only to the depth needed to detect, hunt, and mitigate it, names commands only to recognise them in telemetry, and ships no wiping, timestomping, or log-clearing tooling.
