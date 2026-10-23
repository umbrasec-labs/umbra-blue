---
name: detect-linux-privesc
description: "Detection and hardening methodology for Linux local privilege escalation through setuid/setgid binaries, file capabilities, and sudo abuse (MITRE ATT&CK T1548, T1548.001, T1548.003, plus T1068 for vulnerable SUID/sudo/polkit binaries such as PwnKit and Baron Samedit). Keys off auditd EXECVE/SYSCALL records, sudo logs in /var/log/auth.log, /var/log/secure, and journald, Sysmon for Linux Event ID 1, and osquery/EDR telemetry. Gives the defender view of a privesc chain, the records to watch, a hypothesis-driven hunt, links to public rule sources, and a framework-mapped hardening plan. Use when investigating a suspected local root escalation, triaging a sudo or pkexec alert, auditing SUID binaries and file capabilities, hunting for GTFOBins-style abuse, writing Linux privesc detections, or hardening sudoers and setuid surface."
---

# Linux Privilege Escalation (SUID, Capabilities, Sudo) - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

A local attacker who already has a low-privileged shell looks for three cheap paths to root: a setuid-root binary they can coerce into running their code, a binary that carries a dangerous Linux file capability (for example `cap_setuid+ep`), or a sudo rule (or a sudo/polkit vulnerability) that lets them run something as root. In telemetry the tell is almost always the same shape: a process whose audit login id (`auid`) stays as the unprivileged user while its effective uid (`euid`) becomes `0`, often with an unexpected child shell. Turn on auditd with execve and setuid rules plus `/etc/sudoers*` watches, forward sudo authpriv logs, and alert on root-gaining execs that do not come from your known admin accounts and known binaries. Patch the perennial local-root bugs (PwnKit, Baron Samedit) fast, shrink the SUID and capability surface, and lock sudoers down to explicit commands.

## What it looks like, defender view

In normal operation setuid-root binaries (`passwd`, `su`, `sudo`, `mount`, `ping` on older distros) are launched by ordinary users all day and exit cleanly without spawning shells. An escalation attempt looks different: a setuid or capability-bearing binary, or a sudo-invoked command, is used to break out to a shell or read/write a file it has no business touching, so you see an interactive shell or scripting interpreter running with `euid=0` while the original login session (`auid`) is still an unprivileged user. Exploitation of a vulnerable binary (pkexec for CVE-2021-4034, sudo for CVE-2021-3156 or CVE-2019-14287) adds a crash, an odd argv, or a runas id of `-1`/`4294967295`, immediately followed by a root process parented to the exploit. This skill explains the technique only to the depth needed to catch and reduce it; it ships no escalation tooling.

## Log sources and signals

- **Linux Audit framework (auditd)** is the primary source. Load rules so the kernel emits the records you need:
  - `type=SYSCALL`/`type=EXECVE`/`type=PROCTITLE`/`type=PATH` for `execve`. The decisive fields are `auid` (the immutable login uid of the session), `uid`/`euid`/`suid`, `comm`, `exe`, and your rule `key`. The core signal is `auid` = an unprivileged user while `euid=0`.
  - A watch on the sudoers surface: `-w /etc/sudoers -p wa -k sudoers` and `-w /etc/sudoers.d/ -p wa -k sudoers`, which produce `type=PATH`/`CONFIG_CHANGE` records on edit.
  - Syscall rules for the setuid family (`-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setresuid -F key=privesc`) and for `setcap`/`chmod` so new SUID bits and capabilities are logged when they are created.
- **sudo logging.** sudo writes to the `authpriv` syslog facility, landing in `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora), and to journald (`journalctl _COMM=sudo`). auditd also records `type=USER_CMD` with the `cwd=`, `cmd=` (hex-encoded command), `terminal=`, and `res=` fields, keyed to the invoking `uid`/`auid`; the runas target is in sudo's own syslog line (`USER=`), not in USER_CMD. Failed or unexpected `runas` targets and `command not allowed` lines are high value. Where `log_output`/`log_input` are enabled, `sudoreplay` session logs under `/var/log/sudo-io` give full command context.
- **polkit/pkexec.** Authentication and pkexec invocations also land in `auth.log`/`secure` and journald; a pkexec run with no controlling terminal or a malformed environment is the PwnKit shape.
- **Sysmon for Linux** (sysmon-for-linux): Event ID 1 (ProcessCreate) gives parent/child lineage, command line, and the executing user, which complements auditd for the "root shell with an unprivileged parent" pattern.
- **osquery / EDR.** The `suid_bin` table enumerates setuid/setgid files for baselining, `process_events` (with the audit publisher) captures execs with uid/euid, and the `sudoers` table surfaces rule changes. Falco provides runtime rules for setuid use and unexpected privilege changes.

What normal looks like: SUID binaries invoked by real users, exiting without a child shell; sudo commands by accounts that appear in `/etc/sudoers`, matching allowed commands, with `success=yes`; a stable inventory of SUID files and file capabilities that only changes during patching. Deviation from those baselines is the anomaly.

## Detection approach

Alert on the uid transition, not on the binary name alone. The strongest, lowest-noise rule is: an `execve` of an interactive shell or interpreter (`bash`, `sh`, `dash`, `python*`, `perl`, `find`, `vim`, and similar GTFOBins candidates) where `euid=0` but `auid` is an unprivileged, non-root login id, excluding your known administrative accounts and your legitimate root-owned service launchers. Pair it with:

- Sudo misuse: `USER_CMD`/auth.log entries where `runas` is root but the invoking user is not expected, `command not allowed` denials, and any `runas` id of `-1`/`4294967295` (the CVE-2019-14287 pattern).
- Config tampering: any write to `/etc/sudoers` or `/etc/sudoers.d/` not performed by your change-management workflow (the `sudoers` watch key above).
- New attack surface: creation of a new setuid/setgid file (`chmod u+s`/`g+s`) or a new file capability (`setcap`) outside patching, which is both a persistence and a privesc indicator.
- Known-exploit shapes: a pkexec execution with an empty or malformed environment and no tty (PwnKit, CVE-2021-4034), and a sudo/sudoedit crash or anomalous argv (Baron Samedit CVE-2021-3156, sudoedit CVE-2023-22809).

A tuned UMBRASEC rule is not yet shipped for this threat. Use maintained public rules as your starting point and tune them to your baseline:

- SigmaHQ Linux rules, especially the auditd and process-creation sets: <https://github.com/SigmaHQ/sigma/tree/master/rules/linux/auditd> and <https://github.com/SigmaHQ/sigma/tree/master/rules/linux/process_creation> (includes setuid-bit, sudo CVE, and GTFOBins-style shell-spawn rules).
- Elastic prebuilt detection rules for Linux, including setuid/setgid capability-set, sudoers modification, and PwnKit/pkexec coverage: <https://github.com/elastic/detection-rules/tree/main/rules/linux>.
- Falco default ruleset (runtime detection for setuid and privilege changes): <https://github.com/falcosecurity/rules>.
- GTFOBins as the public reference for which SUID/sudo/capability binaries are abusable, so you know which execs to prioritise: <https://gtfobins.github.io/>.

## Threat hunt

Hypothesis: an unprivileged account has gained root through SUID, a file capability, or sudo, and the velocity-based alerts did not fire on a single quiet escalation.

1. Baseline the surface. Enumerate current SUID/SGID files (`find / -perm -4000 -o -perm -2000` via osquery `suid_bin` or an authorised sweep) and file capabilities (`getcap -r /`). Diff against a golden image; anything new or non-standard is a lead.
2. Over a long window, pull every `execve` where `euid=0` and `auid` is a non-root login id, group by `auid` and `exe`, and exclude known admins and known root service launchers. Rank by whether the `exe` is a GTFOBins candidate.
3. Join sudo `USER_CMD`/auth.log activity to the account inventory: find users running sudo who are not in `/etc/sudoers`, runs with unusual `runas` ids, and any `command not allowed` bursts.
4. Correlate the root-gaining process to its parent (Sysmon Event ID 1 or auditd `ppid`). A root shell whose parent is an unprivileged user session, a web server, or a cron-spawned script is the escalation to chase.
5. Pull the sudoers watch key and the setuid/setcap syscall key for the same window and timeline them against the suspect process.

## Hardening

Shrink the surface so a foothold does not reach root. These controls ground in the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html) Essential Eight baseline; a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Restrict sudo and admin rights | Lock sudoers to explicit commands per account, remove `NOPASSWD`/`ALL` grants, and review who holds privileged access | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Patch local-root bugs fast | Shut the window on PwnKit, Baron Samedit, sudoedit, and kernel/setuid CVEs that need no remote access | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security |
| Reduce SUID/capability surface | Remove the setuid bit or dangerous capabilities from binaries that do not need them; prefer capabilities scoped tightly over broad SUID-root | - | A.8.19 Software on systems | PR.PS Platform Security |
| Application control | Constrain which binaries and interpreters can execute, limiting GTFOBins-style breakouts | Application control | A.8.19 Software on systems | PR.PS Platform Security |

Alongside the table: enforce Mandatory Access Control (SELinux or AppArmor) to confine what a compromised SUID process can do, mount non-system filesystems `nosuid` where practical, and apply seccomp/system-call filtering to service accounts. These map to MITRE D3FEND countermeasures (below) rather than to the Essential Eight baseline.

## Honest limitations

A patient attacker who gains root once, quietly, and does nothing anomalous afterward may produce only the single `euid=0` exec in step 2 of the hunt, which is easy to lose in a busy estate; that is why baselining admins and golden-image SUID/capability sets matters. Kernel exploits (T1068) that escalate through a memory bug may never touch sudo or a setuid file and can leave little more than a crash and a root process, so EDR process lineage and crash telemetry carry the load there. auditd rules add kernel overhead and can be tuned down by an attacker who already has root, so treat the audit log as evidence up to the moment of compromise, not after. Finally, legitimate automation (configuration management, package postinstall scripts, backup agents) runs root-gaining execs constantly and will dominate your false positives until allowlisted. Baseline in report-only mode before you alert, and treat every rule threshold as a dial.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/), [T1548.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/), [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/), and [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) for vulnerable SUID/sudo/polkit binaries.
- MITRE D3FEND countermeasures: Mandatory Access Control (D3-MAC), System Call Filtering (D3-SCF), Local File Permissions (D3-LFP), and Executable Allowlisting (D3-EAL). See <https://d3fend.mitre.org/>.
- Public rule sources: SigmaHQ Linux (<https://github.com/SigmaHQ/sigma/tree/master/rules/linux>), Elastic detection-rules Linux (<https://github.com/elastic/detection-rules/tree/main/rules/linux>), Falco rules (<https://github.com/falcosecurity/rules>).
- Reference CVEs for the known-exploit shapes: CVE-2021-4034 (PwnKit, polkit pkexec), CVE-2021-3156 (Baron Samedit, sudo), CVE-2019-14287 (sudo runas `-1` bypass), CVE-2023-22809 (sudoedit arbitrary file write).

**Scope note.** This is a defensive skill. It explains Linux privilege escalation only to the depth needed to detect and mitigate it, and ships no escalation, breakout, or exploit tooling; UMBRASEC publishes defense, not offense.
