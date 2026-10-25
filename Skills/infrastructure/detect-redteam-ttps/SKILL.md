---
name: detect-redteam-ttps
description: "Purple-team detection coverage for a full red team or adversary-simulation engagement lifecycle, from resource development and C2 infrastructure through evasion, collection, and exfiltration. Maps the recurring operator TTPs (MITRE ATT&CK T1583, T1071, T1090.004, T1568.002, T1573, T1685, T1055, T1003.001, T1021, T1560, T1041) to the telemetry that catches them: Windows Security and Sysmon, EDR process and image-load events, DNS and proxy egress logs, and TLS fingerprints. Gives a tactic-by-tactic coverage method, a layered hunt, and the deconfliction and debrief workflow that turns an engagement into validated detections. Use when preparing for or debriefing a red team engagement, building ATT&CK detection coverage, running a purple team, hunting for C2 beacons or EDR tampering, or validating whether your sensors would catch an adversary simulation."
---

# Advanced Red Team TTPs - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public, maintained rule sources by URL. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

A red team engagement is not one technique, it is a chain across the ATT&CK tactics, and no single alert catches all of it. Build coverage per tactic instead: watch infrastructure and C2 at the network edge (DNS, proxy, TLS fingerprints), watch evasion and injection on the endpoint (EDR plus Sysmon image loads and process access), and watch collection and exfiltration where data is staged and leaves. The single highest-value move is to treat the engagement as a test: use the red team's own deconfliction log and purple-team debrief to find which links in the chain produced no telemetry, then close those gaps with public rules before calling the detection done. Coverage is measured end to end, not by counting alerts.

## What it looks like, defender view

Across an engagement the same shapes recur in telemetry. Infrastructure appears first as freshly categorized domains and valid-TLS hosts that your users have never visited before (Resource Development, T1583). C2 shows up as beaconing: regular-interval connections to one destination with low jitter, small uniform request sizes, and a TLS or HTTP profile that does not match the browser or app it claims to be, including domain-fronted requests where the SNI and the HTTP Host header disagree (T1071, T1090.004, T1573), or long-lived DNS TXT and A-record query streams to one zone (T1071.004), or bursts of lookups, many returning NXDOMAIN, for algorithmically generated domains (T1568.002). On the endpoint, evasion presents as a process tampering with security tooling or AMSI, unsigned or hollowed modules loaded into a legitimate process, and cross-process memory access to LSASS (T1685, T1055, T1003.001). Late in the chain you see archives built in staging directories and a burst of outbound data to the same host the beacon talks to (T1560, T1074, T1041). A mature operator keeps each step quiet; the win comes from correlating the faint signals across tactics, not from one loud alert.

## Log sources and signals

Coverage needs sensors in three planes. Name them explicitly so the gaps are visible.

Network and C2 plane:
- **DNS resolver / sinkhole logs** and Sysmon **Event ID 22** (DNSQuery): query volume and entropy per domain, TXT and NULL record use, newly observed domains. Beaconing shows as periodic queries to one zone.
- **Proxy and firewall egress logs** (for example Zscaler, Palo Alto, Squid): destination, bytes in/out, request cadence, user agent, and URL category. Low-jitter periodicity and small uniform transfers are the beacon tell.
- **Zeek / network metadata** and **JA3 / JA3S or JA4 TLS fingerprints**: a client TLS fingerprint that is not a known browser, or an SNI that disagrees with the HTTP Host header, flags domain fronting and non-browser C2.

Endpoint plane:
- **EDR telemetry** (the primary sensor) for process creation, module loads, memory operations, and tamper events.
- **Sysmon**: **Event ID 1** (process create, with command line and hashes), **Event ID 7** (image loaded, catches unsigned or unexpected DLLs in a host process), **Event ID 8** (CreateRemoteThread), **Event ID 10** (ProcessAccess, catches handles opened to lsass.exe), **Event ID 11** (file create, staging), **Event ID 13** (registry, persistence).
- **Windows Security log**: **4688** (process creation with command line auditing on), **4697** (service install); plus **4104** (PowerShell script-block logging, AMSI-relevant) from the Microsoft-Windows-PowerShell/Operational log and **7045** (service install) from the System log (Service Control Manager), **4769 / 4624 Type 3** (lateral movement over Kerberos / network logon), **1102** (audit log cleared, an OPSEC indicator-removal tell, T1070).
- **Antimalware / AMSI**: Microsoft Defender **Event ID 1116/1117** and operational logs showing AMSI init failures or tamper attempts.

Data and exfil plane:
- Staging shows in Sysmon **11** and EDR file events: archive creation (.zip, .7z, .rar) in temp or user profile directories (T1560).
- Exfil shows where the proxy/firewall and DLP/CASB record large or anomalous outbound volume, often to the same destination as the beacon (T1041), or to a sanctioned web service used as a dead drop (T1567).

What normal looks like: browsers produce bursty, varied-size traffic to many destinations with well-known TLS fingerprints; service accounts talk to known internal hosts on a schedule; LSASS is opened by a short, known list of system processes. The anomaly is legible only once that baseline exists, which is why centralized logging has to be in place before the engagement starts.

## Detection approach

Do not try to write one rule for "red team." Assemble coverage tactic by tactic and alert on the correlation, highest precision first.

1. **C2 beaconing.** Alert on periodic, low-jitter connections to a single external destination with uniform payload sizes, scored over a time window from proxy and Zeek logs. Pair it with TLS-fingerprint anomaly (a non-browser JA3/JA4 to an external host) and with the SNI-versus-Host mismatch that reveals domain fronting. This is the broadest-coverage signal against most C2 frameworks.
2. **Newly observed and recently categorized domains.** Flag first-contact to domains your population has never resolved, weighted up when the domain's registration or categorization is recent. Catches aged-but-new infrastructure early.
3. **Endpoint evasion and injection.** Alert on handles opened to lsass.exe by non-system processes (Sysmon 10), remote-thread creation into another process (Sysmon 8), unsigned image loads into signed host processes (Sysmon 7), AMSI tamper or init failure, and Security log 1102 (log cleared). These are high-precision because the benign baseline is small.
4. **Lateral movement.** Correlate network logons (4624 Type 3), Kerberos TGS requests (4769), and service installs (7045) that originate from a host that just showed injection or credential-access activity.
5. **Collection and exfil.** Alert on archive creation in staging paths followed by outbound volume to the beacon destination, correlating Sysmon 11 with proxy byte counts.

Use public, maintained rule sets rather than inventing one. A tuned UMBRASEC rule is not yet shipped for this threat. Start from these real sources:
- **SigmaHQ**, organized by ATT&CK tactic, at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (see `rules/windows/` for process-access, image-load, PowerShell, and log-clear rules, and `rules/network/` for DNS and proxy analytics).
- **MITRE Cyber Analytics Repository (CAR)** at [car.mitre.org](https://car.mitre.org/) for tactic-mapped analytics such as process injection and LSASS access.
- **Elastic detection-rules** at [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules) and **Splunk Security Content** at [research.splunk.com](https://research.splunk.com/) for productionized C2, injection, and exfil analytics.
- **MITRE D3FEND** at [d3fend.mitre.org](https://d3fend.mitre.org/) to pick the countermeasure for each technique you are covering.

## Threat hunt

Treat the engagement as the hunt's ground truth. Hypothesis: an operator is present and at least one link in the chain produced no alert.

1. **Beacon hunt.** Over 7 to 30 days of proxy/Zeek data, group outbound connections by (source host, destination) and compute inter-arrival interval regularity and payload-size variance. Rank destinations by low variance and low jitter. A human-browsed site scores high variance; a beacon scores low. Review the top of the list against newly observed domains.
2. **TLS mismatch hunt.** List TLS sessions where SNI and HTTP Host differ, or where the JA3/JA4 fingerprint is not on your allowlist of browser and known-app fingerprints. Each hit is a domain-fronting or non-browser-C2 candidate.
3. **LSASS access hunt.** List every Sysmon 10 event targeting lsass.exe, exclude the known-good accessors (your EDR agent, Defender, lsass maintenance processes), and investigate the remainder by source process and granted-access mask.
4. **Indicator-removal hunt.** List every 1102 (Security log cleared) and Sysmon registry/file-delete on log paths; correlate timing with the deconfliction log to tell an operator's cleanup from a real intruder's.
5. **Coverage gap hunt.** Replay the red team's deconfliction log (timestamp, host, technique) against your alert and raw-telemetry stores. For each logged action, confirm whether (a) an alert fired, (b) raw telemetry exists but no alert, or (c) no telemetry at all. Category (c) is a sensor gap; category (b) is a rule gap. That table is the deliverable of the purple-team debrief.

Validate detections safely with **Atomic Red Team** ([github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)) in a controlled environment to confirm each tactic's sensor fires before the live engagement.

## Hardening

Coverage is a prerequisite, not an afterthought: you cannot detect what you do not log. The controls below shrink the blind spots an operator exploits, and they ground in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html), which maps this stage to the frameworks directly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Centralized log collection and retention | Ships Security, Sysmon, DNS, and proxy logs to one place and keeps them long enough to investigate a whole engagement | ML2+ event-log collection | A.8.15 Logging | DE.CM |
| EDR everywhere | Puts a behavioral sensor on every endpoint so injection, LSASS access, and tamper are visible | ML2+ | A.8.7 Malware; A.8.16 Monitoring | DE.CM; DE.AE |
| High-signal alerting and monitoring | Someone watches the logs and tunes alerts so the faint cross-tactic signals are actioned, not buried | ML2+ monitoring | A.8.16 Monitoring activities | DE.AE; DE.CM |
| Build-vs-buy monitoring (MDR) | Ensures 24/7 eyes on the telemetry when the team cannot cover it | - | A.8.16; A.5.24 IR planning | DE; RS.MA |
| Incident response plan with evidence handling | A tested plan so the debrief turns gaps into fixes and preserves evidence | - | A.5.24-A.5.26 IR; A.5.28 Evidence | RS.MA; RC.RP |
| Tabletop and purple-team exercises | Rehearses the response loop and feeds detection gaps back into coverage | - | A.5.27 Learning from incidents | ID.IM |

## Honest limitations

A disciplined operator defeats single-signal detection by design: jittered and long-haul C2 (for example DNS-over-HTTPS with randomized intervals) flattens the beaconing signal, domain fronting and legitimate CDNs hide the destination, and direct-syscall or unhooking tradecraft can blind an EDR that relies on user-mode hooks, so an injection may leave only a faint image-load or memory trace. Any one plane can be evaded; the defense is correlation across all three plus the ground truth of the deconfliction log. Newly observed domain and TLS-fingerprint logic generates false positives from new SaaS, CDN rotation, and non-browser clients, so baseline and allowlist before enforcing. None of this replaces a tested response plan: detection buys time only if someone acts on it. State your coverage honestly per tactic and let the purple-team debrief, not an alert count, decide whether a link in the chain is actually covered.

## ATT&CK and D3FEND

- MITRE ATT&CK (representative, not exhaustive): [T1583 Acquire Infrastructure](https://attack.mitre.org/techniques/T1583/) and [T1608 Stage Capabilities](https://attack.mitre.org/techniques/T1608/) (Resource Development, TA0042); [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/), [T1090.004 Domain Fronting](https://attack.mitre.org/techniques/T1090/004/), [T1568.002 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/), [T1573 Encrypted Channel](https://attack.mitre.org/techniques/T1573/), [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) (Command and Control, TA0011); [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) (Defense Impairment); [T1055 Process Injection](https://attack.mitre.org/techniques/T1055/), [T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620/), [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/) (Stealth); [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) (Credential Access); [T1021 Remote Services](https://attack.mitre.org/techniques/T1021/) (Lateral Movement); [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560/) and [T1074 Data Staged](https://attack.mitre.org/techniques/T1074/) (Collection); [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) and [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) (Exfiltration).
- MITRE D3FEND countermeasures: [Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) and [Protocol Metadata Anomaly Detection](https://d3fend.mitre.org/) for C2 and domain fronting; [Process Analysis](https://d3fend.mitre.org/) and [System Call Analysis](https://d3fend.mitre.org/) for injection and LSASS access; [Decoy Object](https://d3fend.mitre.org/) deception for high-confidence tripwires.
- Public rule sources: [SigmaHQ](https://github.com/SigmaHQ/sigma), [MITRE CAR](https://car.mitre.org/), [Elastic detection-rules](https://github.com/elastic/detection-rules), [Splunk Security Content](https://research.splunk.com/), and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for validation.

**Scope note.** This is a defensive skill. It explains red team tradecraft only to the depth needed to detect and mitigate it, maps each tactic to the telemetry and public rules that catch it, and deliberately ships no C2, evasion, or offensive tooling. UMBRASEC publishes defense, not offense.
