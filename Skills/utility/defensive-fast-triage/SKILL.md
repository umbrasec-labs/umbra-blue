---
name: defensive-fast-triage
description: "Fast blue-team triage checklist for a SOC analyst working an alert queue under time pressure, the defensive answer to a speed-run recon and quick-win scan (MITRE ATT&CK T1595 Active Scanning, T1595.002 Vulnerability Scanning, T1595.003 Wordlist Scanning, T1592 Gather Victim Host Information). Shows how that activity presents in web server and WAF access logs, proxy and firewall egress, Zeek conn metadata, and SIEM tables (Microsoft Sentinel W3CIISLog, AzureDiagnostics WAF, CommonSecurityLog; Splunk web access), then gives a repeatable scope-enrich-pivot-decide workflow, the reputation and enrichment sources to pull, a hunt for the scan that turned into a hit, and escalation hardening mapped to ISO 27001:2022 and NIST CSF 2.0. Use when triaging a SOC alert fast, building an alert triage runbook or playbook, deciding true positive versus false positive, working a noisy scanner or directory-brute-force alert, or standing up a blue-team fast triage checklist."
---

# Fast Blue-Team Triage - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's triage method, the log sources and signals, the hunt, and the escalation hardening, and points to public, maintained rule sources by URL. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Triage is a decision discipline, not a tool. When an alert fires, the analyst's job is to decide fast and correctly: true positive, false positive, or benign, and whether to escalate. Run the same four gates every time, in order: **scope** (what fired, on which asset, at what confidence), **enrich** (reputation and context on the source and target), **pivot** (did the same actor touch anything else, and did any probe succeed), **decide** (verdict, severity, escalate or close, with notes). The highest-value habit is to always pivot from the noisy signal to the success signal: a thousand blocked scans are low severity, but one `200 OK` on `/admin` or one successful logon from the scanning source changes the whole call. Speed comes from a fixed checklist and pre-wired enrichment, not from skipping steps.

## What it looks like, defender view

The offensive counterpart to this skill is a speed-run assessment: map the surface, brute-force directories and files, fingerprint the stack, find the origin behind the CDN or WAF, and chase quick-win vulnerabilities before the clock runs out. In telemetry that activity is loud and shallow. A single source IP (or a small rotating set) generates a burst of requests in a short window: many `404` and `403` responses as wordlists hit paths that do not exist, occasional `200`/`301`/`302` where a path does exist, scanner-shaped User-Agent strings or a missing/blank UA, requests for `/.git/`, `/.env`, `/admin`, `/wp-login.php`, `/actuator`, `/swagger.json`, and probing of debug parameters. Origin-discovery attempts show as direct hits to the backend IP that bypass the CDN, and as SNI or Host header values that disagree with the destination. The triage view is the inverse of the offensive view: the analyst is not looking at one target, they are looking at an alert and must reconstruct, in a few minutes, what the source did and whether any of it worked.

## Log sources and signals

Fast triage is only as fast as the data already being on hand. Name the sources so the gaps are visible:

- **Web server / reverse proxy access logs.** IIS W3C logs (Microsoft Sentinel table `W3CIISLog`), nginx and Apache access logs, or your proxy's access logs. Key fields: client IP (`c-ip` / `cs(X-Forwarded-For)`), `sc-status`, `cs-uri-stem`, `cs(User-Agent)`, `cs-method`, `sc-bytes`, and request time. The signal is a high count of distinct `cs-uri-stem` values with `sc-status` 404/403 from one `c-ip` in a short window, plus any 200 on a sensitive path.
- **WAF logs.** AWS WAF, Azure Application Gateway WAF (Sentinel `AzureDiagnostics`, `Category == "ApplicationGatewayFirewallLog"`) and Azure Front Door WAF (`Category == "FrontDoorWebApplicationFirewallLog"`), Cloudflare, F5. Fields: action (block/allow/count), matched rule, URI, client IP, country, and `ja3`/`ja4` where exposed. A block is a control working, not an incident; an **allow or count** on the same pattern is the one to read.
- **Firewall and NDR egress / ingress.** CEF firewall logs (Sentinel `CommonSecurityLog`), Zeek `conn.log` and `http.log`. Signal: inbound session volume per source IP, connection fan-out across ports or URIs, and new/rare destinations.
- **Endpoint (if the probe lands on a host).** Sysmon **Event ID 1** (process create) and **Event ID 3** (network connection), Windows Security **4688** (process create with command-line auditing), Microsoft Defender `DeviceNetworkEvents` and `DeviceProcessEvents`.
- **Identity.** Entra ID `SigninLogs` and `AADNonInteractiveUserSignInLogs`, Okta System Log. The pivot that matters: did the scanning source IP or ASN later produce a **successful** authentication (Entra result code `0`) against any account?

What normal looks like: legitimate crawlers and uptime monitors generate steady, low-rate, repeatable traffic with stable User-Agents and almost no 404 fan-out; real users do not request `/.git/config`.

## Detection approach

Triage usually starts from an existing detection, so the detection engineering here is to make sure the alert that lands in the queue is enrichable and not just a raw block count. Alert on the shape, not the single request: a correlation that counts distinct URIs or 404s per source IP over a short window (for example 50+ distinct 404 paths in 5 minutes from one `c-ip`), scanner User-Agent and sensitive-path requests, and WAF **allow/count** hits on injection or path-traversal signatures. Do not ship a hand-rolled rule from this skill; use public, maintained sources and tune them to your baseline:

- **SigmaHQ** web and proxy rule categories at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (the `rules/web` and `rules/web/webserver_generic` and proxy content) cover scanner User-Agents, suspicious path requests, and web exploitation patterns.
- **Elastic detection rules** at [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules) and **Microsoft Sentinel analytics** at [github.com/Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) for web, WAF, and sign-in analytics with KQL you can read and adjust.
- **MITRE D3FEND** [Inbound Session Volume Analysis (D3-ISVA)](https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis/) and [Network Traffic Analysis (D3-NTA)](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) describe the countermeasure class for scanning and recon detection.

The triage **workflow** itself, applied to whatever rule fired:

1. **Scope.** Read the alert: which rule, what confidence/severity, which asset, and is that asset internet-facing or crown-jewel. Pull the raw events behind the alert, not just the alert title.
2. **Enrich.** Source IP against reputation and context: [GreyNoise](https://www.greynoise.io/) (is this internet background scan noise or targeted), AbuseIPDB, VirusTotal, Shodan, Spur, and your own CMDB/asset inventory and allow-lists. Resolve ASN, geo, and whether the IP is a known good crawler, your own VA scanner, or a monitoring service.
3. **Pivot.** Same source IP / ASN / `ja3` across every source above. Specifically: any `sc-status` 200/301/302 on a sensitive path, any WAF **allow** on an exploit pattern, any successful sign-in, any outbound connection from a host that received the probe. This is the step that distinguishes a scan from a breach.
4. **Decide.** Verdict (TP / FP / benign-true-positive), severity, and action (escalate to IR, block the source, suppress/tune, or close), with a short note so the next analyst and the tuning backlog can learn from it.

## Threat hunt

For the scan that already got through, do not wait for an alert. Hypothesis: a recon source found a live path and a probe succeeded.

1. Over 7 to 30 days of web access logs, group by `c-ip` and compute distinct `cs-uri-stem` count and the 404:200 ratio. Rank sources by a high distinct-path count. These are your scanners.
2. For each top scanning source, pull its **200/301/302** responses only. A scanner that got mostly 404s but a handful of 200s on `/admin`, `/.env`, `/actuator/env`, `/api/`, or an upload endpoint is the lead.
3. Join those scanning source IPs and their ASNs to `SigninLogs` / Okta for the same window. A successful authentication from a scanning source is a priority escalation.
4. Join to firewall/Zeek egress: did any host that served a 200 to a scanner then make a new outbound connection to a rare destination shortly after.
5. Check WAF **allow/count** (not block) events from the same sources for injection or traversal patterns that slipped the ruleset.

## Hardening

Fast triage is a capability, not a one-off control. Shrink the time-to-verdict by wiring the inputs before the alert fires: pre-built enrichment lookups, a fixed triage runbook, asset criticality in the SIEM, and a clear escalation path. The mappings below follow the control codes used in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Retain the logs triage reads from | Web, WAF, proxy, sign-in logs kept long enough to reconstruct an event | ML2/ML3 event-log collection | A.8.15 Logging | DE.CM |
| High-signal, enrichable alerts | Alert on the shape (volume/fan-out), carry source and asset context so triage is fast | - (beyond E8, detection gap) | A.8.16 Monitoring activities | DE.AE; DE.CM |
| Written triage runbook and severity scale | A fixed checklist and clear TP/FP/escalate gates so verdicts are consistent | - (beyond E8) | A.5.24-A.5.26 Incident management | RS.MA |
| Escalation and reporting path | Who gets called, and the authorities/obligations when triage confirms an incident | - (beyond E8) | A.5.5 Authorities; A.6.8 Event reporting | RS.CO |

## Honest limitations

A fast triage checklist is built for speed, and speed trades against depth. A low-and-slow or distributed scan that stays under the volume threshold will not raise the shape-based alert, so the hunt above exists to catch it out of band. Reputation enrichment is probabilistic: a clean GreyNoise or VirusTotal result does not clear a source, and a dirty one does not convict. Attackers rotate IPs and spoof User-Agents, so source-based pivots can fragment. Triage only reconstructs what was logged: if WAF allow/count events or 200-response bodies are not retained, the "did it work" pivot has nothing to read. Finally, triage decides; it does not contain. A confirmed true positive hands off to full incident response, and this checklist is the front door to that process, not a substitute for it.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/), [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/), [T1595.003 Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/), [T1592 Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/). Triage as a discipline spans the whole matrix; these are the techniques the mirrored offensive checklist produces in telemetry.
- MITRE D3FEND: [D3-ISVA Inbound Session Volume Analysis](https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis/), [D3-NTA Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/).
- Public rule and method sources: [SigmaHQ](https://github.com/SigmaHQ/sigma), [Elastic detection-rules](https://github.com/elastic/detection-rules), [Microsoft Sentinel](https://github.com/Azure/Azure-Sentinel), and NIST SP 800-61 (Computer Security Incident Handling Guide) for the detection-and-triage lifecycle.

**Scope note.** This is a defensive skill. It explains the recon and scanning activity only to the depth a triage analyst needs to recognize and decide on it, and ships no scanning, brute-force, or exploitation tooling.
