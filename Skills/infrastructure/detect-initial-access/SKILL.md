---
name: detect-initial-access
description: "Detection methodology for initial access via exploitation of public-facing applications and the payload delivery that follows (MITRE ATT&CK T1190, T1133, T1105, tactic TA0001). Generalises defender lessons from two 2026 cases, the Metabase unauthenticated SQL injection (CVE-2026-72898) and the N-able N-central authentication bypasses (CVE-2026-18556, CVE-2026-18577): the attack shows up first as anomalous requests to an unauthenticated edge endpoint, then as an unexpected process or outbound connection on the host behind it. Log sources: reverse-proxy and WAF access logs, netflow and firewall egress, and host process-creation and service-install telemetry (Sysmon Event ID 1 or Windows Security 4688, System 7045). Gives the method, the signals, a hunt, and the hardening. Use when triaging a possible exploit of an internet-facing app, hunting for initial access or first-stage payload delivery, or hardening the exposed attack surface."
---

# Initial Access via Public-Facing Exploitation - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet. For the two specific cases this generalises, the shipped Tier 1 skills are [detect-metabase-sqli](../../web/detect-metabase-sqli/SKILL.md) and [detect-ncentral-post-exploitation](../../post-exploitation/detect-ncentral-post-exploitation/SKILL.md).

## TL;DR for defenders

Initial access through an internet-facing application is a two-part event, and you detect it in two places. First, an anomalous request reaches an exposed endpoint that should rarely or never take hostile input: Metabase's unauthenticated `/api/session/reset_password`, or the alternate authentication path abused in N-central (CWE-288). Second, the exploited host does something it has never done before: spawns an unexpected process, writes a binary into a user directory, or opens an outbound tunnel. Catch the first with edge logs (reverse proxy, WAF, netflow); catch the second with host process and service telemetry. Neither signal alone is decisive, so instrument both and correlate them by host and time. The single highest-value move is a current inventory of what you actually expose, mapped to patch level, so that a CISA KEV listing becomes a lookup rather than a scramble.

## What it looks like, defender view

In telemetry the pattern is consistent across cases. A request lands on an edge endpoint that normal users do not drive with crafted input, carrying either SQL or template metacharacters in the body, or hitting an authentication route by an unusual method or path. Minutes to hours later the host behind it deviates: a web or application service process spawns a shell or a LOLBin, a file with a trusted name appears in an untrusted location (the N-central operators dropped a binary named `svchost.exe` into a user's Documents folder), or a new service and an outbound connection to a tunnelling provider appears (a `Cloudflared` service in the N-central case). Bulk data egress can follow, inverting a host's normal inbound-heavy profile. The request side proves attempt; the host side proves success. No offensive how-to is needed to recognise either.

## Log sources and signals

- **Reverse-proxy and web server access logs** for every internet-facing app. Key fields are the request path (`cs-uri-stem`), query string (`cs-uri-query`), method, status, source IP, and user agent. Normal: authenticated users hit known routes with known verbs. Anomaly: unauthenticated POSTs with SQL or template metacharacters, or auth endpoints reached by an off-nominal method or path.
- **Body-capturing WAF or proxy logs** where available. Access logs record the request line only, and a competent exploit carries its payload in the POST body, so the authoritative version of request-side detection lives wherever you capture bodies.
- **Netflow, firewall, and proxy egress logs** for each exposed host. Signal: a host that normally serves modest responses suddenly producing sustained outbound volume, or any connection to a tunnelling or anonymising endpoint.
- **Host process creation with command lines.** Sysmon **Event ID 1**, or Windows Security **Event ID 4688** (which carries no command line unless you enable "Include command line in process creation events"). Signal: a web or application service process spawning `cmd.exe`, `powershell.exe`, or a renamed binary; a trusted process name running from an untrusted path.
- **Service installation.** System log **Event ID 7045** (`ServiceName`, `ImagePath`), low volume and on by default but often not collected. Signal: a new service pointing at a binary in a user-writable location or to a tunnelling client.
- **Asset and version inventory** of what is internet-reachable. Not a detection feed, but the lookup that turns a KEV listing into an answer. An inventory that records only "product installed" without the build number cannot tell you if you are vulnerable.

## Detection approach

Alert on the request side where the exposed endpoint has a narrow legitimate shape. The strongest edge detections anchor on a specific vulnerable path and a specific class of hostile input, rather than on generic "suspicious" scoring: for example, SQL metacharacters in traffic to a named unauthenticated endpoint, or authentication requests that reach a route by a method the primary path does not use. Where a vendor publishes an interim workaround that blocks an endpoint outright, that endpoint becomes a clean tripwire, because on a patched and hardened instance any input there is already anomalous.

On the host side, alert on the deviation the exploit produces: a renamed system binary running outside its canonical directory, a service process spawning a command interpreter, a new service that points at a user-writable path or a tunnelling client, and sustained unexpected egress. Correlate an edge hit and a host deviation on the same asset inside a short window to raise confidence.

This Tier 2 skill ships no tuned UMBRASEC rule. Use public, maintained rules instead and tune them to your estate:

- SigmaHQ web and proxy rules: [github.com/SigmaHQ/sigma/tree/master/rules/web](https://github.com/SigmaHQ/sigma/tree/master/rules/web)
- SigmaHQ emerging-threats exploit rules (CVE-specific, including public-facing application exploitation): [github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats](https://github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats)
- SigmaHQ Windows process-creation rules for masquerading and tool transfer: [github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation)
- Convert any of these with [sigma-cli](https://github.com/SigmaHQ/sigma-cli); ground every rule against your own baseline before enforcing.

## Threat hunt

Hypothesis: an exposed application was exploited and the attacker established a foothold that no rule fired on. Steps:

1. Enumerate every internet-reachable application and appliance, with product, version, and patch date. Flag any build that appears in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) or has an open advisory.
2. For each flagged host, pull edge access logs over the exposure window and look for requests to unauthenticated or authentication endpoints that carry metacharacters, use off-nominal methods, or come from source IPs with no prior history against that app.
3. On the same hosts, review process-creation (Sysmon 1 / 4688) for the application or web service account spawning interpreters or binaries from unusual paths, and service-install (7045) for services added in the window pointing at user-writable paths or tunnelling clients.
4. Baseline outbound byte volume per exposed host and surface any sustained inversion of its normal inbound-heavy profile.
5. Where an edge anomaly and a host anomaly line up on one asset in one window, treat it as a confirmed-until-cleared foothold and move to containment and credential rotation.

## Hardening

Shrink and instrument the exposed surface. The control codes below are grounded in the UMBRASEC guide ([foundation](https://umbrasec.dev/guide/foundation.html), [detection and response](https://umbrasec.dev/guide/detection-and-response.html)); a cell is blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Inventory exposed assets and versions | Turns a KEV listing into a lookup, not a scramble | Assumed prerequisite | A.5.9 Inventory of assets | ID.AM Asset Management |
| Patch public-facing apps and OS fast | Removes the exploited vulnerability; prioritise KEV-listed and internet-reachable | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security |
| Edge logging and visibility | Captures the request-side signal; body-capturing proxy or WAF for POST payloads | ML2/ML3 event-log requirements | A.8.15 Logging | DE.CM Continuous monitoring |
| High-signal alerting on exposed hosts | Surfaces the host deviation after exploitation | - (beyond E8) | A.8.16 Monitoring activities; A.8.7 Malware | DE.AE Adverse events; DE.CM |
| Application control | Blocks the dropped first-stage payload from executing | Application control | A.8.19 Software on systems | PR.PS Platform Security |

Also minimise the surface itself: do not expose management or RMM consoles to the internet, put remote services behind VPN or allowlists, and adopt any vendor interim workaround (such as blocking a named endpoint at the proxy) which doubles as a tripwire.

## Honest limitations

Request-line rules miss payloads delivered in the POST body, so they need body-capturing logs to be authoritative. A zero-day exploited before an advisory or KEV listing will not light up a version lookup, which is why the host-side deviation signals matter independently. For software that runs on a provider's infrastructure (the N-central server sits in your MSP's rack), you cannot patch or log the exploited system at all and can only detect the operator's artifacts on the endpoints you own. Correlating edge and host signals assumes clock sync and collection from both tiers; a gap on either side breaks the correlation. Baseline every rule in report-only mode first, because scanners, uptime monitors, and legitimate automation will trip naive request-side logic.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/), [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/); tactic [TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001/).
- MITRE D3FEND countermeasures: Inbound Traffic Filtering (D3-ITF), Network Traffic Analysis (D3-NTA), File Analysis (D3-FA), Executable Allowlisting (D3-EAL), and Application Configuration Hardening (D3-ACH). See [d3fend.mitre.org](https://d3fend.mitre.org/).
- Public rule sources: SigmaHQ [rules/web](https://github.com/SigmaHQ/sigma/tree/master/rules/web), [rules-emerging-threats](https://github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats), and [rules/windows/process_creation](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation); [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Case references: CVE-2026-72898 (Metabase), CVE-2026-18556 and CVE-2026-18577 (N-able N-central), both N-central CVEs in CISA KEV.

**Scope note.** This is a defensive skill. It explains public-facing exploitation and payload delivery only to the depth needed to detect and mitigate them, reconstructs no exploit, and ships no offensive tooling.
