---
name: monitor-external-attack-surface
description: "Monitoring the internet-facing attack surface against the CISA Known Exploited Vulnerabilities (KEV) catalog, so a public advisory for a service you run becomes an alert instead of a breach (MITRE ATT&CK T1595, T1596.005, T1592, leading to T1190; MITRE D3FEND D3-AI, D3-AVE). Ships the UMBRASEC kev-watch exposure-check procedure keyed to the CISA KEV JSON feed, plus a Sigma rule for exploitation attempts in webserver, WAF, and reverse-proxy logs, with tuning, false-positive notes, and Essential Eight / ISO 27001:2022 / NIST CSF 2.0 mappings. Use when building an external attack-surface monitor, cross-referencing your stack against CISA KEV, triaging whether a new KEV CVE affects something you expose, hunting for scanning or exploitation of an internet-facing app, or asking 'what are we exposed to that is being exploited in the wild'."
---

# External Attack Surface - KEV Exposure Monitoring

An attacker's first move against an organization is rarely an exploit; it is reconnaissance. Public search engines such as Shodan and Censys, certificate-transparency logs, DNS records, and a plain port scan tell an adversary exactly which internet-facing services you run and roughly which versions they are, long before anything is sent at them. When one of those services carries a vulnerability that is already being exploited in the wild - the kind CISA records in its Known Exploited Vulnerabilities (KEV) catalog - the gap between a public advisory and your patch is the whole attack. The Metabase case took sixteen days from KEV listing to a million-record exfiltration, and every date was public before the data moved; the failure was that nothing connected the advisory to the asset. This skill is defensive: it watches the same external surface an attacker enumerates, matches it against KEV, and detects exploitation while a window is still open. It explains reconnaissance only as far as monitoring and mitigation require, and ships no scanning or exploitation tooling.

## TL;DR for defenders

Keep a live inventory of everything you expose to the internet, then run the UMBRASEC [kev-watch](https://umbrasec.dev/tools/kev-watch/) tool daily against the CISA KEV feed, filtered to the vendors and products you actually run, so a newly exploited CVE in your stack pages you the morning it lands. Patch KEV items on internet-facing services inside the Essential Eight 48-hour window. Where you cannot patch at once, watch the edge: webserver, WAF, and reverse-proxy logs for probing and exploitation of the exposed endpoint. The highest-value, lowest-effort control here is the daily KEV-to-asset check - it is a public JSON feed and a cron job, and it is the single best public signal for "patch this now".

## Why it still matters in 2026

The KEV catalog exists because disclosure now outruns patching. Edge and internet-facing software is the preferred initial-access route for ransomware crews and access brokers, and mass exploitation increasingly starts within hours of a CVE going public, not weeks. The catalog only lists vulnerabilities with confirmed in-the-wild exploitation, so an entry is not a theoretical risk; it means someone is using it now, which is exactly why CISA attaches a federal remediation due date to each one.

The Metabase intrusion (CVE-2026-72898) is the worked example this skill is built around. Metabase confirmed active exploitation on the day it published the fix, 6 August 2026; CISA added the CVE to KEV on 11 August; a self-hosted instance was accessed on 10 August and 1,079,819 records were downloaded on 27 August. The flaw was an unauthenticated SQL injection in a public-facing endpoint, CVSS 10.0, scope-changed - a BI tool is pre-joined access to every database it is credentialed to reach. Nothing in that timeline was secret. A daily KEV check filtered to the stack would have surfaced the CVE on 11 August with sixteen days still on the clock, provided the instance was in the asset inventory. It was not. That is the failure mode this skill is designed to close: KEV exposure monitoring is only as good as the inventory it runs against.

## Log sources required

- **CISA KEV JSON feed** (public): `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. This is the one feed kev-watch reads. It does not scan, probe, or touch any target - it is a watchlist, not a scanner.
- **External asset inventory / CMDB**: the authoritative list of internet-facing hostnames, IP ranges, products, and versions. Without it, KEV matching is guesswork; an exposure that is not in the inventory is invisible to every check below.
- **Edge telemetry**: webserver access logs (W3C / NCSA), WAF logs, reverse-proxy and load-balancer logs, and CDN logs. These catch the scanning that precedes exploitation and the exploitation itself. Prefer a source that captures the request body as well as the request line, because body-borne payloads do not appear in plain webserver logs.

Fields you will lean on:

| Field | Source | Why it matters |
|---|---|---|
| `cveID` | KEV feed | The identifier to match against your stack and track to a patch. |
| `vendorProject` / `product` | KEV feed | What kev-watch filters on with `--watch` to narrow the catalog to what you run. |
| `dateAdded` | KEV feed | When CISA listed it; the start of your clock. kev-watch surfaces entries new since the last run. |
| `dueDate` | KEV feed | CISA's federal remediation deadline; drives `--due-soon` triage. |
| `knownRansomwareCampaignUse` | KEV feed | CISA flag for ransomware use; promote these to the top of the queue. |
| `cs-uri-stem` | Webserver / WAF | The requested path - the exposed endpoint being probed or exploited. |
| `cs-uri-query` | Webserver / WAF | The query string, where request-line injection markers show up. |
| `c-ip` | Webserver / WAF | Source address, for ranking a single scanning or exploiting origin. |
| `sc-status` | Webserver / WAF | Response code; bursts of 404s to CVE-specific paths signal enumeration. |

## Detection

Two layered artifacts, the exposure check first and the exploitation detection second. The Sigma rule is a canonical copy from the UMBRASEC [sigma-pack](https://umbrasec.dev/tools/sigma-pack/); the writeup explains it in full.

### 1. Daily KEV exposure check (the kev-watch tool)

This is the core of external-surface monitoring: turn the KEV feed into a per-stack exposure list every morning. kev-watch remembers what it has already seen in a local state file, so after a quiet baseline run it surfaces only genuinely new entries. Filter to the vendors and products in your asset inventory so the output is signal, not the whole catalog.

```bash
# One-time baseline: record what is already in the catalog (prints a notice and exits).
python3 kev_watch.py

# Daily cron: alert on KEV entries new since the last run, scoped to your stack.
# Weekday mornings, mail anything touching the products you expose.
0 8 * * 1-5  /usr/bin/python3 /opt/kev-watch/kev_watch.py \
    --watch fortinet ivanti citrix metabase "microsoft windows" \
    | mail -s "New KEV entries affecting our stack" soc@example.com

# Deadline triage: KEV items whose CISA remediation due date is within 14 days.
python3 kev_watch.py --due-soon 14

# Backfill after onboarding a new asset, without advancing the baseline.
python3 kev_watch.py --since 2026-08-01 --watch metabase

# Machine-readable, to join against your CMDB or feed a ticket queue.
python3 kev_watch.py --json --watch metabase > kev_metabase.json
```

Each reported CVE shows the vendor/product, the vulnerability name, the date CISA added it, the federal remediation due date, the required action, and the NVD link; entries CISA flags as used in ransomware campaigns are highlighted. `--since` and `--due-soon` are independent queries and never advance the seen-state, so they will not hide a future "new" result. State is written next to the script by default; override with the `KEV_WATCH_STATE` environment variable.

### 2. Exploitation of an exposed KEV item in edge logs (worked example)

When kev-watch flags a CVE for a service you expose and you cannot patch in the hour, watch the endpoint. This canonical rule is the Metabase KEV case from the writeup: a request to the unauthenticated password-reset endpoint carrying SQL metacharacters. It is the concrete shape of "KEV exposure, exploited" in webserver-category logs, and the pattern generalizes - swap the endpoint and markers for whichever KEV item you are exposed to.


```yaml
# metabase-reset-password-sqli.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: Metabase Password Reset SQL Injection Attempt
id: fbeecaf9-c9de-4071-b9c6-3576b195e679
status: experimental
description: >
    A request to Metabase's unauthenticated password-reset endpoint carrying
    SQL metacharacters. CVE-2026-72898 is an unauthenticated SQL injection in
    /api/session/reset_password that yields administrator access to the
    Metabase instance, and through it every database connection that instance
    holds. Metabase confirmed active exploitation on the day of disclosure,
    6 August 2026, and CISA added the CVE to the KEV catalog on 11 August.
    The vendor's own interim workaround is to block this endpoint outright, so
    on a patched and hardened instance any match here is worth review.
    Limitation: this matches metacharacters in the request line only. An
    exploit that carries its payload in the POST body is invisible to
    webserver-category logs, so pair this with body-capturing proxy or WAF
    logs and with the volume hunt in the writeup.
references:
    - https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf
    - https://www.cve.org/CVERecord?id=CVE-2026-72898
    - https://attack.mitre.org/techniques/T1190/
    - https://umbrasec.dev/research/mathspace-metabase-internal-tooling.html
author: UMBRASEC
date: 2026-09-17
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    endpoint:
        cs-uri-stem|contains: '/api/session/reset_password'
    sqli_markers:
        cs-uri-query|contains:
            - ''''
            - ' or '
            - ' and '
            - 'union'
            - 'select'
            - 'sleep('
            - 'pg_sleep'
            - '--'
            - '/*'
            - ';'
    condition: endpoint and sqli_markers
falsepositives:
    - Vulnerability scanners probing the path after public disclosure
    - Authorised security testing against the patched endpoint
    - A password-reset token that legitimately contains a matched character,
      which is why the markers are matched in the query string rather than
      across the whole request
level: high
```

## Tuning and false positives

- **kev-watch (exposure check).** The first run is quiet by design: it records a baseline and exits, so do not treat an empty first run as "nothing exposed". Keep the `--watch` list in sync with your asset inventory - a product you stop running but leave in the filter is harmless noise; a product you add and forget to list is a blind spot. Vulnerability scanners and researchers will begin probing a KEV path within hours of listing, so expect rule 2 to light up shortly after kev-watch flags the same CVE.
- **Rule 2 (edge exploitation).** It matches SQL metacharacters in the request line only. Authorised security testing and post-disclosure scanners probing the path are the expected benign hits; investigate them anyway, because a real exploit looks identical at this layer. A password-reset token can legitimately contain a matched character, which is why the markers are matched in the query string rather than across the whole request. An exploit that carries its payload in the POST body is invisible to webserver-category logs - pair this rule with body-capturing proxy or WAF logs and with the outbound-volume hunt in the writeup.

## Threat hunt

The alert path assumes the exposed asset is in your inventory. The dangerous case is the asset you forgot you had. Hunt for it:

1. **Rediscover the surface.** Do not trust the CMDB alone. Enumerate your own external footprint from certificate-transparency logs, your authoritative DNS, and the `Host` headers your edge logs actually received over the last 90 days. Anything answering that is not in the inventory - a forgotten staging box, shadow IT, an acquired subsidiary's host - is the gap. The asset you do not know about is the one no KEV check covers.
2. **Match each live product and version to KEV.** For every internet-facing service found, run a lookback such as `kev_watch.py --json --since 2021-11-01 --watch <product>` (which does not advance the seen-state) and query NVD for its CVEs. Rank by `knownRansomwareCampaignUse` first, then by `dueDate`, then by exposure (unauthenticated and pre-auth endpoints outrank authenticated ones).
3. **Hunt the scanning that precedes exploitation.** Across your whole external IP range, not just known hosts, look in edge logs for bursts of `sc-status` 404 to CVE-specific or admin paths (for example the Metabase `/api/session/reset_password` path, login panels, or version-fingerprinting URIs) from a single `c-ip` in a short window. That pattern is reconnaissance (T1595); it often arrives days before the exploit attempt and points at which exposed asset an adversary has already noticed.

## Mitigation

Detection buys time; these controls shrink the surface and close the advisory-to-asset gap. Mappings follow the control codes used in the UMBRASEC [security foundations guide](https://umbrasec.dev/guide/foundation.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); D3FEND countermeasures are added where one maps. A cell is left `-` where nothing maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 | MITRE D3FEND |
|---|---|---|---|---|---|
| Maintain an external asset inventory | Enumerate everything internet-facing so a KEV advisory can be matched to an asset you own - the control that failed in the Metabase case | Assumed prerequisite (know what you own) | A.5.9 Inventory of assets | ID.AM Asset Management | D3-AI Asset Inventory; D3-NNI Network Node Inventory |
| Cross-reference the stack against CISA KEV daily (kev-watch) | Turn the KEV feed into a per-asset exposure list and patch flagged internet-facing services inside the Essential Eight 48-hour window | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security | D3-AVE Asset Vulnerability Enumeration |
| Monitor edge, web, and WAF logs continuously | Catch scanning and exploitation of an exposed service even before the patch lands | - (beyond E8; a detection gap) | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM Continuous monitoring; DE.AE Adverse events | D3-NTA Network Traffic Analysis |
| Reduce external exposure and apply vendor interim blocks | Retire unused internet-facing endpoints and apply the vendor's interim endpoint block when no patch exists yet | - | - | PR.PS Platform Security | - |

## Honest limitations

KEV is a floor, not a ceiling: it lists only confirmed in-the-wild exploitation, so a brand-new or narrowly targeted zero-day will not be in it, and the exposure check cannot warn you about what CISA has not yet recorded. kev-watch is a watchlist, not a scanner - it never touches a target and cannot confirm you are actually running the flagged version; it only tells you a CVE is worth checking against your inventory. That inventory is the weak link in the whole chain: an unknown exposure is invisible to every control here, which is why the hunt leads with rediscovery. Edge-log detection sees only what crosses logged infrastructure - a service exposed outside your logging, or a body-borne payload against webserver-only logs, slips past rule 2. Lay the layers together, baseline kev-watch and the Sigma rule before you rely on either, and treat the asset inventory as the detection it really is.

## ATT&CK and references

- MITRE ATT&CK: [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (incl. [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)), [T1596.005 Scan Databases](https://attack.mitre.org/techniques/T1596/005/), [T1592 Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/) (Reconnaissance, TA0043); [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access).
- MITRE D3FEND: D3-AI Asset Inventory, D3-NNI Network Node Inventory, D3-AVE Asset Vulnerability Enumeration, D3-NTA Network Traffic Analysis.
- UMBRASEC tool: [kev-watch](https://umbrasec.dev/tools/kev-watch/) - zero-dependency CISA KEV monitor.
- UMBRASEC writeup: [Sixteen Days From KEV to Exfiltration: What the Mathspace Breach Says About Internal Tooling](https://umbrasec.dev/research/mathspace-metabase-internal-tooling.html) (2026-09-17).
- UMBRASEC [sigma-pack](https://umbrasec.dev/tools/sigma-pack/); canonical rule `metabase-reset-password-sqli.yml`.
- CISA [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Metabase advisory GHSA-vwf4-m7j8-wcjf; [CVE-2026-72898](https://www.cve.org/CVERecord?id=CVE-2026-72898).

**Scope note.** This is a defensive skill. It explains external reconnaissance and KEV exposure only to the depth needed to monitor, detect, and mitigate them, and deliberately ships no scanning, enumeration, or exploitation tooling. UMBRASEC publishes defense, not offense.
