---
name: detect-metabase-sqli
description: "Detection and response for unauthenticated SQL injection in self-hosted Metabase (CVE-2026-72898, CWE-89, CVSS 10.0) via the /api/session/reset_password endpoint, which returns administrator access to the instance and every database Metabase can query. Maps to MITRE ATT&CK T1190, T1213.006, and T1567. Ships two Sigma rules for webserver logs (SQL metacharacters against the reset endpoint, and a per-source request burst that also counts POST-body payloads) and a KQL egress baseline on firewall logs that flags a day of outbound bytes from the Metabase host at a multiple of its own median, with tuning, false-positive notes, and Essential Eight / ISO 27001:2022 / NIST CSF 2.0 mitigations. Use when investigating a Metabase compromise or suspicious traffic to /api/session/reset_password, triaging CVE-2026-72898 or GHSA-vwf4-m7j8-wcjf, writing detections for unauthenticated SQLi against BI tooling, hunting bulk exfiltration from a BI host, or hardening internal tools holding standing database credentials."
---

# Metabase Unauthenticated SQL Injection - Detection and Response

CVE-2026-72898 is an unauthenticated SQL injection in self-hosted Metabase's `/api/session/reset_password` endpoint. It needs no credentials and no user to trick, and it returns administrator access to the instance, and through it every database Metabase is connected to. A business intelligence tool is pre-joined access to everything you have: it holds standing credentials to the databases that matter, so compromising it removes the need to move laterally, escalate, or find the data. This skill is defensive: it explains the flaw only as far as detection and mitigation require, uses no exploit string (none is public), and ships no offensive tooling.

## TL;DR for defenders

Confirm whether you run Metabase, at what build, and whether it is reachable from the internet. Get to a fixed build (**58.24, 59.21, 60.17, 61.11, 62.9 or 63.5**) and block `/api/session/reset_password` at the proxy until you have. The vendor's own interim workaround is to block that endpoint outright, which makes it a clean detection anchor: on a patched and hardened instance, any SQL metacharacters in traffic to that path are already anomalous. The first Sigma rule below is the high-precision tripwire for that. The second counts requests to the endpoint per source and reads no payload, because the first reads the request line only and a competent exploit carries its payload in the POST body. The KQL query watches the egress side, where the data actually left. If you ran an affected build while exposed, follow the vendor's guidance: revoke sessions, audit API keys and administrator accounts, rotate every database credential the instance held, and read the access logs.

## Why it matters

The whole value of a BI tool is that it answers questions across all of your data at once, so it holds live credentials to production datastores in a form built for convenient querying rather than least privilege. Compromise it and the tool has already found the data for you. The public record on CVE-2026-72898 is a timeline, not a clever exploit: Metabase published advisory GHSA-vwf4-m7j8-wcjf and patched builds on 6 August 2026 stating it had confirmed active exploitation; the CVE was published and CISA added it to the Known Exploited Vulnerabilities catalog on 11 August; and on 27 August, sixteen days after the KEV listing, 1,079,819 records were downloaded from one Australian platform's self-hosted instance. Every date was public before the data moved. Six release branches were affected (`>=58.0 <58.24`, `>=59.0 <59.21`, `>=60.0 <60.17`, `>=61.0 <61.11`, `>=62.0 <62.9`, `>=63.0 <63.5`), so an inventory that records only "Metabase is installed" without the build number cannot answer the question.

## Log sources required

This is a web-layer detection. It keys off the request to the reset endpoint, not off anything inside Metabase.

- **Webserver-category access logs** from the reverse proxy or web server in front of Metabase (for example nginx). The markers rule reads two fields from the request line: `cs-uri-stem` (the path) and `cs-uri-query` (the query string). The burst rule reads `cs-uri-stem` and the client address `c-ip`; if a proxy logs its own address there, log the forwarded client address instead. Ship these for the Metabase host.
- **Body-capturing WAF or proxy logs**, where available. Webserver access logs record the request line only. An exploit that carries its payload in the POST body does not appear in them, and you should assume a competent one does. If you have a WAF or proxy that captures request bodies, that is where the authoritative version of this detection lives.
- **Outbound byte volume** for the Metabase host, from netflow, firewall, or proxy egress logs. A BI host normally takes substantial inbound queries and returns modest responses to internal clients; bulk extraction inverts that profile, and outbound volume is the signal that mattered on 27 August. The KQL query reads firewall logs in Microsoft Sentinel's `CommonSecurityLog` (`SourceIP`, `DestinationIP`, `SentBytes`, `ReceivedBytes`); list the host's addresses, and its reverse proxy's, as the firewall logs them.
- Metabase's own application logs are **not** what this rule reads, and neither the advisory nor the rule names a Metabase audit setting to enable. If you adopt the vendor's workaround and block the endpoint at the proxy, attempts show up in the proxy log, not the application server.

## Detection

Two Sigma rules and a KQL query, inlined verbatim below. Convert the Sigma rules with [sigma-cli](https://github.com/SigmaHQ/sigma-cli).

**1. SQL metacharacters against the reset endpoint.** The request-line tripwire.

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
    The markers are matched both literally and percent-encoded, because many
    access logs keep the query string encoded.
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
modified: 2026-10-23
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
            - '/\*'
            - ';'
            - '%27'
            - '%20or%20'
            - '+or+'
            - '%20and%20'
            - '+and+'
            - 'sleep%28'
            - '%2d%2d'
            - '%2f%2a'
            - '%2f\*'
            - '/%2a'
            - '%3b'
    condition: endpoint and sqli_markers
falsepositives:
    - Vulnerability scanners probing the path after public disclosure
    - Authorised security testing against the patched endpoint
    - A password-reset token that legitimately contains a matched character,
      which is why the markers are matched in the query string rather than
      across the whole request
level: high
```

Be clear about what this does not do. Webserver-category logs record the request line, so an exploit that carries its payload in the POST body will not match, and you should assume a competent one does. This rule catches scanners, opportunistic spray, and the naive case; it is a tripwire, not a guarantee. The authoritative version belongs on body-capturing WAF or proxy logs.

**2. A burst of requests from one source.** Password reset is a rare, human-paced action; exploiting a blind or error-based injection is not. This correlation rule fires on ten or more requests to the endpoint from one client address in ten minutes, the writeup's own dial. It counts requests and reads no payload, so an exploit carried in the POST body still counts.

```yaml
# metabase-reset-password-burst.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: Metabase Password Reset Request Burst From One Source
id: d3d4483d-c16d-4515-8453-17a65391aa2a
status: experimental
description: >
    Ten or more requests to Metabase's unauthenticated password-reset
    endpoint from one client address within ten minutes. Password reset is a
    rare, human-paced action; exploiting a blind or error-based SQL injection
    such as CVE-2026-72898 is not. The rule counts requests and reads no
    payload, so it also sees an exploit that carries its payload in the POST
    body, which the request-line rule metabase-reset-password-sqli cannot.
    The threshold is the writeup's own figure: ten resets from one address in
    ten minutes is not a forgetful employee.
    Limitation: an exploit that succeeds in fewer than ten requests, one paced
    so that no ten-minute window holds ten, or one spread across many source
    addresses stays under the threshold.
references:
    - https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf
    - https://www.cve.org/CVERecord?id=CVE-2026-72898
    - https://attack.mitre.org/techniques/T1190/
    - https://umbrasec.dev/research/mathspace-metabase-internal-tooling.html
author: UMBRASEC
date: 2026-10-26
tags:
    - attack.initial-access
    - attack.t1190
correlation:
    type: event_count
    rules:
        - metabase_reset_password_request
    group-by:
        - c-ip
    timespan: 10m
    condition:
        gte: 10
falsepositives:
    - Vulnerability scanners and authorised testing that hit the endpoint repeatedly
    - A reverse proxy or load balancer that logs its own address as c-ip, so every
      user's resets share one address - log the forwarded client address instead
    - Many users behind one NAT or office egress address resetting at the same
      time, for example after a forced password change
level: medium
---
title: Metabase reset_password request
id: a2fd64ff-e92f-4b01-8dff-a77c3c550040
name: metabase_reset_password_request
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/api/session/reset_password'
    condition: selection
```

**3. Egress inversion on the Metabase host.** One day's outbound bytes from the host against the median of the fourteen days before it, alerting on a multiple (default 3) above a 100 MB floor. Run it daily over the day that just closed, or set `TestDay` to hunt a past day.

```kql
// metabase-egress-inversion.kql (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
// UMBRASEC sigma-pack - Metabase bulk extraction: egress inversion on a BI host (T1567)
// A day's outbound bytes from one host measured against that host's own daily median
// Source writeup: https://umbrasec.dev/research/mathspace-metabase-internal-tooling.html
// A BI host takes large query results in from its databases and sends modest
// responses to internal clients. Bulk extraction inverts that: outbound volume jumps.
// The writeup's advice is to alert on a multiple of the host's daily norm rather than
// an absolute threshold, and that is all this query does. Run it once a day over the
// day that just closed, or set TestDay to hunt a past day.
// Tuning: list the Metabase host's addresses as the firewall logs them, plus any
// reverse proxy or load balancer in front of it, because a download through the proxy
// leaves from the proxy, not the host. Scheduled exports, backups and large legitimate
// reports raise a day; set Multiple and MinEgressBytes from report-only runs. If the
// firewall logs both the start and the end of a session, keep only one of them.
// Limitation: an extraction paced so that no single day reaches the multiple, or split
// across many days (T1030 Data Transfer Size Limits), stays under it, and so does data
// that leaves by a path this firewall does not log. PublicEgress counts IPv4 peers only.
let MetabaseHosts = dynamic(["10.0.20.15"]);  // example address: replace with yours
let TestDay = startofday(ago(1d));            // datetime(2026-08-27) hunts that day
let BaselineSpan = 14d;
let MinBaselineDays = 7;
let Multiple = 3.0;
// A 100 MB floor: a quiet host tripling a small day is not an alert
let MinEgressBytes = 100000000;
// Microsoft documents SentBytes as "bytes transferred outbound" and ReceivedBytes as
// "inbound", without saying outbound from which end of the session, and devices
// differ. With true, SentBytes is read as the bytes the session's source sent. Check
// it once: download a large file from the host and see which column grows.
let SentBytesFromSource = true;
let Daily = CommonSecurityLog
    | where TimeGenerated >= TestDay - BaselineSpan and TimeGenerated < TestDay + 1d
    | where SourceIP in (MetabaseHosts) or DestinationIP in (MetabaseHosts)
    | extend HostIsSource = SourceIP in (MetabaseHosts)
    | extend Host = iff(HostIsSource, SourceIP, DestinationIP),
             Peer = iff(HostIsSource, DestinationIP, SourceIP),
             FromSource = iff(SentBytesFromSource, SentBytes, ReceivedBytes),
             ToSource = iff(SentBytesFromSource, ReceivedBytes, SentBytes)
    | extend EgressBytes = iff(HostIsSource, FromSource, ToSource),
             IngressBytes = iff(HostIsSource, ToSource, FromSource)
    | summarize Egress = sum(EgressBytes), Ingress = sum(IngressBytes),
                PublicEgress = sumif(EgressBytes, not(ipv4_is_private(Peer))),
                Peers = dcount(Peer)
             by Host, Day = startofday(TimeGenerated);
let Baseline = Daily
    | where Day < TestDay
    | summarize BaselineEgress = percentile(Egress, 50),
                BaselineIngress = percentile(Ingress, 50),
                BaselineDays = count()
             by Host;
Daily
| where Day == TestDay
| join kind=inner Baseline on Host
// Too little history to call anything a multiple of the norm
| where BaselineDays >= MinBaselineDays
| extend EgressMultiple = round(todouble(Egress) / max_of(BaselineEgress, 1), 1),
         EgressToIngress = round(todouble(Egress) / max_of(Ingress, 1), 2),
         BaselineEgressToIngress = round(todouble(BaselineEgress)
                                         / max_of(BaselineIngress, 1), 2)
| where Egress >= MinEgressBytes and EgressMultiple >= Multiple
| project Day, Host, Egress, BaselineEgress, EgressMultiple, PublicEgress,
          EgressToIngress, BaselineEgressToIngress, Ingress, Peers, BaselineDays
```

## Tuning and false positives

Baseline first in report-only mode and treat the marker list as a dial, not gospel. The benign hits to expect, taken from the rule's own `falsepositives`:

- **Vulnerability scanners** probing the path after public disclosure. Allowlist their source addresses rather than widening the rule.
- **Authorised security testing** against the patched endpoint.
- **A password-reset token that legitimately contains a matched character.** This is why the markers are matched in the query string (`cs-uri-query`) rather than across the whole request.
- **Burst rule: a proxy or a shared address.** A reverse proxy or load balancer that logs its own address as `c-ip` makes every user's reset look like one source; log the forwarded client address first. Many users behind one NAT or office address, for example after a forced password change, can also cross ten; allowlist or raise `gte` for those addresses rather than lengthening the window.
- **Egress query: direction and normal busy days.** Microsoft documents `SentBytes` and `ReceivedBytes` only as outbound and inbound, not from which end of a session, and devices differ: download a large file from the host once and check which column grows, then set `SentBytesFromSource`. Scheduled exports, backups and large legitimate reports raise a day; tune `Multiple` and `MinEgressBytes` in report-only runs. If the firewall logs both the start and the end of a session, keep only one.
- **Noisiest markers.** `;` and `--` trip most often on benign query strings; if the rule is loud, drop those two first, together with their encoded forms `%3b` and `%2d%2d`, and keep the SQL-keyword and timing markers (`union`, `select`, `sleep(`, `sleep%28`, `pg_sleep`). If you have body-capturing logs, relocate the rule there and widen the markers, because that is where a real payload lands.

## Threat hunt

For the body-borne exploit the rule misses, and for the post-exploitation stages, hunt rather than wait for an alert:

1. **Slower request rates to the reset endpoint.** The burst rule alerts at the writeup's dial of ten in ten minutes. For sources paced under it, group requests to `/api/session/reset_password` by source address per hour and per day, and look for any source responsible for more requests than your users plausibly generate in a day.
2. **Outbound volume over a longer span.** The egress query compares one day with the fourteen before it. To find an extraction split across many days, chart the host's daily outbound bytes over a month or more and look for a sustained rise rather than one spike.
3. **Post-exposure state (T1213.006, T1567).** If you ran an affected build while exposed, assume admin access was obtained and check for it: unexpected administrator accounts, unrecognised API keys, and unexpected active sessions. This is the vendor's guidance, not ours, and it is where the "assume admin" posture belongs.

## Mitigation

Detection buys time; these changes shrink the attack surface. Control codes below reuse the mappings in the UMBRASEC [foundation](https://umbrasec.dev/guide/foundation.html) and [detection and response](https://umbrasec.dev/guide/detection-and-response.html) guides; a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Patch to a fixed build; block the reset endpoint until patched | Removes the vulnerable code path; the proxy block closes it in the interim | Patch applications | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security |
| Inventory self-hosted internal tooling, with build number and exposure | Starts the patch clock; six affected branches mean "installed" is not an answer | Assumed prerequisite | A.5.9 Inventory of assets | ID.AM Asset Management |
| Put KEV on an automatic trigger against that inventory | Turns a public catalogue into a dated alert with a named owner | - | A.8.8 Technical vulnerabilities | ID.RA |
| When rotating credentials, re-issue least-privilege database accounts | After the required rotation, scope the BI tool's accounts to the minimum each report needs | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Web/proxy logging and outbound-volume baselining on the host | Makes the rules, the egress query and the hunts possible at all | ML2/ML3 event-log requirements | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM Continuous monitoring |

## Honest limitations

- **Request line only.** The markers rule reads `cs-uri-stem` and `cs-uri-query`. A payload in the POST body is invisible to webserver-category logs, and you should assume a competent exploit uses the body. Pair the rule with body-capturing logs and the burst rule.
- **The burst rule needs volume.** An exploit that succeeds in fewer than ten requests, one paced so that no ten-minute window holds ten, or one spread across many source addresses stays under the threshold.
- **The egress query needs a norm and a jump.** It needs seven days of history, it cannot see an extraction split across days so that no single day reaches the multiple ([T1030](https://attack.mitre.org/techniques/T1030/) Data Transfer Size Limits), and it cannot see data that leaves by a path the firewall does not log. Its byte direction depends on your firewall; check it before you trust the numbers.
- **The rules are `experimental`** and have not been validated against a real exploitation attempt. No exploit string is public and none is reconstructed here; treat them as a starting point and tune them against your own logs before alerting.
- **No intrusion visibility beyond the public record.** The sequence between the 10 August intrusion and the 27 August download is not public; the hunts are derived from the endpoint the vendor published and from the host's expected traffic shape, not from a disclosed attack chain.
- **Inventory is the real precondition.** With six affected branches, a detection that fires does you no good if nothing told you that you run Metabase on the internet in the first place.

## ATT&CK and references

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (the injection against the reset endpoint); [T1213.006 Data from Information Repositories: Databases](https://attack.mitre.org/techniques/T1213/006/) (reading the reporting database once admin is held); [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) (the bulk download).
- UMBRASEC writeup: [Sixteen Days From KEV to Exfiltration](https://umbrasec.dev/research/mathspace-metabase-internal-tooling.html) (2026-09-17).
- Metabase advisory: [GHSA-vwf4-m7j8-wcjf](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf), SQL injection using an unauthenticated endpoint leading to admin access.
- [MITRE CVE-2026-72898](https://www.cve.org/CVERecord?id=CVE-2026-72898); [NVD CVE-2026-72898](https://nvd.nist.gov/vuln/detail/CVE-2026-72898); [MITRE CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CVE added 11 August 2026).
- [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) and [v4.0](https://www.first.org/cvss/v4.0/specification-document) specifications (both score 10.0).
- [ASD's ACSC Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight).

**Scope note.** This is a defensive skill. It explains CVE-2026-72898 only to the depth needed to detect and mitigate it, contains no exploit code or proof of concept, and reconstructs no injection string. UMBRASEC publishes defense, not offense.
