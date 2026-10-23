---
name: detect-c2-beaconing
description: "Detection and hunt methodology for command-and-control beaconing, where an implant calls home on a regular interval over HTTP(S), DNS, or a tunnel service, hidden inside normal egress (MITRE ATT&CK T1071 Application Layer Protocol, T1071.004 DNS, T1573 Encrypted Channel, T1571 Non-Standard Port, T1572 Protocol Tunneling, T1090 Proxy; tactic TA0011 Command and Control). Works from Zeek conn.log/ssl.log/dns.log, Suricata EVE JSON, firewall and web-proxy logs, NetFlow/IPFIX, and endpoint Sysmon Event ID 3/22. It gives the defender's view of beacon periodicity and jitter, JA3/JA3S and JA4 TLS fingerprinting, and tunnel-service detection, plus hunt steps and hardening. Use when hunting for regular callbacks, triaging a long-lived outbound connection, analyzing JA3/JA4 hashes, investigating suspected Cobalt Strike, Sliver, or Mythic C2, chasing DNS or HTTPS tunneling, or baselining egress for periodic traffic."
---

# Command-and-Control Beaconing - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Beaconing is an implant phoning home on a schedule. The three signals that survive encryption are **timing** (connections repeat on a near-fixed interval even when the operator adds jitter), **TLS fingerprint** (the client hello is often identical across every call-out, giving a stable JA3/JA4 hash that may match a known tooling fingerprint), and **destination shape** (a single internal host holding a long-lived or endlessly repeating session to one external endpoint, often a tunnel provider or a freshly registered domain). You do not need to decrypt payloads. Score internal-to-external pairs on connection-interval regularity and consistent data size, fingerprint the TLS handshake, and flag egress to tunnel services and high-entropy DNS. None of these is decisive alone; stack them.

## What it looks like, defender view

In flow and proxy telemetry a beacon shows up as the same source reaching the same destination over and over, at intervals that cluster tightly around a base period (for example roughly every 60 seconds) even when jitter spreads each individual connection by plus or minus a percentage. Request and response sizes are often small and repetitive (a check-in with no tasking), punctuated by a larger burst when a task or download runs. Over TLS the payload is opaque, but the client hello is not: many implants reuse one TLS stack, so every call-out produces the same **JA3** client fingerprint and the server answers with a repeated **JA3S**, and default tool profiles frequently carry self-signed or default certificates and odd or absent HTTP `Host`/`User-Agent` values. DNS-based C2 presents as a flood of queries for long, high-entropy subdomain labels under one parent domain, heavy on `TXT`/`NULL`/`CNAME` record types, or as `A`/`AAAA` records encoding data. Tunnel-service C2 presents as egress to ngrok, Cloudflare Tunnel, or DNS-over-HTTPS resolvers that the host has no business using.

## Log sources and signals

- **Zeek `conn.log`** - the backbone for timing analysis. Key fields: `id.orig_h`, `id.resp_h`, `id.resp_p`, `ts`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `proto`. Group by orig/resp pair and study the sequence of `ts` deltas (interval regularity) and the distribution of `orig_bytes` (payload-size consistency). A long `duration` or an endless run of short identical sessions to one external host is the anomaly.
- **Zeek `ssl.log`** (with the JA3 Zeek package) and **Suricata EVE JSON** `tls` events - carry `ja3`, `ja3s`, `server_name` (SNI), `version`, `validation_status`, and issuer/subject. A JA3 that repeats on every beacon, or that matches a published tooling fingerprint, is the signal. Newer collectors also emit **JA4** (the FoxIO successor that is more robust to TLS field reordering) and JA4S server fingerprints; **JARM** is a separate active server fingerprint that you get by scanning the destination, not from passive sensor logs.
- **Zeek `x509.log`** - self-signed certs, default issuer strings, very short validity windows, and SNI/certificate mismatches, all common in default C2 profiles.
- **Zeek `dns.log`** and endpoint DNS logs - query name length and entropy, record type mix (spikes in `TXT`/`NULL`), query volume per parent domain, and `NXDOMAIN` rate for DNS-tunnel and domain-generation behavior.
- **Firewall / web-proxy / NetFlow / IPFIX** - bytes sent and received, destination IP/ASN/category, allow/deny, and session counts per source/destination when you have no packet broker. Flow alone is enough to score periodicity.
- **Endpoint (Windows)** - **Sysmon Event ID 3** (network connection: `Image`, `DestinationIp`, `DestinationPort`, `DestinationHostname`) ties a beacon back to the process; **Sysmon Event ID 22** (DNS query) and the **Microsoft-Windows-DNS-Client/Operational** log (Event ID 3008) give per-process DNS. A signed-but-unexpected process (for example `rundll32.exe` or a LOLBIN) making regular outbound connections is a strong pivot.
- **What normal looks like** - software-update agents, telemetry, CRL/OCSP checks, and SaaS sync also poll on fixed intervals. The baseline is that benign periodic traffic goes to well-known, categorized, high-reputation destinations with sane certificates; beacons tend to go to uncategorized, newly registered, or tunnel-provider destinations.

## Detection approach

Alert on the combination, not one field. The core logic:

- **Periodicity and jitter scoring.** For each internal/external pair over a rolling window, order the connection timestamps, take the deltas, and measure how tightly they cluster. Low dispersion (a small coefficient of variation, or a sharp peak in a delta histogram or FFT) indicates an automated interval. Operator jitter widens the spread but rarely destroys the central tendency, so a jittered beacon still scores far more regular than human browsing. Combine the timing score with **data-size consistency** (repeated near-identical `orig_bytes`) and **connection count** to cut false positives. This is exactly the model implemented by the open-source **RITA / AC-Hunter** project (github.com/activecm/rita), which is the recommended tool for this analysis rather than a hand-rolled rule.
- **TLS fingerprinting.** Compute JA3/JA3S (or JA4/JA4S) at the sensor and match against a maintained blocklist of tooling fingerprints, then alert on any single JA3 that appears on a stable periodic channel. Treat fingerprint matches as a lead, not proof, because JA3 collides across apps sharing a TLS library and some implants now randomize the client hello.
- **Destination and certificate reputation.** Flag egress to tunnel-service domains and ASNs (ngrok, Cloudflare Tunnel/`argotunnel`, localtunnel), to non-sanctioned DNS-over-HTTPS resolvers, and to newly registered or uncategorized domains, and flag self-signed or default certificates on long-lived sessions.
- **DNS tunnel heuristics.** Alert on sustained high query volume to one parent domain with long, high-entropy labels and a `TXT`/`NULL`-heavy record mix.

Point to public, maintained rules rather than inventing one. Useful sources: the **SigmaHQ** rule directories (github.com/SigmaHQ/sigma) - `rules/network/dns` for DNS-tunnel heuristics such as high `TXT`/`NULL` rates and large query names, `rules/network/zeek` for Zeek-based C2 and certificate rules, `rules/windows/network_connection` and `rules/windows/dns_query` for the Sysmon Event ID 3 and 22 pivots, and `rules/web` for proxy rules; **Suricata / Emerging Threats** open ruleset, which ships JA3-hash and C2 signatures (rules.emergingthreats.net); the **abuse.ch SSLBL JA3 fingerprint** feed (sslbl.abuse.ch/ja3-fingerprints/); and MITRE **D3FEND** for the countermeasure model. A tuned UMBRASEC rule is not yet shipped for this threat.

## Threat hunt

Hypothesis: an implant is beaconing out of the environment hidden inside normal-looking egress.

1. Pull a long window (7 to 30 days) of `conn.log` or NetFlow and reduce to internal-to-external pairs only. Exclude known update/telemetry/CDN destinations by reputation and category.
2. For each pair, compute connection count, the interval-regularity score (dispersion of `ts` deltas), and the data-size-consistency score. Rank by the combined score. Run RITA over the same data to cross-check; it scores beacons natively.
3. For the top pairs, pull `ssl.log`/`tls` events and group by JA3/JA4. A single fingerprint carrying the whole periodic channel, a known-tooling match, or a self-signed/default cert raises confidence. Check SNI against certificate subject and against the destination's reputation and registration age.
4. For DNS, aggregate queries by parent domain and flag parents with high label entropy, long labels, high query volume, or a `TXT`/`NULL`-heavy mix.
5. Pivot to the endpoint: use Sysmon Event ID 3/22 and the DNS-Client Operational log to identify the exact process and parent making the call-outs, and confirm whether it is a LOLBIN or an unexpected binary.
6. Decide and document. A tight interval plus a tooling JA3 plus an uncategorized destination is high confidence; one weak signal alone is a lead to keep watching, not a verdict.

## Hardening

Shrink where a beacon can hide and make its channel expensive. The highest-value controls are: force all egress through an authenticated web proxy and **default-deny** direct outbound (so an implant cannot reach an arbitrary IP), block or sinkhole known tunnel-service and unsanctioned DoH endpoints, pin DNS to internal resolvers and log every query, and inspect TLS at the egress boundary where policy and privacy allow so SNI and certificates are visible. None of that works without the telemetry turned on first, so the table below maps the visibility and detection controls that underpin all of the above to the frameworks the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html) uses; the tunnel-blocking and proxy controls above sit in prose because no single framework code maps to them cleanly.

| Control | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| Collect network, proxy, and DNS logs centrally (the prerequisite for every signal here) | ML2/ML3 event-log collection and monitoring | A.8.15 Logging | DE.CM Continuous monitoring |
| EDR on endpoints to tie a beacon to its process | - (beyond E8 - detection gap) | A.8.7 Malware; A.8.16 Monitoring | DE.CM; DE.AE Adverse events |
| High-signal beacon/tunnel alerting and triage | - (beyond E8 - detection gap) | A.8.16 Monitoring activities | DE.AE; DE.CM |

## Honest limitations

A patient operator who sets a long base interval with heavy jitter (for example a check-in measured in hours) produces too few data points in any practical window for timing analysis to be confident, and may be indistinguishable from benign polling. JA3/JA4 is a lead, not an identity: it collides across applications that share a TLS library, and modern implants can randomize the client hello or clone a common browser fingerprint to defeat it. Full-TLS or domain-fronted and legitimate-CDN-hosted C2 hides destination reputation behind a trusted front. If you have no TLS visibility you are limited to timing, size, and destination. And every periodic-traffic rule will surface real update and telemetry agents, so baseline and allowlist before you enforce. Stack the signals, pivot to the endpoint to confirm, and leave the verdict to the analyst.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) and [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/); [T1573 Encrypted Channel](https://attack.mitre.org/techniques/T1573/); [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/); [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/); [T1090 Proxy](https://attack.mitre.org/techniques/T1090/). Tactic TA0011 Command and Control.
- MITRE D3FEND: Network Traffic Analysis (D3-NTA), Network Traffic Community Deviation (D3-NTCD), Per Host Download-Upload Ratio Analysis (D3-PHDURA), DNS Traffic Analysis (D3-DNSTA), and Outbound Traffic Filtering (D3-OTF) for the hardening side.
- Public rule sources: SigmaHQ network and web rules (github.com/SigmaHQ/sigma), Suricata/Emerging Threats open ruleset (rules.emergingthreats.net), abuse.ch SSLBL JA3 fingerprints (sslbl.abuse.ch/ja3-fingerprints/), and RITA (github.com/activecm/rita).

**Scope note.** This is a defensive skill. It explains beaconing only to the depth needed to detect and mitigate it, ships no C2 framework, profile, or evasion tooling, and leaves the verdict to the defender.
