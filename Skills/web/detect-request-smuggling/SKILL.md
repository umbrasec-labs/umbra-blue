---
name: detect-request-smuggling
description: "Detection and response for HTTP request smuggling (HTTP desync) against front-end/back-end chains: CL.TE, TE.CL, TE.TE and HTTP/2 downgrade variants H2.CL / H2.TE, where a proxy and origin disagree on request boundaries so an attacker prepends bytes to a victim's request (cache poisoning, request hijacking, control bypass). Maps to MITRE ATT&CK T1190; the flaw is CWE-444. Works off reverse-proxy and load-balancer access logs (nginx, Apache, HAProxy, AWS ALB, Cloudflare, Akamai, F5), origin web-server logs, and WAF logs, keyed on Content-Length and Transfer-Encoding headers and front-end to back-end mismatches. Gives desync detection, front-end hardening, and public rule sources. Use when investigating suspected request smuggling or desync, triaging dual Content-Length and Transfer-Encoding requests, hunting CL.TE or TE.CL signatures, explaining cache poisoning or cross-user responses, or hardening a proxy chain."
---

# HTTP Request Smuggling (Desync) - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

Request smuggling exists because a front-end proxy and the back-end origin disagree about the length of an HTTP/1.1 message. When a request carries both a `Content-Length` and a `Transfer-Encoding: chunked` header, RFC 9112 says `Transfer-Encoding` wins and the combination "ought to be handled as an error"; a smuggle happens when the two hops resolve that conflict differently (CL.TE and TE.CL), or when one hop is fooled by an obfuscated `Transfer-Encoding` value the other ignores (TE.TE). The single highest-value signal is any inbound request that reaches the chain carrying both headers, or a malformed `Transfer-Encoding`. The catch: those two headers are not written to any access log by default, so your first job is to log them. Then watch for the back-end seeing a corrupted or orphaned request line that the front-end never recorded, and for AWS ALB classifying requests as `Ambiguous` or `Severe`. Normalize or reject ambiguous requests at the edge; that removes the class, not just the alert.

## What it looks like, defender view

On the wire a smuggle is one TCP/TLS connection, reused between the front-end and the origin, carrying what the front-end counts as one request but the origin splits into two (or the reverse). The prepended bytes the attacker smuggles become a prefix on the *next* request to traverse that upstream connection, which is usually some other user's. So the defender rarely sees a single malicious request; they see a pair of symptoms split across two log tiers.

At the edge the tell is a request that violates framing rules but is still forwarded: both `Content-Length` and `Transfer-Encoding` present, a duplicated `Transfer-Encoding`, or an obfuscated value such as `Transfer-Encoding: chunked` with a leading space or tab, a trailing junk token, or odd casing meant to be parsed by one hop and ignored by the other. At the origin the tell is downstream: a `400` on a request line whose method is not a valid HTTP token or that carries a stuck prefix from the previous body, a spike of `408`/socket read timeouts where the origin waits for chunk bytes the front-end already consumed, cross-user responses (a client receiving another user's reply), and cache entries holding content no legitimate request would have produced. Treat all of these as symptoms to correlate, never as instructions to reproduce.

## Log sources and signals

The primary signal is carried in two request headers that almost no deployment logs by default, so the first step is to make them visible, then correlate the edge against the origin.

- **Reverse-proxy and load-balancer access logs.** Add the framing headers to the log format: nginx `$http_transfer_encoding` and `$http_content_length` in `log_format`; Apache `%{Transfer-Encoding}i` and `%{Content-Length}i` in `LogFormat`; HAProxy `capture request header Transfer-Encoding len 64` surfaced through `%hr`; IIS (8.5+) custom W3C request-header fields. Without these the core signal does not exist in your data.
- **AWS Application Load Balancer access logs.** ALB writes a `classification` field and a `classification_reason`, produced by the open-source http-desync-guardian and governed by `routing.http.desync_mitigation_mode` (`monitor`, `defensive`, `strictest`). RFC-compliant requests log `-` in both fields; non-compliant requests are classified `Acceptable`, `Ambiguous`, or `Severe`. Any row classified `Ambiguous` or `Severe` is a named, vendor-supplied desync signal; alert on it directly, and keep `Acceptable` rows as low-risk context.
- **Origin web-server logs.** Apache, IIS, nginx, Tomcat, Node, Gunicorn. Watch for `400` responses on malformed request lines (invalid method token, embedded CRLF, a path that begins mid-stream) and for `408`/`501` from protocol parse failures. A request logged at the origin with no matching entry at the front-end for the same connection is the smuggled prefix surfacing.
- **WAF logs.** OWASP CRS (ModSecurity/Coraza), AWS WAF, Azure Front Door/WAF, Cloudflare, Akamai. CRS carries the relevant rule hits named in Detection approach below; most WAFs also expose a rule-id and anomaly-score field to key on.
- **Connection and timing telemetry.** Front-end to back-end request-count per upstream connection, upstream response time, and keep-alive reuse counters. A desync shows as a count mismatch (front-end counts N requests on a connection, origin processes N+1) and as timeout bursts tied to specific upstream sockets.

What normal looks like: requests specify length through exactly one mechanism, `Content-Length` values are plain integers, `Transfer-Encoding` is the bare token `chunked` only on bodies that are actually chunked, ALB logs `-` (RFC-compliant) for effectively everything, with only rare `Acceptable` rows, and front-end and origin agree on how many requests crossed each connection. The anomaly is any departure from that, which is the shape MITRE D3FEND calls Protocol Metadata Anomaly Detection.

## Detection approach

No bespoke UMBRASEC rule ships for this threat yet. Build detection from the framing headers at the edge first, the origin request-line anomalies second, and lean on public, maintained rules rather than inventing a signature. The RFC-grounded rationale for the top alert: RFC 9112 section 6.1 says a server MAY reject a request that contains both `Content-Length` and `Transfer-Encoding` (or process it by `Transfer-Encoding` alone) and MUST close the connection after responding to it, and section 6.3 says when both are present `Transfer-Encoding` overrides `Content-Length` and such a message "might indicate an attempt to perform request smuggling (Section 11.2) or response splitting (Section 11.1) and ought to be handled as an error." That is your alert justification, not a heuristic.

- **Dual framing headers (highest precision).** Alert on any request reaching the origin that carries both `Content-Length` and `Transfer-Encoding`, once you have logged both headers per the previous section. A correctly configured edge should strip or reject these, so a hit at the origin means the edge did not normalize.
- **Obfuscated Transfer-Encoding.** Alert on `Transfer-Encoding` values that are not the exact token `chunked`: leading or trailing whitespace, a second `Transfer-Encoding` header, a trailing comma token, unusual casing, or `chunked` combined with another coding. These are the TE.TE discrepancies one hop parses and the other does not.
- **Origin-side framing errors.** Alert on origin `400`/`501` where the request line is not a valid method-SP-target-SP-version, and on bursts of `408` and upstream read timeouts bound to reused keep-alive connections. Correlate against the edge: no matching front-end request for an origin request on the same connection is the smuggled request surfacing.
- **ALB classification.** Where AWS ALB fronts the app, alert on any access-log row whose `classification` is `Ambiguous` or `Severe`, and record the `classification_reason`.
- **Downstream effects.** Hunt for cache entries whose stored response does not match the keyed request, and for user reports of receiving another session's response; both are high-severity confirmations that a smuggle already landed.

Public, maintained rule and reference sources to point detection engineering at:

- OWASP CRS `REQUEST-920-PROTOCOL-ENFORCEMENT.conf`, rule **920181** "Content-Length and Transfer-Encoding headers present" (paranoia level 1), the direct dual-header detector, and rule **920160** "Content-Length HTTP header is not numeric" which rejects malformed length values: <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf>.
- OWASP CRS `REQUEST-921-PROTOCOL-ATTACK.conf`, rule **921110** "HTTP Request Smuggling Attack", plus the response-splitting and header-injection rules (**921120**, **921130**, **921190**) that cover the CRLF-injection cousins: <https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-921-PROTOCOL-ATTACK.conf>.
- SigmaHQ web rules directory: <https://github.com/SigmaHQ/sigma/tree/master/rules/web>. There is no smuggling-specific Sigma rule to rely on; what is there are generic webserver and proxy rules keyed on status codes and request anomalies, which only help once you have added the `Content-Length` and `Transfer-Encoding` fields from the log-sources section.
- MITRE D3FEND Protocol Metadata Anomaly Detection (D3-PMAD): <https://d3fend.mitre.org/technique/d3f:ProtocolMetadataAnomalyDetection>.
- RFC 9112 (HTTP/1.1 message syntax, obsoletes RFC 7230), sections 6.1 and 6.3: <https://www.rfc-editor.org/rfc/rfc9112> and CWE-444: <https://cwe.mitre.org/data/definitions/444.html>.

## Threat hunt

For the attacker who lands a single smuggle and stops, no threshold rule fires. Hunt the framing conflict and the two-tier mismatch instead:

1. Over a long window, pull every inbound request that carried both `Content-Length` and `Transfer-Encoding`, or a `Transfer-Encoding` value other than the bare token `chunked`. If those headers are not in your logs yet, add them first and hunt forward; this is the primary signal and it is invisible without the log change.
2. If you front with AWS ALB, list all access-log rows where `classification` is `Ambiguous` or `Severe` (and, as lower-priority context, `Acceptable`; compliant rows carry `-`), group by `classification_reason` and source, and rank by count.
3. Join the edge and origin logs on the upstream connection identifier and a tight time window. Flag connections where the origin processed more requests than the front-end forwarded, or where an origin request line has no matching client request. That orphaned request is the smuggled prefix.
4. Pull origin `400`/`501` with malformed request lines and `408`/read-timeout bursts, and line them up in time against the edge-side dual-header or ALB-ambiguous events on the same backend pool.
5. Check the cache: list cached responses whose body does not correspond to their cache key, and any surge of identical anomalous responses served to many clients, which is the cache-poisoning footprint of a successful smuggle.

Load balancers doing health checks, legacy clients that genuinely chunk oddly, and security scanners will surface in steps 1 and 2; build the allowlist from that first pass, then alert on what remains. These surface candidates for triage, not verdicts.

## Hardening

The durable fix is at the front-end: remove the ambiguity so the two hops cannot disagree. Prefer HTTP/2 end-to-end, because its binary framing carries an explicit length and eliminates the `Content-Length`/`Transfer-Encoding` conflict entirely; be aware that an HTTP/2 front-end rewriting to an HTTP/1.1 back-end reintroduces the flaw as H2.CL / H2.TE during the downgrade. Configure the edge to reject, not forward, any request bearing both framing headers or a malformed `Transfer-Encoding` (AWS ALB `routing.http.desync_mitigation_mode` set to `defensive` or `strictest`; Apache `HttpProtocolOptions Strict`, available since 2.4.24; equivalent strict parsing on your proxy). Require the front-end and back-end to use the same HTTP parser or at least the same framing interpretation, and disable reuse of back-end keep-alive connections where throughput allows, so a smuggled prefix has no following victim request to attach to. Patch front-end proxies and origin servers; most desync bugs are parser CVEs fixed upstream. Finally, log the framing headers and the ALB classification so the detection above is possible at all.

These map to the control codes used in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html) and [foundation guide](https://umbrasec.dev/guide/foundation.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Reject ambiguous requests at the edge | Removes the desync class: no request with dual or malformed framing headers reaches the origin | - | - | PR.PS Platform Security |
| HTTP/2 end-to-end / strict parser alignment | Explicit framing removes the CL/TE conflict; identical parsing stops the two hops disagreeing | - | - | PR.PS Platform Security |
| Patch front-end proxy and origin | Closes the parser-discrepancy CVEs that enable specific desync variants | Patch applications | A.8.8 Technical vulnerabilities | PR.PS Platform Security |
| Log framing headers and ALB classification, monitor | Supplies the telemetry every detection above depends on | ML2/ML3 event-log collection | A.8.15 Logging; A.8.16 Monitoring | DE.CM Continuous monitoring; DE.AE Adverse events |

## Honest limitations

- **HTTP/2 downgrade desync hides the dual headers.** With an HTTP/2 front-end and an HTTP/1.1 back-end, the smuggling payload is introduced when the edge rewrites the request, so inspecting the HTTP/2 side never shows a `Content-Length`/`Transfer-Encoding` pair. The dual-header detector is blind to H2.CL / H2.TE; you are left with origin-side anomalies and ALB classification.
- **No header logging, no primary signal.** The framing headers are off by default everywhere; until you add them to the log format you cannot run the highest-precision detection, only the coarse origin symptoms.
- **A single successful smuggle is quiet.** One landed request may leave only a subtle orphaned origin request and a victim side effect, with no volume to threshold on. That is why the two-tier correlation and the cache check matter.
- **Encryption limits inline inspection.** You can only read framing headers where TLS is terminated; a signal that only exists on an encrypted hop will not appear until that hop logs it.
- **Client-side and browser-powered desync differ.** Variants that originate the ambiguity from a victim browser rather than the attacker's own request present differently and may not trip edge header inspection at all.
- **Legitimate oddities exist.** Some appliances, health checks, and older clients chunk or frame unusually and will trip these detectors; they need an allowlist tuned to your environment.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access). ATT&CK has no dedicated request-smuggling technique, so T1190 is the closest honest map for exploiting the HTTP-parsing flaw to reach the origin or bypass edge controls.
- MITRE D3FEND: [D3-PMAD Protocol Metadata Anomaly Detection](https://d3fend.mitre.org/technique/d3f:ProtocolMetadataAnomalyDetection) for the detection side, and [D3-ITF Inbound Traffic Filtering](https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering) for rejecting ambiguous requests at the edge.
- Weakness and reference sources: [CWE-444 Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html), [RFC 9112 sections 6.1 and 6.3](https://www.rfc-editor.org/rfc/rfc9112), [OWASP CRS rules](https://github.com/coreruleset/coreruleset/tree/main/rules), and [SigmaHQ web rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web).

**Scope note.** This is a defensive skill. It explains request smuggling only to the depth needed to detect and mitigate it and deliberately provides no desync payloads, obfuscation recipes, or smuggling tooling. UMBRASEC publishes defense, not offense.
