---
name: detect-hpp
description: "Detection and hardening methodology for HTTP Parameter Pollution (HPP), where an attacker sends the same parameter name more than once (for example role=user&role=admin) so the WAF, reverse proxy, and origin app each parse a different value, letting the request pass inspection on one value while the app acts on another. Maps to MITRE ATT&CK T1190 (CAPEC-460, OWASP WSTG-INPV-04). Log sources are reverse-proxy and web-server access logs (nginx, Apache, IIS), CDN and load-balancer logs, WAF logs, and the app's parsed-parameter map. Gives the defender view of duplicate parameters, how parser divergence creates the WAF-versus-origin gap, a per-endpoint detection and hunt method, and parsing hardening. Use when triaging a WAF bypass, investigating duplicate query-string or POST-body parameters, hunting for parameter pollution against a web app or API, or hardening against HPP."
---

# HTTP Parameter Pollution - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

HTTP Parameter Pollution abuses the fact that HTTP never defined how to handle a parameter name that appears twice. A WAF, a reverse proxy, a CDN, and the origin framework can each pick a different value from `id=1&id=2`: some take the first, some the last, some concatenate, some build an array. An attacker uses that gap to show the WAF a benign value and the application a malicious one, so no payload signature fires because the dangerous value never sits in a single field the WAF inspects. You catch it by looking for duplicate parameter names in your request telemetry, especially on sensitive parameters (authorization, identity, redirect, price), and by reconciling what your edge parsed against what the origin parsed. The highest-value operational fact: if you run the OWASP Core Rule Set at the default paranoia level, the HPP rule is not active, so a stock WAF deployment often has no HPP detection at all.

## What it looks like, defender view

In telemetry the signal is a single request whose query string or body carries the same parameter name two or more times: `?id=1&id=2`, `role=user&role=admin`, `redirect=/home&redirect=//evil.example`, or the same name split across channels (once in the query string, once in the POST body, once in a cookie). Variants add encoding and casing to defeat naive matching: `id=1&%69d=2`, `id=1&id%00=2`, or trailing-space and array-suffix forms such as `id[]=1&id[]=2`. On the wire none of these is malformed; each value is individually well formed, which is why signature and schema checks pass it. The tell is not the value, it is the repetition and the disagreement it causes downstream: a WAF log that records one value and allowed the request, next to an application log that acted on a different value for the same request id.

## Log sources and signals

The signal lives in whatever component logs the raw request line and body, and the WAF-versus-origin gap is only visible if you can line up two of them by request id or timestamp.

- **Reverse-proxy and web-server access logs.** nginx `$request` and `$args` carry the full query string by default; the POST body is only in `$request_body`, and only when nginx reads the body (for example with `proxy_pass`), so by default you see GET pollution but not POST pollution. Apache logs the request line and query with `%r` and `%q`; the body needs `mod_security` or `mod_dumpio`. IIS and CloudFront expose `cs-uri-query`; AWS ALB access logs carry the `request` field. The asymmetry matters: tune per method, and do not assume a clean access log shows body pollution.
- **WAF logs.** AWS WAF logs `httpRequest.args` plus `terminatingRuleId` and `action`, so you can see the value the WAF evaluated and whether it allowed the request. ModSecurity and Coraza audit logs are the richest source: Part B holds the raw request headers and query, Part C holds the request body, and the audit log shows exactly which value the engine matched on. Cloudflare, Akamai, and Imperva expose the matched value and rule id similarly.
- **Application and framework logs.** The origin's own parsed-parameter map is the ground truth for what the app actually used. Without it you can see that a parameter was duplicated but not which value won downstream, so the WAF-versus-app reconciliation is impossible. If the app does not log its resolved parameters for sensitive endpoints, adding that is the single most useful change for this detection.
- **API gateway logs.** AWS API Gateway, Kong, Apigee, or Azure API Management carry the resolved path, method, and query, letting you spot duplicated parameters on API routes and OpenAPI-typed fields.

What normal looks like: most endpoints receive each parameter name exactly once. Legitimate repetition is confined to known multi-value fields (a multi-select filter, `tags=a&tags=b`, OpenAPI `explode: true` arrays), which is why the baseline is per endpoint and per parameter, not global.

## Why the WAF and the origin disagree

Duplicate-parameter handling is implementation-defined, so a request can mean one thing at the edge and another at the origin. The OWASP Web Security Testing Guide (WSTG-INPV-04) documents the per-stack behaviour; the point for a defender is that the WAF and the application may each read a different value from the same bytes, which is the entire mechanism to detect.

| Component behaviour on `p=1&p=2` | Value the component uses | Why it matters to the defender |
|---|---|---|
| Takes the last occurrence (common in PHP, and in many frameworks for scalar binding) | `2` | If the WAF reads the first value and the app the last, the WAF inspected the wrong one |
| Takes the first occurrence (common in a Java Servlet `getParameter`) | `1` | Edge and origin can split on first-versus-last |
| Concatenates the values (classic ASP.NET `Request.Params` comma-join) | `1,2` | A split payload can reassemble only at the origin |
| Builds an array or list (Express via the qs parser, and the `name[]` convention in PHP and Rails; plain Rails/Rack keeps the last value for `p=1&p=2`) | `[1,2]` | Legitimate for multi-value fields, which is the main false-positive source |

Attribute this table to WSTG rather than any single version claim; verify the exact behaviour of your own stack and framework version before you rely on it. The defensive takeaway is only that divergence exists, not any recipe for causing it.

## Detection approach

Alert in prose terms on two independent logics, strongest when combined.

1. **Duplicate parameter names per request.** From access, WAF, or gateway logs, tokenize the query string (and the body where you log it) and count occurrences of each parameter name within one request. Flag any name that appears more than once. Make it usable by baselining per endpoint and per parameter: suppress the known multi-value fields and raise the priority when the duplicated name is an authorization, identity, redirect, price, or quantity parameter. A global any-duplicate alert is noise; a per-endpoint one is a signal. Normalize names before counting (URL-decode, strip null bytes and trailing whitespace, case-fold) so encoding tricks do not split the count.
2. **Edge-versus-origin value reconciliation.** Join the WAF or proxy log to the application's parsed-parameter log by request id, and alert when the value the edge evaluated differs from the value the application resolved for the same sensitive parameter. A disagreement means some component in the chain was inspecting a value the app never used, which is the exact condition HPP exploits.

No portable signature covers this, and no tuned UMBRASEC rule ships for it yet. Point your implementation at public, maintained sources rather than inventing one:

- OWASP Core Rule Set, the 921 PROTOCOL-ATTACK family, is the maintained HPP rule source. Rule 921170 counts parameter names into a counter (it does not block), and rule 921180 fires when a name count exceeds one. 921180 is gated behind a higher paranoia level, so at the default PL1 it is inactive; check which paranoia level enables it in your CRS version and raise the PL on routes that must reject duplicates. See https://coreruleset.org/ and the ruleset source at https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-921-PROTOCOL-ATTACK.conf
- SigmaHQ web rules for the access-log primitives (status-code anomalies, redirect and parameter abuse): https://github.com/SigmaHQ/sigma/tree/master/rules/web
- OWASP WSTG-INPV-04 Testing for HTTP Parameter Pollution, for the per-stack parsing behaviour: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
- CAPEC-460 HTTP Parameter Pollution, for the attack pattern and its relationships: https://capec.mitre.org/data/definitions/460.html
- MITRE D3FEND countermeasures listed in the final section.

## Threat hunt

Hypothesis-driven, run over a long window against access, WAF, and application logs:

1. **Which requests carried a duplicated parameter at all?** Extract each request's query string, URL-decode and case-fold the parameter names, and list every request where one name appears twice or more. Rank by whether the duplicated name is an authorization, identity, redirect, or price field, since a duplicate on `role` or `redirect` outranks a duplicate on a search filter.
2. **Did the edge and the origin ever disagree?** For the sensitive endpoints, join the WAF or proxy parsed value to the application's resolved value by request id, and surface every case where they differ. Each mismatch is a candidate WAF-bypass event even if nothing downstream looked anomalous on its own.
3. **Is pollution crossing channels?** Look for the same parameter name present in more than one location of a single request (query string plus POST body, or plus a cookie), which frameworks resolve by precedence (for example a PHP `$_REQUEST`-style merge) and which a query-string-only WAF rule never sees.
4. **Did a flagged request succeed?** Pivot any hit to its response status and the downstream action (a privilege change, a redirect to an external host, an order total). A duplicated `redirect` that returned a 302 to an off-site host, or a duplicated `role` that preceded an authorization change, moves the finding from curiosity to incident.

## Hardening

The durable fix is a single canonical parsing policy enforced consistently across the whole chain: decide how duplicate parameters are handled, make the WAF, the proxy, and the origin agree on it, and reject requests that carry duplicate names on sensitive parameters at the edge so the origin never has to adjudicate. That core control has no clean mapping in the UMBRASEC guide, so it is stated here in prose rather than forced into the table. The two rows below are grounded in the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); Essential Eight is left blank for the logging row because its strategies target OS and admin hardening rather than application request handling.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Patch and maintain the WAF, CRS, proxy, and web framework | Keeps duplicate-parameter parsing current and consistent across the chain and closes known HPP bypasses | Patch applications (ML2) | A.8.8 Technical vulnerabilities | PR.PS |
| Log the full request line and body, and monitor parameter anomalies | Records the raw query and resolved values the detection and reconciliation need, and watches for duplicate-name spikes | - | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM; DE.AE |

## Honest limitations

Access logs frequently omit the POST body, so body and cross-channel pollution is invisible unless the proxy or WAF is configured to capture it; a clean-looking GET log is not proof of absence. Encoding, null-byte, and casing variants split a naive name count unless you normalize first, and duplicate JSON keys in a request body are a parallel blind spot that query-string tokenizers never touch. The edge-versus-origin reconciliation only works when the application logs its resolved parameter map, which many apps do not. The biggest practical problem is false positives: multi-select forms, array conventions such as `tags=a&tags=b`, and OpenAPI `explode: true` fields are legitimately duplicated, so a global rule is unusable and every detection must be baselined per endpoint and per parameter. Low-volume, single-request abuse will not stand out by frequency, which is why sensitivity-based prioritization and the reconciliation join matter more than any threshold. Treat every rule as environment-specific, run it in report-only mode first, and leave the verdict to an analyst who knows which parameters the endpoint is allowed to repeat.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access) is the closest Enterprise mapping, since HPP is a technique for getting a payload or logic change through a public-facing application and its defenses. ATT&CK Enterprise has no dedicated parameter-pollution technique, so [CAPEC-460 HTTP Parameter Pollution](https://capec.mitre.org/data/definitions/460.html) and [OWASP WSTG-INPV-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution) map the behaviour more precisely.
- MITRE D3FEND: [D3-PMAD Protocol Metadata Anomaly Detection](https://d3fend.mitre.org/technique/d3f:ProtocolMetadataAnomalyDetection/) is the tightest fit for spotting the duplicate-parameter structure in the request, [D3-NTA Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/) is the broader detection countermeasure, and [D3-ITF Inbound Traffic Filtering](https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering/) aligns with normalizing or rejecting polluted requests at the edge.
- Public rule sources: OWASP CRS 921 PROTOCOL-ATTACK (rules 921170 and 921180), SigmaHQ web rules, OWASP WSTG-INPV-04, and CAPEC-460, all linked in Detection approach above.

**Scope note.** This is a defensive skill: it explains HTTP Parameter Pollution only to the depth needed to detect and mitigate it, names no exploitation steps or bypass recipes, and ships no offensive tooling.
