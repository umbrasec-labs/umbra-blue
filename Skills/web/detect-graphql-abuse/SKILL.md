---
name: detect-graphql-abuse
description: "Detection and response methodology for GraphQL endpoint abuse - introspection and field-suggestion schema reconnaissance, batching and alias abuse to bypass rate limits and brute force login or OTP mutations, and depth and complexity attacks that exhaust the backend. Maps to MITRE ATT&CK T1190, with T1595, T1110, and T1499.003. Works off Apollo Server and Router logs, Hasura logs, API gateway and WAF logs with body capture, and reverse-proxy logs, keyed on the POST body, errors array, and authenticated principal rather than HTTP status, since GraphQL returns 200 on errors. Gives methods for spotting introspection probing, counting aliases per request, and baselining query cost per principal. Use when investigating suspicious GraphQL traffic, hunting introspection or schema enumeration, triaging GraphQL error spikes from one token, building batch, alias, or depth-limit detection, or hardening a GraphQL endpoint."
---

# GraphQL Endpoint Abuse - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

GraphQL abuse hides from the signals that work on REST. A single endpoint (usually `/graphql`) serves every operation over POST, and the server returns HTTP `200` even when the query is rejected, so status-code and path-based detection sees nothing. The signal lives in the request body and the response `errors` array. Watch three things, keyed on the authenticated principal: introspection queries (`__schema` or `__type` in the query text, `operationName` often `IntrospectionQuery`, a large response from a first-seen or unauthenticated caller) and, when introspection is disabled, bursts of field-suggestion errors from one principal rebuilding the schema by guessing; batching and alias abuse, where one HTTP request carries a JSON array of operations or one operation repeats the same mutation under many aliases to multiply work and slip past per-request rate limits; and depth, breadth, or cost attacks that spike resolver count, latency, and backend load from one caller. Harden first: turn off introspection and field suggestions in production, cap query depth, aliases, batch size, and cost, and prefer a persisted-query (trusted-document) allow-list so only known operations run.

## What it looks like, defender view

In telemetry, introspection presents as a POST to the GraphQL endpoint whose body contains `__schema`, `__type`, or the `IntrospectionQuery` operation name, returning an unusually large JSON response (the full type system) to a caller that has no business reading the schema in production, frequently before authentication. When introspection is off, an attacker reconstructs the schema by guessing field names, which presents as a rapid run of `errors` entries of the form "Cannot query field X on type Y. Did you mean ...?" from one principal in a short window. Batching presents as a request body that is a JSON array of operations rather than a single object, or a single operation that declares many aliases of the same field or mutation (for example repeating a login mutation dozens of times under different alias keys in one request) so that one HTTP request counts as one against a naive rate limiter but drives many backend actions; against authentication mutations this is how a batched credential or OTP brute force gets under per-request throttles. Depth and complexity abuse presents as deeply nested or cyclic selection sets, a resolver or query-count spike, elevated latency, and correlated backend 5xx or database saturation, all tracing to one principal. None of this is legible from the gateway status line; it is legible only in the operation body, the error array, response size, and per-principal aggregation.

## Log sources and signals

GraphQL multiplexes everything through one POST endpoint and answers errors with `200`, so request-body-level logging is mandatory. Confirm these are enabled and shipped to your SIEM, because body capture is usually off by default:

- **GraphQL application and router logs.** Apollo Server request logging and the Apollo Router request and usage-reporting telemetry, Hasura `http-log` and `query-log`, and the equivalent from graphql-java, graphql-ruby, or Strawberry. These are the only sources that reliably carry the parsed operation, `operationName`, variables, and the resolver or query count. Mask secret variables (passwords, tokens) at the logger.
- **API gateway and WAF logs with request-body capture.** AWS WAF and API Gateway, Azure API Management (`ApiManagementGatewayLogs`) and Front Door, Cloudflare (including its API Shield GraphQL protections), Kong, and Envoy, where configured to log or inspect the POST body. Without body capture the gateway sees only `POST /graphql 200` and is blind to the operation.
- **Reverse-proxy access logs.** nginx and Apache give you `$request`, `$status`, `$body_bytes_sent`, `$remote_addr`, and `$http_user_agent`. Status is near-useless here, but `body_bytes_sent` is a strong proxy: a very large response to `/graphql` is a prime introspection indicator even without body logging, and request size flags batch and alias payloads.
- **Authenticated principal identity.** The field every detection below aggregates on - JWT `sub` or `oid`, API key ID, or session ID - captured on every request, ideally injected by the gateway or router. Without a stable per-principal key the per-principal baselines do not work.

Fields you lean on: the query text (for `__schema`, `__type`, nesting depth, alias count), `operationName`, the `errors` array (field-suggestion messages and their volume), the operation count in a batched array, response byte count, resolver or query count, latency, and the authenticated principal.

What normal looks like: production clients run a small, stable set of named operations (ideally a fixed persisted-query set), introspection is off and never requested, batch arrays are small or absent, alias use is modest, and query depth and cost sit in a tight band per operation. The anomaly is a departure from that per-principal, per-operation baseline.

## Detection approach

No bespoke UMBRASEC rule ships for this threat yet, and there is no GraphQL-specific Sigma rule in the public SigmaHQ repository as of writing, so build detection as body-aware, per-principal aggregation over the GraphQL and gateway logs rather than relying on a path or status signature.

- **Introspection.** Alert on any request whose body contains `__schema` or `__type`, or whose `operationName` is `IntrospectionQuery`, against a production endpoint - especially from an unauthenticated or first-seen principal, and corroborated by a large response byte count. In a hardened environment introspection should never fire in production, so this is high precision once introspection is disabled server-side (the detection then catches the attempts).
- **Schema-reconstruction probing.** When introspection is off, alert on a burst of field-suggestion errors ("Cannot query field ... Did you mean") grouped by principal over a short window. One or two are typos; dozens in minutes from one caller is schema brute forcing.
- **Batching and alias abuse.** Parse the request body: alert when the operation count in a single batched array exceeds a baseline, or when one operation declares aliases above a threshold, and raise severity when the repeated field is an authentication or OTP mutation (batched credential or OTP brute force, which otherwise hides under per-request rate limits because it is one HTTP request). Count operations and resolver invocations, not HTTP requests.
- **Depth, breadth, and cost.** Alert on query depth or complexity above the operation's baseline, or on a per-principal spike in resolver or query count, latency, and correlated backend errors - the application-exhaustion signal. Enforce these as limits inline (see Hardening) as well as detecting them.

Public, maintained sources to point detection engineering at:

- OWASP GraphQL Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>. The authoritative single reference for the abuse classes above and the controls that both prevent and surface them.
- OWASP API Security Top 10 (2023): <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>, specifically API4:2023 Unrestricted Resource Consumption (batching, aliases, depth, cost) and API8:2023 Security Misconfiguration (introspection and schema explorers exposed in production).
- SigmaHQ web rules directory: <https://github.com/SigmaHQ/sigma/tree/master/rules/web>. No GraphQL-specific rule lives here today; the generic webserver and proxy rules give only partial coverage (large-response and error-burst patterns), and they key on source IP, so retune them to your GraphQL body fields and principal.
- MITRE D3FEND: <https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis> and <https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis>.

## Threat hunt

For the low-and-slow attacker who maps the schema quietly and pulls a little at a time, no volume rule fires. Hunt the body instead:

1. Over a long window, pull every request to the GraphQL endpoint whose body contains `__schema`, `__type`, or `IntrospectionQuery`. In a production environment that should have introspection off, any hit is worth a look; rank by principal and by whether the caller was authenticated.
2. Group `errors` entries matching the field-suggestion pattern ("Cannot query field ... Did you mean") by principal and by hour. A principal generating many distinct suggestion errors is reconstructing the schema by hand.
3. Parse batched request bodies and alias-heavy operations: rank principals by maximum operations per request and maximum aliases per operation. Inspect the top talkers, and flag any whose repeated operation is a login, token, or OTP mutation.
4. Rank principals by maximum query depth, resolver or query count, and latency per operation. Join a per-principal cost spike to backend 5xx or database saturation in the same window to confirm an exhaustion attempt.
5. Baseline the operation set: list the distinct `operationName` values each principal runs. A principal running operations outside the known application set - or running raw, unnamed queries where the app only issues persisted queries - is anomalous by construction.

Legitimate tools skew these rankings: developer consoles, CI integration tests, schema-registry tooling, and monitoring probes run introspection and varied operations by design. Build the allowlist from the first pass, then alert on what remains. Non-production environments where introspection is intentionally on are out of scope for the introspection rule.

## Hardening

The durable fix is server-side: remove the schema-exposure and resource-amplification surface so the detections above catch attempts, not successes. Turn off introspection and field (`Did you mean`) suggestions in production, and disable GraphiQL or any schema explorer on public endpoints. Cap query depth, alias count, batch size, and query cost or complexity, and reject anything over the limit. Prefer a persisted-query (trusted-document) allow-list so only known, named operations run in production, which closes introspection, arbitrary deep queries, and alias tricks in one move. Rate-limit per principal counting operations and resolver invocations, not HTTP requests, and apply a per-object limit so batched or aliased auth mutations cannot brute force under a request-level cap. Require and verify authentication before any resolver runs, and enforce object-level and field-level authorization in resolvers. And log the operation name, body, and (masked) variables so the detection above is possible. These map to the control codes used in the UMBRASEC [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html) and [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Disable introspection and field suggestions in production | Removes the schema-reconnaissance surface so enumeration costs the attacker guesswork and noise | - | - | PR.PS Platform security |
| Limit query depth, aliases, batch size, and cost | Caps the amplification that turns one request into heavy backend work (API4:2023) | - | A.5.15 Access control | PR.PS; DE.CM Continuous monitoring |
| Persisted-query / trusted-document allow-list | Only known named operations run, closing introspection, arbitrary deep queries, and alias abuse at once | - | A.5.15 Access control | PR.AA-05 Least privilege |
| Per-principal, per-operation rate limiting | Counts operations and resolvers, not HTTP requests, so batched or aliased auth brute force is throttled | - | A.8.5 Secure authentication | PR.AA-05; DE.CM |
| Enforce authn and field-level authorization in resolvers | Stops anonymous introspection and object exposure regardless of query shape | - | A.8.2 Privileged access rights; A.5.17 Authentication information | PR.AA-05 Least privilege |
| Log operation name, body, and masked variables | Supplies the body-level telemetry every detection above depends on | ML2/ML3 event-log collection | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM; DE.AE Adverse events |

## Honest limitations

- **No body logging, no detection.** If the router, app, or gateway does not capture the POST body and the `errors` array, you see only `POST /graphql 200` and every method here fails. This is the most common and most damaging blind spot. Response byte count from the proxy is a weak fallback for introspection only.
- **Introspection disabled in prod is both a control and a gap.** Disabling it is the right call, but it does not stop an attacker reconstructing the schema by field guessing; that is why the field-suggestion-burst hunt exists, and why turning off suggestions matters.
- **Legitimate high-volume and introspection callers exist.** Dev consoles, CI, schema registries, and monitoring run introspection and varied operations by design, and look like reconnaissance in the aggregate. These detections surface candidates, not verdicts, and need an allowlist tuned to your environment.
- **Low and slow beats volume.** A patient attacker who maps the schema over days and issues modest queries stays under batch, alias, depth, and cost thresholds. That is why the persisted-query allow-list and server-side limits matter more than any detector.
- **No dedicated ATT&CK or Sigma coverage.** ATT&CK has no GraphQL-specific technique and SigmaHQ ships no GraphQL rule today, so both the mapping and the rule pointers are the closest honest approximations, not exact matches. Detection here is bespoke to your schema and operation baseline.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access) is the closest honest map for abusing the endpoint, since ATT&CK has no dedicated GraphQL technique. Introspection and schema enumeration resemble [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (Reconnaissance); batched or aliased abuse of authentication mutations resembles [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) (Credential Access); deep, broad, or batched query floods resemble [T1499.003 Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003/) (Impact).
- MITRE D3FEND: [D3-RAPA Resource Access Pattern Analysis](https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis) - baseline a principal's GraphQL operation set and cost, and alert on deviation; [D3-ISVA Inbound Session Volume Analysis](https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis) - analyse inbound request and operation volume for the batch, alias, and exhaustion signals.
- Public rule and reference sources: [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html), [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) (API4 and API8), [SigmaHQ web rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web) (generic, partial coverage), CWE-200 (Exposure of Sensitive Information) and CWE-770 (Allocation of Resources Without Limits or Throttling).

**Scope note.** This is a defensive skill. It explains GraphQL abuse only to the depth needed to detect and mitigate it and deliberately ships no introspection tooling, batching or alias payloads, or query-flooding scripts. UMBRASEC publishes defense, not offense.
