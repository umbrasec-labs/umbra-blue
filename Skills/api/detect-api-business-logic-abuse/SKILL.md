---
name: detect-api-business-logic-abuse
description: "Detection and response methodology for API business logic abuse - BOLA / IDOR (OWASP API1:2023), request-rate abuse (API4:2023), and out-of-order workflow attacks against REST and GraphQL APIs (MITRE ATT&CK T1190, with high-volume enumeration resembling T1595). Works off API gateway and reverse-proxy access logs (nginx, Apache, AWS ALB / API Gateway, Azure APIM and Front Door, Cloudflare) plus WAF and application audit logs. Gives the method for spotting one principal touching object IDs across many owners, per-principal velocity spikes, and workflow step-skipping, plus public rule sources and object-level-authorization hardening. Use when investigating suspicious API access, hunting for IDOR or BOLA enumeration, triaging a spike of 403 or 404 responses from one token, building rate or sequence anomaly detection, or hardening an API against BOLA."
---

# API Business Logic Abuse (BOLA / IDOR, Rate and Sequence) - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

API business logic abuse does not look like an exploit. Every request is well formed, authenticated, and returns a normal status code. The abuse is in the aggregate: one principal reads invoice `1001`, then `1002`, then `1003` (Broken Object Level Authorization, OWASP API1:2023); one token makes ten thousand requests a minute (unrestricted resource consumption, API4:2023); or a client calls `POST /checkout` without ever calling `POST /cart` (a skipped workflow step). You catch it by baselining per-principal behaviour at the API gateway: the set of distinct object IDs a principal touches, its request velocity, and the order of its calls. Enforce object-level authorization in the application so BOLA cannot succeed, and log enough at the gateway that you can see enumeration when it does. There is no single event ID here; the signal lives in access-log aggregation.

## What it looks like, defender view

In telemetry, BOLA enumeration shows as one authenticated identity (a user ID, JWT `sub`, session, or API key) issuing requests to the same endpoint with a changing object identifier in the path or query, for example `GET /api/v1/orders/{id}` walking across IDs the principal has never accessed before. Successful BOLA returns `200` for objects belonging to other users; a probing attacker generates a telltale mix of `200`, `403`, and `404` as they sweep an ID range. Rate abuse shows as a sharp rise in requests per principal per minute against a baseline, often against a cheap read endpoint used for scraping or a login or OTP endpoint used for stuffing. Sequence abuse shows as a state-changing call arriving without the requests that normally precede it, or a multi-step flow completed far faster than a human could. None of this is visible one request at a time; it is only visible in aggregation over a principal and a time window.

## Log sources and signals

The data lives at the edge, not on the host. Confirm these are enabled and shipped to your SIEM or data lake, because most are off or short-retention by default:

- **API gateway / reverse-proxy access logs.** nginx `access.log` (with `$request`, `$status`, `$body_bytes_sent`, `$remote_addr`, `$http_user_agent`), Apache combined log, AWS Application Load Balancer access logs (S3) and API Gateway execution / access logs (CloudWatch, with `$context.identity.sourceIp`, `$context.authorizer.principalId`, `$context.status`), Azure API Management diagnostic logs (`ApiManagementGatewayLogs`) and Front Door logs, Google Cloud Apigee analytics, Kong and Envoy access logs. These carry the method, full request path (the object ID), response status, and response byte count.
- **Authenticated principal identity.** The single most important field, and the one most often missing from raw access logs. Capture the user ID, JWT `sub` or `oid`, API key ID, or session ID on every request, ideally injected by the gateway or authorizer. Without a stable per-principal key you cannot aggregate, and these detections do not work.
- **WAF logs.** AWS WAF (including rate-based rule match events), Azure WAF / Front Door, Cloudflare (API Shield, rate limiting, and sequence analytics), Akamai. These give rule hits and, for rate-based rules, the blocking decisions.
- **Application audit logs.** The authoritative record of which principal accessed which object ID and whether the application authorized it. This is where you see a BOLA that the gateway cannot (the gateway sees the request succeed; only the app knows the object belonged to someone else).

What normal looks like: a given user touches a small, stable set of object IDs that belong to them; request velocity sits in a human or known-integration band; and multi-step flows arrive in order with human-plausible gaps. The anomaly is a departure from that per-principal baseline, which is exactly the shape MITRE D3FEND calls Resource Access Pattern Analysis.

## Detection approach

No bespoke UMBRASEC rule ships for this threat yet. Build the detection as per-principal aggregation over gateway logs, and lean on public rule sources and your API gateway's native controls rather than inventing a signature.

- **BOLA / IDOR (object-access spread).** Over a short window, group requests by principal and count distinct object IDs accessed on sensitive endpoints, and count `403` / `404` responses per principal. A principal touching far more distinct IDs than its baseline, or generating a burst of `403`/`404` on an endpoint with an ID path parameter, is the enumeration signal. The highest-fidelity variant correlates against ownership: an access to an object the principal does not own (visible only in application audit logs) is BOLA by definition. Parameterize the path so `/orders/1001` and `/orders/1002` collapse to one endpoint template before you count.
- **Rate abuse (velocity).** Alert on requests per principal per minute above a baseline, and prefer enforcing it inline with the gateway's own rate limiter (AWS WAF rate-based rules, Azure APIM rate-limit policy, Cloudflare Rate Limiting) so you throttle as well as detect. This covers OWASP API4:2023 unrestricted resource consumption.
- **Sequence / workflow abuse.** Model the expected state machine for a sensitive flow (cart then checkout then pay) and alert when a state-changing endpoint is reached without its prerequisites in the same session, or when a flow completes faster than humanly possible. Cloudflare API Shield Sequence Analytics and similar API-security platforms (Salt, Traceable, Noname) do this natively; otherwise it is a session-scoped correlation query.

Public, maintained rule sources to point detection engineering at:

- SigmaHQ web rules directory: <https://github.com/SigmaHQ/sigma/tree/master/rules/web>. The webserver fuzzing and distinct-URL rules there (mapped to T1595) catch the high-volume `403`/`404` enumeration pattern directly, though they key on source IP rather than authenticated principal, so retune them to your principal field.
- MITRE D3FEND Resource Access Pattern Analysis (D3-RAPA): <https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis>.
- OWASP API Security Top 10 (2023): <https://owasp.org/API-Security/editions/2023/en/0x11-t10/> for the API1 (BOLA) and API4 (resource consumption) definitions and test guidance.

## Threat hunt

For the low-and-slow attacker who pulls a handful of objects and waits, no velocity rule fires. Hunt the access pattern instead:

1. Pick a sensitive, ID-addressable endpoint (for example `/api/*/users/{id}`, `/invoices/{id}`, `/documents/{id}`). Parameterize the path so the object ID is a field, not part of the URL string.
2. Over a long window (days, not minutes), aggregate by authenticated principal: count distinct object IDs accessed, and the ratio of `403`/`404` to `200`. Rank principals by distinct-ID count.
3. Join the accessed object IDs to their owner in application data or audit logs. A principal whose accessed-ID set extends well beyond the objects it owns is the BOLA signal, regardless of volume.
4. Look for sequential or dictionary-ordered IDs in one principal's history (1001, 1002, 1003) - a human does not browse their own records in numeric order, so a sweep is machine-driven enumeration.
5. For workflow abuse, reconstruct per-session call order on a sensitive flow and flag sessions that reached a state-changing step without its prerequisites.

Service accounts, data-sync integrations, and vulnerability scanners will top these rankings legitimately. Build the allowlist from that first pass, then alert on what remains.

## Hardening

The durable fix is in the application, not the detector: BOLA exists because the server does not check, on every request, that the authenticated principal is authorized for the specific object being addressed. Enforce object-level authorization server-side on every object reference; do not rely on unguessable IDs alone, because they leak through other endpoints. Prefer server-generated, non-sequential identifiers or an indirect reference map so enumeration is at least expensive. Apply least privilege to API scopes and tokens so a stolen token reaches only what its owner needs. Rate-limit per principal and per endpoint at the gateway. And make sure the gateway logs the authenticated principal, object ID, status, and byte count, because the detection above is impossible without it. These map cleanly to the control codes used in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html):

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Enforce object-level authorization per request | Removes the BOLA flaw at the source: the server checks ownership on every object reference | - | A.5.15 Access control | PR.AA-05 Least privilege |
| Least-privilege API scopes and tokens | Shrinks what any one token or principal can reach, limiting blast radius of abuse | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Per-principal rate limiting at the gateway | Caps velocity so enumeration and scraping are slow and noisy, and enforces as well as detects | - | A.5.15 Access control | DE.CM Continuous monitoring |
| Log the principal, object ID, status, and size | Supplies the telemetry every detection above depends on | ML2/ML3 event-log collection | A.8.15 Logging | DE.CM; DE.AE Adverse events |

## Honest limitations

- **No authenticated principal, no detection.** If the gateway does not log a stable per-principal identifier, you cannot aggregate, and every method here fails. This is the most common blind spot.
- **Low and slow beats velocity.** An attacker who pulls a few objects per day stays under any rate threshold and under most access-spread baselines. That is why object-level authorization in the app matters more than the detector.
- **Legitimate high-volume principals exist.** Integrations, data-sync jobs, and scanners look exactly like enumeration in the aggregate. These detections surface candidates for triage, not verdicts, and need an allowlist tuned to your environment.
- **The gateway sees the request, not the ownership.** A successful BOLA returns `200` and looks benign at the proxy. Confirming it needs application-side knowledge of who owns the object, so pair gateway telemetry with application audit logs.
- **Sequential vs opaque IDs.** Numeric sequential IDs make enumeration trivial to spot and trivial to perform; opaque UUIDs hide the sweep from the ID-ordering heuristic but do not fix the underlying authorization flaw.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access). The high-volume object-ID enumeration pattern also resembles [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (Reconnaissance); ATT&CK has no dedicated BOLA/IDOR technique, so T1190 is the closest honest map for exploiting the authorization flaw.
- MITRE D3FEND: [D3-RAPA Resource Access Pattern Analysis](https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis) - baseline a principal's resource access and alert on large deviations.
- Public rule and reference sources: [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), [SigmaHQ web rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web), CWE-639 (Authorization Bypass Through User-Controlled Key) and CWE-285 (Improper Authorization).

**Scope note.** This is a defensive skill. It explains API business logic abuse only to the depth needed to detect and mitigate it and deliberately provides no enumeration scripts, IDOR tooling, or request-replay kits. UMBRASEC publishes defense, not offense.
