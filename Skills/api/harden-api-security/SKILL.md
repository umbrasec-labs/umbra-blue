---
name: harden-api-security
description: "Defensive methodology for API-layer abuse across REST, gRPC, and WebSocket: broken object- and function-level authorization (BOLA/BFLA), broken authentication and token replay, mass assignment, SSRF from URL-accepting parameters, and unrestricted resource consumption (MITRE ATT&CK T1190, T1078, T1528, T1552.005, T1499.003). Keys off API gateway and reverse-proxy access logs (AWS API Gateway, Azure APIM, Kong, Envoy/Istio), WAF logs (AWS WAF, Azure Front Door/App Gateway), and application authorization-decision logs. Gives the defender view, log sources, a detection approach pointing to public rule sources, a hypothesis-driven hunt, and gateway plus authorization hardening. Use when hardening a REST/gRPC/WebSocket API, writing API-abuse detections, hunting for BOLA/IDOR enumeration or BFLA, triaging bursts of 401/403/429 on an API gateway, or designing edge authorization and schema-validation controls."
---

# API Abuse (REST, gRPC, WebSocket) - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

The most damaging API attacks are authorization failures, not memory-corruption exploits: an authenticated, in-scope caller asks for an object or a function that is not theirs, and the backend hands it over. HTTP status alone will not catch this, because a successful BOLA returns `200`, not `403`. The highest-value defensive move is to log the authorization decision as a structured event (who asked, which object, who owns it, allow or deny) so that "User A read User B's record" becomes one legible line instead of an invisible `200`. Layer that with per-principal access-breadth monitoring on the gateway, schema validation that rejects unexpected fields at the edge (closing mass assignment), and allowlist-based egress for any URL-accepting parameter (closing SSRF to cloud metadata). Enforce the same authorization at the gRPC interceptor and the WebSocket upgrade, not only on REST.

## What it looks like, defender view

In gateway and proxy logs the campaign presents as one authenticated principal touching an unusual number of distinct object identifiers in a short window (sequential IDs, or a fan-out of UUIDs harvested elsewhere), often with a mix of `200`, `403`, and `404` as the caller probes ownership boundaries. Broken function-level authorization shows as a non-admin subject reaching `/admin` or `/internal` paths, or invoking admin gRPC methods. Mass assignment shows as request bodies carrying fields the client UI never sends (`role`, `is_admin`, `permissions`). SSRF shows as URL-valued parameters (`webhook_url`, `avatar_url`, `import_url`) containing internal or link-local addresses. Resource-consumption abuse shows as bursts against login or search endpoints and oversized pagination (`per_page=100000`) or payloads. On gRPC you see calls to the reflection service and metadata headers such as `x-user-role` or `x-forwarded-for` set by the client. On WebSocket you see `101 Switching Protocols` upgrades carrying a foreign `Origin`.

## Log sources and signals

Centralize these at the edge, where every REST, gRPC, and WebSocket request is already observed:

- **AWS API Gateway access logs** (CloudWatch Logs). Enable access logging and capture `$context.identity.caller` / `$context.authorizer.principalId` (the authenticated subject), `$context.httpMethod`, `$context.resourcePath`, `$context.status`, `$context.error.message`, and `$context.integrationLatency`. The authorizer principal is the field that lets you tie object access to an identity.
- **Azure API Management** diagnostic logs in Log Analytics: table `ApiManagementGatewayLogs`, fields `Method`, `Url`, `ResponseCode`, `BackendResponseCode`, `ClientProtocol`, `ApimSubscriptionId`, `RequestSize`, `ResponseSize`.
- **WAF logs.** AWS WAF (`webacl` logs: `httpRequest`, `terminatingRuleId`, `action`), Azure Front Door and Application Gateway WAF (`AzureDiagnostics` with category `FrontDoorWebApplicationFirewallLog` or `ApplicationGatewayFirewallLog`, or the resource-specific `AGWFirewallLogs` table). WAF carries matched rule IDs for SSRF and injection signatures.
- **Reverse proxy / ingress.** Kong (`http-log` / access logs), nginx and Kubernetes ingress access logs. For gRPC, Envoy / Istio access logs expose `grpc_status`, `:method`, `:path`, `response_code`, and `response_flags`.
- **Application authorization-decision logs.** The one source the gateway cannot give you: a structured event per authorization check with `subject`, `action`, `object_id`, `object_owner`, and `decision`. Without this, successful BOLA is invisible.
- **Browser CSP violation reports** (`report-to` / `report-uri` endpoint) for cross-site WebSocket hijacking signals.

Status codes carry most of the velocity signal: `401` (unauthenticated), `403` (authorization denied), `429` (rate limited), `400` (schema rejected at the edge). What matters is the shape over time per principal, not any single line.

## Detection approach

Do not hand-write a rule here; a tuned UMBRASEC rule is not yet shipped for this threat. Describe the logic and lean on maintained public rules and your own structured authZ events:

- **BOLA / IDOR enumeration.** Alert on a single `principalId` requesting object tickets across many distinct object identifiers in a short window, especially with an elevated `403`/`404` ratio (ownership probing). This is a `value_count` or `stats dc(object_id) by principal` pattern over your gateway logs. True success detection comes from the application authZ-decision log where `subject != object_owner` and `decision = allow` is a near-binary alarm, analogous to a honeypot.
- **BFLA.** Alert when a subject whose role is not administrative reaches an `/admin`, `/internal`, or privileged gRPC method path and receives `2xx`. Join the authenticated role claim to the resource path.
- **Mass assignment.** Reject-and-log at the gateway when a request body contains fields outside the endpoint's declared schema (see hardening). An inbound body carrying `role`, `is_admin`, or `permissions` to a self-service profile endpoint is the signal.
- **SSRF.** Match URL-valued parameters against link-local and metadata targets (`169.254.169.254`, `metadata.google.internal`, `127.0.0.1`, `[::1]`, `0x7f000001`). WAF managed rule sets flag these; also watch for backend egress to those destinations.
- **Resource consumption and credential stuffing.** Burst of `429`, or burst of `401` against auth endpoints from one source, or abnormally large `RequestSize`/`per_page`.
- **gRPC reflection and WebSocket origin.** Calls to `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` from non-development source IPs, and `101` upgrades whose `Origin` is not an allowlisted host.

Public rule sources to adapt rather than invent: SigmaHQ web proxy and web rules at [github.com/SigmaHQ/sigma/tree/master/rules/web](https://github.com/SigmaHQ/sigma/tree/master/rules/web), threat-hunting variants at [github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/web](https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/web), AWS cloud rules at [github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws), and the OWASP API Security Top 10 2023 for the threat taxonomy at [owasp.org/API-Security/editions/2023/en/0x11-t10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

## Threat hunt

For the low-and-slow attacker who reads a handful of other users' objects and stops, velocity rules will not fire. Hunt instead:

1. From gateway access logs over a long window, build a per-principal profile of distinct `object_id` values touched on each resource path. Rank principals whose breadth sits far above the per-endpoint median.
2. For the top principals, join to the application authZ-decision log and keep only events where `object_owner != subject` with `decision = allow`. Any hit is a real cross-tenant read; triage by object sensitivity, not by count.
3. Sweep request bodies to self-service endpoints for privilege fields (`role`, `is_admin`, `is_superuser`, `permissions`, `account_type`) that were accepted (`2xx`). A single accepted privilege field is a mass-assignment finding.
4. List URL-valued parameters whose values resolved to link-local, loopback, or cloud-metadata ranges, and correlate with backend egress NetFlow to those addresses.
5. Enumerate every deprecated API version still returning `2xx` (`/api/v0`, `/api/v1-beta`, `internal`) and confirm each enforces the same authorization as the current version; inconsistent controls on old versions are a common BFLA path.

## Hardening

Shrink the attack surface so detection is the backstop, not the only line. The control codes below are grounded in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Object-level authorization on every endpoint and verb | Check `subject` owns or is granted `object_id` server-side, on GET and on PUT/PATCH/DELETE alike; closes BOLA | Restrict administrative privileges (ML2+) | A.5.15 Access control | PR.AA-05 Least privilege |
| Function-level authorization by role | Deny admin and internal paths and gRPC methods to non-admin subjects; closes BFLA | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Strong, phishing-resistant authentication and short-lived tokens | Validate tokens fully, bind to session, rotate and revoke on password change; closes broken-auth replay | Multi-factor authentication (ML2+) | A.8.5 Secure authentication | PR.AA-03 Users authenticated |
| Schema validation at the gateway (allowlist fields) | Reject unknown or privilege fields before they reach the model; closes mass assignment and malformed input | - | A.8.26 Application security requirements | PR.PS |
| Egress allowlist for URL-accepting parameters | Block requests to link-local, loopback, and metadata ranges; closes SSRF | - | A.8.23 Web filtering | PR.IR-01 |
| Rate limiting and payload/pagination caps | Bound request frequency, body size, and page size; closes resource exhaustion and credential stuffing | - | A.8.6 Capacity management | PR.PS |
| Structured authorization-decision logging and monitoring | Emit and monitor allow/deny per object so BOLA is legible | ML2/ML3 event-log and monitoring | A.8.15 Logging; A.8.16 Monitoring | DE.CM Continuous monitoring |
| WebSocket origin validation and gRPC auth parity | Validate `Origin` on upgrade and enforce the same authZ at the interceptor as at REST | - | A.5.15 Access control | PR.AA-05 Least privilege |

ISO codes `A.8.26`, `A.8.23`, and `A.8.6` name real ISO 27001:2022 controls but are not referenced in the UMBRASEC guide; they are included for completeness and should be confirmed against your own control set.

## Honest limitations

HTTP status and gateway logs cannot see a successful BOLA; only the application authorization-decision log makes `subject != object_owner, allow` visible, and most teams do not emit it, so the single most important control is also the one most often missing. Velocity and breadth rules miss the patient attacker who reads one high-value object and stops, which is why the hunt and the structured authZ log matter more than any threshold. Gateway schema validation only helps where the gateway parses the body, not for opaque gRPC or binary payloads unless you decode protobuf. WAF SSRF signatures are bypassable with alternate encodings and DNS rebinding, so egress allowlisting at the network layer is the durable control. gRPC and WebSocket frequently sit behind controls that were designed for REST and silently skip them; verify parity explicitly. Baseline every threshold in report-only mode before enforcing.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (BOLA/BFLA/mass assignment via the API surface); [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) and [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) (broken authentication and token replay); [T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) (SSRF to cloud metadata); [T1499.003 Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003/) (unrestricted resource consumption).
- MITRE D3FEND: Resource Access Pattern Analysis (D3-RAPA) for BOLA/IDOR breadth, Inbound Session Volume Analysis (D3-ISVA) for resource-consumption and credential-stuffing bursts, User Account Permissions (D3-UAP) and Multi-factor Authentication (D3-MFA) for authorization and authentication hardening, and Application Configuration Hardening (D3-ACH) for gateway and version hygiene. Browse the matrix at [d3fend.mitre.org](https://d3fend.mitre.org/).
- Public rule and guidance sources: [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/); OWASP [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), and [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) cheat sheets; [SigmaHQ web rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web); gRPC [authentication guide](https://grpc.io/docs/guides/auth/); WebSocket security in [RFC 6455 Section 10](https://datatracker.ietf.org/doc/html/rfc6455#section-10).

**Scope note.** This is a defensive skill. It explains API-layer attacks only to the depth needed to detect and mitigate them and ships no offensive tooling, exploit code, or probing scripts. UMBRASEC publishes defense, not offense.
