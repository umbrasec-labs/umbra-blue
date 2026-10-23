---
name: detect-idor
description: "Detection and response for Insecure Direct Object References (IDOR) and broken access control in web apps: horizontal privilege escalation (reading another owner's objects), vertical escalation (a non-admin reaching admin routes), and object-ID enumeration. Maps to MITRE ATT&CK T1190, with ID sweeps resembling T1595; the flaw is CWE-639 and CWE-285, OWASP A01:2021. Works off web server and reverse-proxy access logs (nginx, Apache, IIS), WAF logs, and framework authorization-decision logs (Spring Security, ASP.NET Core, Django, Rails Pundit), keyed on principal, object ID, status, and response size. Gives a method for spotting authorization failures and enumeration plus object-level-authorization hardening. Use when investigating suspicious object access, hunting for IDOR or broken access control, triaging a burst of 403 or 404 responses from one user, spotting object-ID enumeration, or hardening an app against authorization bypass."
---

# Insecure Direct Object References (IDOR) - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

IDOR does not look like an exploit on the wire. Each request is well formed, authenticated, and often returns `200`. The abuse is that the application failed to check that the authenticated principal owns, or is entitled to, the object it just handed back. You catch it in two places: the application's own authorization-decision logs (where a denied access raises a named exception, and a successful cross-owner read is only visible if the app logs the object owner), and the web server access logs aggregated per principal (where enumeration shows up as one user sweeping object IDs, a burst of `403`/`404` on ID-parameterized or role-gated paths, or an unusual response size on a `200`). The durable fix is server-side object-level authorization on every reference; the detection exists to catch the cases where that check is missing or wrong. This skill covers the application-side and web-server view of IDOR; for gateway-level rate and workflow-sequence abuse on APIs, see the sibling skill [detect-api-business-logic-abuse](../../api/detect-api-business-logic-abuse/SKILL.md).

## What it looks like, defender view

Two shapes dominate. **Horizontal escalation** is one principal reading or changing objects that belong to other owners: the same endpoint (`GET /account/{id}`, `GET /api/v1/orders/{id}`, or an ID carried in a query string, cookie, hidden form field, or JSON body) called with identifiers the principal has never legitimately touched. A successful horizontal IDOR returns `200`; at the proxy the only passive tell is a response size that deviates from this principal's norm, because the body now contains someone else's record. A probing attacker who sweeps an ID range leaves a telltale mix of `200`, `403`, and `404`. **Vertical escalation** is a lower-privileged principal reaching higher-privileged functionality: requests to `/admin/`-class paths, management endpoints, or role-gated actions from an account that should never see them, usually showing as `403`/`401` clusters, or as a `200` where the role check was missing entirely. Object references hidden in the body, a cookie, or a header are invisible to gateway and web-server logs, which is why application authorization logging is the center of gravity here, not the edge.

## Log sources and signals

The signal lives partly at the edge and critically inside the application. Confirm these are enabled and shipped to your SIEM, because the application-side ones are usually off by default:

- **Application framework authorization-decision logs.** The highest-fidelity source, and the one the sibling API skill does not cover. A denied access raises a named, loggable event: Spring Security `AccessDeniedException` / `AuthorizationDeniedEvent`, ASP.NET Core `Microsoft.AspNetCore.Authorization.DefaultAuthorizationService` "Authorization failed" log lines, Django `PermissionDenied`, Rails Pundit `NotAuthorizedError`, Laravel `AuthorizationException`. Configure the app to log, on every object reference, the authenticated principal, the object ID requested, the object's owner, and the allow/deny outcome. Only this source distinguishes a successful cross-owner read from a legitimate one; the proxy cannot.
- **Web server / reverse-proxy access logs.** nginx (`$remote_user` or the decoded auth principal, `$request_uri`, `$status`, `$body_bytes_sent`), Apache combined log, IIS W3C fields (`cs-username`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `sc-bytes`). These carry the method, the object ID when it rides in the path or query, the response status, and the response byte count that exposes a size anomaly on a `200`.
- **WAF logs.** AWS WAF, Azure WAF / Front Door, Cloudflare, Akamai. These give rule hits and rate-based decisions; most do not understand object ownership, so they catch the crude ID-sweep, not the targeted single read.
- **Authenticated principal identity.** The field everything aggregates on: user ID, session ID, JWT `sub`, or API key ID, stamped on every log line. Without a stable per-principal key none of these detections work.

What normal looks like: a given principal touches a small, stable set of object IDs that belong to it, generates few or no authorization denials, requests role-appropriate paths only, and returns response sizes in a steady band per endpoint. The anomaly is a departure from that per-principal baseline, which is the shape MITRE D3FEND calls Resource Access Pattern Analysis.

## Detection approach

No bespoke UMBRASEC rule ships for this threat yet. Build detection from application authorization logs first and web-server aggregation second, and lean on public rule sources rather than inventing a signature.

- **Horizontal escalation (cross-owner access).** The authoritative detector correlates principal to object owner: any allowed access where principal does not equal owner and no sharing grant exists is IDOR by definition, visible only in application authz logs that record the owner. Where you only have proxy logs, approximate it by grouping per principal over a short window and counting distinct object IDs on ID-parameterized endpoints, plus the ratio of `403`/`404` to `200`; a principal touching far more distinct IDs than its baseline, or sweeping sequential IDs, is the enumeration signal. Parameterize the path so `/orders/1001` and `/orders/1002` collapse to one template before counting.
- **Vertical escalation (role bypass).** Alert on authorization-denied events (the framework exceptions above) clustered by principal, and on requests to admin-scoped or role-gated routes from principals outside that role. A `403` cluster is a probe; a `200` on a route that should have denied the role is a missing check and the more serious finding.
- **Response-size anomaly on success.** For sensitive single-object endpoints, baseline the `200` response size per principal and flag deviations, since a successful horizontal IDOR returns a larger or simply different body than the principal's own record.

Public, maintained rule and reference sources to point detection engineering at:

- SigmaHQ web rules directory: <https://github.com/SigmaHQ/sigma/tree/master/rules/web>. The webserver enumeration and distinct-URL rules there (mapped to T1595) catch the high-volume `403`/`404` ID-sweep directly, though they key on source IP rather than authenticated principal, so retune them to your principal field.
- MITRE D3FEND Resource Access Pattern Analysis (D3-RAPA): <https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis>.
- OWASP A01:2021 Broken Access Control: <https://owasp.org/Top10/A01_2021-Broken_Access_Control/> for the authorization-bypass and IDOR definitions and test guidance.

## Threat hunt

For the targeted attacker who reads one high-value object and stops, no velocity or threshold rule fires. Hunt the ownership relationship and the enumeration shape instead:

1. Pick a sensitive, ID-addressable endpoint (for example `/account/{id}`, `/invoices/{id}`, `/documents/{id}`, or an action keyed on an ID in the body or a cookie). Parameterize so the object ID is a field, not part of the URL string.
2. From application authz logs, join every accessed object ID to its owner. List accesses where principal does not equal owner and no sharing grant exists. Rank by the sensitivity of the object, not by volume, so a lone cross-owner read of a high-value record surfaces.
3. Where you only have web-server logs, aggregate over a long window (days) per authenticated principal: count distinct object IDs and the ratio of `403`/`404` to `200`, and rank principals by distinct-ID count.
4. Look for sequential or dictionary-ordered IDs in one principal's history (`1001`, `1002`, `1003`): a human does not browse their own records in numeric order, so an ordered sweep is machine-driven enumeration.
5. For vertical escalation, list principals that generated authorization-denied exceptions on admin-scoped routes, then check whether any later request to the same route from the same principal returned `200` (a check that was added, bypassed, or inconsistent).

Service accounts, data-sync integrations, support staff with legitimate cross-account access, and vulnerability scanners will top these rankings legitimately. Build the allowlist from that first pass, then alert on what remains. These surface candidates for triage, not verdicts.

## Hardening

The durable fix is in the application, not the detector: IDOR exists because the server does not verify, on every object reference, that the authenticated principal is authorized for that specific object and action. Enforce object-level authorization server-side on every reference, including IDs carried in the body, cookies, headers, and hidden fields, not just the path. Enforce role and function checks centrally so vertical escalation cannot slip a missing guard. Do not rely on unguessable identifiers alone: an indirect reference map or server-generated non-sequential IDs is defense in depth that makes enumeration expensive, but it does not fix the authorization flaw and IDs leak through other endpoints. Log the authorization decision with principal, object ID, owner, and outcome so the detection above is possible. These map to the control codes used in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Per-request object-level authorization | Removes the IDOR flaw at the source: the server checks principal-to-object entitlement on every reference | - | A.5.15 Access control | PR.AA-05 Least privilege |
| Central role and function enforcement | Blocks vertical escalation by gating admin-scoped routes and actions rather than per-handler checks | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Log authorization decisions (principal, object, owner, outcome) | Supplies the telemetry every detection above depends on | ML2/ML3 event-log collection | A.8.15 Logging; A.8.16 Monitoring | DE.CM Continuous monitoring; DE.AE Adverse events |
| Indirect reference map / non-sequential IDs | Defense in depth: makes enumeration expensive; does not replace authorization | - | A.5.15 Access control | - |

## Honest limitations

- **No ownership data, no high-fidelity detection.** If the application does not log the object's owner alongside the principal, the proxy sees a successful IDOR as an ordinary `200`, and you are left with the coarse enumeration heuristics only.
- **One targeted read is invisible.** A single horizontal IDOR against a known high-value ID is one `200` with no sweep and no denial; without ownership correlation nothing distinguishes it from a legitimate access.
- **Logs cannot prove intent on IDs.** They cannot tell you a GUID was guessed versus known from a shared link or a referral header, nor whether a hashed or encoded indirect reference was reverse-engineered. The access pattern is the signal, not the identifier format.
- **Opaque IDs hide the sweep without fixing the flaw.** UUIDs defeat the numeric-ordering heuristic but the underlying missing authorization check remains, and the object still leaks if referenced elsewhere.
- **404-for-unauthorized moves the signal.** Apps that return `404` instead of `403` for objects the principal may not see (a reasonable anti-enumeration choice) shift the enumeration tell from the `403` cluster to the `404` cluster; tune the detector to whichever the app uses.
- **Legitimate cross-account access exists.** Support, admin, and integration principals read other owners' objects by design and will light up every detector here; they need an allowlist tuned to your environment.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access). The high-volume object-ID enumeration pattern also resembles [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) (Reconnaissance). ATT&CK has no dedicated IDOR or broken-access-control technique, so T1190 is the closest honest map for exploiting the authorization flaw.
- MITRE D3FEND: [D3-RAPA Resource Access Pattern Analysis](https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis) - baseline a principal's object-access pattern and alert on large deviations.
- Weakness and reference sources: [OWASP A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), [SigmaHQ web rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web), CWE-639 (Authorization Bypass Through User-Controlled Key) and CWE-285 (Improper Authorization).

**Scope note.** This is a defensive skill. It explains IDOR only to the depth needed to detect and mitigate it and deliberately provides no enumeration scripts, object-ID fuzzing, or request-replay tooling. UMBRASEC publishes defense, not offense.
