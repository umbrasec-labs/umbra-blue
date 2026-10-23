---
name: detect-web-race-condition
description: "Detection and hunting methodology for web application race conditions: limit-overrun, multi-endpoint, single-endpoint, and time-sensitive flaws abused with last-byte-sync (HTTP/1.1) and single-packet (HTTP/2) request bursts to redeem a coupon or gift card twice, overdraw a balance, or defeat login, OTP, and MFA rate limits (MITRE ATT&CK T1190, and T1110 when the race defeats auth throttling). Works from reverse-proxy and load-balancer access logs, WAF logs, application event logs, and database error logs. Gives the burst and duplicate-success signatures, a hypothesis-driven hunt, and application-layer hardening. Use when investigating duplicate redemptions or double-spends, triaging a burst of near-simultaneous requests to one endpoint, hunting for single-packet or last-byte-sync race attacks, explaining why an idempotent endpoint produced two successes, or hardening payment, coupon, and auth flows against concurrency abuse."
---

# Web Race Conditions - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

A web race condition is a many-at-once collision inside a narrow time window between the moment an application checks a limit and the moment it commits the result. An attacker fires a burst of near-simultaneous requests so several of them pass the same check before any of them writes, then one coupon is redeemed five times, one gift-card balance is spent twice, or a login or OTP endpoint is hit faster than its rate limiter can count. The attack is overwhelmingly a second-order signal: you rarely see the race itself, you see its footprint. Watch for a tight burst of requests to one sensitive endpoint on a single connection, more successful responses than the business logic should ever allow, and a spike of database uniqueness or serialization errors on endpoints that are supposed to be idempotent.

## What it looks like, defender view

In telemetry the attack presents as an abnormally tight cluster of requests to a state-changing endpoint, often several within a few milliseconds and frequently over one HTTP/2 connection (the single-packet technique) or several HTTP/1.1 connections, each with its final byte withheld and then released together (last-byte synchronization). Downstream you see the business-logic effect: a discount code or gift card that produced two or more `200` successes, a wallet or ledger with duplicate credit entries, or an authentication throttle that logged more attempts in a window than its own limit permits. A well-built backend that catches the collision at the last line of defense leaves a different but equally useful trace: a burst of unique-constraint violations or transaction serialization and deadlock failures. This skill explains the mechanism only as far as detection and hardening require and ships no race tooling.

## Log sources and signals

The signal lives at the edge and in the application, not in the OS. Collect and correlate:

- **Reverse-proxy and web-server access logs** (nginx, Apache httpd, HAProxy). In nginx, log `$msec` (seconds with millisecond resolution; `$time_iso8601` has only one-second resolution), `$request_time` and `$upstream_response_time`, `$connection` (the connection serial), `$connection_requests` (how many requests rode that connection), and the HTTP version. A single `$connection` carrying many requests to one sensitive path within sub-second spacing is the core burst signature; HTTP/2 makes this cheap because the final frames of many concurrent streams can be delivered in a single TCP packet.
- **Cloud load-balancer and CDN access logs** (AWS ALB access logs, Cloudflare HTTP request logs, Azure Front Door). Key fields: client IP, timestamp to the millisecond, target/origin processing time, request processing time, and the matched request URL. These are your best source when TLS terminates at the edge.
- **WAF logs** (AWS WAF, Azure WAF, Cloudflare, ModSecurity audit log). Rate-based rule counters and per-rule match counts show when many requests to one URI arrived inside the rule's evaluation window.
- **Application event logs.** The high-value source. Log every state transition on sensitive flows (coupon redeemed, balance debited, order confirmed, OTP verified) with a correlation or idempotency key, the acting account, and the outcome. More than one success per logical resource is the anomaly.
- **Database engine logs.** Uniqueness collisions and concurrency aborts are the "backend caught it" signal: PostgreSQL `SQLSTATE 23505` (unique_violation), `40001` (serialization_failure), and `40P01` (deadlock_detected); MySQL/MariaDB error `1062` (ER_DUP_ENTRY) and `1213` (ER_LOCK_DEADLOCK). A spike of these on an endpoint that should never legitimately collide is a near-certain race footprint.

Know your baseline. Normal users retry and double-click, so a couple of close requests are routine. What is not routine is tens of requests to a payment, redemption, or auth endpoint inside one connection and one short window, or two committed successes for a one-time resource.

## Detection approach

Alert on three independent, layered conditions rather than any single one.

1. **Request burst to a sensitive endpoint.** Over proxy or load-balancer logs, group by connection identifier (or client IP where no connection ID exists) and endpoint, bucket by a short window (start at 200 ms), and flag when a single source issues an abnormal count to a state-changing path. HTTP/2 connections carrying many concurrent streams to one path deserve extra weight because that is the single-packet shape.
2. **Excess successes.** From application logs, alert when the same logical resource (coupon code, gift-card ID, account balance operation, password-reset token) records more than one success inside a short window. This is the most precise signal because it keys on business logic, not traffic shape.
3. **Backend collision spike.** From database logs, alert on a rise in `23505` / `1062` uniqueness violations or `40001` / `40P01` / `1213` serialization and deadlock aborts on endpoints that are meant to be idempotent.

No tuned UMBRASEC rule ships for this threat yet, and there is no single canonical community Sigma rule for the single-packet attack, because the decisive evidence is application-specific. Build detections 1 and 3 in your SIEM against the fields above, and point generic web-anomaly coverage at the maintained public sources rather than inventing a rule:

- SigmaHQ web rule directory for proxy and web-server analytics: https://github.com/SigmaHQ/sigma/tree/master/rules/web
- PortSwigger Web Security Academy, Race Conditions (authoritative description of the attack classes and their server-side signals): https://portswigger.net/web-security/race-conditions
- Vendor rate-based and anomaly analytics you likely already own: AWS WAF rate-based rules (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html) and Cloudflare Rate Limiting.
- MITRE D3FEND User Behavior Analysis for the velocity and duplicate-success modeling: https://d3fend.mitre.org/technique/d3f:UserBehaviorAnalysis/

## Threat hunt

Hypothesis: an attacker used a near-simultaneous request burst to defeat a one-time check on a sensitive endpoint.

1. Enumerate your state-changing, limit-enforcing endpoints first: redemption, checkout and payment confirmation, balance transfer, referral and signup bonus, password reset, OTP and MFA verification, and login.
2. In proxy or load-balancer logs, for each endpoint, group by connection ID (or client IP) and count requests per 200 ms bucket. Rank by the highest burst counts. On nginx, `$connection_requests` on sensitive paths is a fast first cut.
3. For the top bursts, pivot into application logs on the correlation or idempotency key: did more than one request commit a success for the same resource? Are there duplicate ledger, redemption, or credit rows?
4. Independently, query database logs over the same window for clusters of `23505`/`1062` or `40001`/`40P01`/`1213` tied to those endpoints. A collision spike without a matching application "double success" means the backend held, but the attempt happened and the endpoint is exposed.
5. For HTTP/2 traffic, look for a single connection opening many concurrent streams to one path, and for the timing tells PortSwigger documents: a slow first request followed by a tight cluster, or persistently jittery response times on one endpoint that hint at backend contention.

## Hardening

Race conditions are fixed in the application, not at the perimeter, so treat a confirmed one as a technical vulnerability to remediate, not merely to alert on. The authoritative prevention guidance is PortSwigger's: make the whole check-and-commit sequence atomic inside a single datastore transaction; add database integrity constraints (column uniqueness, balance-non-negative checks) as defense in depth so the datastore itself rejects the second writer; keep the authoritative state in one place and do not use one storage layer (a session) to guard a limit enforced in another (the database); apply an idempotency key so a replayed or raced request resolves to one effect; and take a pessimistic lock (`SELECT ... FOR UPDATE`) or optimistic concurrency version check on the contended row. Enforce auth and OTP rate limits at the datastore or a shared atomic counter, never only in per-session state that parallel requests can each read as "still under the limit."

Framework grounding: the UMBRASEC [detection-and-response guide](https://umbrasec.dev/guide/detection-and-response.html) maps the logging that makes this visible to ISO 27001:2022 A.8.15 (Logging) and NIST CSF 2.0 DE.CM (continuous monitoring), and the monitoring and alerting to A.8.16 (Monitoring activities) and DE.AE (adverse event analysis). The fix itself is ordinary technical-vulnerability management (ISO 27001:2022 A.8.8). A framework table is omitted here because the decisive controls are application-logic patterns the SMB guide does not enumerate, and a table built past its evidence would overstate the mapping.

## Honest limitations

- **Second-order by nature.** You usually detect the consequence (duplicate success, constraint spike), not the race. If exactly one request wins, the backend holds, and no constraint fires, there may be no durable trace at all.
- **Low-volume bursts hide.** A limit-overrun that needs only two or three parallel requests will not exceed a count threshold tuned for obvious floods. Favor the "more than one success per resource" signal, which does not depend on volume.
- **Edge visibility gaps.** When TLS terminates at a CDN and logs are sampled or aggregated, per-connection and per-stream granularity can be lost, blurring the single-packet shape. Confirm your log pipeline keeps millisecond timestamps and a connection identifier.
- **Protocol differences.** HTTP/1.1 last-byte synchronization and HTTP/2 single-packet bursts look different on the wire; a detection tuned for one may miss the other.
- **Benign look-alikes.** Impatient users, double-clicks, client retries, and legitimate bulk tools produce close-spaced requests. Baseline per endpoint and alert on the business-logic violation, not traffic shape alone.

Baseline in report-only mode before enforcing, and present findings as evidence for an analyst's decision, not as an automated verdict.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access); [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) (Credential Access) when the race is used to defeat login, OTP, or MFA rate limiting.
- MITRE D3FEND: [D3-ACH Application Configuration Hardening](https://d3fend.mitre.org/technique/d3f:ApplicationConfigurationHardening/) for the atomic-transaction, constraint, and idempotency fixes; [D3-UBA User Behavior Analysis](https://d3fend.mitre.org/technique/d3f:UserBehaviorAnalysis/) for the velocity and duplicate-success detection.
- Public rule and reference sources: SigmaHQ web rules (https://github.com/SigmaHQ/sigma/tree/master/rules/web); PortSwigger Web Security Academy Race Conditions (https://portswigger.net/web-security/race-conditions).

**Scope note.** This is a defensive skill: it explains web race conditions only as far as detection, hunting, and hardening require, and ships no race tooling, single-packet harness, or exploit steps.
