---
name: detect-business-logic-abuse
description: "Detection and hardening methodology for business logic abuse in web and API applications: workflow/state-machine bypass (skipping payment or approval steps) and pricing abuse (client-side price tampering, coupon cracking, discount stacking, refund and inventory-hold abuse). Requests are individually valid, so no payload signature fires; the skill teaches session-journey reconstruction, server-vs-client price reconciliation, and redemption-velocity baselining. Maps to MITRE ATT&CK T1190 and T1499, plus OWASP API Security Top 10 2023 API6 and OWASP Automated Threats (OAT). Log sources: application access logs (nginx/Apache, ALB/CloudFront), API gateway, WAF, and application transaction/audit logs. Use when investigating coupon or promo abuse, checkout or price manipulation, orders that skip payment, bonus or referral farming, inventory hold abuse, or building workflow-bypass and pricing-abuse detections for an e-commerce or SaaS app."
---

# Business Logic Abuse - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

Business logic abuse exploits the gap between how a workflow is *meant* to run and how the server *actually enforces* it. Every request is well formed and often authenticated, so WAF signatures, SQLi/XSS rules, and IDS pattern matching all pass it. You catch it at the application layer, not the packet layer, by asking three questions per session: did the steps happen in the allowed order, does the price the server charged match the price the catalog says, and is any single identity or IP redeeming codes or placing orders faster than a human could. Build detection on your application transaction logs and access logs keyed by session and user, not on generic network telemetry. There is no portable signature; the detection is specific to your app's intended state machine and pricing policy.

## What it looks like, defender view

In telemetry, workflow bypass appears as a request to a late-stage endpoint (for example `POST /api/order/confirm` or `/checkout/complete`) in a session that never carried the earlier steps (`/cart`, `/payment/authorize`), or with a state token that does not match the server's record of where the session should be. Pricing abuse appears as a checkout whose charged total is below the catalog floor: a quantity set to zero or a negative number, a client-submitted `price` or `amount` field that differs from the server catalog, several discount codes applied to one order, or a single-use coupon redeemed repeatedly. Code cracking appears as a burst of distinct coupon or gift-card codes tried from one session, user, or IP, most returning an "invalid code" response and a few returning success. None of these is malformed input, so the signal is semantic, not syntactic.

## Log sources and signals

Business logic lives in your application, so the authoritative signal is in application-layer logs, not host event logs.

- **Application transaction / audit logs** (the highest-value source): order lifecycle events, coupon and gift-card redemptions, cart mutations, refund events, and state transitions. Fields to carry: `session_id`, `user_id`/`account_id`, `order_id`, `event` (state name), `coupon_code`, `discount_amount`, `subtotal`, `charged_total`, `quantity`, `client_submitted_price`, `server_catalog_price`, and timestamp. If your checkout service does not already log the server-computed price alongside the client-submitted one, add that field first; it is the single best pricing-abuse signal.
- **Web / reverse-proxy access logs**: nginx `access.log`, Apache `access_log`, AWS ALB access logs, CloudFront/Cloudflare logs. Key fields: request method and path, HTTP status, `session`/auth cookie or JWT subject, source IP, `User-Agent`, `Referer`, bytes, and request time. These let you reconstruct the per-session sequence of endpoints and measure velocity.
- **API gateway logs**: AWS API Gateway access logging, Kong, Apigee, or Azure API Management. Carry the resolved endpoint, HTTP method, authenticated principal, and latency, so you can model the API call sequence and spot out-of-order or skipped calls.
- **WAF and bot-management logs**: AWS WAF (rate-based statement hits), Cloudflare, Akamai, or Imperva. Rate-based rule hits and low bot scores corroborate automated abuse, though they do not by themselves prove business logic abuse.

What normal looks like: a human checkout walks the funnel in order (`view -> cart -> address -> payment -> confirm`) over tens of seconds to minutes, applies at most one valid promo, and charges a total equal to subtotal minus a policy-bounded discount. Deviations from that shape are the anomaly.

## Detection approach

Alert in prose terms on three independent logics; combine them for confidence.

1. **State-machine / sequence violation.** Reconstruct each session's ordered list of endpoints from access or gateway logs, then compare against the allowed transition set for your funnel. Alert when a terminal step (confirm, complete, approve, grant) appears without its required predecessors in the same session, or when a server-side workflow token is missing or stale. This is application-specific; you must encode your own funnel.
2. **Price reconciliation.** For every completed order, compare `charged_total` against the server-recomputed expected total (`server_catalog_price * quantity - allowed_discount`). Alert on any mismatch, on `quantity <= 0`, on `discount_amount` exceeding the policy maximum, and on more discount codes applied than policy permits. A mismatch means the client, not the server, decided the price.
3. **Redemption and order velocity.** Count distinct coupon/gift-card codes attempted per session, user, and IP over a short window; a burst dominated by "invalid" responses is code cracking. Count single-use coupon successes per code; more than one is reuse abuse. Count orders per account and inventory holds that never convert to purchase to catch inventory-denial and bonus-farming patterns.

There is no portable signature for this class, and no tuned UMBRASEC rule ships for it yet. Point your implementation at public, maintained sources rather than inventing a one-size rule:

- SigmaHQ web rules for the access-log primitives (velocity, enumeration, status-code anomalies): https://github.com/SigmaHQ/sigma/tree/master/rules/web and the hunting variants under https://github.com/SigmaHQ/sigma/tree/master/rules-threat-hunting/web
- OWASP API Security Top 10 2023, API6:2023 Unrestricted Access to Sensitive Business Flows: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
- OWASP Automated Threats to Web Applications (OAT handbook) for the named abuse patterns, including OAT-002 Token Cracking, OAT-010 Card Cracking, OAT-012 Cashing Out, and OAT-021 Denial of Inventory: https://owasp.org/www-project-automated-threats-to-web-applications/
- OWASP CRS / Coraza for WAF-side rate and anomaly primitives: https://coreruleset.org/
- AWS WAF rate-based rule statements for enforcement at the edge: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html
- MITRE D3FEND countermeasures listed in the final section.

## Threat hunt

Hypothesis-driven, run over a long window against transaction and access logs:

1. **Did any order skip a step?** List every `order confirm`/`complete` transaction, join back to the same `session_id` in access logs, and flag sessions whose endpoint history is missing the required payment-authorize step. Rank by order value.
2. **Did the client set the price?** Pull all orders where `charged_total` is below `server_catalog_price * quantity`, or where `quantity <= 0`, or where `discount_amount / subtotal` exceeds the policy ceiling. Each hit is a candidate price-tampering or stacked-discount event.
3. **Is a code being cracked?** Group redemption attempts by `session_id` and source IP over 10 minutes; flag groups with many distinct `coupon_code` values and a high invalid-to-valid ratio. Then pivot to any `coupon_code` marked single-use with more than one success.
4. **Is one identity farming?** Rank accounts and IPs by new-account signups, referral bonuses granted, and inventory holds that never convert. Low-and-slow farming spread across many fresh accounts is the hard case; look for shared payment instruments, device fingerprints, or source ASNs tying the accounts together.

## Hardening

The durable fix is server-side enforcement: the client must never be trusted for state, price, or entitlement. Recompute price on the server, enforce the workflow state machine server-side with a non-guessable per-session token, make coupons atomically single-use at the datastore, and rate-limit sensitive business flows per identity and per IP. The control codes below are grounded in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); Essential Eight is left blank because its eight strategies target OS and admin hardening, not application business logic, and no single strategy maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Server-side authorization and workflow-state enforcement | Rejects terminal steps reached out of order and entitlements the user does not hold | - | A.5.15 Access control; A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Server-side price and discount recomputation | Ignores client-submitted price/quantity; caps and de-duplicates discounts at the server | - | A.5.15 Access control | PR.AA-05 Least privilege |
| Transaction logging and monitoring of sensitive flows | Records the fields detection needs and continuously watches redemptions, prices, and sequences | - | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM; DE.AE |

## Honest limitations

Every request in this attack is syntactically valid and often from a real, authenticated account, so signature and anomaly tools tuned for malformed input see nothing. Detection depends on ground truth that only the application owner has: the intended state machine and the pricing policy. Encode those wrong and you alert on legitimate flows (a saved cart resumed days later, a valid stacked promotion, a bulk B2B order) or miss the abuse entirely. Velocity logic is evaded by low-and-slow abuse distributed across many accounts and residential-proxy IPs, where no single identity crosses a threshold; correlating those requires device fingerprinting or payment-instrument linkage you may not collect. If the checkout service does not log the server-computed price next to the client-submitted one, price reconciliation is impossible until you add the field. Treat every rule as environment-specific, baseline in report-only mode first, and leave the final verdict to an analyst who knows the business flow.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access) is the closest Enterprise mapping, since business logic flaws are exploited through the public-facing application; [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) loosely covers the inventory-hold and resource-exhaustion variants, though "denial of inventory" is a business outcome rather than true endpoint resource exhaustion. ATT&CK Enterprise has no dedicated business-logic technique, so the OWASP API Security Top 10 2023 (API6) and OWASP Automated Threats (OAT) taxonomies above map the behaviour more precisely.
- MITRE D3FEND: [D3-UBA User Behavior Analysis](https://d3fend.mitre.org/technique/d3f:UserBehaviorAnalysis/), [D3-RAPA Resource Access Pattern Analysis](https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis/), and [D3-ISVA Inbound Session Volume Analysis](https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis/) are the countermeasures that align with the sequence, pricing, and velocity logics respectively.
- Public rule sources: SigmaHQ web rules, OWASP API Top 10 2023, OWASP Automated Threats handbook, OWASP CRS, and AWS WAF rate-based statements, all linked in Detection approach above.

**Scope note.** This is a defensive skill: it explains business logic abuse only to the depth needed to detect and mitigate it, names no exploitation steps, and ships no offensive tooling.
