---
name: defend-open-redirect
description: "Defensive methodology for open redirect (CWE-601) abuse, where a link on a trusted domain sends the victim off-site via a redirect parameter, used to cloak phishing behind your brand (MITRE ATT&CK T1566.002, T1204.001) and to steal OAuth authorization codes and tokens through an attacker-controlled redirect_uri (T1528). Keys off web server, reverse-proxy, and WAF access logs (nginx, Apache, IIS), 30x responses with an off-domain Location header, IdP sign-in logs (Entra ID, Okta), and Defender for Office 365 UrlClickEvents. Gives the defender view, signal-carrying log fields, a redirect-endpoint hunt, and allowlist and token-leak hardening. Use when hardening a redirect, returnUrl, or next parameter, reviewing OAuth redirect_uri validation, hunting phishing links cloaked by your own domain, investigating an off-site Location header, or preventing code and token leakage via Referer."
---

# Open Redirect - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

An open redirect is an endpoint on your own domain that takes a destination from user input and sends the browser there without checking it. Attackers do not exploit it to break into your app; they use it so a phishing link reads as `https://trusted.example.com/login?returnUrl=https://evil.tld` and inherits your reputation, your TLS, and your email-gateway allowlisting. The same flaw in an OAuth or OIDC flow leaks authorization codes and access tokens when a loosely matched `redirect_uri` or a trailing open redirect bounces the credential to an attacker host. Fix it by never redirecting to a caller-supplied absolute URL: map an opaque key to a server-side destination, or enforce an exact-host allowlist after full canonicalization. Detect it by parsing redirect endpoints out of web and proxy logs and flagging off-domain targets.

## What it looks like, defender view

In telemetry this shows up as a request to one of your redirect endpoints carrying a target parameter that resolves off-domain: an absolute URL (`?next=https://evil.tld`), a protocol-relative URL (`?url=//evil.tld`), an authority trick (`?r=https://trusted.example.com@evil.tld`), or an encoded or double-encoded variant (`%2F%2Fevil.tld`, `%252f`). The matching response is a 301/302/303/307/308 whose `Location` header points to that external host. In the OAuth variant the signal is a `redirect_uri` that does not exactly match a registered value, or a `Referer` header on a downstream request that still carries `code=` or `access_token=`. When the link arrived by email, the click chain in a mail-security log traverses your domain first and then lands on an unrelated host.

## Log sources and signals

- **Web server access logs** - nginx `access.log`, Apache `access_log`, IIS W3C logs. Confirm the log format records the full query string (`cs-uri-query` in IIS, `$request`/`$args` in nginx, `%q` in Apache) and, where possible, the response `Location` header. Default formats often drop both, which is the first gap to close.
- **Reverse proxy, WAF, and CDN logs** - Cloudflare, AWS WAF, Akamai, F5, Azure Front Door. These usually capture the decoded query string and sometimes the upstream `Location`, and they sit in front of every app, so they are the best single vantage point.
- **IdP and authorization-server logs** - Entra ID exposes the per-request `redirect_uri` only where your own authorization server logs it; on the Entra side, audit the registered reply URLs through the Entra audit log "Update application" events or the Microsoft Graph `redirectUris` property and flag wildcards or redirect endpoints. Okta System Log records OAuth authorization requests as `app.oauth2.authorize` (and `app.oauth2.as.authorize` for a custom authorization server) events, whose `debugContext` carries the request details; compare the requested redirect against the registered allowlist.
- **Mail security / URL-click telemetry** - Microsoft Defender for Office 365 advanced hunting tables `UrlClickEvents` and `EmailUrlInfo`, plus gateway click logs (Proofpoint URL Defense, Mimecast). These reveal links that bounce through your trusted domain to a final external destination.
- **Fields that carry the signal.** Redirect parameter names: `url`, `next`, `redirect`, `redirect_uri`, `returnUrl`, `return`, `returnTo`, `dest`, `destination`, `target`, `continue`, `goto`, `callback`, `r`, `u`, `to`, `out`. Response field: the `Location` header host. Request field: the `Referer` header on any step that follows an auth callback.
- **What normal looks like.** Legitimate redirects resolve to a same-origin relative path or to a small, fixed set of partner hosts. The anomaly is an absolute off-domain host, a `//` or `@` authority, a non-`https` scheme (`javascript:`, `data:`), or a target that only appears after decoding.

## Detection approach

Extract every request to your known redirect endpoints from web, proxy, or WAF logs, fully URL-decode the destination parameter (decode twice to defeat double-encoding), and parse out the host. Alert where the resolved host is not same-origin and not on your allowlist, where the value begins `//` or contains an `@` before the host, or where the scheme is not `http(s)`. In parallel, alert on 30x responses whose `Location` host is off-domain and not allowlisted. For the OAuth variant, alert when an authorization request presents a `redirect_uri` that is not an exact match for a registered value, and on any downstream `Referer` carrying `code=` or `access_token=` to a third-party host. For the phishing variant, pivot flagged targets into Defender for Office 365 `UrlClickEvents` to see whether the links arrived by email as a campaign.

No tuned UMBRASEC rule ships for this threat yet. For public, maintained detection content, browse the webserver and proxy rule categories in the SigmaHQ repository at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and adapt what fits your log format; confirm any rule against your own data before trusting it. Build the logic above directly in your SIEM query language rather than copying an unverified rule.

## Threat hunt

Hypothesis: an attacker is abusing one of our redirect endpoints to cloak phishing behind our domain, or to bounce an OAuth code or token to a host they control.

1. **Inventory your own endpoints.** Grep the application source for redirect sinks (`res.redirect`, `sendRedirect`, `RedirectToAction`, `HttpResponseRedirect`, `header("Location: ...")`, framework `return redirect(...)`) and list the parameters that feed them. You cannot hunt an endpoint you have not enumerated.
2. **Pull 30 to 90 days** of web and WAF logs for requests to those endpoints. Decode the destination parameter once, then again, and extract the host.
3. **Bucket by target host.** Same-origin and allowlisted partners are baseline. Flag off-domain hosts, protocol-relative `//`, userinfo `@` tricks, raw IP-literal targets, punycode or homoglyph lookalikes of your domain, and hosts seen for the first time in the window.
4. **For OAuth and OIDC**, audit the registered redirect URIs first (Entra app registration reply URLs via the audit log or Graph `redirectUris`, Okta app settings) and treat any wildcard or on-domain open-redirect endpoint as a finding. Where your authorization server logs the per-request redirect (Okta `app.oauth2.authorize` events, or a self-hosted server such as Keycloak or Auth0), compare each requested redirect to the registered allowlist. Search web logs for `Referer` headers leaking `code=` or `access_token=` off-domain.
5. **Pivot the flagged targets** into Defender for Office 365 `UrlClickEvents` and the mail gateway to establish whether they arrived as emailed links, which turns a single anomaly into a campaign.
6. **Rank** by whether the redirect carried a credential (code or token) and whether the destination resembles a credential-harvest page; a lone redirect that leaked a token outweighs any volume signal.

## Hardening

The durable fix is to remove caller control over the destination. Prefer an indirect map: accept an opaque key or index from the client and look up the real URL in a server-side table of approved destinations, so untrusted input never becomes a URL. Where a URL genuinely must be accepted, canonicalize and fully decode it first, then require an exact host match against an allowlist (match the full host, never a substring or suffix test, which `evil-trusted.tld` and `trusted.tld.evil.tld` defeat), require the `https` scheme, and reject protocol-relative values, userinfo `@` authorities, and non-`http(s)` schemes. Default to returning a relative path only, stripping any scheme and host. Show an interstitial "you are leaving this site" page for any off-domain redirect.

For OAuth and OIDC, register exact `redirect_uri` values with no wildcards and enforce exact string matching, as required by the OAuth 2.0 Security Best Current Practice (RFC 9700), which tightens the looser registration rules of RFC 6749; use PKCE and bind `state`. To stop credential leakage through the browser, set `Referrer-Policy: no-referrer` or `strict-origin-when-cross-origin` on authenticated and callback responses so an `access_token` or `code` cannot ride a `Referer` header to a downstream host.

The authoritative control guidance is the OWASP Unvalidated Redirects and Forwards Cheat Sheet, cited below.

## Honest limitations

- **DOM-based open redirects are invisible server-side.** When the destination is read from the URL fragment (`#`) or set by client JavaScript, it never reaches the server, so web and WAF logs show nothing. Catch these with client telemetry, a Content-Security-Policy report endpoint, or real-user monitoring, not access logs.
- **Logs may not carry the target.** Default server log formats often truncate the query string and rarely log the response `Location`, so the destination is simply absent until you change the format. Opaque or encrypted redirect tokens also hide the destination from logs by design.
- **Low volume hides in the noise.** A single phishing link in a single email will not trip a volume threshold; the value is in the allowlist-mismatch logic, not in counting.
- **Validation bugs defeat naive detection.** Suffix or substring allowlist checks pass `trusted.tld.evil.tld`; detecting the bypass requires modelling the same canonicalization the app should have done, not a simple regex over the parameter.
- **Newly registered lookalikes look benign** without threat intelligence; an off-domain host that resolves cleanly and has valid TLS will not stand out on its own.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1566.002 Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) and [T1204.001 User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/) for the brand-cloaked phishing use; [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) for the OAuth code and token leak.
- MITRE D3FEND: [D3-UA URL Analysis](https://d3fend.mitre.org/technique/d3f:URLAnalysis/) for inspecting redirect targets, and [D3-ACH Application Configuration Hardening](https://d3fend.mitre.org/technique/d3f:ApplicationConfigurationHardening/) for the allowlist and exact `redirect_uri` registration.
- Reference and public rule sources: [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html); [CWE-601 URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html); [OAuth 2.0 Security BCP, RFC 9700](https://datatracker.ietf.org/doc/rfc9700/); the webserver and proxy rule categories at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

**Scope note.** This is a defensive skill. It explains open redirect only to the depth needed to detect and mitigate it and ships no redirect-abuse, phishing, or token-theft tooling. UMBRASEC publishes defense, not offense.
