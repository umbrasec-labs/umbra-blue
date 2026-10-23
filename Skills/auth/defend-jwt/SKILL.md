---
name: defend-jwt
description: "Defensive methodology against JSON Web Token (JWT) forgery and verification bypass: the alg:none downgrade, RS256-to-HS256 key confusion, unverified signatures, and missing claim checks that let an attacker mint a token your app will trust (MITRE ATT&CK T1606 Forge Web Credentials, then T1550.001 Use Alternate Authentication Material: Application Access Token). Signals live in application and API-gateway logs, WAF logs, and auth-service logs: the decoded JWT header alg and kid, the iss/aud/exp claims, and signature-verification failures. This skill gives the defender view of each bypass, the exact fields to log and alert on, a hypothesis-driven hunt, and library and key-management hardening mapped to ISO 27001:2022 and NIST CSF 2.0. Use when hardening JWT or bearer-token validation, reviewing a JWT auth flow, hunting for alg:none or key-confusion forgery, triaging a spike in JWT signature failures, or deciding how to rotate signing keys."
---

# JWT Forgery and Verification Bypass - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

JWT bypasses almost always live in the verification step, not the token. Log the decoded JWT header `alg` and `kid` and the validation outcome at whatever component actually verifies the signature (API gateway, auth middleware, or app), then alert on three things: a header with `alg` set to `none`/`None`/`NONE` or empty, an `alg` that disagrees with what this issuer is supposed to use (an `HS256` token where you only ever issue `RS256` is the key-confusion tell), and a burst of signature-verification failures from one source or against one account. Harden by pinning an explicit algorithm allowlist, keeping signing-key material separated by algorithm, validating `iss`/`aud`/`exp`/`nbf` server-side on every request, and rotating keys on a schedule with a `kid` header.

## What it looks like, defender view

A forged token is designed to look ordinary, so the signal is in the header and the verification result rather than the payload. In `alg:none`, the attacker submits a token whose header declares no signing algorithm and whose signature segment is empty; a verifier that honors `none` accepts it without checking anything, so you see a successful authentication carrying an unsigned token. In key confusion, a public verification key (meant for an asymmetric algorithm such as `RS256`) is fed to a symmetric verifier (`HS256`) that treats the public key bytes as the shared secret; the token the app issues is `RS256`, but the one that authenticates a session is suddenly `HS256`. A third pattern is simple non-verification: the service decodes the token and reads claims but never checks the signature, in which case you will see tokens with a malformed or stale signature still authenticating. All three present as a valid-looking session whose header or signature state does not match your issuance baseline. This skill does not show how to craft any of these tokens.

## Log sources and signals

The signal exists only where something logs the token header and the verification result. Few environments do this by default, so the first defensive step is often to add it.

- **Auth middleware / library telemetry.** The verifying library is the ground truth. `express-jwt` and `jsonwebtoken` throw `JsonWebTokenError: invalid signature` and `JsonWebTokenError: invalid algorithm`; PyJWT raises `InvalidSignatureError`, `InvalidAlgorithmError`, and `DecodeError`; Spring Security / Nimbus JOSE raises `BadJwtException` and signature-verification failures. Log these as structured events with the decoded header `alg` and `kid`, the `iss`/`aud`/`sub` claims, and the outcome.
- **API gateway authorizer logs.** AWS API Gateway JWT authorizers, Azure API Management `validate-jwt`, Kong `jwt` plugin, and Apigee `VerifyJWT` all emit validation success or failure and can surface the claims. These sit in front of the app and are the best single chokepoint to instrument.
- **Identity provider logs.** Entra ID sign-in logs, AWS Cognito, Auth0 tenant logs, and Okta System Log record token issuance events; take the algorithms and keys each issuer signs with from its OIDC discovery metadata (`id_token_signing_alg_values_supported`) and its JWKS, which gives you the issuance baseline to compare live traffic against.
- **WAF and reverse-proxy logs.** AWS WAF, Cloudflare, and Azure WAF can match on the `Authorization: Bearer` header. The first base64url segment of a JWT is the header; `{"alg":"none"}` encodes to a header segment beginning `eyJhbGciOiJub25lI`, and the case variants `None`/`NONE` begin `eyJhbGciOiJOb25lI` and `eyJhbGciOiJOT05FI`. These prefixes are a cheap, if evadable, gateway signal.

Fields you will lean on: the decoded header `alg` (the downgrade and confusion signal), `kid` (which key was claimed; unknown or missing `kid` is suspicious), `iss` and `aud` (wrong or absent values indicate a token minted for another context), `exp`/`nbf`/`iat` (expiry handling), and the verifier outcome plus error class.

## Detection approach

Detect at the verifier, in three layers. **Normalize and inspect the header:** decode the first JWT segment and alert when `alg` is `none` in any casing or empty, which no correct issuer produces. **Compare `alg` to your issuance baseline:** maintain the set of algorithms each `iss` is known to sign with (from the IdP logs above) and alert on any deviation, because an `HS256` token from an issuer that only mints `RS256` is the key-confusion signature even when the signature itself verifies. **Threshold verification failures:** count `invalid signature` / `invalid algorithm` outcomes grouped by source IP, account, and `kid`, and alert on bursts that stand out from your baseline of expired-token noise. A decoy consideration also helps: if you publish a `kid` that maps to no live key, any token presenting it is forged by construction.

There is no tuned UMBRASEC rule for this threat yet. For public, maintained starting points, see the SigmaHQ repository's proxy and web categories at [github.com/SigmaHQ/sigma/tree/master/rules/web](https://github.com/SigmaHQ/sigma/tree/master/rules/web) and the webserver generic category under the same tree; JWT-specific logic is usually written against your own verifier telemetry rather than shipped as a generic Sigma rule, so treat these as scaffolding. MITRE D3FEND's [Message Authentication (D3-MAN)](https://d3fend.mitre.org/technique/d3f:MessageAuthentication/) is the countermeasure these detections enforce. Ground the validation requirements themselves in [RFC 8725, JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725) and the [OWASP JSON Web Token cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html).

## Threat hunt

For the attacker who forges one high-value token and uses it quietly, the failure-threshold rule will not fire, because a correctly forged token verifies cleanly. Hunt instead:

1. Over a long window, pull every authenticated request and project the decoded header `alg` and `kid`. Any row where `alg` is `none`/empty is a finding; triage it directly.
2. Per `iss`, build the distribution of `alg` values actually seen on the wire and compare it to the algorithms that issuer is configured to sign with in the IdP logs. A low-volume `HS256` tail under an `RS256`-only issuer is the key-confusion hunt result.
3. Pull the set of `kid` values presented by clients and diff it against the live keys in your JWKS. Tokens citing a `kid` that was never published, or one retired before the token's `iat`, warrant investigation.
4. Rank surviving findings by the privilege of the `sub` and `aud`: a single anomalous token scoped to an admin audience outweighs any volume signal.

## Hardening

Shrink the window in which a forged or downgraded token is ever accepted. Mappings below use control codes grounded in the UMBRASEC guide ([identity-and-access.html](https://umbrasec.dev/guide/identity-and-access.html), [foundation.html](https://umbrasec.dev/guide/foundation.html)); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Explicit algorithm allowlist | Pin the verifier to the exact expected algorithm(s) so `none` and unexpected algorithms are rejected before any signature math runs | - | A.8.5 Secure authentication | PR.AA-03 Users authenticated |
| Separate key material by algorithm | Never let a verifier accept an asymmetric public key as a symmetric secret; bind each key to one algorithm, which removes the RS256-to-HS256 confusion path | - | A.8.5 Secure authentication | PR.AA-03 Users authenticated |
| Full claim validation | Verify `iss`, `aud`, `exp`, and `nbf` server-side on every request, not just the signature, so a validly signed token for another context is still rejected | - | A.8.5 Secure authentication | PR.AA-03 Users authenticated |
| Strong secrets and keyed rotation | Use high-entropy signing keys, publish a `kid`, and rotate signing keys on a schedule so a leaked key has a short useful life | - | A.5.17 Authentication information | PR.AA-01 Identities and credentials |
| Short TTL and least-privilege scope | Keep token lifetimes short and audiences and scopes minimal so a forged token buys little and expires fast | - | A.5.18 Access rights | PR.AA-05 Least privilege |
| Patch JWT libraries | Keep signing and verification libraries current; several alg-confusion and signature-skip flaws were library defects fixed upstream | Patch applications | A.8.8 Technical vulnerabilities | PR.PS Platform Security |

## Honest limitations

This approach depends on logging the token header and verification outcome, which most stacks do not do out of the box; without that instrumentation there is no signal to hunt. A correctly forged token that verifies under a weak or leaked symmetric secret produces no failure event and will only surface through the `alg`-versus-baseline hunt or through claim anomalies, not through failure thresholds. The WAF prefix match on `alg:none` is trivially evaded by whitespace or encoding variation in the header JSON, so it is a backstop, not a control. And none of this replaces fixing the verifier: a library or configuration that honors `none` or accepts a mismatched key is the actual vulnerability, and detection only buys time until it is patched and the algorithm allowlist is enforced.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1606 Forge Web Credentials](https://attack.mitre.org/techniques/T1606/) (minting the token), then [T1550.001 Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) (using it to authenticate).
- MITRE D3FEND: [Message Authentication (D3-MAN)](https://d3fend.mitre.org/technique/d3f:MessageAuthentication/) enforces sender authenticity and integrity via signatures and MACs; [Credential Rotation (D3-CRO)](https://d3fend.mitre.org/technique/d3f:CredentialRotation/) and [Certificate Rotation (D3-CERO)](https://d3fend.mitre.org/technique/d3f:CertificateRotation/) cover signing-key rotation.
- Standards and public rule sources: [RFC 8725 JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725), [RFC 7519 JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519), [OWASP JSON Web Token cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html), [SigmaHQ web rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web).

**Scope note.** This is a defensive skill. It explains JWT forgery and verification bypass only to the depth needed to detect and mitigate it and deliberately provides no token-forging or exploitation tooling. UMBRASEC publishes defense, not offense.
