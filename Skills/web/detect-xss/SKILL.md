---
name: detect-xss
description: "Detection, hunting, and hardening methodology for Cross-Site Scripting (XSS), where attacker-controlled script executes in a victim's browser session on a trusted origin (CWE-79; MITRE ATT&CK T1059.007, T1189 for stored XSS served to visitors, T1539 as the usual objective). Primary signals come from Content-Security-Policy violation reports, WAF logs (OWASP CRS 941xxx, AWS WAF, Azure Application Gateway), web server access logs, and SAST findings on DOM sinks. Gives the method for catching reflected, stored, and DOM-based XSS and closing output-encoding and CSP gaps, pointing to public rule sources. Use when investigating a suspected XSS report, triaging CSP violation reports, writing or tuning XSS detections, hunting for DOM sinks or script injection in access logs, or hardening a web app with a strict CSP and output encoding."
---

# Cross-Site Scripting - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

XSS executes attacker-controlled JavaScript inside a victim's browser on a trusted origin, usually to steal the session cookie, perform actions as the user, or keylog credentials. Deploy a strict, nonce-or-hash Content-Security-Policy first in `Report-Only` mode, collect the violation reports to a logging endpoint, and treat a new `blocked-uri` or an inline `script-sample` containing your own page content as the primary signal. Pair that with WAF XSS rules on the request side and SAST on dangerous DOM sinks. CSP reporting is the one control that gives you telemetry for DOM-based XSS, which otherwise leaves no server-side trace.

## What it looks like, defender view

Reflected and stored XSS show up server-side as request parameters or stored fields carrying `<script>`, `javascript:`, `onerror=`, `onload=`, `<svg onload=`, or their URL- and HTML-entity-encoded forms, landing in a response that is later rendered. Stored XSS is worse: the payload is written once and served to every visitor, so the attack presents as normal traffic from many clients after a single poisoned write. DOM-based XSS never touches the server with a recognisable payload; the injection happens entirely in client JavaScript when untrusted data (a URL fragment, `location.search`, `postMessage`) reaches a sink such as `innerHTML` or `document.write`. Once script runs, the observable outcome is session-cookie theft, requests to attacker collection endpoints, or new DOM elements the application never emits. None of these is offensive detail; they are the traces a defender catches.

## Log sources and signals

- **CSP violation reports** via the `report-to` directive (and `report-uri` for wider browser support) to a collector. Key fields in a `report-uri` report: `document-uri`, `violated-directive`, `effective-directive`, `blocked-uri`, `source-file`, `line-number`, `disposition`, and `script-sample`; the `report-to` (Reporting API) body uses `documentURL`, `effectiveDirective`, `blockedURL`, `sourceFile`, `lineNumber`, `disposition`, and `sample`. The sample is populated only when the policy sets `'report-sample'`. A Trusted Types violation arrives the same way with `violated-directive: require-trusted-types-for 'script'`. Normal baseline: a tuned `Report-Only` policy produces a steady trickle of reports caused by browser extensions and ad/analytics scripts; the anomaly is a new `blocked-uri`, or an inline `script-sample` that echoes your own input.
- **WAF logs.** OWASP Core Rule Set XSS rules fire in the `941xxx` range from `REQUEST-941-APPLICATION-ATTACK-XSS.conf`. AWS WAF `AWSManagedRulesCommonRuleSet` emits labels `CrossSiteScripting_BODY`, `CrossSiteScripting_QUERYARGUMENTS`, `CrossSiteScripting_COOKIE`, and `CrossSiteScripting_URIPATH`; pivot on `ruleGroupList[].terminatingRule.ruleId` (for a managed rule group the top-level `terminatingRuleId` holds the rule group name, not the individual XSS rule). Azure Application Gateway WAF lands in Microsoft Sentinel `AzureDiagnostics` where `Category == "ApplicationGatewayFirewallLog"`, keyed on `ruleId_s`.
- **Web server access logs** (IIS `W3CIISLog`, nginx, Apache). Query the request URI and query string for `<script`, `javascript:`, `onerror=`, `onload=`, `<svg`, `document.cookie`, and their percent-encoded and HTML-entity variants. These catch reflected and stored injection attempts in the request, not DOM-based XSS.
- **SAST / code-scan findings** on dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout`/`setInterval` with string arguments, React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrustHtml`, and jQuery `.html()`. A sink fed by untrusted input is the root-cause signal for DOM-based XSS.

## Detection approach

Alert on three distinct surfaces, because no single surface sees all three XSS classes.

1. **CSP violations.** The highest-value runtime signal. In enforcing or `Report-Only` mode, alert when `blocked-uri` is an origin not on your allowlist, when `script-sample` contains markup that matches content a user submitted, or when `violated-directive` is `script-src`/`require-trusted-types-for` on a page that should emit no inline or dynamic script. Suppress the known-benign extension and analytics noise you baselined.
2. **Request-side WAF and access-log matches.** Alert on CRS `941xxx` blocks and the AWS/Azure XSS labels above, and on access-log entries carrying script-injection tokens. These are noisy with scanners, so rank by whether the same payload later appears in a stored field or a response body.
3. **Build-time SAST gates.** Fail the pipeline when untrusted input reaches a sink listed above without passing a context-aware encoder or a Trusted Types policy.

This skill ships no bespoke UMBRASEC rule. Use these public, maintained sources: the SigmaHQ access-log rule [web_xss_in_access_logs.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_xss_in_access_logs.yml) and its surrounding [webserver_generic](https://github.com/SigmaHQ/sigma/tree/master/rules/web/webserver_generic) directory; the OWASP Core Rule Set XSS file [REQUEST-941-APPLICATION-ATTACK-XSS.conf](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf); and your cloud WAF vendor's managed XSS rule group.

## Threat hunt

Hypothesis-driven, for the stored or DOM-based XSS that evades point alerts. Run as prose steps, not a packaged query:

1. Pull CSP reports over a long window and group by `document-uri`. Pages that generate inline-script or `script-src` violations they never produced before are candidate stored-XSS sinks.
2. For each candidate page, retrieve the `script-sample` and `source-file` values and compare the sampled markup against recently stored user content (comments, profile fields, support tickets). A match places the stored payload.
3. Cross-reference web access logs: find the earliest request that wrote the matching value and identify the writing account and source IP. That request is the injection point even though it looks benign in isolation.
4. Independently, enumerate DOM sinks in your JavaScript bundles and trace each back to its data source. Any path from `location`, `document.URL`, `document.referrer`, or `postMessage` to `innerHTML`/`document.write`/`eval` without sanitisation is a DOM-XSS finding that no log would have shown.
5. Rank findings by blast radius: a stored payload on an authenticated, high-traffic page that can read `document.cookie` outranks a reflected parameter requiring a crafted link.

## Hardening

Shrink the attack surface so an injected string cannot become executing script. The controls below are grounded in the UMBRASEC guide only where a code maps cleanly; XSS-specific application-security controls (context-aware output encoding, CSP authoring, Trusted Types) have no single framework code in the guide and are given as prose.

- **Strict Content-Security-Policy.** Deploy a nonce- or hash-based policy with `'strict-dynamic'`, `object-src 'none'`, and `base-uri 'none'`, rolled out in `Report-Only` first and tuned against the baseline. A strict CSP turns most injection into a blocked, reported event rather than code execution. See web.dev [Mitigate XSS with a strict CSP](https://web.dev/articles/strict-csp).
- **Trusted Types.** Set `require-trusted-types-for 'script'` to make dangerous DOM sinks reject raw strings, which closes most DOM-based XSS at the browser.
- **Context-aware output encoding and framework autoescaping.** Encode on output for the exact context (HTML body, attribute, JavaScript, URL, CSS) and keep the framework's autoescaping on; never route untrusted data through the bypass APIs (`dangerouslySetInnerHTML`, `bypassSecurityTrustHtml`, `.html()`, `document.write`). Follow the OWASP [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) and [DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) cheat sheets.
- **Session-cookie protection.** Set `HttpOnly` so injected script cannot read the session cookie, and `SameSite` to blunt cross-site use. This limits T1539 even when injection succeeds.
- **Drop the legacy XSS auditor.** Send `X-XSS-Protection: 0` or omit the header; the browser auditor is deprecated and historically introduced its own information-leak issues.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Patch web frameworks and third-party JS libraries | Removes known XSS sinks and vulnerable components an attacker would target | Patch applications | A.8.8 Technical vulnerabilities | PR.PS Platform Security |
| Ship and monitor CSP / Trusted Types violation reports | Turns injection into logged, alertable events and feeds the SOC | ML2/ML3 event-log requirements | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM Continuous monitoring; DE.AE Adverse events |
| Remove unneeded web software, plugins, and legacy browser features | Cuts the client-side attack surface the script would exploit | User application hardening | A.8.19 Software on systems | PR.PS Platform Security |

## Honest limitations

CSP violation reports are generated by the victim's browser, so an attacker running script in a browser they control can suppress or never send them; reporting catches opportunistic and broad-reach XSS, not a targeted one-shot. `Report-Only` and enforcing CSP catch nothing on any host that does not yet carry a policy, so coverage is exactly as wide as your rollout. WAF signatures miss heavily encoded, mutation (mXSS), and context-specific payloads, and they add scanner noise. DOM-based XSS leaves no server-side trace at all unless Trusted Types or CSP reporting is deployed, so without them the only detection is source review. Finally, any third-party script your CSP allowlists runs inside your trust boundary; a compromise of that dependency is XSS your own policy permits. Baseline in `Report-Only`, tune, and layer the request-side, runtime, and build-time controls rather than relying on one.

## ATT&CK and D3FEND

ATT&CK has no XSS-specific technique, so the mapping is to the execution primitive, the delivery, and the objective. The precise identifiers for the flaw itself are CWE-79 and CAPEC-63.

- MITRE ATT&CK: [T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) (the injected script runs in the browser JS engine); [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189/) (stored XSS served to visitors); [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) (common objective).
- MITRE D3FEND: the countermeasures the D3FEND graph associates with T1059.007 are file-oriented (for example Content Filtering D3-CF and Content Modification D3-CM under the Isolate tactic, and File Analysis D3-FA and Dynamic Analysis D3-DA under Detect). D3FEND does not endorse a CSP-specific generalisation; in practice the web-layer controls a defender deploys for XSS are the strict CSP, context-aware output encoding, and Trusted Types described under Hardening.
- Public rule and reference sources: SigmaHQ [web_xss_in_access_logs.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_xss_in_access_logs.yml); OWASP Core Rule Set [REQUEST-941-APPLICATION-ATTACK-XSS.conf](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf); OWASP [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) and [DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) cheat sheets; web.dev [strict CSP](https://web.dev/articles/strict-csp).

**Scope note.** This is a defensive skill. It explains XSS only to the depth needed to detect, hunt, and mitigate it, and deliberately ships no payloads, injection strings, or offensive tooling.
