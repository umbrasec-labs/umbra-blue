---
name: detect-phishing
description: "Detection, hunting, and hardening methodology for phishing as initial and credential access: credential-harvest and attacker-in-the-middle (AiTM) link lures, malicious attachments, spearphishing via service, and OAuth consent phishing (MITRE ATT&CK T1566, T1566.001, T1566.002, T1566.003, T1598, T1528). Signals live in Defender for Office 365 advanced-hunting tables, the Exchange Online Unified Audit Log, Entra ID SigninLogs and AuditLogs, and web-proxy and DNS logs. Gives the defender view, a hunt, framework-mapped hardening, and pointers to public and sibling consent-phishing rules. Use when triaging a reported phishing email, investigating suspected AiTM session-token theft or a post-delivery inbox rule, hunting for credential-harvest URL clicks or newly registered lookalike domains, writing or reviewing email-phishing detections, or hardening a tenant against spearphishing and illicit consent grants."
---

# Phishing - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet. The one exception is the consent-phishing variant, which already has a Tier 1 sibling: [detect-oauth-consent-phishing](../../auth/detect-oauth-consent-phishing/SKILL.md) ships tuned KQL for that path, and this skill defers to it instead of duplicating it.

## TL;DR for defenders

Phishing is a delivery technique, not a single artifact, so detection works best as a chain across three moments: the message arriving, the user acting on it, and the account being abused afterward. In a Microsoft 365 estate, confirm Defender for Office 365 advanced-hunting is retained and then watch **EmailEvents** and **EmailUrlInfo** for lures that passed filtering, **UrlClickEvents** for the click that turned a delivered mail into an active one, and **SigninLogs** plus the Unified Audit Log for the aftermath: a sign-in from new infrastructure followed by a **New-InboxRule** forwarding or deleting mail is the classic attacker-in-the-middle and business-email-compromise tell. Treat SPF, DKIM, and DMARC results in the message headers as the cheapest first filter, and treat the consent-phishing branch (an OAuth app the victim clicked Accept on) as a distinct path handled by the sibling skill. None of these is a verdict alone; the signal is the sequence.

## What it looks like, defender view

A phishing campaign shows up first as mail your gateway let through: a sender domain that is new or a near-miss of a brand you trust, a display name that impersonates an internal executive or a known supplier, and either a link to a credential-harvest or AiTM proxy page or an attachment that carries a macro, an HTML smuggling payload, or a link to one. Modern credential phishing increasingly skips the password entirely: an AiTM reverse proxy relays the real login and steals the issued session cookie, so the follow-on sign-in succeeds with no failed-logon noise and no second MFA prompt. The defender-visible residue is therefore rarely the mail alone. It is a delivered-then-clicked URL, an anomalous sign-in that reuses a stolen token, and within minutes a new inbox rule that hides the attacker's replies or auto-forwards invoices. The consent-phishing variant presents differently again: no credential is taken at all, only an Accept click on a real Microsoft consent screen, after which an OAuth app reads mail and files on the victim's behalf.

## Log sources and signals

Microsoft 365 is the dominant case; the on-prem and generic sources matter when mail or web egress is not cloud-filtered.

- **Defender for Office 365 / Microsoft 365 Defender advanced hunting.**
  - `EmailEvents` - one row per message, with `SenderFromAddress`, `SenderMailFromDomain`, `SenderIPv4`, `AuthenticationDetails` (the SPF / DKIM / DMARC verdicts), `DeliveryAction` (Delivered, Blocked, Junked), `DeliveryLocation`, and `ThreatTypes` (Phish, Malware). A message `Delivered` to `Inbox` with `DeliveryAction == "Delivered"` despite a phish verdict is the gap to hunt.
  - `EmailUrlInfo` - the URLs inside messages, joined to `EmailEvents` on `NetworkMessageId`. Carries `Url` and `UrlDomain` for lookalike and newly-registered-domain checks.
  - `EmailAttachmentInfo` - `FileName`, `FileType`, `SHA256`, and the detonation verdict for attachment-borne lures (T1566.001).
  - `UrlClickEvents` - the Safe Links click record: `Url`, `ActionType` (`ClickAllowed`, `ClickBlocked`), `IsClickedThrough` (the user overrode a block), `AccountUpn`. The transition from delivered to clicked is the highest-value user-action signal.
- **Exchange Online Unified Audit Log** (surfaced via `CloudAppEvents` or Purview Audit Search). Watch `New-InboxRule` and `Set-InboxRule` operations that forward externally, move to RSS/Archive, or mark-as-read-and-delete - the standard post-compromise persistence and concealment move. Also `Set-Mailbox` enabling `ForwardingSMTPAddress`.
- **Entra ID `SigninLogs`.** `RiskLevelDuringSignIn`, `RiskEventTypes`, `IPAddress`, `Location`, `AuthenticationRequirement`, and `UserAgent`. An AiTM-replayed token tends to show a sign-in from a hosting or residential-proxy ASN and geography unrelated to the user, often flagged `unfamiliarFeatures` or `anomalousToken`, with MFA satisfied because the cookie already carried it.
- **Entra ID `AuditLogs`** for the consent branch: the `Consent to application` operation and app-role assignments. The tuned detection for this path lives in the sibling [detect-oauth-consent-phishing](../../auth/detect-oauth-consent-phishing/SKILL.md) skill; do not rebuild it here.
- **Message headers** on any sampled lure: the `Authentication-Results` header records `spf=`, `dkim=`, and `dmarc=` outcomes, and the `Return-Path` / `From` mismatch exposes spoofing that passed cosmetic inspection.
- **On-prem and generic.** Web-proxy logs (requests to the harvest or proxy domain after a click), DNS resolver logs (first-seen and newly-registered domains, punycode/homoglyph lookalikes), and the secure email gateway's own verdict logs where mail is not filtered by Microsoft.

What normal looks like: legitimate bulk senders pass DMARC with an aligned domain, users click links to domains your organization already talks to, and inbox rules are created rarely and tend to sort rather than forward-and-delete. The anomaly is a DMARC failure or lookalike domain, a click-through on a blocked URL, or a forwarding rule created minutes after an anomalous sign-in.

## Detection approach

Alert on the sequence, not any single row. The practical chain, cheapest signal first:

1. **Delivered-despite-verdict and lookalike sender.** In `EmailEvents`, surface mail where `ThreatTypes has "Phish"` yet `DeliveryAction == "Delivered"` to an inbox, and mail whose sender domain is newly registered or a homoglyph of an internal or supplier domain. Enrich `EmailUrlInfo` domains against newly-registered-domain and threat-intel feeds.
2. **Click-through.** In `UrlClickEvents`, alert when `IsClickedThrough == 1` or `ActionType == "ClickAllowed"` for a URL that your intel scored as malicious. This is the moment a delivered lure becomes an active incident.
3. **AiTM aftermath.** Correlate a risky `SigninLogs` event (`RiskEventTypes` containing `anomalousToken` or `unfamiliarFeatures`, hosting/proxy ASN) with an `EmailEvents` phish to the same user, then with a `New-InboxRule` in the audit log within a short window. Microsoft publishes this exact correlation pattern as an AiTM detection; use it as the template.
4. **Consent grant.** Defer to the sibling skill's KQL for `Consent to application` and `oauth2PermissionGrants` POST signals.

Do not hand-write these as one-off queries when a maintained public rule already exists. Point your pipeline at:

- **SigmaHQ** - the open rule repository at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma). The `rules/cloud/m365` and `rules/cloud/azure` trees carry inbox-rule-forwarding, consent-grant, and risky-sign-in rules; the `rules/web/proxy_generic` and other `rules/web` trees carry credential-harvest URL and newly-registered-domain analytics. Map these to your tables rather than authoring equivalents.
- **Microsoft Defender XDR built-in detections and hunting queries** - the Microsoft 365 Defender [advanced-hunting query library](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries) and the product's own AiTM and consent-phishing alerts.
- **MITRE D3FEND** - the countermeasure mappings for T1566 at [d3fend.mitre.org](https://d3fend.mitre.org/), covering Message Authentication and Sender Reputation Analysis.

A tuned UMBRASEC rule is not yet shipped for the email-phishing path; this skill is methodology plus public sources until that research lands (see [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md)).

## Threat hunt

For the campaign that beat the gateway and the alert rules, hunt the state it leaves behind rather than the moment it arrived.

1. **Lookalike inventory.** Over a long window, pull distinct `SenderMailFromDomain` and `EmailUrlInfo.UrlDomain` values, and diff them against the domains your organization legitimately corresponds with. First-seen and homoglyph domains are the candidate lures; rank by how many users received them.
2. **Click-through survivors.** List `UrlClickEvents` where the user clicked through a block (`IsClickedThrough == 1`). For each `AccountUpn`, pivot to that account's `SigninLogs` in the hours after the click, looking for a sign-in from new infrastructure.
3. **Hidden-rule sweep.** Enumerate every mailbox's current inbox rules and forwarding settings, not just newly created ones, and reconcile each against the owner. An external-forwarding or move-to-RSS-and-mark-read rule the user does not recognize corroborates a compromise that predates your alerting. This is the single highest-yield artifact after a business-email-compromise.
4. **Rank by blast radius.** A finance or executive mailbox with a forwarding rule outweighs a volume signal, because that is where invoice-redirect fraud lands.

## Hardening

Detection buys time; configuration removes most of the attack surface. The mappings below are grounded in the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html) step 7 (Defend the inbox) and step 6 (Harden macros), and the [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) MFA and consent controls. A cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Publish and enforce SPF, DKIM, DMARC | Lets receivers reject mail that spoofs your domain, and raises the bar for inbound spoofing when you enforce `p=reject` | - (supports inbox defense) | A.8.7 Protection against malware | PR.PS Platform Security |
| Mail-platform anti-phishing / anti-spoofing | Turns on the gateway's impersonation, spoof-intelligence, and Safe Links / Safe Attachments filtering so fewer lures reach the inbox | - (supports inbox defense) | A.8.7 Protection against malware | PR.PS Platform Security |
| Phishing-resistant MFA | FIDO2 / passkeys defeat AiTM token relay because there is no phishable shared secret; the standard MFA that AiTM beats is the gap | Multi-factor authentication (ML2+) | A.8.5 Secure authentication | PR.AA-03 Users authenticated |
| Block internet-sourced Office macros | Closes the attachment-macro delivery route (T1566.001) that remains a classic initial-access path | Configure Microsoft Office macro settings; User application hardening | A.8.7 Protection against malware; A.8.19 Software on operational systems | PR.PS Platform Security |
| Security-awareness training and payment-change verification | Teaches staff to recognize lures and, critically, to verify any change of bank details through a second channel - the control that catches invoice fraud | - (supports inbox defense) | A.6.3 Information security awareness, education and training | PR.AT Awareness and Training |
| Restrict user consent to applications | Stops a user granting company-data access to an OAuth app on their own, closing the consent-phishing path; see the sibling skill | Restrict administrative privileges (ML2+) | A.5.16 Identity management; A.5.18 Access rights | PR.AA-01 Identities and credentials; PR.AA-05 Least privilege |

## Honest limitations

- **Phishing is a delivery vector, not one signature.** No single rule covers link, attachment, service, and consent variants; coverage is a chain, and a gap in any one log source breaks it.
- **AiTM defeats standard MFA.** If the second factor is a phishable code or push, a relayed session cookie signs in cleanly. Only phishing-resistant methods and anomalous-token detection close that, and token-anomaly detection fires after the sign-in, not before.
- **Delivered-despite-verdict depends on retained telemetry.** If Defender advanced-hunting is not retained or `UrlClickEvents` is not available in your licensing tier, the click signal never reaches your SIEM.
- **Lookalike detection is noisy.** New and homoglyph domains surface candidates for triage, not confirmed lures; the verdict comes from who received it and what they did next.
- **This is Microsoft-shaped.** The same pattern exists against Google Workspace and other platforms; the tables and fields here are Defender and Entra specific, though the method transfers.
- **The consent branch is deliberately out of scope here.** Its tuned rules live in the sibling Tier 1 skill, and this skill only points at that path rather than re-deriving it.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1566 Phishing](https://attack.mitre.org/techniques/T1566/) (Initial Access), with sub-techniques [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/), [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/), and [T1566.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/); [T1598 Phishing for Information](https://attack.mitre.org/techniques/T1598/) (Reconnaissance); and [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) (Credential Access) for the consent variant.
- MITRE D3FEND: Message Authentication (validates SPF / DKIM / DMARC against inbound mail) and Sender Reputation Analysis map to T1566; see the ATT&CK-to-D3FEND countermeasure view at [d3fend.mitre.org](https://d3fend.mitre.org/).
- Public rule sources: [SigmaHQ](https://github.com/SigmaHQ/sigma) (cloud/m365, cloud/azure, and web/proxy_generic rule trees); [Microsoft 365 Defender hunting queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries); Microsoft Learn - [Detect and remediate the Outlook rules and custom forms injection](https://learn.microsoft.com/en-us/defender-office-365/) anti-phishing documentation and the AiTM detection guidance.
- Sibling skill for the consent-phishing path: [detect-oauth-consent-phishing](../../auth/detect-oauth-consent-phishing/SKILL.md).

**Scope note.** This is a defensive skill. It explains phishing only to the depth needed to detect and mitigate it and deliberately provides no lure templates, harvest-page kits, AiTM-proxy tooling, or consent-app code. UMBRASEC publishes defense, not offense.
