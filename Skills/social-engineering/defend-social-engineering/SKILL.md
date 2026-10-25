---
name: defend-social-engineering
description: "Detection, hunting, and hardening methodology for social engineering against people: help-desk impersonation and vishing to reset credentials or MFA (Scattered Spider / UNC3944, Storm-1811), pretext calls to run a remote-access tool, and BEC payment-redirect fraud (MITRE ATT&CK T1566.004, T1598.004, T1684.001, T1534, T1204). Signals live in help-desk ticketing, Entra ID AuditLogs and SigninLogs, the Microsoft 365 Unified Audit Log, call-detail records, badge and visitor logs, and EDR/Sysmon telemetry for Quick Assist, AnyDesk, and TeamViewer. Gives the defender view, a hunt, public rule sources, and framework-mapped awareness, physical, and process hardening. Use when investigating a suspicious help-desk MFA or password reset, triaging a vishing or fake-IT-support report, hunting a remote-access tool launched after an inbound call, responding to a suspected BEC invoice-redirect, or hardening the help desk and payment-change process."
---

# Social Engineering - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, the hunt, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

Social engineering attacks the human process, so most of the attack happens off your logs and the residue is an administrative action taken by a tricked insider. The three highest-value moments to watch in a Microsoft 365 estate are: a help-desk-initiated **password reset or MFA re-registration** in Entra ID **AuditLogs**, immediately followed by a sign-in from new infrastructure in **SigninLogs**; a **remote-support tool** (Quick Assist, AnyDesk, TeamViewer, ScreenConnect) launching on an endpoint shortly after an inbound phone call, visible in **EDR/Sysmon process creation**; and a **New-InboxRule** or a payment-detail change request that lands after an out-of-band pretext. Pair this telemetry with two process controls that no detection can substitute for: verify the caller before the help desk resets anything, and verify every bank-detail change through a second channel. None of these signals is a verdict alone; the tell is the sequence of a human action plus an anomalous follow-on.

## What it looks like, defender view

The attacker never touches your perimeter first; they phone a person. In the dominant 2024-2025 pattern (Scattered Spider / UNC3944), an attacker calls the IT help desk, impersonates a named employee using details scraped from LinkedIn and prior breaches, claims a lost phone, and talks the agent into resetting the password and re-registering MFA onto an attacker-controlled device. From the defender's chair this is not an exploit; it is a legitimate-looking `Reset password (by admin)` and `Admin registered security info` event in Entra, then a successful, sometimes MFA-satisfied sign-in from a residential-proxy or new-country IP minutes later. A second common pattern (Storm-1811-style) is a pretext call to an end user posing as IT support, steering them to open **Quick Assist** or install a remote-access tool, after which the "helper" drives the session; the defender-visible residue is a signed binary (`quickassist.exe`, `AnyDesk.exe`, `TeamViewer.exe`) spawning with no prior enterprise deployment, often followed by a child PowerShell or script. The third pattern is business email compromise: no malware at all, just an impersonated executive or supplier and a user who updates a payment destination, so the only trace is a mailbox-forwarding or inbox rule and an invoice that routes to a new account. Physical social engineering (tailgating, a planted "visitor") leaves its residue in badge-reader and visitor-management logs rather than SIEM telemetry.

## Log sources and signals

Social engineering spans IT, telephony, and physical systems, so the signal is spread across sources that are rarely correlated. Pull them together deliberately.

- **IT help-desk ticketing (ServiceNow, Jira Service Management, Freshservice).** Reset and MFA-re-registration tickets, the identity-verification method recorded, and the agent who actioned it. A reset with a thin or skipped verification note is the signal.
- **Entra ID `AuditLogs` (Azure AD audit).** Operations `Reset password (by admin)`, `Reset user password`, `Admin registered security info`, `User registered security info`, `Admin updated security info`, and `Update user` where `StrongAuthenticationMethod` changed. Key fields: `initiatedBy` (help-desk account), `targetResources`, `activityDateTime`.
- **Entra ID `SigninLogs` / `AADNonInteractiveUserSignInLogs`.** The follow-on sign-in: `ipAddress`, `location`, `deviceDetail`, `riskLevelDuringSignIn`, `authenticationRequirement`, `conditionalAccessStatus`. New device plus new geography shortly after a reset is the tell.
- **Microsoft 365 Unified Audit Log (Exchange Online).** `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox` (ForwardingSMTPAddress), and mailbox permission changes that follow a BEC pretext.
- **EDR and Sysmon on endpoints.** Process creation (Sysmon Event ID 1, or Microsoft Defender `DeviceProcessEvents`) for `quickassist.exe`, `AnyDesk.exe`, `TeamViewer.exe`, `ScreenConnect` / `ConnectWiseControl`, and `UltraViewer`, especially where the tool is not in your sanctioned software inventory and spawns a scripting-engine child. Network connection events (Sysmon Event ID 3) to those tools' relay domains corroborate.
- **Telephony / contact-center call-detail records (Amazon Connect, Genesys, Teams Phone, carrier CDRs).** Inbound calls to the help-desk queue correlated in time to a reset event; caller-ID spoofing and STIR/SHAKEN attestation level where the carrier provides it.
- **Physical access control and visitor-management logs.** Badge-reader anti-passback violations, an entry read with no matching egress (tailgating), first-ever access to a sensitive door, out-of-hours access, and the same credential used at two readers too far apart to be one person.

What normal looks like: help-desk resets happen, but with a recorded verification step; remote-support tools exist, but deployed centrally to known assets; payment-detail changes happen, but through the finance workflow, not an email reply.

## Detection approach

Alert on the correlation, not the single event, because each component is individually legitimate. The core analytic is a temporal join: an Entra `AuditLogs` password reset or security-info registration, grouped by target user, followed within a short window (for example 60 minutes) by a `SigninLogs` success from a device ID or country not previously seen for that user. Raise severity when the target is privileged, when the sign-in IP is a known residential-proxy or anonymizer, or when `Admin registered security info` added an authenticator on a brand-new device. For the vishing-to-remote-tool path, alert on first-seen execution of a remote-support binary on a host that has no history of it, scoped tighter by a short time window after a logged inbound support call and by a suspicious child process. For BEC, alert on a new inbox-forwarding rule created soon after an interactive sign-in from new infrastructure (this path overlaps the sibling [detect-phishing](../detect-phishing/SKILL.md) and [detect-oauth-consent-phishing](../../auth/detect-oauth-consent-phishing/SKILL.md) methodology).

No tuned UMBRASEC rule ships for this threat yet. Build on public, maintained sources rather than inventing one:

- SigmaHQ rules for remote-access tooling and cloud identity events, in the Sigma ruleset at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (see `rules/windows/process_creation/` for Quick Assist, AnyDesk, and TeamViewer process rules, and `rules/cloud/azure/` for Entra sign-in and identity-change analytics).
- Microsoft Sentinel analytics and hunting queries in [github.com/Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel), including the Entra password-reset and risky-sign-in templates.
- MITRE D3FEND countermeasure catalog at [d3fend.mitre.org](https://d3fend.mitre.org) for the identity-hardening controls (see ATT&CK and D3FEND below).

## Threat hunt

Hypothesis: an attacker has socially engineered the help desk to take over an account, or vished a user into a remote session, in a way that did not trip a signature.

1. Pull all Entra `AuditLogs` security-info and password-reset operations for the window of interest, grouped by `targetResources` user. For each, join to that user's next successful `SigninLogs` entry and compare `deviceDetail.deviceId` and `location.countryOrRegion` against their 30-day baseline. Flag resets followed by a first-seen device or country.
2. Rank the flagged users by privilege and by whether the reset ticket recorded a real identity-verification step. A privileged reset with a missing or weak verification note is the strongest lead.
3. For each flagged host, search `DeviceProcessEvents` / Sysmon ID 1 for remote-support binaries in the same window, and inspect their child processes for scripting engines or credential-access tooling.
4. Cross-reference the timeline with contact-center CDRs: an inbound call to the help-desk or executive-support line immediately before the reset, especially with a spoofed or low-attestation caller ID, corroborates the pretext.
5. For the physical hypothesis, query badge logs for anti-passback violations, tailgate entries, and impossible-travel badge use over the same period, and reconcile against the visitor register.

## Hardening

Social engineering is defeated mainly by process, so the controls below are weighted toward verification and least privilege rather than a product. The mappings follow the control codes used in the UMBRASEC [security foundation guide](https://umbrasec.dev/guide/foundation.html) and [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html); a cell is blank where no single framework control maps cleanly. Security-awareness training and inbox defence sit under the "Defend the inbox" essentials item, which the foundation guide maps to A.6.3 and PR.AT; the Essential Eight has no standalone user-training strategy, so that column is deliberately blank for the human-process controls.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Security-awareness training | Short, regular training so staff recognise pretext calls, vishing, and BEC lures | - | A.6.3 Awareness, education and training | PR.AT Awareness and Training |
| Out-of-band callback verification | Confirm any bank-detail or payment change through a second, known channel, not the one that requested it | - | A.6.3 Awareness, education and training | PR.AT Awareness and Training |
| Help-desk caller verification | Treat MFA re-registration like a password reset: prove the caller's identity before resetting, since attackers ring help desks for exactly this | - | A.5.16 Identity management; A.5.17 Authentication information | PR.AA-01 |
| Phishing-resistant MFA | FIDO2 or certificate-based auth that a fake login or a reset-to-attacker-device cannot relay; number matching on push so a tap cannot be blind-approved | Multi-factor authentication | A.5.17 Authentication information | PR.AA-01 |
| Restrict administrative privileges | Keep the privileged population tiny and separated, so a socially engineered account take-over has a small blast radius | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 Least privilege |

## Honest limitations

This methodology catches the digital residue of social engineering, not the conversation that caused it. A patient attacker who takes over an account and then waits, or who uses credentials entirely within the victim's normal device and geography, will not light up the reset-then-anomalous-sign-in correlation. A help-desk agent who follows every step of a verification process that the attacker has already defeated with stolen personal data leaves a clean ticket. Vishing that ends in the user reading out a one-time code, with no remote tool and no reset, produces almost no endpoint telemetry. Physical social engineering is only as observable as your badge and camera coverage. The honest conclusion is that process hardening (strict caller verification, out-of-band payment confirmation, phishing-resistant MFA, least privilege) prevents more of this class than any detection catches, and detection exists to shorten the time from a successful trick to a response. Baseline your own help-desk, telephony, and badge data before alerting; the correlation windows and privilege weighting are dials.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1566.004 Phishing: Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/); [T1598.004 Phishing for Information: Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004/); [T1684.001 Social Engineering: Impersonation](https://attack.mitre.org/techniques/T1684/001/); [T1534 Internal Spearphishing](https://attack.mitre.org/techniques/T1534/); [T1204 User Execution](https://attack.mitre.org/techniques/T1204/).
- MITRE D3FEND: [D3-MFA Multi-factor Authentication](https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/) hardens the account-takeover path. D3FEND is a technical-countermeasure catalog and has thin coverage for the human and voice vectors, so the awareness and callback-verification controls above have no clean D3FEND mapping; that gap is expected for this class.
- Public rule sources: [SigmaHQ](https://github.com/SigmaHQ/sigma) (remote-access-tool process rules and Entra identity analytics); [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) (password-reset and risky-sign-in templates); [MITRE D3FEND](https://d3fend.mitre.org).
- Primary references: CISA #StopRansomware: Scattered Spider advisory AA23-320A; Microsoft Threat Intelligence reporting on Octo Tempest (UNC3944) help-desk social engineering and on Storm-1811 abuse of Quick Assist.

**Scope note.** This is a defensive skill. It explains social engineering only to the depth needed to detect and mitigate it and deliberately provides no pretext scripts, vishing guidance, or impersonation tooling. UMBRASEC publishes defense, not offense.
