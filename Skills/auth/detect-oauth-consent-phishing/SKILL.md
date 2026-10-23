---
name: detect-oauth-consent-phishing
description: "Detection and response methodology for OAuth consent phishing / illicit consent grants in Microsoft 365 and Entra ID (MITRE ATT&CK T1528). An attacker phishes a user into consenting to an OAuth app with delegated Graph permissions such as Mail.Read and offline_access, so no password is stolen and MFA is never challenged, yet the refresh token is a durable key to mail and files. Ships three KQL detections over Entra AuditLogs 'Consent to application' and app-role-assignment events and MicrosoftGraphActivityLogs oauth2PermissionGrants, with tuning, false-positive notes, a hunt, and consent-restriction mitigations. Use when investigating a suspicious enterprise app or consent grant, triaging a 'Consent to application' event, hunting illicit OAuth grants or refresh-token abuse in Entra ID, writing consent-phishing detections, or responding to a Midnight Blizzard-style app-consent attack."
---

# OAuth Consent Phishing - Detection and Response

OAuth consent phishing never asks for a password and sails straight through MFA, because the victim is not tricked into logging in - they are tricked into clicking Accept. The attacker registers an OAuth application, phishes a user into consenting to delegated Microsoft Graph permissions, and walks away with an access token plus, if offline_access was requested, a long-lived refresh token. Because the app authenticates as itself and the consent already happened, the attacker's later Graph calls trigger no interactive sign-in and no MFA prompt. Revoking the user's password does nothing; you have to revoke the grant. This skill is defensive: it explains the technique only as far as detection and mitigation require, and ships no app-registration templates, phishing kits, or token-abuse tooling.

## TL;DR for defenders

Make sure Entra ID logs are actually exported to a Log Analytics workspace or Microsoft Sentinel, not just living in the portal's 30-day view. Then watch the Entra **AuditLogs** table for a `Consent to application` event granting sensitive scopes (mail, files, directory, or `offline_access`), and watch **MicrosoftGraphActivityLogs** for the **POST** to a URI containing `oauth2PermissionGrants` - that POST is the act of granting delegated permission and is the single highest-fidelity moment. A tenant-wide `IsAdminConsent == "True"` grant, or an app-role (application permission) assignment like `full_access_as_app`, is the high-severity branch. Then shrink the blast radius by turning off unrestricted user consent. Queries below; none is a verdict on its own.

## Why a click beats a credential

Most phishing aims at credentials, so most defenses sit around the login: MFA, conditional access, impossible-travel rules. Consent phishing routes around all of it. The OAuth 2.0 authorization-code flow is designed to let a third-party app act on a user's behalf, so when the victim clicks Accept on a consent screen, everything that follows is technically working as intended. The consent link points at a legitimate Microsoft endpoint (`login.microsoftonline.com/.../oauth2/v2.0/authorize`) carrying the attacker's `client_id` and a `scope` list, so the domain is real, the TLS is valid, and the page is Microsoft's - which is exactly why it is convincing.

This is not a lab curiosity. In January 2024 Microsoft disclosed that Midnight Blizzard (APT29 / NOBELIUM) password-sprayed into a legacy test account, found a dormant OAuth application with elevated access, then created additional malicious OAuth apps and granted them the Office 365 Exchange Online `full_access_as_app` role to read corporate mailboxes, all routed through residential proxies to blend in. Same primitive, nation-state hands.

The scopes worth alerting on are the ones that give reach: `Mail.Read`, `Mail.ReadWrite`, and `Mail.Send` (full mailbox read and send-as, useful for internal spear-phishing); `MailboxSettings.ReadWrite` (hidden inbox rules for auto-forward or auto-delete, a classic persistence trick); `Files.ReadWrite.All` and `Sites.ReadWrite.All` (OneDrive and SharePoint content); `offline_access` (the refresh token that turns a momentary click into durable access); and anything `.All` or directory-wide such as `User.Read.All` or `Directory.Read.All` (reconnaissance far beyond the consenting user).

## Log sources required

The detections assume Entra ID logs are shipping into Microsoft Sentinel or any Log Analytics workspace via Entra diagnostic settings. Confirm each of these is enabled and exported; the data is useless if it only lives in the portal's 30-day view.

- **Entra ID audit logs** (`AuditLogs` table) - the primary source. Records the `Consent to application` operation and the `Add app role assignment to service principal` / `Add app role assignment grant to user` operations, with `Result`, `InitiatedBy.user.userPrincipalName`, and the `TargetResources.modifiedProperties` bag that carries `ConsentAction.Permissions`, `ConsentContext.IsAdminConsent`, `TargetId.ServicePrincipalNames`, `AppRole.Value`, and `ServicePrincipal.DisplayName`.
- **Microsoft Graph activity logs** (`MicrosoftGraphActivityLogs`) - per-request telemetry for Graph calls, including the write that creates the grant and the reads that follow it. Fields used: `RequestMethod`, `RequestUri`, `ResponseStatusCode`, `UserId`, `AppId`, `IPAddress`. A missing export of this table blinds detection 2 entirely.
- **Service principal sign-in logs** (`AADServicePrincipalSignInLogs`) - shows the application itself authenticating, often from infrastructure unrelated to any of your users. Used by the hunt below.
- If you are licensed for it, mirror the **Unified Audit Log** in Microsoft Purview, where the same consent events surface for compliance search.

## Detection

Three layers, cheapest signal first. Treat the KQL as a starting point: the exact property paths inside `modifiedProperties` shift between schema versions, so validate field names against your own tenant before you alert on them. Canonical copies of these rules live in the UMBRASEC [sigma-pack](https://umbrasec.dev/tools/sigma-pack/); the writeup explains each in full.

### 1. Consent grants that include sensitive scopes

The bread-and-butter detection: a successful `Consent to application` where the granted permissions touch mail, files, or directory data. The consenting `Actor` and the `IsAdminConsent` flag tell you immediately how bad it could be.

```kql
// oauth-consent-sensitive-scopes.kql (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
// UMBRASEC sigma-pack - OAuth consent phishing (T1528), detection 1 of 3
// Entra ID audit: consent to an app requesting sensitive delegated scopes
// Source writeup: https://umbrasec.dev/research/detecting-oauth-consent-phishing.html
// Tuning: allowlist sanctioned AppIds; IsAdminConsent == "True" is the
// high-severity branch (tenant-wide grant). Validate modifiedProperties
// field names against your own tenant before alerting.
AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| mv-expand TargetResources
| extend mods = TargetResources.modifiedProperties
| mv-expand mods
| extend propName = tostring(mods.displayName), newVal = tostring(mods.newValue)
| summarize props = make_bag(bag_pack(propName, newVal))
        by CorrelationId, TimeGenerated,
           Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Permissions   = tostring(props["ConsentAction.Permissions"]),
         IsAdminConsent = tostring(props["ConsentContext.IsAdminConsent"]),
         AppDisplayName = tostring(props["TargetId.ServicePrincipalNames"])
| where Permissions has_any (
        "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
        "Files.ReadWrite.All", "Sites.ReadWrite.All", "offline_access",
        "User.Read.All", "Directory.Read.All")
| project TimeGenerated, Actor, AppDisplayName, IsAdminConsent, Permissions
```

### 2. The grant itself, in Graph activity (high fidelity)

The single highest-fidelity moment is the API write that creates the grant. A `POST` to a URI containing `oauth2PermissionGrants` is the act of granting delegated permission. When it is initiated by a non-privileged user, or from a residential-proxy IP as in the Midnight Blizzard case, it deserves a hard look.

```kql
// oauth2-permission-grant-post.kql (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
// UMBRASEC sigma-pack - OAuth consent phishing (T1528), detection 2 of 3
// The moment a delegated permission grant is created via Microsoft Graph
// Source writeup: https://umbrasec.dev/research/detecting-oauth-consent-phishing.html
// Tuning: your own admins legitimately create grants during app onboarding.
// Scope this to actors outside your identity/app-admin roles, or correlate
// the source IP against known administrative networks.
MicrosoftGraphActivityLogs
| where RequestMethod == "POST"
| where RequestUri has "oauth2PermissionGrants"
| where ResponseStatusCode in (200, 201)
| project TimeGenerated, UserId, AppId, IPAddress, RequestUri, ResponseStatusCode
// Enrich UserId against your privileged-role list; grants from standard users
// - or from hosting / proxy ASNs - are the ones to surface.
```

### 3. Application (app-only) permission grants

The Midnight Blizzard variant did not stop at delegated consent - it assigned an app application permissions, which grant standing access that outlives any user session. New app-role assignments should be change-controlled, so alert on them and reconcile against a ticket.

```kql
// app-role-assignment.kql (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
// UMBRASEC sigma-pack - OAuth consent phishing (T1528), detection 3 of 3
// App-role (application permission) assignments - standing, user-independent access
// Source writeup: https://umbrasec.dev/research/detecting-oauth-consent-phishing.html
// Tuning: high-value app roles to flag by name include full_access_as_app
// (Exchange), Mail.ReadWrite, and any *.ReadWrite.All. These should be rare,
// deliberate, and reconciled against a change ticket.
AuditLogs
| where OperationName in ("Add app role assignment to service principal",
                          "Add app role assignment grant to user")
| where Result == "success"
| mv-expand TargetResources
| extend mods = TargetResources.modifiedProperties
| mv-expand mods
| extend propName = tostring(mods.displayName), newVal = tostring(mods.newValue)
| where propName in ("AppRole.Value", "ServicePrincipal.DisplayName")
| project TimeGenerated, OperationName,
          Actor = tostring(InitiatedBy.user.userPrincipalName), propName, newVal
```

## Tuning and false positives

Baseline each rule in report-only mode before alerting; the scope lists and thresholds are dials, not gospel.

- **Rule 1 (sensitive scopes).** Scope strings are noisy - plenty of legitimate apps request `Mail.Read`. Maintain an allowlist of `AppId`s for sanctioned applications and exclude them. Treat `IsAdminConsent == "True"` as the high-severity branch: a tenant-wide grant exposes every user, not just the clicker. Validate the `modifiedProperties` field names (`ConsentAction.Permissions`, `ConsentContext.IsAdminConsent`) against your own tenant first, because the shape has changed across schema versions.
- **Rule 2 (the grant POST).** Your own admins legitimately create grants during app onboarding. Scope this to actors outside your identity and app-admin roles, or correlate the source `IPAddress` against known administrative networks; grants from standard users, or from hosting and proxy ASNs, are the ones to surface.
- **Rule 3 (app-role assignments).** These should be rare and deliberate. Flag high-value roles by name - `full_access_as_app` (Exchange), `Mail.ReadWrite`, and any `*.ReadWrite.All` - and reconcile every hit against a change ticket. Because the application-permission path generally requires an already-privileged actor, a hit is as much an insider or compromised-admin signal as a phishing one.

## Threat hunt

The alert rules fire on the moment of the grant. For an attacker who is already in - the dormant app Midnight Blizzard found, or a grant that predates your logging - hunt the standing state instead. No new query is needed; work the artifacts you already have:

1. Enumerate the current `oauth2PermissionGrants` and app-role assignments across your enterprise applications, and reconcile each against a known, owned application. Anything unrecognized is a candidate - refresh tokens persist until the grant is revoked.
2. For each candidate app, pull its `AADServicePrincipalSignInLogs` (app-only, client-credentials access) and its `AADNonInteractiveUserSignInLogs` filtered on the app's AppId (delegated refresh-token use on behalf of the consenting user) and look at where the app authenticates from. An app signing in from hosting or residential-proxy ASNs, or from geography unrelated to any of your users, is the Midnight Blizzard tell.
3. For any user who consented to a mail-scoped app, check their mailbox for hidden inbox rules - `MailboxSettings.ReadWrite` lets an attacker create auto-forward or auto-delete rules for persistence. An unexplained rule on a recently-consented account corroborates the grant.
4. Rank by blast radius: a tenant-wide admin consent or a `full_access_as_app` application permission outweighs a single delegated grant, because it reaches every mailbox rather than one.

## Mitigation

Detection tells you it happened; configuration stops most of it from happening at all, in order of impact. Mappings below follow the control codes used in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) (steps 3 and 7); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Restrict user consent | Move off "allow user consent for all apps" so users cannot grant company data access on their own; allow consent only for verified-publisher apps and a defined low-risk permission set | Restrict admin privileges (service accounts) | A.5.16 Identity management; A.5.18 Access rights | PR.AA-01 Identities and credentials; PR.AA-05 Least privilege |
| Admin consent workflow | Routes any request beyond what a user can grant to a human reviewer, keeping a person between the click and the grant | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Review and revoke existing grants | Audit enterprise applications and their `oauth2PermissionGrants` regularly and revoke anything unrecognized, because refresh tokens persist until you do | - | A.5.16 Identity management; A.5.18 Access rights | PR.AA-01 Identities and credentials |
| Let Entra step up risky consent | Entra ID can detect a risky user-consent request and require admin approval automatically | - | - | - |

Layer a lure filter in front of all of this where you have it: Microsoft Defender for Office 365 can catch the consent-phishing email before the link is ever clicked, which is the cheapest layer when it works. This sits outside the identity-control mapping above.

## Honest limitations

None of this is a silver bullet, and pretending otherwise would be the opposite of useful.

- **Scope strings are noisy.** Plenty of legitimate apps request `Mail.Read`. These detections surface candidates for triage, not confirmed incidents - the verdict comes from who consented, to what app, and what the app did next.
- **Schema drift is real.** The shape of `modifiedProperties` has changed over time, so a query that works today can silently return nothing after a platform update. Test for regressions.
- **A missing export is a blind spot.** Detection 2 depends entirely on `MicrosoftGraphActivityLogs` being enabled and exported; if it is not, the highest-fidelity signal never reaches your SIEM. The same applies to `AADServicePrincipalSignInLogs` for the hunt.
- **App-only grants need privilege.** The application-permission path generally requires an already-privileged actor, so detection 3 is as much an insider or compromised-admin signal as a phishing one.
- **This is Microsoft-shaped.** The same consent-phishing pattern exists against Google Workspace and other OAuth providers; the artifacts and queries here are specific to Entra ID.

## ATT&CK and references

- MITRE ATT&CK: [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) (Credential Access).
- UMBRASEC writeup: [Detecting OAuth Consent Phishing in Microsoft 365](https://umbrasec.dev/research/detecting-oauth-consent-phishing.html) (2026-06-11).
- Microsoft Entra - [Protect against consent phishing](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/protect-against-consent-phishing).
- Microsoft Entra - [Configure how users consent to applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent).
- Microsoft - [App consent grant investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent).
- Microsoft Defender for Office 365 - [Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants).
- Microsoft Security Blog - [Midnight Blizzard: Guidance for responders on nation-state attack](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/) (Jan 2024).
- Thomas Naunheim - [Detection and mitigation of illicit consent grant attacks in Azure AD](https://www.cloud-architekt.net/detection-and-mitigation-consent-grant-attacks-azuread/).
- Practical 365 - [Investigating OAuth app abuse with the Graph Activity Log](https://practical365.com/investigating-oauth-app-abuse-with-the-graph-activity-log/).

**Scope note.** This is a defensive skill. It explains OAuth consent phishing only to the depth needed to detect and mitigate it and deliberately provides no app-registration templates, phishing kits, or token-abuse tooling. UMBRASEC publishes defense, not offense.
