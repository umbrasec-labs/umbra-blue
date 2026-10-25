---
name: detect-cloud-attack-paths
description: "Detection and hunt methodology for cloud IAM attack paths across AWS, Azure, and GCP: privilege-escalation chains, credential and role manipulation, and control-plane log tampering that turn a foothold into tenant-wide control (MITRE ATT&CK T1078.004, T1098/.001/.003, T1136.003, T1548.005, T1685.002, T1580). Keys off AWS CloudTrail management events, Microsoft Entra ID audit and sign-in logs plus Azure Activity Log, and GCP Cloud Audit Logs, naming the exact event and identity fields to pivot on, then points to public rule sources and gives hardening mapped to the UMBRASEC guide. Use when triaging a suspicious IAM change, hunting cloud privilege escalation, investigating new access keys or role grants, chasing CloudTrail being disabled, writing or reviewing cloud control-plane detections, or asking how to detect cloud attack paths."
---

# Cloud IAM Attack Paths - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## What it looks like, defender view

**TL;DR.** A cloud attack path is a short chain of control-plane actions that converts a low-value foothold into durable high privilege: the actor adds a credential or role they should not have, assumes it, and often blinds the logs on the way out. You rarely see a single smoking gun; you see a sequence by one principal in minutes. Watch the identity services (`iam`, `sts` in AWS, RoleManagement in Entra, `iam.googleapis.com` in GCP) and the logging-config services, and correlate by the acting principal rather than alerting on any one event.

In telemetry this presents as an identity doing something it has never done before: an IAM user minting a second access key, a service principal getting a new client secret, a service account key being created, a role assignment to Owner or a policy attaching `AdministratorAccess`, followed by use of that new power from a new source IP, ASN, or user agent. Control-plane recon (bulk list and describe calls) often precedes it, and log tampering (stopping a trail, deleting a sink) often follows.

## Log sources and signals

- **AWS CloudTrail** management events. Pivot on `userIdentity.arn`, `userIdentity.type` (IAMUser, AssumedRole, Root, FederatedUser), `sourceIPAddress`, `userAgent`, and `errorCode` (AccessDenied, UnauthorizedOperation signal recon or escalation probing). Escalation and persistence `eventName` values from `iam.amazonaws.com` and `sts.amazonaws.com`: `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `CreateUser`, `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy`, `AddUserToGroup`, `AssumeRole`, and any call that relies on `iam:PassRole`. Log tampering from `cloudtrail.amazonaws.com`: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`. `GuardDuty` surfaces several of these pre-triaged, including `Stealth:IAMUser/CloudTrailLoggingDisabled`, `Policy:IAMUser/RootCredentialUsage`, and the `*:IAMUser/AnomalousBehavior` family.
- **Microsoft Entra ID** AuditLogs and SignInLogs (and AADServicePrincipalSignInLogs for workload identities), plus the **Azure Activity Log** (AzureActivity) for the resource plane. Signals: audit `OperationName` values such as Add member to role, Add eligible member to role for PIM, Add service principal credentials, and the Update application operation that covers certificate and secret management; Activity Log `Microsoft.Authorization/roleAssignments/write` granting Owner, Contributor, or User Access Administrator. Pivot on the initiating user or service principal, `IPAddress`, and `ResultType`.
- **GCP Cloud Audit Logs**. Admin Activity logs are always on; Data Access logs are opt-in per service and carry the impersonation calls. Pivot on `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, and `protoPayload.serviceName`. Key `protoPayload.methodName` values: `SetIamPolicy` granting `roles/owner` or `roles/editor`, `google.iam.admin.v1.CreateServiceAccountKey`, `google.iam.admin.v1.CreateServiceAccount`, and `GenerateAccessToken` or `SignJwt` from `iamcredentials.googleapis.com` for service-account impersonation. Security Command Center Event Threat Detection pre-labels some of this, for example the Persistence: IAM anomalous grant finding.

Normal baseline: these same calls are made constantly by infrastructure-as-code pipelines, CI/CD service principals, and SSO federation. That baseline is the whole problem, which is why detection keys off who, from where, and in what sequence, not the event alone.

## Detection approach

Alert on the sequence, not the single event. The highest-value pattern is a correlation: one principal performs a privilege-granting action (new credential, new role, policy attach to an admin policy) and then exercises it, especially from a source IP, ASN, or user agent that principal has not used before. A second durable pattern is any logging-configuration change (`StopLogging`, trail or sink deletion, diagnostic-setting removal) by a non-automation identity: in a healthy tenant only IaC touches those, so a human or interactive session doing it is near-binary. A third is `errorCode` AccessDenied fan-out from one principal across many IAM or describe actions, which is escalation probing or discovery.

Do not hand-roll these when maintained rules exist. SigmaHQ carries cloud control-plane detections under `rules/cloud` with `aws`, `azure`, and `gcp` subdirectories at [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma). For Azure, the analytics in [github.com/Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) cover role-assignment and app-credential abuse. AWS GuardDuty and GCP Event Threat Detection ship managed analytics for the same attack paths; prefer enabling and tuning those over writing from scratch. A tuned UMBRASEC rule is not yet shipped for this threat. Lay out the correlated evidence and let the defender make the call; a lone new key is a ticket, a new key plus immediate admin-policy attach plus a novel IP is an incident.

## Threat hunt

Hypothesis: an attacker added themselves durable high privilege in the last 30 days and the single events were individually unremarkable.

1. Pull every privilege-granting control-plane event in the window, per platform: AWS `CreateAccessKey` or `AttachUserPolicy` or `CreatePolicyVersion`; Entra Add member to role and Add service principal credentials; GCP `SetIamPolicy` and `CreateServiceAccountKey`.
2. Group by acting principal and keep principals whose grant action is their first-ever occurrence of that action, or whose grant targets an admin-tier role or policy.
3. For each survivor, join the grant time to subsequent use of the new credential or role and compare the source IP, ASN, and user agent against that principal's 90-day history. A new path used from a new origin is the lead.
4. Cross-check whether any logging-configuration change by the same principal brackets the activity. Rank by blast radius of the privilege gained, not by event count.

## Hardening

Shrink the paths before you have to detect them. Mappings follow the control codes in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Enforce MFA on all human and privileged identities | Removes the stolen-password path into the control plane | Multi-factor authentication (ML2+) | A.8.5 Secure authentication | PR.AA-03 |
| Least privilege and remove standing admin | Shortens or breaks the escalation chain; cuts blast radius | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 |
| Periodic access-rights review for human and non-human identities | Finds the orphaned keys, stale roles, and over-granted service principals that are the links in a path | - | A.5.18 Access rights | PR.AA-01; PR.AA-05 |
| Centralized, tamper-resistant control-plane logging | Ensures the trail survives `StopLogging` and sink deletion so detection has data | ML2/ML3 event-log retention | A.8.15 Logging | DE.CM |
| Continuous monitoring and alerting on identity changes | Turns the logs into timely signal | - | A.8.16 Monitoring activities | DE.AE; DE.CM |

## Honest limitations

A legitimate IaC or CI/CD identity is the natural cover for every call here; if the attacker rides one of those pipelines, grant plus use will look like normal automation and sequence correlation weakens. Break-glass accounts and SSO federation (for example AssumeRoleWithSAML) legitimately produce novel-looking role assumptions and will generate false positives until allowlisted. In GCP, service-account impersonation via `GenerateAccessToken` only appears if Data Access audit logs are enabled for `iamcredentials.googleapis.com`; with Admin Activity logs alone that step is invisible. A patient attacker who grants once and waits days before use defeats the short-window correlation, which is why the hunt uses a long window and why least privilege matters as much as detection. None of these signals proves intent on its own; they rank leads for a human to judge.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/); [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) with [.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) and [.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/); [T1136.003 Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/); [T1548.005 Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005/); [T1685.002 Disable or Modify Tools: Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/); [T1580 Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/).
- MITRE D3FEND countermeasures that map: User Behavior Analysis (D3-UBA) and Resource Access Pattern Analysis (D3-RAPA) for the anomaly detection above, User Geolocation Logon Pattern Analysis (D3-UGLPA) for the novel-origin signal, and Multi-factor Authentication (D3-MFA) for the hardening. See [d3fend.mitre.org](https://d3fend.mitre.org/).
- Public rule sources: [SigmaHQ cloud rules](https://github.com/SigmaHQ/sigma) (`rules/cloud` with `aws`, `azure`, `gcp`); [Microsoft Sentinel analytics](https://github.com/Azure/Azure-Sentinel); AWS GuardDuty finding types and GCP Security Command Center Event Threat Detection managed analytics.

**Scope note.** This is a defensive skill. It explains cloud attack paths only to the depth needed to detect and mitigate them and deliberately provides no escalation, enumeration, or evasion tooling. UMBRASEC publishes defense, not offense.
