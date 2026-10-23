---
name: detect-cicd-secret-exposure
description: "Detection, hunting, and hardening methodology for secrets exposed in CI/CD pipelines: deployment keys, cloud tokens, API secrets, and registry passwords leaked through build logs, caches, artifacts, credential stores, and OIDC federation trust. Maps to MITRE ATT&CK T1552 Unsecured Credentials and its sub-techniques T1552.001 Credentials In Files, T1552.004 Private Keys, and T1552.007 Container API. Keys off GitHub and GitLab audit logs, CI job logs, AWS CloudTrail, Azure Key Vault diagnostic logs, GCP Cloud Audit Logs, and HashiCorp Vault audit devices. Gives the defender's method for spotting a leaked or abused pipeline secret, a hypothesis-driven hunt, and least-privilege hardening, and points to public rule sources. Use when investigating a possible CI/CD secret leak, a secret-scanning alert, an unexpected GetSecretValue or AccessSecretVersion, an AssumeRoleWithWebIdentity from a pipeline, a push-protection bypass, or when hardening GitHub Actions, GitLab CI, Jenkins, or Azure DevOps secret handling."
---

# CI/CD Secret Exposure - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Pipeline secrets leak two ways: they are written somewhere a reader can reach (a build log, a cache, an artifact, a fork's pull-request run), or they are read and used by an identity that should never have touched them. You catch the first with secret scanning plus push protection on every repository, and the second by watching the credential store and cloud audit trail for reads and federation events that do not line up with a legitimate deployment. The highest-value single control is replacing long-lived static secrets with short-lived OIDC federation, because it shrinks what a leaked value is worth. A leaked secret that is scoped tight and rotated on exposure is a near-miss; a broad, long-lived one is an incident.

## What it looks like, defender view

In telemetry a leaked pipeline secret shows up as a mismatch, not as a single malicious event. A secret-scanning alert fires on a commit, or a cloud read of a secret arrives from an identity or an IP range that has never deployed that service, or a web-identity role assumption presents a subject claim that does not match a protected branch or environment. Build logs that should show a masked `***` instead carry a readable token because masking was never a security control, only a convenience. None of these is proof on its own; together they describe a credential that left the pipeline's trust boundary.

## Log sources and signals

The signal is split across the code platform, the secret store, and the cloud or service the secret unlocks. Collect all three; any one alone is a blind spot.

- **GitHub audit log (org and enterprise).** The `create_actions_secret` action, and its `update_` and `remove_` counterparts, at both `org.` and `repo.` scope, record when Actions secrets are set or changed. Secret-scanning alert lifecycle events (alert created, resolved, reopened) have been written to the audit log since 2022 and are the first place a leak surfaces. Push-protection activity is recorded under `repository_secret_scanning_push_protection`, and bypasses under `secret_scanning_push_protection.bypass` - a bypass means someone chose to commit a flagged secret anyway. The `org_secret_scanning_push_protection_bypass_list` and `repository_secret_scanning_push_protection_bypass_list` categories record changes to the delegated list of who may bypass, which is also worth alerting on.
- **CI job logs (GitHub Actions, GitLab CI, Jenkins, Azure DevOps).** Platforms mask known secret values in output on a best-effort basis, so treat any readable high-entropy string or `BEGIN PRIVATE KEY` block in a job log as a potential leak, especially in pull-request runs from forks and in failed-job debug output.
- **GitLab.** Watch for CI/CD variable changes in audit events, protected-variable exposure to unprotected branches, and `CI_JOB_TOKEN` use outside the job that was issued it.
- **AWS CloudTrail.** `GetSecretValue` (Secrets Manager) and `GetParameter` with `WithDecryption` (SSM Parameter Store) show secret reads. `AssumeRoleWithWebIdentity` (STS) is the OIDC federation event: the `sub` claim in the token tells you which repository, branch, or environment presented it, and a `sub` that does not match a protected ref is the tell.
- **Azure Key Vault diagnostic logs.** The `AuditEvent` category records `SecretGet` operations with the calling identity; forward it to a Log Analytics workspace and alert on reads from pipeline identities outside a deploy window.
- **GCP Cloud Audit Logs.** `AccessSecretVersion` on `secretmanager.googleapis.com` is the read event; the principal and caller IP are in the `authenticationInfo` and `requestMetadata`.
- **HashiCorp Vault audit device.** Each request logs `request.path` and `auth.display_name`; a pipeline role reading paths outside its policy, or from an unexpected source, is the anomaly.

What normal looks like: a given pipeline identity reads a stable set of secrets, from a stable source range, on a cadence that tracks its deploy schedule. The anomaly is a read of a new secret, from a new identity or IP, or outside that cadence.

## Detection approach

Alert on three families of signal, all in prose below; no tuned UMBRASEC rule ships for this threat yet, so pair these with the public rule sources named at the foot.

1. **Leak at rest.** Every secret-scanning alert and every push-protection bypass is a detection in its own right. Route alert-created and bypass events to a queue with a human on the end, because secret scanning does not rotate the exposed credential for you.
2. **Abnormal secret read.** Baseline which identity reads which secret from which source, then alert when a `GetSecretValue`, `AccessSecretVersion`, Key Vault `SecretGet`, or Vault read comes from an identity, role, or IP that is new for that secret, or lands outside the deploy window.
3. **OIDC federation drift.** On every `AssumeRoleWithWebIdentity`, compare the token `sub` claim against the allowlist of repositories, branches, and environments that role is meant to serve. A subject that does not match, or a role whose trust policy accepts a wildcard subject, is the finding.

Tuning and false positives, since Tier 2 has no separate tuning section: bot and dependency-update accounts legitimately create secrets; scheduled rotation and health-check jobs legitimately call `GetSecretValue` on a cadence, so baseline them before alerting; secret scanners trip on test fixtures and example keys, which you allowlist by path rather than by disabling the scanner. Build the identity-and-cadence baseline in report-only mode for a week before you enforce.

Public rule and tooling sources to build on, rather than inventing a rule here:

- SigmaHQ cloud rules for GitHub audit activity: https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/github and for AWS CloudTrail: https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws/cloudtrail
- GitHub secret scanning and push protection: https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning and https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
- GitLab Secret Detection: https://docs.gitlab.com/ee/user/application_security/secret_detection/
- Gitleaks (open-source scanner): https://github.com/gitleaks/gitleaks and TruffleHog: https://github.com/trufflesecurity/trufflehog
- MITRE D3FEND Credential Rotation (D3-CRO): https://d3fend.mitre.org/technique/d3f:CredentialRotation/

## Threat hunt

For the low-and-slow case, where an attacker pulls one high-value secret and uses it quietly, alerting thresholds will not fire. Hunt instead:

1. Over a long window, list every secret-read event (`GetSecretValue`, `AccessSecretVersion`, Key Vault `SecretGet`, Vault reads) and join the calling principal to its history. A secret accessed by an identity that has never deployed that service before is the lead.
2. Pull every `AssumeRoleWithWebIdentity` and extract the `sub` claim. Rank by subjects that do not match a protected branch or a named environment, and by roles whose trust policy subject condition is a wildcard.
3. Cross-reference secret-scanning alerts closed as a false positive against whether the underlying credential was actually rotated. An alert resolved without a rotation is an exposed secret still live.
4. Correlate `CI_JOB_TOKEN`, `GITHUB_TOKEN`, or a PAT used against the API outside the window of the job that was issued it - token reuse after the job ended points at exfiltration.
5. Rank every finding by blast radius: a leaked read-only artifact token outweighs nothing, a leaked cloud deploy role outweighs everything.

## Hardening

Shrink what a leaked secret is worth and shrink the chance it leaks at all. Mappings follow the control codes used in the UMBRASEC guide ([foundation](https://umbrasec.dev/guide/foundation.html), [identity and access](https://umbrasec.dev/guide/identity-and-access.html), [detection and response](https://umbrasec.dev/guide/detection-and-response.html)); a cell is blank where no single control maps cleanly.

| Control | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| Replace long-lived static secrets with short-lived OIDC federation, scoped to a repository, branch, or environment | Restrict administrative privileges | A.5.17 Authentication information | PR.AA-05 |
| Environment-scoped secrets with required reviewers, and least-privilege `GITHUB_TOKEN` / job-token permissions | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 |
| Secret scanning plus push protection enforced on every repository | - | A.8.8 Technical vulnerabilities | DE.CM |
| Centralized pipeline, secret-store, and cloud audit logging retained for hunting | - (ML2/ML3 event-log collection) | A.8.15 Logging; A.8.16 Monitoring activities | DE.AE |
| Rotate or revoke on suspicion of exposure, not on a blind calendar | - | A.5.17 Authentication information | PR.AA |

On rotation, follow the house line: rotate on suspicion of compromise rather than on a fixed schedule for its own sake, and when a secret is exposed, revoke it rather than relying on the scanner to have found it first.

## Honest limitations

Masking in build logs is best-effort and never a control, so a secret printed in an unusual format or split across lines can pass it; do not treat a clean log as proof. The abnormal-read detections depend on a credible baseline, which a brand-new pipeline or a noisy shared runner will not give you yet. A secret leaked to a fork pull-request run, or exfiltrated and used from the attacker's own infrastructure, may never read the legitimate store again, so cloud-side read anomalies will not see it - that is why leak-at-rest scanning and tight scoping matter as much as read monitoring. OIDC federation drift detection is only as good as your inventory of which role serves which ref. Baseline in report-only mode and let the evidence, not the alert, drive the call: these signals narrow where to look, they do not by themselves prove a secret is compromised.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552/), [T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/), [T1552.004 Private Keys](https://attack.mitre.org/techniques/T1552/004/), [T1552.007 Container API](https://attack.mitre.org/techniques/T1552/007/).
- MITRE D3FEND: [Credential Rotation (D3-CRO)](https://d3fend.mitre.org/technique/d3f:CredentialRotation/), under [Credential Hardening (D3-CH)](https://d3fend.mitre.org/technique/d3f:CredentialHardening/).
- Public rule sources: SigmaHQ cloud rules (links above), GitHub secret scanning and push protection docs, GitLab Secret Detection docs, Gitleaks, TruffleHog.

**Scope note.** This is a defensive skill. It explains the technique only to the depth needed to detect and mitigate CI/CD secret exposure and deliberately provides no extraction, dumping, masking-bypass, or pivoting tooling. UMBRASEC publishes defense, not offense.
