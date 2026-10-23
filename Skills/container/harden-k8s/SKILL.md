---
name: harden-k8s
description: "Defensive methodology for Kubernetes cluster attacks: over-privileged RBAC and stolen service-account tokens driving the API server, interactive access to running workloads, and attacker-deployed or privileged pods used to escape to the node and persist (MITRE ATT&CK T1078, T1552.007, T1609, T1610, T1525, T1611, T1613, T1053.007). Signals live in the Kubernetes API server audit log and its managed equivalents (EKS control-plane logs, GKE Cloud Audit Logs, AKSAudit tables) plus Falco runtime events. Gives the defender view of each path, the audit fields to alert on, a hunt, and RBAC, admission-control, and audit-logging hardening mapped to the UMBRASEC guide. Use when hardening a Kubernetes cluster, reviewing RBAC roles and bindings, designing PodSecurity or Kyverno/Gatekeeper admission policy, tuning API server audit logging, hunting a privileged-pod foothold, or triaging an unexpected clusterrolebinding change or pods/exec event."
---

# Kubernetes Cluster Attacks - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

A Kubernetes cluster is a credential and a control plane in one. Most post-compromise damage runs through the API server, so most of the defense is RBAC that grants too little to matter, admission control that refuses the dangerous pod, and an audit log that records every verb. Turn on **API server audit logging** (`--audit-policy-file`, `--audit-log-path`, or the managed-platform equivalent) and watch five things: **permission enumeration** (`SelfSubjectAccessReview` and `SelfSubjectRulesReview`, the `kubectl auth can-i --list` call), **RBAC changes** that bind a subject to `cluster-admin` or the `system:masters` group, **interactive access** to workloads (the `pods/exec` and `pods/attach` subresources), **dangerous pod admission** (`securityContext.privileged`, `hostPID`/`hostNetwork`/`hostIPC`, `hostPath` mounts), and **secret harvesting** (`get`/`list` on `secrets` across namespaces). Harden by stripping wildcard and `cluster-admin` RBAC, disabling automatic service-account token mounting, and enforcing the PodSecurity `restricted` profile at admission so a privileged pod cannot be created in the first place. Layer all of it; audit detection buys time, admission control closes the door.

## What it looks like, defender view

These attacks almost never arrive as a novel event type. They arrive as the API server faithfully doing what an over-privileged identity is allowed to do, so the signal is the mismatch between the subject and the action, not the action itself. A compromised workload uses the service-account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` to call the API as its own identity; if that identity can list secrets or create pods, the audit log shows a legitimate, authorized request whose only anomaly is that this service account has no business making it. An attacker who lands a kubeconfig or exec's into a pod shows up as a normal `pods/exec` or a normal `get secrets`, authorized and successful. Privilege escalation shows up as a clean `create`/`patch` on a `clusterrolebinding`, and host escape begins with a perfectly valid `create pods` whose manifest sets `privileged: true` or mounts `hostPath: /`. The defender's job is to know which subjects are supposed to do each of those things and alert on the rest. This skill explains each path only as far as detection and hardening require and ships no cluster-exploitation tooling.

## Log sources and signals

The primary source is the **Kubernetes API server audit log**, structured JSON `audit.k8s.io/v1` `Event` objects. It is off or minimal by default on self-managed clusters: enable it with an audit policy that records at least `Metadata` for reads and `Request`/`RequestResponse` for writes and for `secrets`, `configmaps`, and RBAC resources, via `--audit-policy-file` and `--audit-log-path` on `kube-apiserver` (or a webhook backend to your SIEM).

Managed control planes expose the same events:

- **EKS**: enable control-plane logging and read the `audit` and `authenticator` log streams in the CloudWatch log group `/aws/eks/<cluster>/cluster`.
- **GKE**: Cloud Audit Logs for resource type `k8s_cluster` in Cloud Logging, Admin Activity and Data Access logs, under `protoPayload` with `methodName`, `authenticationInfo.principalEmail`, and `authorizationInfo`.
- **AKS**: turn on the diagnostic settings categories `kube-audit` and `kube-audit-admin` and query the `AKSAudit` and `AKSAuditAdmin` tables (or `AzureDiagnostics`) in Log Analytics / Microsoft Sentinel.

Fields you will lean on in each audit event:

- `verb` (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, `impersonate`) and `objectRef.resource` / `objectRef.subresource` / `objectRef.namespace` / `objectRef.name`.
- `user.username` and `user.groups` (the authenticated subject; `system:anonymous` and the `system:unauthenticated` group are the ones that should almost never succeed), and `impersonatedUser` when impersonation is used.
- `annotations["authorization.k8s.io/decision"]` (`allow` or `forbid`) and `annotations["authorization.k8s.io/reason"]` (which role or binding granted it) - the pair that tells you what RBAC actually permitted.
- `requestURI`, `sourceIPs`, `userAgent`, `responseStatus.code`, and `stage` (filter to `ResponseComplete`).
- For write verbs on pods, the `requestObject.spec` fields `containers[].securityContext.privileged` (and `initContainers[]` / `ephemeralContainers[]`), `hostPID`, `hostNetwork`, `hostIPC`, and `volumes[].hostPath`.

High-value signal events: `selfsubjectaccessreviews` / `selfsubjectrulesreviews` creation (the `can-i` enumeration), `create`/`patch` on `clusterrolebindings` and `rolebindings`, the `pods/exec` and `pods/attach` subresources, `create` on `pods` with a privileged or host-namespace spec, `get`/`list` on `secrets`, `create` on `serviceaccounts/token` (the TokenRequest API), `create` on `cronjobs` or `daemonsets`, the `escalate` and `bind` verbs on `roles`/`clusterroles`, and any authorized action by `system:anonymous`. Runtime escape is corroborated on the node by **Falco** (CNCF) syscall rules and by host EDR / `auditd`.

What normal looks like: a small, enumerable set of human and controller identities perform writes; `pods/exec` comes from a known operator group or a break-glass account, not from a workload service account; RBAC bindings change through your GitOps pipeline, not interactively; and no legitimate subject is `system:anonymous`. Deviation from each baseline is the alertable condition.

## Detection approach

Alert on the authorization-plus-subject mismatch, in prose, across the audit stream.

**Permission enumeration.** Alert on bursts of `selfsubjectaccessreviews` / `selfsubjectrulesreviews`, and on `list`/`get` fan-out across `roles`, `clusterroles`, `rolebindings`, and `clusterrolebindings` from a single subject, which is the reconnaissance that precedes RBAC abuse.

**RBAC privilege escalation.** Alert on `create`/`patch` of a `clusterrolebinding` or `rolebinding` whose `roleRef` is `cluster-admin` or whose subject is a broad group (`system:authenticated`, `system:unauthenticated`), and on use of the `escalate` or `bind` verbs, which let a subject grant itself more than it holds.

**Interactive access and secret access.** Alert on `pods/exec` and `pods/attach` from any subject outside your operator allowlist, and on `get`/`list` of `secrets` by a workload service account or across namespaces it does not own.

**Dangerous pod admission.** Alert on `create pods` whose spec sets `privileged: true`, a host namespace, or a sensitive `hostPath` mount (`/`, `/var/run/docker.sock`, `/proc`), especially in `kube-system`. This is the host-escape precursor and the one admission control should also block outright.

**Anonymous and unauthenticated success.** Any `allow` decision for `system:anonymous` or the `system:unauthenticated` group is high-signal by construction.

There is no tuned UMBRASEC rule for this threat yet. For public, maintained starting points, the SigmaHQ repository ships Kubernetes audit rules under [rules/application/kubernetes/audit](https://github.com/SigmaHQ/sigma/tree/master/rules/application/kubernetes/audit), including `kubernetes_audit_rbac_permisions_listing.yml`, `kubernetes_audit_rolebinding_modification.yml`, `kubernetes_audit_exec_into_container.yml`, `kubernetes_audit_privileged_pod_creation.yml`, `kubernetes_audit_hostpath_mount.yml`, `kubernetes_audit_secrets_enumeration.yml`, `kubernetes_audit_change_admission_controller.yml`, `kubernetes_audit_serviceaccount_creation.yml`, and `kubernetes_audit_unauthorized_unauthenticated_actions.yml`; treat them as scaffolding to tune against your own subject allowlist. For runtime detection use the [Falco](https://github.com/falcosecurity/rules) rule set and its `k8s_audit` plugin. The authoritative hardening references are the CISA/NSA [Kubernetes Hardening Guidance](https://www.cisa.gov/news-events/alerts/2022/08/29/updated-kubernetes-hardening-guide), the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes), Microsoft's [Threat matrix for Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/), and the Kubernetes project's [auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) and [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) documentation.

## Threat hunt

For the quiet attacker who makes one authorized call and waits, the volume alerts will not fire. Hunt the trust itself, not just the activity:

1. Enumerate RBAC and grade it. List every `clusterrolebinding` and `rolebinding`, resolve each `roleRef` to its verbs and resources, and flag any subject bound to `cluster-admin`, any role with wildcard `verbs: ["*"]` or `resources: ["*"]`, any binding whose subject is `system:authenticated`, `system:unauthenticated`, or `system:anonymous`, and any role granting `secrets` `get`/`list`, `pods/exec`, `escalate`, `bind`, or `impersonate`. These are the paths an attacker would use whether or not anyone has used them yet.
2. Map service-account reach. For each namespace, list service accounts, the pods that mount their tokens, and what RBAC those tokens grant. A workload service account that can read secrets cluster-wide or create pods is the over-privileged identity that turns one compromised container into cluster control.
3. In the audit log over a long window, project `pods/exec`, `create clusterrolebinding`, `create pods` with a privileged or host spec, and `create serviceaccounts/token`, grouped by `user.username`. Rank by the privilege of the subject and by whether the action came from a workload service account rather than a human or controller.
4. Grep workload manifests across the cluster for `privileged: true`, `hostPID`/`hostNetwork`/`hostIPC`, `hostPath` mounts, and `automountServiceAccountToken` left at its default. These are the admission gaps that make step 3 possible.
5. Correlate: an over-privileged service-account token (step 2) mounted in a pod that an attacker can reach (step 1), able to create a privileged pod (step 4), is a full path from container compromise to node and cluster takeover. Close that chain first.

## Hardening

Shrink the privilege and the attack surface each path depends on. Mappings below use control codes grounded in the UMBRASEC guide ([identity-and-access.html](https://umbrasec.dev/guide/identity-and-access.html), [foundation.html](https://umbrasec.dev/guide/foundation.html), [detection-and-response.html](https://umbrasec.dev/guide/detection-and-response.html)); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| RBAC least privilege | Remove `cluster-admin` and wildcard `verbs`/`resources`; scope roles to namespaces and named resources; never bind to `system:authenticated`, `system:unauthenticated`, or `system:anonymous` | Restrict administrative privileges | A.8.2 Privileged access rights; A.5.15 Access control; A.5.18 Access rights | PR.AA-05 Least privilege |
| Service-account token hygiene | Set `automountServiceAccountToken: false` by default, give each workload a dedicated minimal service account, and prefer short-lived bound tokens over long-lived secrets | - | A.5.16 Identity management; A.5.17 Authentication information | PR.AA-01 Identities and credentials |
| Admission control on pod security | Enforce the PodSecurity `restricted` profile and use Kyverno or OPA Gatekeeper to refuse privileged, host-namespace, and `hostPath` pods and to require signed or allowlisted images, blocking the dangerous workload before it is admitted | Application control | A.8.19 Software on systems | PR.PS Platform security |
| Patch the control plane and nodes | Keep `kube-apiserver`, `kubelet`, the container runtime, and node OS current so a known CVE does not bypass the controls above | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | PR.PS Platform security |
| Audit logging enabled and shipped | Turn on API server audit logging with a policy that captures RBAC, secrets, and pod writes, and stream it off-cluster so the detections above have data | - | A.8.15 Logging; A.8.16 Monitoring activities | DE.CM Continuous monitoring |

## Honest limitations

Audit detection is only as good as the policy and the baseline: if a workload service account is legitimately over-privileged, its abuse is an authorized `allow` and will surface only through the step 1 and step 2 RBAC hunts, not a real-time rule. The audit log records API server activity, so an attacker who escapes to a node and acts through the container runtime or the kubelet directly, or who exfiltrates a mounted secret and uses it off-cluster, is visible to node EDR and Falco but not to the audit stream alone. On managed clusters you see the control-plane audit log but not the master host, and audit verbosity is capped by what the provider exposes. None of this substitutes for fixing the privilege itself: a `cluster-admin` binding, a wildcard role, an automounted token on a reachable pod, or a cluster that admits privileged pods is the actual vulnerability, and detection only buys time until RBAC is scoped, token mounting is turned off, and admission control refuses the dangerous pod. Baseline every rule in report-only mode before enforcing; the thresholds and allowlists are dials.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) and [T1552.007 Unsecured Credentials: Container API](https://attack.mitre.org/techniques/T1552/007/) (service-account token and kubeconfig abuse); [T1609 Container Administration Command](https://attack.mitre.org/techniques/T1609/) (kubectl exec into a workload); [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/) and [T1525 Implant Internal Image](https://attack.mitre.org/techniques/T1525/) (attacker-deployed or backdoored workloads); [T1611 Escape to Host](https://attack.mitre.org/techniques/T1611/) (privileged or hostPath pod to node); [T1613 Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/) (API enumeration); [T1053.007 Scheduled Task/Job: Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007/) (CronJob and DaemonSet persistence).
- MITRE D3FEND: [Application Configuration Hardening (D3-ACH)](https://d3fend.mitre.org/technique/d3f:ApplicationConfigurationHardening/) for RBAC least privilege, token-mount defaults, and admission policy as configuration; [Execution Isolation (D3-EI)](https://d3fend.mitre.org/technique/d3f:ExecutionIsolation/) for refusing privileged and host-namespace pods at admission so untrusted workloads stay confined.
- Public rule and guidance sources: [SigmaHQ Kubernetes audit rules](https://github.com/SigmaHQ/sigma/tree/master/rules/application/kubernetes/audit), [Falco rules](https://github.com/falcosecurity/rules), [CISA/NSA Kubernetes Hardening Guidance](https://www.cisa.gov/news-events/alerts/2022/08/29/updated-kubernetes-hardening-guide), [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes), [Microsoft Threat matrix for Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/), [Kubernetes auditing docs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/), [Kubernetes RBAC docs](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

**Scope note.** This is a defensive skill. It explains Kubernetes cluster attacks only to the depth needed to detect and mitigate them and deliberately provides no cluster-exploitation, privilege-escalation, or container-escape tooling. UMBRASEC publishes defense, not offense.
