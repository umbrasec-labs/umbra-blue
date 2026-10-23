---
name: detect-container-escape
description: "Detection, hunting, and hardening for container escape to the host (MITRE ATT&CK T1611 Escape to Host, Privilege Escalation; related T1610 Deploy Container and T1613 Container and Resource Discovery). Keys off Linux auditd syscall records, CNCF Falco and eBPF runtime sensors, and the Kubernetes kube-apiserver audit log to catch namespace breakout, privileged or sensitive-mount workloads, capability abuse, and host-namespace process execution. Gives the defender view, the exact log sources and fields, a prose detection approach pointing to public rule sources, a hypothesis-driven hunt, seccomp and capability hardening, and the honest blind spots. Use when detecting or hunting container escape, investigating a shell spawned in a container, triaging a privileged pod or hostPath mount alert, monitoring seccomp and Linux capabilities on container hosts, or hardening Docker and Kubernetes against breakout to the node."
---

# Container Escape to Host - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

Container escape is a process inside a container gaining code execution on the host node (MITRE ATT&CK **T1611 Escape to Host**). It almost always leaves one of a small set of host-visible traces: a workload started with `--privileged` or `CAP_SYS_ADMIN`, a host path or the container socket mounted into the container, a process changing its namespace back to the host (`setns`/`unshare`), a mount of the host filesystem from inside a container, or a write to a sensitive kernel interface such as a cgroup `release_agent` or `core_pattern`. You detect it at two layers at once: the Linux kernel (auditd syscalls plus a runtime sensor like **Falco** or an eBPF tool) on every node, and the **Kubernetes kube-apiserver audit log** for the dangerous pod spec that enables the escape in the first place. This skill ships no UMBRASEC rule for this threat; it points to maintained public rule sets instead.

## What it looks like, defender view

In telemetry an escape shows up as container-origin activity that crosses the container boundary. The container runtime (runc, containerd-shim) normally confines a workload to its own PID, mount, and network namespaces with a restricted capability set and a seccomp profile. An escape breaks that confinement, so the defender signal is a workload that either was granted too much up front (privileged, extra capabilities, host namespaces, host mounts) or performs an action no ordinary application in a container performs: joining a host namespace, mounting block devices or the host root, writing to `/proc/sys` or cgroup control files, or opening `/var/run/docker.sock`. A shell interactively spawned inside a running container, while sometimes legitimate for debugging, is the common precursor and belongs in the same triage lane.

## Log sources and signals

Collect from the node kernel and from the orchestrator control plane. Both matter: the kernel catches the escape action, the control plane catches the misconfiguration that permitted it.

- **Linux auditd (host).** Watch `execve`, `mount`, `setns`, `unshare`, `clone`/`clone3` with namespace flags, `open`/`openat` on sensitive paths, and `ptrace`. Key fields: `syscall`, `exe`, `comm`, `cwd`, `key` (your audit rule tag), `a0`-`a3` syscall arguments, `auid`, `ses`, and the subject SELinux context `subj`. A `mount` syscall whose process lives in a container cgroup, or a `setns`/`unshare` that moves a process out of its namespace, is the primary anomaly.
- **Runtime security sensor (host).** CNCF **Falco** or an eBPF tool (Aqua **Tracee**, **Tetragon**) emits enriched events that already carry container context (`container.id`, `container.image.repository`, `proc.pname`, `evt.type`). The Falco rules repository (stable, incubating, and sandbox files) includes rules that name the behaviours that matter here, for example "Terminal shell in container" and "Redirect STDOUT/STDIN to Network Connection in Container" (stable), "Launch Privileged Container" and "Change thread namespace" (incubating), and "Launch Sensitive Mount Container" (sandbox).
- **Kubernetes kube-apiserver audit log.** JSON records with `verb`, `objectRef.resource`, `user.username`, `requestObject`, and `responseStatus`. Hunt for `create`/`update` on `pods` whose `requestObject` sets `securityContext.privileged: true`, `hostPID`, `hostNetwork`, `hostIPC`, a `hostPath` volume, `allowPrivilegeEscalation: true`, added capabilities (`SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`, `NET_ADMIN`), or `seccompProfile.type: Unconfined`. Also flag `create` on the `pods/exec` subresource, the API-level equivalent of a shell in a container.
- **Container runtime and daemon logs.** `dockerd`/`containerd` logs and the EDR process tree showing a container-spawned process reparenting to a host process, or `runc` being invoked or overwritten unexpectedly (the historic `runc` `/proc/self/exe` overwrite class, CVE-2019-5736, and the `WORKDIR`/fd leak class, CVE-2024-21626).

What normal looks like: application containers run as non-root, with a default or tightened seccomp profile, no added capabilities, no host mounts, and never call `setns`, `unshare`, or `mount`. CI builders, service meshes, CNI plugins, and node-level DaemonSets (logging, monitoring) are the main legitimate users of privilege and host namespaces, so baseline them by name before alerting.

## Detection approach

Alert on the breakout action and on the enabling misconfiguration, and correlate the two.

At the kernel layer, alert when a process whose cgroup places it inside a container performs a namespace-changing syscall (`setns`, `unshare`, or `clone` with `CLONE_NEWNS`/`CLONE_NEWPID`) or a `mount`, especially a mount of a host block device or bind mount of host paths. Alert on writes to known escape primitives: cgroup v1 `release_agent` and `notify_on_release` files, `/proc/sys/kernel/core_pattern`, and `/proc/sysrq-trigger`. Alert on any container process opening `/var/run/docker.sock` or `/run/containerd/containerd.sock`. Treat an interactive shell inside a container (`bash`/`sh` with a tty, parent is the runtime) as medium severity triage, higher if it precedes any of the above.

At the control-plane layer, alert on pod admission that sets privilege, host namespaces, host mounts, dangerous capabilities, or `seccompProfile: Unconfined`, and on `pods/exec`. Prefer to block these at admission with Kubernetes **Pod Security Admission** (the `restricted` profile) or a policy engine rather than only alerting after the fact.

This skill ships **no UMBRASEC rule** for container escape. Use these public, maintained rule sources:

- Falco rules (CNCF): https://github.com/falcosecurity/rules - the host rules in `falco_rules.yaml` (stable), `falco-incubating_rules.yaml`, and `falco-sandbox_rules.yaml`. The Kubernetes audit rules ship with the k8saudit plugin at https://github.com/falcosecurity/plugins under `plugins/k8saudit/rules/` for the kube-apiserver audit feed.
- SigmaHQ Linux and auditd rules: https://github.com/SigmaHQ/sigma/tree/master/rules/linux - process-creation and auditd rules covering namespace, mount, and capability abuse.
- Aqua Tracee behavioural signatures: https://github.com/aquasecurity/tracee - including container-escape detection signatures.
- MITRE ATT&CK data sources and detections for T1611: https://attack.mitre.org/techniques/T1611/
- MITRE D3FEND countermeasures (below).

## Threat hunt

Hypothesis: an attacker who gained code execution in a container has already broken out to a node, using privilege it was granted or a primitive it reached.

1. From the kube-apiserver audit log over a long window, list every pod created with `privileged: true`, `hostPID`, `hostNetwork`, `hostPath`, added `SYS_ADMIN`/`SYS_PTRACE`/`DAC_READ_SEARCH`, or `seccompProfile: Unconfined`. Rank by namespace sensitivity and by whether the image is an approved node-level workload or something ad hoc. Each unexpected one is a standing escape path, whether or not it has been used.
2. On the nodes, query auditd and the runtime sensor for container-origin processes that called `setns`, `unshare`, or `mount`, or that opened `docker.sock`/`containerd.sock`, `release_agent`, or `core_pattern`. Join each hit back to its `container.id` and image.
3. Pivot on any match: enumerate the full process tree, look for a process that reparented from the container to the host, for outbound connections from that process, and for new node-level persistence (cron, systemd units, SSH keys) created around the same time.
4. For the low-and-slow case, review which service accounts and users have `create` rights on privileged pods or on `pods/exec`, and whether any used them off-hours or from an unusual source.

## Hardening

Shrink both the standing escape surface (what a container is allowed to do) and the blast radius (what the node exposes). The mappings below use the control codes carried in the UMBRASEC [governance and maturity guide](https://umbrasec.dev/guide/governance-and-maturity.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Run unprivileged, drop all capabilities, add back only what is needed | Removes `CAP_SYS_ADMIN` and privileged mode, the most common escape enablers | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Enforce a seccomp profile and AppArmor or SELinux (no Unconfined) | Blocks the syscalls (mount, setns, keyctl, ptrace) an escape relies on | - | - | PR.PS Platform security |
| Block privileged and host-namespace pods at admission (Pod Security Admission `restricted`, policy engine) | Stops the dangerous spec being created rather than alerting after | Restrict administrative privileges | A.8.2 Privileged access rights | PR.PS Platform security |
| Patch the container runtime and host kernel | Closes runc and kernel escape CVEs (for example CVE-2019-5736, CVE-2024-21626) | Patch operating systems; Patch applications | A.8.8 Technical vulnerabilities | ID.RA |
| Runtime monitoring on every node (auditd plus Falco or eBPF) | Produces the telemetry this detection depends on | - | A.8.16 Monitoring activities | DE.CM Continuous monitoring |
| Never mount the container socket or host root into a workload | Removes the direct host-control primitive | - | - | PR.PS Platform security |

## Honest limitations

A kernel-level escape through a 0-day that corrupts the kernel directly may issue no auditable syscall from the container and can leave the node telemetry silent; in that case the only signal is the anomalous host behaviour afterward. If a workload is legitimately privileged (a node-level DaemonSet, a CI builder, a service mesh init container), its escape-like actions look normal, so baseline and allowlist those by image and namespace or they will drown the signal. auditd and eBPF sensors can be heavy and are sometimes thinned in production, and a sensor that is not on every node leaves a blind node. Control-plane detection only sees escapes that required a visible pod spec or `exec`; an escape from an already-running, already-privileged container is invisible to the audit log and must be caught at the kernel layer. None of this fires unattended: layer kernel and control-plane signals, baseline your legitimate privileged workloads first, and let an analyst make the call.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1611 Escape to Host](https://attack.mitre.org/techniques/T1611/) (Privilege Escalation); related [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/) and [T1613 Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/).
- MITRE D3FEND: System Call Filtering (D3-SCF) via seccomp, and Mandatory Access Control (D3-MAC) via AppArmor or SELinux. See https://d3fend.mitre.org/
- Public rule sources: Falco rules https://github.com/falcosecurity/rules, SigmaHQ Linux rules https://github.com/SigmaHQ/sigma/tree/master/rules/linux, Aqua Tracee https://github.com/aquasecurity/tracee.

**Scope note.** This is a defensive skill. It explains container escape only to the depth needed to detect and mitigate it and deliberately ships no escape tooling, exploit code, or breakout instructions. UMBRASEC publishes defense, not offense.
