---
name: detect-supply-chain-compromise
description: "Detection and response for supply-chain compromise: a poisoned software package or tampered build artifact that executes on install (MITRE ATT&CK T1195.002, T1546 for .pth / import-hook persistence, T1552 for credential stealers), and a trusted MSP or RMM platform turned into a delivery channel (T1199, T1543.003, T1572). Keyed off Linux file-creation telemetry (auditd, Sysmon for Linux, EDR) over site-packages, Windows System Event ID 7045, Windows process creation (Sysmon 1 / Security 4688), and package and container inventory. Ships two UMBRASEC sigma-pack rules plus a hunt, with tuning and Essential Eight / ISO 27001 / NIST CSF 2.0 mappings. Use when a dependency or Docker image you run was backdoored, triaging a PyPI, npm, or container supply-chain advisory, hunting a cook.pth import hook or dropped credential stealer, responding to an MSP or RMM compromise, or chasing an unexpected Cloudflared tunnel service."
---

# Supply-Chain Compromise - Detection and Response

Supply-chain compromise reaches you through something you already trust: a package you pulled from a registry, a container image you deployed, or the managed service provider that runs your fleet. The breach itself usually happens somewhere you cannot patch - an upstream maintainer account, a vendor build pipeline, an RMM console in your provider's rack - so the defensive win is not stopping the compromise upstream but catching what it drops on the hosts you do own. This skill is defensive: it explains the technique only as far as detection and mitigation require, and ships no package-poisoning, implant, or tunnelling tooling.

## TL;DR for defenders

You often cannot patch the thing that was breached, so detect its leave-behinds on your own hosts. For a **poisoned package or tampered artifact**, watch file creation under Python **site-packages / dist-packages** for an unexpected **`.pth` import hook plus a credential-stealer payload** - the compromised LiteLLM 1.107.0 release dropped `cook.pth` and `cook.py` so that every Python start reran a stealer. For a **compromised MSP or RMM**, hunt the operator's leave-behinds: a Windows service named **Cloudflared** nobody requested (**System log Event ID 7045**), and a binary **masquerading as `svchost.exe` outside System32** (process creation). The highest-value control here is **inventory**: you cannot detect a backdoored dependency, image, or supplier channel you did not know you ran. Rule 1 below is the high-fidelity one for the package case; rule 2 is the persistence tripwire for the RMM case.

## Two shapes of supply-chain compromise

The same trust abuse shows up in two operationally distinct ways, and the log source differs for each.

- **Compromised software supply chain (MITRE ATT&CK T1195.002).** An attacker gets malicious code into a package, dependency, or image that you then install yourself. The LiteLLM 1.107.0 case is the clean example: poisoned PyPI wheels (live for roughly two hours on 21 Oct 2026) and several Docker/GHCR tags shipped a `cook.pth` / `cook.py` pair into the site-packages root. A `.pth` file is executed by the Python interpreter at every startup, so the stealer reran on every `python` and `pip` invocation (**T1546 Event Triggered Execution**) and harvested credentials from the host (**T1552 Unsecured Credentials**). The artifact on disk is the evidence the poisoned release was installed.
- **Trusted relationship / RMM compromise (MITRE ATT&CK T1199).** A provider you have granted standing access is breached, and their tooling becomes the delivery channel. In the August 2026 N-able N-central intrusions, two authentication bypasses let operators drive **Take Control** remote sessions to managed endpoints, drop a binary named `svchost.exe` into a user's Documents folder, and register a **Cloudflared** service to hold access after N-central credentials were revoked (**T1543.003 Windows Service**, **T1572 Protocol Tunneling**). The vulnerable server is not yours to patch; every artifact the operator left ran on hardware you own.

## Log sources required

Different artifacts, different telemetry. Collect all of these or accept the corresponding blind spot.

- **Package and container inventory (the prerequisite).** `pip freeze` / lockfiles, container image digests and tags, and any SBOM you hold. A poisoned release is only actionable if you can answer "do we run that version?" quickly. Treat this as a log source, not a one-off audit.
- **Linux file-creation events** for the dropped-artifact case: auditd file watches, Sysmon for Linux (`FileCreate`), or EDR file telemetry carrying a `TargetFilename` field. On container hosts this must be the **node/host sensor**, because the writes land under the overlay or rootfs path of the container.
- **Windows System log, Event ID 7045** ("A service was installed in the system") for the Cloudflared persistence service. On by default, low volume, frequently not collected. Carries `ServiceName` and `ImagePath`.
- **Windows process creation with command line**: Sysmon **Event ID 1**, or Security **Event ID 4688** with "Include command line in process creation events" enabled, for the masqueraded `svchost.exe`.
- **Take Control / RMM agent logs** on managed endpoints, for the MSP case: for N-central, `C:\ProgramData\GetSupportService_N-Central\Logs\` files matching `BASupSrvc_*.log.gz`. Local files, no provider console required.

## Detection

Two canonical UMBRASEC [sigma-pack](https://umbrasec.dev/tools/sigma-pack/) rules, one per shape. Each is inlined byte-for-byte from the pack; convert with `sigma-cli` for your SIEM.

### 1. Credential stealer dropped by a poisoned package (high fidelity)

A `.pth` import hook plus a payload module landing in the site-packages root is not something a healthy install does. The rule matches the dropped hook, its compiled `.pyc`, and the run-once / lock markers the stealer leaves, so a host or node sensor fires whether the package ran in a VM or a container.

```yaml
# litellm-stealer-files-linux.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: LiteLLM 1.107.0 Credential Stealer Dropped on Linux Host
id: 4b113653-9759-4c81-9fe0-eb8df655df30
status: experimental
description: >
    The compromised LiteLLM 1.107.0 release (PyPI wheels live 11:39-13:23
    UTC on 21 Oct 2026, and the v1.107.0, latest, main-latest and
    main-stable Docker/GHCR tags) drops cook.pth and cook.py into the
    site-packages root (dist-packages on Debian and Ubuntu system Python)
    so that every Python start - pip included - reruns a credential
    stealer. The .pth/.py pair and the compiled .pyc show the poisoned
    release was installed. The stealer works out of /tmp/.pc_sq_* and
    /tmp/.pc_e_* directories, writes a run-once marker under /tmp once
    exfiltration succeeds, and a detached loader daemon holds
    /tmp/remote_code_loader.lock; any of those shows it ran. No path is
    anchored to the start so that host sensors on a Docker or
    Kubernetes node, which see container writes under the overlay or
    rootfs path, still fire. The release also drops sitecustomize.py (the
    loader for the never-activated second stage) beside the hook, but
    distributions and deployments ship legitimate sitecustomize.py files,
    so that name is left to a hunt: look for one created within a minute
    of cook.pth.
references:
    - https://docs.litellm.ai/blog/security-incident-oct-21-2026
    - https://www.wiz.io/blog/litellm-compromised-steals-credentials
    - https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
author: UMBRASEC
date: 2026-10-23
tags:
    - attack.initial-access
    - attack.t1195.002
    - attack.persistence
    - attack.t1546
    - attack.credential-access
    - attack.t1552
logsource:
    category: file_event
    product: linux
detection:
    selection_hook:
        TargetFilename|endswith:
            - '/site-packages/cook.pth'
            - '/site-packages/cook.py'
            - '/dist-packages/cook.pth'
            - '/dist-packages/cook.py'
    selection_pyc:
        TargetFilename|contains:
            - '/site-packages/__pycache__/cook.'
            - '/dist-packages/__pycache__/cook.'
    selection_tmp:
        TargetFilename|endswith:
            - '/tmp/.pc_once_72129118c59f5636c0bb'
            - '/tmp/remote_code_loader.lock'
    selection_temp_dirs:
        TargetFilename|contains:
            - '/tmp/.pc_sq_'
            - '/tmp/.pc_e_'
    condition: 1 of selection_*
falsepositives:
    - Unlikely. A legitimate package that ships a module named cook with a .pth hook would collide on the first two selections; check the package metadata before closing
    - An analyst or test harness recreating the indicator files to exercise this rule
level: high
```

### 2. A Cloudflare Tunnel service appears (persistence tripwire)

When a trusted provider is compromised, the durable artifact is often a tunnel client registered as a Windows service, which gives inbound reach with no inbound firewall rule and survives revocation of the access that planted it. This rule fires on service installation (Event ID 7045) naming cloudflared. It is dual-use software, hence medium severity: if you deploy it deliberately, invert the rule and alert on installs outside the approved path rather than silencing it.

```yaml
# cloudflared-tunnel-service-install.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: Cloudflare Tunnel Service Installed
id: bf3f2f8a-f904-4978-9ff1-6dc3c79a2afb
status: experimental
description: >
    A Windows service was created for cloudflared, the Cloudflare Tunnel
    client. A tunnel client gives an operator inbound reach to a host without
    any inbound firewall rule, and it keeps working after whatever access
    established it has been revoked. Observed in the August 2026 N-able
    N-central intrusions, where a service named Cloudflared was registered on
    managed endpoints specifically to hold access after N-central credentials
    were revoked.
references:
    - https://attack.mitre.org/techniques/T1543/003/
    - https://attack.mitre.org/techniques/T1572/
    - https://www.n-able.com/blog/n-central-security-update-august-6-2026
    - https://umbrasec.dev/research/n-able-ncentral-msp-supply-chain.html
author: UMBRASEC
date: 2026-08-12
tags:
    - attack.persistence
    - attack.t1543.003
    - attack.command-and-control
    - attack.t1572
logsource:
    product: windows
    service: system
detection:
    selection_name:
        EventID: 7045
        ServiceName|contains: 'cloudflared'
    selection_image:
        EventID: 7045
        ImagePath|contains: 'cloudflared'
    condition: 1 of selection_*
falsepositives:
    - Cloudflare Tunnel is legitimate dual-use software. If your organisation
      deploys it deliberately, allowlist the known install path and service
      account and alert only on installs outside it
    - A sanctioned vendor or MSP deploying Cloudflare Tunnel for remote support
level: medium
```

A third artifact from the MSP case, a binary named `svchost.exe` running outside System32, is a high-fidelity masquerading signal (**T1036.005**) and ships in sigma-pack as `masquerading-svchost-outside-system32.yml`. It is covered in the N-central writeup linked below rather than reprinted here.

## Tuning and false positives

- **Rule 1 (package stealer).** False positives are unlikely by construction: no healthy package ships a module named `cook` with a `.pth` hook. The two benign causes are a legitimate package that genuinely ships a `cook` module with a startup hook (check its metadata before closing) and an analyst or test harness recreating the indicator files to exercise the rule. This rule is specific to the known indicator set; it is a confirmation that the poisoned release was installed, not a generic "any new `.pth`" detector. For the generic case, see the hunt below.
- **Rule 2 (Cloudflared service).** Cloudflare Tunnel is legitimate dual-use software, which is why it is level `medium`. If you do not deploy it, any Event ID 7045 naming cloudflared is worth a phone call. If you do, do not silence the rule - allowlist the known install path and service account and alert on installs outside them. Run report-only for a week first to learn your baseline of legitimate installs.

## Threat hunt

For the low-and-slow or not-yet-signatured case the rules miss, hunt rather than wait for an alert.

1. **Version audit against the advisory.** When a supply-chain advisory lands, query your package / container inventory for the named bad versions directly (for LiteLLM: wheel `1.107.0`, and the `v1.107.0`, `latest`, `main-latest`, `main-stable` Docker/GHCR tags). This catches hosts that pulled the poisoned release but where the file-event sensor was absent or the writes rolled out of the window.
2. **Unexpected startup hooks.** Over a long window, list files created in site-packages / dist-packages roots with a `.pth` extension, and any `sitecustomize.py` created within about a minute of a `.pth` file. The stealer dropped a `sitecustomize.py` loader beside its hook, but distributions ship legitimate `sitecustomize.py` files, so this is a hunt input and not an alert on its own.
3. **RMM session reconciliation (MSP case).** Pull the Take Control logs (`C:\ProgramData\GetSupportService_N-Central\Logs\`, `BASupSrvc_*.log.gz`) and correlate session timestamps against your ticket queue and change log. A remote session into a domain controller at 2am with no matching ticket is the finding. For N-central, focus 31 July to 10 August 2026.
4. **Egress from a new tunnel.** If rule 2 fires or a tunnel is suspected, pivot to outbound network telemetry for persistent connections to Cloudflare tunnel edges from a host that has no business originating them.

## Mitigation

Detection buys time; these shrink the attack surface. Mappings follow the exact control language used in the UMBRASEC security guide; a cell is `-` where nothing maps cleanly. D3FEND countermeasures are listed where one applies.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 | D3FEND |
|---|---|---|---|---|---|
| Know what you run (package / image / SBOM inventory) | Makes a supply-chain advisory actionable; you cannot pull or detect a version you cannot find | Assumed prerequisite | A.5.9 Inventory of assets | ID.AM Asset Management | - |
| Treat supplier / MSP security as your security | Supplier assurance: build and date questions, MFA and patch evidence, access review on the provider | Beyond E8 | A.5.19-5.22 Supplier relationships | GV.SC Supply chain | - |
| Patch applications and operating systems | Pull or upgrade off the poisoned release once inventory finds it | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security | - |
| Application control | An allowlist does not care what a dropped file is called, so the masqueraded svchost and the unapproved tunnel client do not run | Application control | A.8.19 Software on systems | PR.PS Platform Security | D3-EAL Executable Allowlisting |
| Restrict administrative privileges | Bounds what a Take Control session or a SYSTEM-level agent can reach once the trusted channel is abused | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 Least privilege | - |
| Multi-factor authentication on provider consoles | Raises the cost of the upstream account takeover that starts many supply-chain intrusions | Multi-factor authentication | A.8.5 Secure authentication | PR.AA-03 Users authenticated | D3-MFA Multi-factor Authentication |
| EDR and malware monitoring | Surfaces the dropped stealer and the masqueraded binary that signature-free inventory checks miss | Beyond E8 (detection gap) | A.8.7 Malware; A.8.16 Monitoring | DE.CM; DE.AE Adverse events | D3-FA File Analysis |
| Egress filtering | Denies or forces review of outbound tunnels, breaking the post-revocation persistence channel | - | A.8.16 Monitoring activities | PR.IR; DE.CM | D3-OTF Outbound Traffic Filtering |

## Honest limitations

These detections confirm a known compromise landed; they are not a generic defence against the next one. Rule 1 keys off a specific indicator set, so a different poisoned package needs its own indicators or the hunt in step 2. The file-event rule needs a Linux file sensor placed on the host or node, which many container estates lack. The MSP case depends on telemetry you may not collect: Event ID 7045 is on by default but rarely shipped, and command-line process auditing is off by default. The code-level root cause of the N-central bypasses is not public and this skill does not reconstruct one. No public IOC list is reproduced for either incident, because addresses and exit nodes rot and the vendor advisories are the live source. Treat both rules as experimental: validated, not run at scale in your environment. Baseline in report-only mode before enforcing.

## ATT&CK and references

- MITRE ATT&CK: [T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/); [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199/); [T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546/); [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552/); [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/); [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/); [T1036.005 Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/).
- MITRE D3FEND: D3-EAL Executable Allowlisting; D3-MFA Multi-factor Authentication; D3-FA File Analysis; D3-OTF Outbound Traffic Filtering.
- UMBRASEC writeup (MSP / RMM case): [Your MSP's RMM Is Your Attack Surface](https://umbrasec.dev/research/n-able-ncentral-msp-supply-chain.html) (2026-08-12).
- UMBRASEC writeup (LiteLLM gateway context): [Detecting the LiteLLM Command Injection](https://umbrasec.dev/research/detecting-litellm-command-injection.html) (2026-06-13).
- UMBRASEC [sigma-pack](https://umbrasec.dev/tools/sigma-pack/): canonical `litellm-stealer-files-linux.yml`, `cloudflared-tunnel-service-install.yml`, and `masquerading-svchost-outside-system32.yml`.
- LiteLLM security incident (21 Oct 2026): https://docs.litellm.ai/blog/security-incident-oct-21-2026 ; Wiz analysis: https://www.wiz.io/blog/litellm-compromised-steals-credentials
- N-able - N-central Security Update (live indicator source): https://www.n-able.com/blog/n-central-security-update-august-6-2026 ; CVE-2026-18556, CVE-2026-18577 (CWE-288, CISA KEV, Aug 2026).

**Scope note.** This is a defensive skill. It explains supply-chain compromise only to the depth needed to detect and mitigate it, reuses detections that already exist in sigma-pack, and deliberately ships no package-poisoning, implant, or tunnelling tooling. UMBRASEC publishes defense, not offense.
