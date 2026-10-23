---
name: detect-litellm-command-injection
description: "Detection and response for the LiteLLM AI gateway under two linked threats: CVE-2026-42271, an authenticated command injection in the MCP stdio preview endpoints (/mcp-rest/test/connection and /mcp-rest/test/tools/list), in CISA KEV, chaining with CVE-2026-48710 (Starlette BadHost) to unauthenticated RCE; and the poisoned LiteLLM 1.107.0 supply-chain release that drops a cook.pth/cook.py credential stealer exfiltrating to litellm.dev. Maps to MITRE ATT&CK T1190, T1059, T1195.002, T1546, T1552, and T1041. Platforms: LiteLLM proxy on Linux and Windows plus web/proxy logs. Ships five Sigma rules (process, webserver, file, proxy). Use when triaging LiteLLM proxy alerts, checking for a vulnerable (below 1.83.7) or poisoned (1.107.0) LiteLLM version, hunting MCP test endpoint requests, investigating a Python proxy that spawned /bin/sh or curl, finding cook.pth or cook.py, or spotting traffic to litellm.dev."
---

# LiteLLM Gateway Command Injection and Supply-Chain Stealer - Detection and Response

LiteLLM is the open-source "AI gateway" many organisations quietly put in front of their LLM APIs: a proxy that fronts 100+ providers behind one OpenAI-compatible API, holding provider keys and sitting in the request path of everything AI in the org. That position makes it a high-value target. This skill covers two linked threats against it. First, CVE-2026-42271 (CVSS 8.8, CISA KEV), an authenticated command injection in LiteLLM's MCP stdio preview endpoints that becomes unauthenticated RCE when chained with the Starlette "BadHost" bug CVE-2026-48710. Second, the October 2026 supply-chain compromise of the LiteLLM 1.107.0 release, which shipped a credential stealer. The skill ships five canonical Sigma rules spanning host process creation, the web front door, dropped-file telemetry on Linux and Windows, and exfiltration at the proxy. It is defensive throughout: it explains each technique only as far as detection and containment require and ships no exploit, payload, or offensive tooling.

Rules 1 and 2 come from the UMBRASEC writeup on CVE-2026-42271 (2026-06-13). Rules 3 to 5 extend that writeup with the October 2026 supply-chain incident; their sources are the LiteLLM vendor incident post and the Wiz analysis, plus the StepSecurity analysis for rules 3 and 4, cited in each rule and in the references below.

## TL;DR for defenders

If you run LiteLLM, patch to 1.83.7 or later now: CVE-2026-42271 is actively exploited and in CISA KEV with a June 22, 2026 federal remediation date. Cannot patch immediately? Block POST /mcp-rest/test/connection and POST /mcp-rest/test/tools/list at your reverse proxy, the vendor's own interim workaround. Also patch Starlette to 1.0.1+ to break the unauthenticated BadHost chain. To detect the command injection, watch two things: requests to those MCP preview endpoints in your front-door HTTP logs (rule 2, the early/noisier signal) and, far higher fidelity, the LiteLLM process spawning a shell or recon binary (rule 1), which a Python web proxy has no legitimate reason to do. Separately, if you installed the LiteLLM 1.107.0 release (PyPI wheels live 11:39-13:23 UTC on 21 Oct 2026, or the v1.107.0 / latest / main-latest / main-stable Docker tags), you have a supply-chain credential-stealer incident: hunt for cook.pth / cook.py on the host (rules 3 and 4) and for any traffic to the litellm.dev lookalike domain (rule 5), then rotate every credential the gateway held.

## Why it matters

CVE-2026-42271 is a command injection (CWE-78) affecting LiteLLM from 1.74.2 up to but not including 1.83.7. LiteLLM can act as a client to MCP (Model Context Protocol) servers. One MCP transport is stdio: instead of talking to a network service, LiteLLM launches a local command and speaks to it over stdin/stdout, so an stdio server config carries command, args, and env fields. Two preview endpoints accepted a full server config and tried to connect to it, which for an stdio server means spawning the supplied command as a subprocess on the proxy host with the LiteLLM process's privileges. Unlike the endpoint that saves an MCP server, these two preview endpoints carried no role check: any holder of a valid LiteLLM API key, including a low-privilege one, could reach them. Chained with CVE-2026-48710 (Starlette BadHost, CWE-444), where the Host header was not validated before being used to rebuild request.url, the API-key requirement disappears and the path becomes unauthenticated RCE against an exposed gateway. Public reporting confirms active exploitation but publishes no in-the-wild IOCs, so the detections here target durable behaviour, not a campaign.

The October 2026 incident is different in kind: the 1.107.0 release itself was poisoned. Per the LiteLLM incident post and Wiz analysis cited in the rules, the compromised wheels dropped cook.pth and cook.py into the Python site-packages root so that every Python start, pip included, reran a credential stealer (cloud, AI-provider, browser, SSH and GPG credentials, plus rows from the proxy's LiteLLM_CredentialsTable), then POSTed an encrypted bundle to www.litellm.dev/healthcheck. litellm.dev is an attacker-controlled lookalike; the project's real domains are litellm.ai and docs.litellm.ai.

## Log sources required

Collect host-based and network telemetry: the host sources are the high-fidelity detections and the network ones are the earlier, noisier signals.

- **Process creation on the LiteLLM host (Linux)** for rule 1: Linux auditd execve telemetry, Sysmon for Linux, or your EDR. In containers this is container runtime / EDR process visibility. Fields: `ParentImage` and `Image` (the rule keys off a python, versioned python3.x, uvicorn or gunicorn parent spawning a shell, busybox, or recon child), and `ParentCommandLine` if your telemetry includes it, to scope to LiteLLM. This is the detection that matters most.
- **Front-door HTTP access logs** for rule 2, from whatever sits in front of LiteLLM (nginx, Caddy, Traefik, ingress, or API gateway): method, URI path, source, and ideally the Host header. Fields: Sigma webserver taxonomy `cs-method` and `cs-uri-stem` (nginx and others name them differently; adapt). This catches the attempt at the front door even without host telemetry.
- **LiteLLM's own logs** for the authenticated context: which API key or user made the request. Useful for scoping once an alert fires.
- **File creation telemetry on the LiteLLM host (Linux and Windows)** for rules 3 and 4: Sysmon for Linux / auditd / EDR on Linux, Sysmon Event ID 11 or EDR file telemetry on Windows. Field: `TargetFilename`. The rules use suffix matches so host sensors on a Docker or Kubernetes node, which see container writes under the overlay or rootfs path, still fire.
- **Forward proxy / egress logs** for rule 5: Field `cs-host`, which the rule matches with or without a port or trailing dot, and `c-uri` for proxies that only log the full URL. Where your proxy retains request headers, the hardcoded `X-Token: XWiA8gZNa7NcX2XRoAEb` header and an Internet Explorer 7 user agent on a POST from a Python host confirm the stealer.

If you have no host or container process telemetry, rule 2 (the front-door endpoint rule) is your only stopgap for the command injection until you fix that collection gap.

## Detection

Five canonical Sigma rules, layered from highest precision to broadest within each threat. Rules 1 and 2 cover CVE-2026-42271; rules 3 to 5 cover the 1.107.0 supply-chain stealer. All five are inlined verbatim below from the UMBRASEC sigma-pack; convert them to your SIEM with sigma-cli.

### 1. The LiteLLM process spawns a shell or recon binary (high fidelity)

This detection survives obfuscation, new payloads, and the unauthenticated chain alike because it watches the effect, not the request. A LiteLLM proxy is a Python web service and does not normally launch /bin/sh, curl, or nc; a child process like that, parented to the proxy, is the command injection landing.

```yaml
# litellm-proxy-spawns-shell.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: LiteLLM Proxy Spawning Shell or Recon Utility
id: 7b3a1f02-9c5d-4e88-a1b6-2f4c7d9e0a13
status: experimental
description: >
    The LiteLLM proxy process (Python/uvicorn/gunicorn) spawned a shell
    or a common recon/download utility. A web proxy has no legitimate
    reason to do this; consistent with exploitation of CVE-2026-42271,
    where the MCP stdio preview endpoints spawn an attacker-supplied
    command on the proxy host. Sensors often report the resolved binary, so
    the rule also lists versioned interpreter names, the Debian/Ubuntu names
    nc resolves to, and busybox, which is /bin/sh on Alpine and Wolfi images.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-42271
    - https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g
    - https://umbrasec.dev/research/detecting-litellm-command-injection.html
author: UMBRASEC
date: 2026-06-13
modified: 2026-10-23
tags:
    - attack.initial-access
    - attack.t1190
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/python'
            - '/python3'
            - '/python3.9'
            - '/python3.10'
            - '/python3.11'
            - '/python3.12'
            - '/python3.13'
            - '/python3.14'
            - '/uvicorn'
            - '/gunicorn'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/curl'
            - '/wget'
            - '/nc'
            - '/ncat'
            - '/nohup'
            - '/busybox'
            - '/nc.openbsd'
            - '/nc.traditional'
            - '/netcat'
    condition: selection_parent and selection_child
falsepositives:
    - Init/entrypoint scripts that legitimately shell out at container start
    - Health-check or sidecar tooling that wraps the proxy in a shell
    - Scope to LiteLLM hosts/containers to cut generic python parent noise
    - On busybox-based images every shell and utility runs as /bin/busybox,
      so the entrypoint and health-check cases above appear under that name too
level: high
```

**Tuning.** Parenting on a generic python is broad, so scope this to your LiteLLM hosts or containers (by host tag, image name, or a more specific `ParentCommandLine|contains: 'litellm'` where the command line is captured). Baseline in report-only mode first: container start-up frequently runs a shell entrypoint once, so allowlist that known parent/child pair. On busybox-based images such as Alpine or Wolfi the entrypoint shell appears as `/bin/busybox`, so allowlist it under that name. The signal you care about is a shell or network utility appearing under the proxy at request time, long after startup.

### 2. Requests to the vulnerable MCP preview endpoints (front-door signal)

Earlier in the chain, and useful even without host telemetry: the two endpoints are an administrator-only preview feature, so in most environments any request to them is worth surfacing, and a burst from an unexpected source is a strong exploitation signal.

```yaml
# litellm-mcp-test-endpoint.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: LiteLLM MCP Test Endpoint Requested
id: 2c8e5b41-6d77-4a90-bb1e-3f0a9c2d4e56
status: experimental
description: >
    A request hit one of LiteLLM's MCP preview endpoints. These accept a
    full MCP server config and, for the stdio transport, spawn the
    supplied command on the proxy host (CVE-2026-42271). They are an
    admin-only preview feature, so requests - especially from untrusted
    sources - warrant review. Chained with CVE-2026-48710 (Starlette
    BadHost) the path becomes unauthenticated RCE.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-42271
    - https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g
    - https://umbrasec.dev/research/detecting-litellm-command-injection.html
author: UMBRASEC
date: 2026-06-13
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains:
            - '/mcp-rest/test/connection'
            - '/mcp-rest/test/tools/list'
    condition: selection
falsepositives:
    - An administrator legitimately previewing an MCP server in the LiteLLM UI
    - Vulnerability scanners probing the path after public disclosure
level: medium
```

**Tuning.** Adapt the field names to your proxy's log schema (`cs-method` / `cs-uri-stem` are the Sigma webserver taxonomy). If you know which admin source addresses legitimately use the preview feature, exclude them and treat everything else as high. Pair this with rule 1: the front-door request plus a shell spawning under the proxy is exploitation with very little doubt left.

### 3. The 1.107.0 credential stealer files dropped on a Linux host (high fidelity)

The compromised 1.107.0 release drops cook.pth and cook.py into the site-packages (or dist-packages) root so every Python start reruns the stealer. The .pth/.py pair and the compiled .pyc show the poisoned release was installed; files under the /tmp/.pc_sq_* and /tmp/.pc_e_* working directories, the /tmp run-once marker written once exfiltration succeeds, or the loader lock show it ran. Any hit means the poisoned release was present on the host.

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

**Tuning.** These are indicator matches on filenames, so false positives are unlikely; a legitimate package shipping a module named cook with a .pth hook would collide on the first two selections, so check package metadata before closing. The release also drops a sitecustomize.py loader beside the hook, but legitimate sitecustomize.py files are common, so that name is left to the hunt below rather than alerted on here.

### 4. The 1.107.0 credential stealer files dropped on a Windows host (high fidelity)

The Windows twin of rule 3. The same poisoned wheels carry cook.pth and cook.py (Wiz published separate Windows and Linux/macOS hashes) dropped into the site-packages root. Files under the .pc_sq_* and .pc_e_* working directories in the system temp folder (%TEMP% for a user, C:\Windows\Temp for a service) show it ran on any Windows host. The /tmp run-once marker usually fails on Windows but is matched where a \tmp directory exists (Git for Windows, MSYS2); the sitecustomize.py second stage only runs on Linux and macOS.

```yaml
# litellm-stealer-files-windows.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: LiteLLM 1.107.0 Credential Stealer Dropped on Windows Host
id: 1cc5748a-ebcf-4958-b479-d231563e20e1
status: experimental
description: >
    Windows twin of litellm-stealer-files-linux. The compromised LiteLLM
    1.107.0 wheels (PyPI, 21 Oct 2026) carry cook.pth and cook.py - Wiz
    published separate Windows and Linux/macOS hashes for them - dropped
    into the site-packages root so that every Python start reruns the
    credential stealer. The .pth/.py pair and the compiled .pyc show the
    poisoned release was installed. The stealer works out of .pc_sq_*
    and .pc_e_* directories in the system temp folder (%TEMP% for a
    user, C:\Windows\Temp for a service), so files written under those
    show it ran on any Windows host. The /tmp run-once marker usually
    fails on Windows because the path rarely exists, but where a \tmp
    directory is present (Git for Windows, MSYS2) it is written once
    exfiltration succeeds, so it is matched too. The sitecustomize.py
    second-stage loader only runs on Linux and macOS.
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
    product: windows
detection:
    selection_hook:
        TargetFilename|endswith:
            - '\site-packages\cook.pth'
            - '\site-packages\cook.py'
    selection_pyc:
        TargetFilename|contains: '\site-packages\__pycache__\cook.'
    selection_temp_dirs:
        TargetFilename|contains:
            - '\Temp\.pc_sq_'
            - '\Temp\.pc_e_'
    selection_marker:
        TargetFilename|endswith: '\tmp\.pc_once_72129118c59f5636c0bb'
    condition: 1 of selection_*
falsepositives:
    - Unlikely. A legitimate package that ships a module named cook with a .pth hook would collide; check the package metadata before closing
    - An analyst or test harness recreating the indicator files to exercise this rule
level: high
```

**Tuning.** Same indicator logic as rule 3: false positives are unlikely, and a legitimate package named cook with a .pth hook would collide, so check package metadata before closing. An analyst or test harness recreating the indicator files to exercise the rule is the other benign cause.

### 5. Stealer exfiltration to the lookalike domain (indicator)

The stealer POSTs its encrypted credential bundle to www.litellm.dev/healthcheck. Any request to litellm.dev from your estate is worth a ticket; where headers are retained, the hardcoded X-Token value and an IE7 user agent on a POST from a Python host confirm it.

```yaml
# litellm-stealer-exfil.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: LiteLLM 1.107.0 Stealer Exfiltration to Lookalike Domain
id: 6f6f10d8-c46a-46dc-89ad-c5b9a800ee72
status: experimental
description: >
    The credential stealer shipped in the compromised LiteLLM 1.107.0
    release POSTs its encrypted bundle (cloud, AI-provider, browser, SSH
    and GPG credentials, plus rows from the proxy's
    LiteLLM_CredentialsTable) to www.litellm.dev/healthcheck. litellm.dev
    is an attacker-controlled lookalike; the project's real domains are
    litellm.ai and docs.litellm.ai, so any request to it from your estate
    is worth a ticket. Where your proxy retains request headers, the
    hardcoded "X-Token: XWiA8gZNa7NcX2XRoAEb" header and an Internet
    Explorer 7 user agent on a POST from a Python host confirm it. The
    second stage read a domain from a GitHub dead drop
    (letters9813/pythonclient-test) and would have fetched
    http://<domain>/codepy; the repo is gone and the drop was never
    populated beyond test values, so it is not matched here. Hosts logged
    with a port or with a trailing dot are matched. The URI selection covers
    proxies that only log the full URL.
references:
    - https://docs.litellm.ai/blog/security-incident-oct-21-2026
    - https://www.wiz.io/blog/litellm-compromised-steals-credentials
    - https://litellm.ai
author: UMBRASEC
date: 2026-10-23
modified: 2026-10-23
tags:
    - attack.exfiltration
    - attack.t1041
logsource:
    category: proxy
detection:
    selection_host:
        cs-host:
            - 'litellm.dev'
            - 'litellm.dev.'
    selection_subdomain:
        cs-host|endswith:
            - '.litellm.dev'
            - '.litellm.dev.'
    selection_hostport:
        cs-host|startswith:
            - 'litellm.dev:'
            - 'litellm.dev.:'
    selection_subdomain_port:
        cs-host|contains:
            - '.litellm.dev:'
            - '.litellm.dev.:'
    selection_uri:
        c-uri|contains:
            - '//litellm.dev'
            - '//www.litellm.dev'
    condition: 1 of selection_*
falsepositives:
    - Analysts or sandboxes deliberately resolving or fetching the indicator
    - If the domain ever changes hands, retire the rule. The signal is the domain, not behaviour
level: high
```

**Tuning.** This keys off the attacker-controlled lookalike domain litellm.dev (the project's real domains are litellm.ai and docs.litellm.ai), so a hit is high confidence. The only benign cause is an analyst or sandbox deliberately resolving or fetching the indicator. The signal is the domain, not behaviour: if litellm.dev ever changes hands, retire the rule.

## Tuning and false positives

- **Rule 1 (process spawn).** Baseline in report-only mode and scope to LiteLLM hosts before enforcing; the generic python parent is the main noise source. Allowlist the container's known start-up shell entrypoint, which shows as `/bin/busybox` on busybox-based images. Thresholds and scope are dials.
- **Rule 2 (endpoint).** Expect legitimate admin previews and, after disclosure, vulnerability scanners probing the path. Allowlist known admin source addresses and treat the rest as high. Adapt the webserver field names to your proxy schema.
- **Rules 3 and 4 (dropped files).** Near-binary indicator matches; the only realistic benign hit is a package legitimately named cook with a .pth hook, so verify package metadata before closing.
- **Rule 5 (exfil domain).** High confidence by construction. Retire it if litellm.dev ever changes ownership, because the signal is the domain rather than any behaviour.

## Threat hunt

For cases the alert rules miss, hunt rather than wait:

1. **Inventory and version (both threats).** List every LiteLLM image and running service (default proxy port 4000, confirmable via /health and OpenAPI routes). Compare tags against 1.83.7 for the command injection, and flag any trace of the poisoned 1.107.0 release: the v1.107.0, latest, main-latest, and main-stable Docker/GHCR tags, and PyPI wheels that were live between 11:39 and 13:23 UTC on 21 Oct 2026. Ask the key question for CVE-2026-42271 first: is the gateway reachable from untrusted networks (the unauthenticated-RCE scenario) or internal-only (still exploitable by any API-key holder)?
2. **BadHost correlation (CVE-2026-48710).** Because the unauthenticated path rides BadHost, malformed or mismatched Host headers reaching the gateway are a supporting signal. This is noisy on its own, so treat it as triage context, not a pager rule: allowlist your real hostnames and alert on the remainder only in correlation with a rule 2 hit. A request whose Host header does not match the gateway's expected hostname(s), arriving alongside a rule 2 hit, raises confidence that you are looking at the unauthenticated chain rather than an authorised admin preview. (Procedure only, not a shipped rule.)
3. **sitecustomize.py neighbour (1.107.0).** Rules 3 and 4 deliberately do not alert on sitecustomize.py because legitimate ones are common. Hunt for a sitecustomize.py created within a minute of cook.pth in the same site-packages root; that pairing points at the never-activated second stage.
4. **Exfil headers (1.107.0).** Where your proxy retains request headers, hunt for the hardcoded `X-Token: XWiA8gZNa7NcX2XRoAEb` header and an Internet Explorer 7 user agent on a POST originating from a Python host, even if the destination was not litellm.dev.

## If a rule fires: contain it

Treat a confirmed hit on rule 1, or any stealer indicator from rules 3 to 5, as host compromise of a system that holds your LLM provider keys. Working from your incident response plan:

- **Isolate** the LiteLLM host or container via EDR rather than wiping it, to preserve the process tree and logs for scoping.
- **Rotate every secret the gateway held**: all upstream LLM provider API keys, the LiteLLM master key, database credentials, and any cloud role the host could assume. For the 1.107.0 incident assume cloud, AI-provider, browser, SSH, and GPG credentials on the host, plus the proxy's LiteLLM_CredentialsTable rows, were taken.
- **Revoke and reissue LiteLLM API keys** and review who held low-privilege keys; the authenticated command-injection path needs only one.
- **Patch then redeploy** from a known-good image at 1.83.7+ (and Starlette 1.0.1+), or a clean non-1.107.0 release, rather than cleaning in place.
- **Scope the reporting question early.** If provider keys or customer data were within reach, your notification clocks may have started; decide that with the plan.

## Mitigation

Detection buys time; these changes shrink the attack surface. Priority order follows the writeup. One mitigation has no single clean framework code and is kept as prose: get the gateway off the public internet where the architecture allows, which removes the unauthenticated scenario entirely and shrinks the authenticated one to insiders and footholds. The mappings below reuse the control codes used in the UMBRASEC guide; a cell is left blank ("-") where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Patch LiteLLM to 1.83.7+ and Starlette to 1.0.1+ | 1.83.7 adds the missing PROXY_ADMIN role check on both preview endpoints; Starlette 1.0.1 closes BadHost and breaks the unauthenticated chain | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security |
| Interim: block POST to the two MCP preview endpoints at the reverse proxy | Compensating control until patched; the vendor's own interim workaround | - | A.8.8 Technical vulnerabilities | PR.PS Platform Security |
| Run LiteLLM non-root in a constrained container | Command execution lands somewhere with little to reach; defence in depth for the next bug in this class | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Verify release provenance before upgrading | Catches a poisoned release like 1.107.0 before it runs; pin and check wheel/tag integrity | - | A.5.19-5.22 Supplier relationships | GV.SC Supply chain |
| Rotate every credential the gateway held after a hit | Assumes disclosure of provider keys, master key, and stored credentials | - | A.5.17 Authentication information | PR.AA-01 |

## Honest limitations

- **Rule 1 needs host or container process telemetry**, which many fast-stood-up LiteLLM deployments do not yet collect. If that is you, rule 2 is the stopgap until you fix the gap.
- **The endpoint rule can be evaded by the chain's framing.** The path is stable, but a clever request shape or a future variant can slip rule 2 alone, which is why the host-based effect rule leads.
- **No public IOCs exist for the CVE-2026-42271 in-the-wild attacks**, so rules 1 and 2 target the technique, not a campaign: durable, but no help for retro-hunting specific infrastructure.
- **Rules 3 to 5 are indicator-based** (filenames, a .pth/.py pair, one lookalike domain) and will age. The exfil rule's own note says retire it if litellm.dev changes hands. The never-populated GitHub dead drop (letters9813/pythonclient-test) and its `http://<domain>/codepy` second-stage fetch are not matched, because the repo is gone and the drop held only test values.
- **Timeliness ages.** Patch status and release provenance are the real controls; detection covers the window before you patch and the assets you have not found yet. Re-run the inventory step after you think you are done.

## ATT&CK and references

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/); [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/); [T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/); [T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546/); [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552/); [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/).
- UMBRASEC writeup: [Detecting the LiteLLM Command Injection (CVE-2026-42271)](https://umbrasec.dev/research/detecting-litellm-command-injection.html) (2026-06-13).
- NVD: [CVE-2026-42271](https://nvd.nist.gov/vuln/detail/CVE-2026-42271) (LiteLLM command injection); [CVE-2026-48710](https://nvd.nist.gov/vuln/detail/CVE-2026-48710) (Starlette BadHost Host-header bypass).
- BerriAI GitHub Security Advisory [GHSA-v4p8-mg3p-g94g](https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g); Starlette GitHub Security Advisory [GHSA-86qp-5c8j-p5mr](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr).
- LiteLLM [v1.83.7-stable release](https://github.com/BerriAI/litellm/releases/tag/v1.83.7-stable) (the command-injection fix).
- CISA [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- LiteLLM [security incident post, 21 Oct 2026](https://docs.litellm.ai/blog/security-incident-oct-21-2026); Wiz [LiteLLM compromised / steals credentials](https://www.wiz.io/blog/litellm-compromised-steals-credentials). StepSecurity [LiteLLM 1.107.0 compromised PyPI wheels](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer).

**Scope note.** This is a defensive skill. It explains these techniques only to the depth needed to detect, contain, and mitigate them, carries no request body, payload, or working exploit, and ships no offensive tooling. UMBRASEC publishes defense, not offense.
