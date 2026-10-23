---
name: detect-deserialization
description: "Detection, hunting, and hardening for insecure deserialization and object-injection gadget chains, where a crafted serialized object sent to a public-facing app becomes remote code execution (MITRE ATT&CK T1190; follow-on T1059 and T1505.003). Keys off web server, WAF, and reverse-proxy logs carrying serialized magic bytes (Java rO0AB, PHP O:, .NET __VIEWSTATE, Python pickle, Ruby Marshal), app deserialization exceptions, ASP.NET ViewState Event ID 1316, and EDR or Sysmon Event ID 1 showing an app server spawning a shell or LOLBIN. Gives log sources and fields, a detection approach pointing to public rule sources, a hypothesis-driven hunt, hardening, and blind spots. Use when hunting insecure deserialization, triaging a suspected gadget-chain exploit, investigating a web app process that spawned cmd or /bin/sh, reviewing ViewState tampering alerts, or hardening Java, .NET, PHP, Python, or Ruby services against untrusted deserialization."
---

# Insecure Deserialization - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

Insecure deserialization is an app reconstructing an attacker-controlled serialized object stream with a native deserializer (Java `ObjectInputStream`, .NET `BinaryFormatter` or `LosFormatter`, Python `pickle`, PHP `unserialize`, Ruby `Marshal`). A gadget chain abuses classes already on the classpath to turn that reconstruction into code execution, usually against a public-facing endpoint (MITRE ATT&CK **T1190 Exploit Public-Facing Application**). You catch it at two layers: at the request layer, serialized payloads carry recognizable markers (Java base64 `rO0AB` or hex `AC ED 00 05`, PHP `O:<n>:` object notation, .NET `__VIEWSTATE`, Ruby Marshal `\x04\x08`) arriving in parameters, cookies, or headers where no serialized blob belongs; at the host layer, a successful chain makes the application process spawn a child it never normally spawns (a shell or scripting interpreter). The request signal is noisy and sometimes blind to TLS bodies; the parent-child process anomaly is the higher-fidelity catch. This skill ships no UMBRASEC rule for this threat; it points to maintained public rule sets instead.

## What it looks like, defender view

In telemetry the attack presents as a serialized object stream reaching a sink that trusts it. Normal apps serialize their own objects for internal state (session blobs, caches, view state, message-queue payloads) and never accept a serialized object from an untrusted boundary, so the defender signal is twofold. First, a serialized blob appears somewhere user-controlled: a request body, a cookie, an HTTP header, a hidden form field, or a deserialization-backed message on a queue. Second, when a gadget chain fires, the application process steps outside its normal behaviour: it throws a burst of deserialization exceptions (a failed or probing chain), or it executes a child process, writes a file into the web root, or opens an outbound connection it never makes in steady state. A successful chain frequently ends in a web shell dropped to disk or an interactive command, which is why the host-side parent-child signal is the one that survives when the payload itself is encrypted in transit.

## Log sources and signals

Collect from the web tier and from the application host. The request layer catches the payload on the wire; the host catches the execution that proves the chain worked.

- **Web server, WAF, and reverse-proxy logs (request layer).** IIS, Apache, Nginx access logs, and WAF or API-gateway request captures that include body, cookies, and headers. Markers to key on: Java serialized streams as base64 `rO0AB` (or `H4sIA` when gzipped) and raw hex `ac ed 00 05`; PHP `unserialize` object notation `O:<digit>:"<classname>"` and `a:<digit>:` arrays in parameters that should be scalars; .NET `__VIEWSTATE` and `__VIEWSTATEGENERATOR` fields, especially a long `__VIEWSTATE` arriving at an endpoint with MAC disabled; Python pickle opcodes (a body beginning `\x80\x04` or base64 `gASV`); Ruby Marshal magic `\x04\x08`. A serialized blob in a field that normally carries a short scalar is the anomaly, regardless of language.
- **Application logs and stack traces.** The deserializer itself is loud when a chain probes or half-fails. Watch for `java.io.InvalidClassException`, `ClassNotFoundException`, and `StreamCorruptedException` from `ObjectInputStream`; .NET `System.Runtime.Serialization.SerializationException`; Python `pickle.UnpicklingError`; PHP `__wakeup`/`__destruct` errors on unexpected classes. A spike of deserialization exceptions tied to one client or one endpoint is a probing chain.
- **ASP.NET ViewState integrity failures (Windows Application event log).** Source `ASP.NET`, **Event ID 1316**, message "Viewstate verification failed" / "The viewstate supplied failed integrity check." This is the direct signal for ViewState tampering and the class of attack behind CVE-2020-0688 (static `machineKey` abuse). Treat repeated 1316 events from one source as ViewState forgery attempts.
- **Process-creation telemetry (host).** Windows **Sysmon Event ID 1** or Security **Event ID 4688**, and Linux **auditd `execve`** or an eBPF sensor (Falco, Tetragon). The high-fidelity signal is a parent-child anomaly: `w3wp.exe`, `java`/`javaw`, `tomcat`, `catalina`, `php-fpm`, `httpd`, or `node` spawning `cmd.exe`, `powershell.exe`, `/bin/sh`, `bash`, `python`, or a LOLBIN (`certutil`, `bitsadmin`, `curl`, `wget`). Fields: `ParentImage`, `Image`, `CommandLine`, `User`. Application servers almost never spawn interactive shells in normal operation.
- **File-create and network telemetry (host).** Sysmon **Event ID 11** (file create) for a new `.jsp`, `.aspx`, `.php`, or script written under the web root (web shell drop, T1505.003), and Sysmon **Event ID 3** (network connect) for an outbound connection from the app process to an unexpected host (gadget chains commonly fetch a second stage).

What normal looks like: serialized blobs stay inside the app's own trust boundary (session store, cache, internal queue) and never arrive from a client; the app process spawns only its known worker children; ViewState MAC validates on every post; deserialization exceptions are rare and tied to genuine version skew, not to one noisy client.

## Detection approach

Alert on the payload at the edge and on the execution on the host, and correlate the two so a request-layer hit that is followed by an app-process shell becomes a single high-confidence incident.

At the request layer, alert when a serialized marker (`rO0AB`, `aced0005`, PHP `O:<n>:`, Python `\x80` pickle opcodes, Ruby `\x04\x08`) appears in a user-controlled field, and when a long or tampered `__VIEWSTATE` reaches an endpoint whose MAC is off. Expect false positives wherever an app legitimately round-trips serialized state through the client (some legacy frameworks do), so baseline which endpoints and fields carry serialized data before alerting broadly. At the application layer, alert on a burst of deserialization exceptions from a single client or endpoint, and on repeated ASP.NET Event ID 1316. At the host layer, alert on the application server spawning a shell, scripting interpreter, or LOLBIN, on a new server-side script written under the web root, and on an unexpected outbound connection from the app process. The parent-child process rule is the detection to invest in first because it survives encrypted request bodies and novel gadget chains alike.

This skill ships **no UMBRASEC rule** for insecure deserialization. Use these public, maintained rule sources:

- OWASP CRS (ModSecurity Core Rule Set): https://github.com/coreruleset/coreruleset - the Java attack rule file `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` and the PHP object-injection rules in `REQUEST-933-APPLICATION-ATTACK-PHP.conf` carry serialized-payload signatures.
- SigmaHQ: https://github.com/SigmaHQ/sigma - `rules/windows/process_creation/` for IIS/`w3wp.exe` and Java spawning a shell, and `rules/web/` for web-attack request patterns.
- Elastic detection rules: https://github.com/elastic/detection-rules - web shell detection and suspicious child processes of web application servers.
- Falco default rules (CNCF): https://github.com/falcosecurity/rules - "Terminal shell in container" and shell-spawn rules for containerized app servers.
- MITRE ATT&CK data sources and detections for T1190: https://attack.mitre.org/techniques/T1190/
- MITRE D3FEND countermeasures (below).

## Threat hunt

Hypothesis: an attacker has sent a gadget-chain payload to a deserialization sink on a public-facing service and gained execution as the app's service account.

1. From process telemetry over a long window, list every child process whose parent is an application server (`w3wp.exe`, `java`, `tomcat`, `php-fpm`, `httpd`, `node`) and whose image is a shell, scripting interpreter, or LOLBIN. Each hit is a candidate exploitation of that service. Rank by whether the service is internet-exposed.
2. For each candidate, pivot to the web and WAF logs for that host and time window and look for a serialized marker (`rO0AB`, `aced0005`, PHP `O:`, `__VIEWSTATE`) arriving just before the child spawned. The join of request marker plus app-process shell is near-conclusive.
3. Sweep the web root and application temp directories for server-side script files created or modified in the window (web shell drop), and diff against known-good deployment state.
4. Review application logs for a preceding spike of deserialization exceptions from the same source address, which marks the probing phase before a working chain landed.
5. For the low-and-slow or memory-only case, review which third-party libraries known to carry gadget chains (for example historically vulnerable serialization and object-mapping libraries) are present on the classpath or in the dependency manifest, and whether any reachable endpoint deserializes untrusted input at all; an unused but reachable native deserializer is a standing exposure even with no hit yet.

## Hardening

Shrink the standing surface (what the app will deserialize at all) and the blast radius (what a chain can do once it fires). The mappings below use the control codes carried in the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Do not deserialize untrusted input with native deserializers; use data-only formats (JSON) with schema validation, and apply a class allowlist (Java `ObjectInputFilter`/JEP 290, a look-ahead `ObjectInputStream`) where native deserialization is unavoidable | Removes the sink the gadget chain needs | - | A.8.19 Software on systems | PR.PS Platform Security |
| Patch and remove vulnerable frameworks and gadget-bearing libraries | Closes known deserialization CVEs and strips the classes a chain pivots through | Patch applications | A.8.8 Technical vulnerabilities | ID.RA |
| Enforce integrity on any serialized data that must leave the server (HMAC-sign, enable ViewState MAC and encryption, rotate `machineKey`) | A tampered stream is rejected before it is deserialized | - | A.8.19 Software on systems | PR.PS Platform Security |
| Application control / allowlisting on app servers | Blocks the shells and LOLBINs a successful chain tries to launch | Application control | A.8.19 Software on systems | PR.PS Platform Security |
| Run the app under a least-privilege service account with egress filtering | Limits what a chain can do and reach once it executes | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Runtime monitoring on every app host (Sysmon/auditd plus EDR) | Produces the process, file, and network telemetry this detection depends on | - | A.8.16 Monitoring activities | DE.CM Continuous monitoring |

## Honest limitations

A request-layer signature only sees what it can read: a serialized payload inside a TLS body that is not terminated and inspected, or one wrapped in gzip or an extra base64 layer, can slip past the edge entirely, which is why the host-side process signal matters more. A novel or heavily obfuscated gadget chain evades payload signatures by construction. Some legitimate frameworks round-trip serialized state through the client, so request-layer rules carry real false positives until you baseline which endpoints and fields are supposed to carry serialized data. The parent-child process rule misses a memory-only chain whose impact is information disclosure, SSRF, or an in-process action that never spawns a child or writes a file. ASP.NET Event ID 1316 only appears when MAC is enabled, so a site that disabled ViewState MAC gives you no integrity signal at all and must be fixed, not just monitored. None of this fires unattended: baseline your legitimate serialized traffic and your app servers' normal child processes first, correlate the request and host layers, and let an analyst make the call.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access); follow-on [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) (Execution) and [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/) (Persistence).
- MITRE D3FEND: Message Authentication (D3-MAN) for signing serialized data so a tampered stream is rejected before deserialization; Process Spawn Analysis for catching the app server launching an unexpected child; Software Update for patching vulnerable frameworks and gadget libraries. See https://d3fend.mitre.org/
- Public rule sources: OWASP CRS https://github.com/coreruleset/coreruleset, SigmaHQ https://github.com/SigmaHQ/sigma, Elastic detection rules https://github.com/elastic/detection-rules.

**Scope note.** This is a defensive skill. It explains insecure deserialization only to the depth needed to detect and mitigate it and deliberately ships no gadget chains, payload generators, or exploitation instructions. UMBRASEC publishes defense, not offense.
