![umbra-blue banner](assets/banner.png)

<div align="center">

# umbra-blue

**Defensive security skills for Claude - drop-in `SKILL.md` files that turn Claude into an evidence-backed blue team analyst.**

<!-- badges:start -->
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-77-1d4ed8.svg)](#skill-index)
[![Categories](https://img.shields.io/badge/categories-23-0f172a.svg)](#categories)
[![Tier 1](https://img.shields.io/badge/tier_1-10-38bdf8.svg)](#two-tiers)
[![Tier 2](https://img.shields.io/badge/tier_2-67-64748b.svg)](#two-tiers)
[![Stars](https://img.shields.io/github/stars/umbrasec-labs/umbra-blue?style=social)](https://github.com/umbrasec-labs/umbra-blue)
<!-- badges:end -->

[Overview](#overview) &bull; [Quickstart](#quickstart) &bull; [Two tiers](#two-tiers) &bull; [Categories](#categories) &bull; [Skill Index](#skill-index) &bull; [Coverage](COVERAGE.md) &bull; [Roadmap](#roadmap) &bull; [Contributing](#contributing)

</div>

---

## Overview

`umbra-blue` is a library of defensive security skills for the [Claude Skills system](https://code.claude.com/docs/en/skills). It is the blue team counterpart to [claude-red](https://github.com/SnailSploit/claude-red): every one of claude-red's offensive skills is paired with the defensive skill that answers it, in the same category folder. Where claude-red teaches Claude how a technique is executed, umbra-blue teaches Claude how to see it, hunt it, and shut it down.

Each skill is a structured `SKILL.md` that primes Claude with detection, hunting, and hardening methodology for one threat: the log sources and event IDs that carry the signal, what to alert on, how to tune out false positives, how to hunt for the quiet variant, and which controls shrink the attack surface, mapped to MITRE ATT&CK and D3FEND. Skills load on demand from their description triggers, so you only pay context for the skill you need.

**What makes it different:** most blue team skill collections teach method, such as how to write a Sigma rule. umbra-blue's Tier 1 skills ship the tuned rule itself, drawn from published [UMBRASEC](https://umbrasec.dev) incident research and reused byte for byte from the [UMBRASEC sigma-pack](https://umbrasec.dev/tools/sigma-pack/), with tuning and false-positive notes. Every skill says plainly which tier it is in, and none fabricates a rule or a citation.

**Use cases:** SOC triage and alert investigation, detection engineering, threat hunting, hardening reviews, purple team exercises against claude-red, incident response support, and defender training.

**Defensive in scope.** Skills explain a technique only to the depth needed to detect and mitigate it. No exploit code, payloads, or offensive tooling ship from here.

---

## Quickstart

### Claude Code (recommended)

Claude Code discovers skills at `~/.claude/skills/<skill-name>/SKILL.md`, one folder per skill, so use the installer. It flattens the category tree into that layout.

```bash
git clone https://github.com/umbrasec-labs/umbra-blue
cd umbra-blue
./install.sh                          # all skills into ~/.claude/skills
./install.sh --category web           # one category (repeatable)
./install.sh --tier 1                 # only the sourced Tier 1 skills
./install.sh --project                # into ./.claude/skills for one project
./install.sh --list                   # categories and counts
./install.sh --uninstall              # remove every umbra-blue skill
```

The installer never overwrites a skill it did not install unless you pass `--force`. Start a new session and Claude loads a matching skill from its triggers: mentioning Kerberoasting or RC4 service tickets loads `detect-kerberoasting`.

### Claude.ai

Zip a single skill folder, for example `Skills/web/detect-xss/`, and upload it under Customize, then Skills. Every skill uses only the `name` and `description` frontmatter keys, and every description fits the 1,024-character limit, so uploads pass validation.

### Any LLM

Paste the contents of a `SKILL.md` into a system prompt or project instructions.

---

## Two tiers

umbra-blue mirrors all of claude-red, so it ships in two clearly labeled tiers. The tier is visible at the top of every skill before you trust it.

| Tier | What you get |
|---|---|
| **1, sourced** | Built from a published UMBRASEC writeup or tool and cites primary sources. Ships a runnable detection or hunt; where that is a rule, it is reused byte for byte from the UMBRASEC sigma-pack. |
| **2, methodology** | The defender's method, log sources and signals, hunt, and hardening, pointing to public rule sources such as SigmaHQ and vendor analytics. A banner states that no bespoke UMBRASEC rule ships yet. |

A Tier 2 skill is promoted to Tier 1 when its UMBRASEC writeup and tuned rule land. The one rule no tier may break: never invent a rule or a citation. See [PRINCIPLES.md](PRINCIPLES.md).

---

## Categories

The category folders match claude-red's, so each offensive skill and its defensive answer sit side by side.

<!-- categories:start -->
| Category | Skills | Tier 1 | Focus |
|---|---:|---:|---|
| [Web Application](#web-application) | 16 | 2 | Detection and hardening for the OWASP Top 10 and advanced web vulnerability classes |
| [Auth & Identity](#auth--identity) | 2 | 1 | JWT validation hardening, OAuth and OIDC consent-grant detection |
| [Active Directory](#active-directory) | 2 | 1 | Kerberoasting, AS-REP roasting, DCSync, and ACL abuse detection |
| [Wireless](#wireless) | 14 | 0 | 802.11, WPA2/3, EAP, WPS, BLE, Zigbee, Z-Wave, LoRa, and sub-GHz detection and hardening |
| [Cloud](#cloud) | 1 | 0 | Control-plane and IAM attack-path detection across AWS, Azure, and GCP |
| [Mobile](#mobile) | 1 | 0 | Android and iOS application hardening |
| [IoT & Embedded](#iot--embedded) | 1 | 0 | Firmware, hardware-interface, RTOS, and ICS/OT hardening |
| [Infrastructure & Endpoint](#infrastructure--endpoint) | 7 | 0 | Initial access, EDR tampering, injection, and red-team TTP detection, Windows hardening |
| [Exploit Mitigation](#exploit-mitigation) | 5 | 0 | Memory-safety hardening and exploit-mitigation verification |
| [Fuzzing & Vulnerability Triage](#fuzzing--vulnerability-triage) | 2 | 0 | Fuzzing in the SDLC and bug-class triage |
| [Exposure Management](#exposure-management) | 2 | 1 | External attack surface monitoring and OSINT exposure reduction |
| [API Security](#api-security) | 2 | 0 | API abuse detection and gateway hardening |
| [Container & Kubernetes](#container--kubernetes) | 2 | 0 | Container-escape detection and cluster hardening |
| [CI/CD & Pipeline](#cicd--pipeline) | 2 | 0 | Pipeline hardening and secret-exposure detection |
| [Cryptography](#cryptography) | 2 | 0 | TLS and cryptographic implementation hardening |
| [Privilege Escalation](#privilege-escalation) | 2 | 0 | Linux and Windows privilege-escalation detection |
| [Post-Exploitation](#post-exploitation) | 3 | 2 | Lateral movement, persistence, and exfiltration detection |
| [Forensics & C2](#forensics--c2) | 2 | 0 | Anti-forensics and command-and-control beaconing detection |
| [Supply Chain](#supply-chain) | 2 | 1 | Compromised-package and dependency-confusion detection |
| [Social Engineering](#social-engineering) | 2 | 0 | Phishing detection and human-layer controls |
| [Network](#network) | 1 | 0 | Layer 2 and 3 poisoning and MITM detection |
| [AI Security](#ai-security) | 2 | 2 | OWASP LLM Top 10 and tool-calling agent defenses |
| [Utility](#utility) | 2 | 0 | Fast defensive triage and evidence-backed reporting |
<!-- categories:end -->

---

## Skill Index

Tier 1 skills are listed first in each category. The full red-to-blue pairing is in [COVERAGE.md](COVERAGE.md), and a visual map is in [MINDMAP.md](MINDMAP.md).

<!-- skill-index:start -->
### Web Application

`Skills/web/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-litellm-command-injection`](Skills/web/detect-litellm-command-injection/SKILL.md) | 1 | `offensive-rce` | LiteLLM proxy RCE (CVE-2026-42271) detection, host and web signals |
| [`detect-metabase-sqli`](Skills/web/detect-metabase-sqli/SKILL.md) | 1 | `offensive-sqli` | Unauthenticated SQLi detection from the Metabase CVE-2026-72898 case |
| [`defend-open-redirect`](Skills/web/defend-open-redirect/SKILL.md) | 2 | `offensive-open-redirect` | Redirect allowlisting, token-leak prevention |
| [`detect-business-logic-abuse`](Skills/web/detect-business-logic-abuse/SKILL.md) | 2 | `offensive-business-logic` | Workflow-bypass and pricing-abuse monitoring |
| [`detect-deserialization`](Skills/web/detect-deserialization/SKILL.md) | 2 | `offensive-deserialization` | Gadget-chain and untrusted-stream indicators |
| [`detect-graphql-abuse`](Skills/web/detect-graphql-abuse/SKILL.md) | 2 | `offensive-graphql` | Introspection lockdown, batching and alias-abuse limits |
| [`detect-hpp`](Skills/web/detect-hpp/SKILL.md) | 2 | `offensive-parameter-pollution` | Duplicate-parameter and WAF-confusion detection |
| [`detect-idor`](Skills/web/detect-idor/SKILL.md) | 2 | `offensive-idor` | Authorization-failure and object-enumeration signals |
| [`detect-malicious-upload`](Skills/web/detect-malicious-upload/SKILL.md) | 2 | `offensive-file-upload` | Upload content inspection, webshell and polyglot detection |
| [`detect-request-smuggling`](Skills/web/detect-request-smuggling/SKILL.md) | 2 | `offensive-request-smuggling` | CL.TE / TE.CL desync signatures and front-end hardening |
| [`detect-ssrf`](Skills/web/detect-ssrf/SKILL.md) | 2 | `offensive-ssrf` | Metadata-endpoint access, egress anomaly, allowlist bypass |
| [`detect-ssti`](Skills/web/detect-ssti/SKILL.md) | 2 | `offensive-ssti` | Template-engine error and payload signatures |
| [`detect-web-race-condition`](Skills/web/detect-web-race-condition/SKILL.md) | 2 | `offensive-race-condition` | Single-packet and limit-bypass anomaly detection |
| [`detect-xss`](Skills/web/detect-xss/SKILL.md) | 2 | `offensive-xss` | CSP, output-encoding gaps, DOM-sink monitoring |
| [`detect-xxe`](Skills/web/detect-xxe/SKILL.md) | 2 | `offensive-xxe` | External-entity and OOB callback detection |
| [`harden-waf`](Skills/web/harden-waf/SKILL.md) | 2 | `offensive-waf-bypass` | Encoding and chunked-transfer evasion coverage, rule tuning |

### Auth & Identity

`Skills/auth/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-oauth-consent-phishing`](Skills/auth/detect-oauth-consent-phishing/SKILL.md) | 1 | `offensive-oauth` | Illicit consent grants and app-role abuse in Entra ID via KQL |
| [`defend-jwt`](Skills/auth/defend-jwt/SKILL.md) | 2 | `offensive-jwt` | Reject alg:none and key confusion, enforce validation and key rotation |

### Active Directory

`Skills/active-directory/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-kerberoasting`](Skills/active-directory/detect-kerberoasting/SKILL.md) | 1 | `offensive-active-directory` | RC4 service-ticket downgrade, SPN fan-out, honeypot SPN via Event 4769 |
| [`detect-ad-credential-abuse`](Skills/active-directory/detect-ad-credential-abuse/SKILL.md) | 2 | `offensive-active-directory` | ASREProast, DCSync, ACL and delegation abuse, MDI alerts |

### Wireless

`Skills/wireless/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-deauth`](Skills/wireless/detect-deauth/SKILL.md) | 2 | `offensive-deauth-disassoc` | Deauth/disassoc flood detection, 802.11w |
| [`detect-rogue-ap`](Skills/wireless/detect-rogue-ap/SKILL.md) | 2 | `offensive-evil-twin` | Rogue and evil-twin AP detection |
| [`detect-wifi-attacks`](Skills/wireless/detect-wifi-attacks/SKILL.md) | 2 | `offensive-wifi` | 802.11 attack detection overview |
| [`detect-wifi-recon`](Skills/wireless/detect-wifi-recon/SKILL.md) | 2 | `offensive-wifi-recon` | Rogue-scan and probe-flood detection |
| [`harden-ble`](Skills/wireless/harden-ble/SKILL.md) | 2 | `offensive-bluetooth-ble` | GATT access control, pairing hardening |
| [`harden-bluetooth-classic`](Skills/wireless/harden-bluetooth-classic/SKILL.md) | 2 | `offensive-bluetooth-classic` | Discovery and SDP exposure reduction |
| [`harden-lorawan-sub-ghz`](Skills/wireless/harden-lorawan-sub-ghz/SKILL.md) | 2 | `offensive-lorawan-sub-ghz` | Join-procedure and session-key hardening |
| [`harden-wpa-enterprise`](Skills/wireless/harden-wpa-enterprise/SKILL.md) | 2 | `offensive-wpa-enterprise` | 802.1X/EAP server-cert validation, anti-rogue-RADIUS |
| [`harden-wpa2`](Skills/wireless/harden-wpa2/SKILL.md) | 2 | `offensive-wpa2-psk` | PSK handshake-capture resistance, strong passphrase policy |
| [`harden-wpa3`](Skills/wireless/harden-wpa3/SKILL.md) | 2 | `offensive-wpa3-sae` | SAE transition-mode and downgrade hardening |
| [`harden-wps`](Skills/wireless/harden-wps/SKILL.md) | 2 | `offensive-wps` | Disable WPS, Pixie-Dust exposure checks |
| [`harden-z-wave`](Skills/wireless/harden-z-wave/SKILL.md) | 2 | `offensive-z-wave` | S0/S2 key and sniffing exposure hardening |
| [`harden-zigbee-thread-matter`](Skills/wireless/harden-zigbee-thread-matter/SKILL.md) | 2 | `offensive-zigbee-thread-matter` | Mesh-protocol key management and monitoring |
| [`patch-krack-fragattacks`](Skills/wireless/patch-krack-fragattacks/SKILL.md) | 2 | `offensive-krack-fragattacks` | KRACK and FragAttacks patch and exposure verification |

### Cloud

`Skills/cloud/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-cloud-attack-paths`](Skills/cloud/detect-cloud-attack-paths/SKILL.md) | 2 | `offensive-cloud` | IAM anomaly and control-plane log detection across AWS, Azure, GCP |

### Mobile

`Skills/mobile/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`harden-mobile-apps`](Skills/mobile/harden-mobile-apps/SKILL.md) | 2 | `offensive-mobile` | Static and runtime hardening for Android and iOS apps |

### IoT & Embedded

`Skills/iot/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`harden-iot`](Skills/iot/harden-iot/SKILL.md) | 2 | `offensive-iot` | Firmware, hardware-interface, and RTOS/ICS hardening |

### Infrastructure & Endpoint

`Skills/infrastructure/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-edr-evasion`](Skills/infrastructure/detect-edr-evasion/SKILL.md) | 2 | `offensive-edr-evasion` | AMSI and ETW tamper detection, unhooking indicators |
| [`detect-initial-access`](Skills/infrastructure/detect-initial-access/SKILL.md) | 2 | `offensive-initial-access` | Public-facing exploit and payload-delivery detection, from the Metabase and N-central cases |
| [`detect-keyloggers`](Skills/infrastructure/detect-keyloggers/SKILL.md) | 2 | `offensive-keylogger-arch` | Input-capture and hook-install detection |
| [`detect-redteam-ttps`](Skills/infrastructure/detect-redteam-ttps/SKILL.md) | 2 | `offensive-advanced-redteam` | Purple-team detection coverage across the engagement lifecycle |
| [`detect-shellcode-injection`](Skills/infrastructure/detect-shellcode-injection/SKILL.md) | 2 | `offensive-shellcode` | Injection and in-memory execution detection |
| [`harden-windows-boundaries`](Skills/infrastructure/harden-windows-boundaries/SKILL.md) | 2 | `offensive-windows-boundaries` | Trust-boundary and token hardening |
| [`verify-windows-mitigations`](Skills/infrastructure/verify-windows-mitigations/SKILL.md) | 2 | `offensive-windows-mitigations` | Confirm exploit mitigations are enforced |

### Exploit Mitigation

`Skills/exploit-dev/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`defend-exploit-mitigations`](Skills/exploit-dev/defend-exploit-mitigations/SKILL.md) | 2 | `offensive-exploit-development` | ASLR, DEP, CFG, CET coverage and gaps |
| [`defend-memory-corruption`](Skills/exploit-dev/defend-memory-corruption/SKILL.md) | 2 | `offensive-basic-exploitation`, `offensive-exploit-dev-course` | Compiler and allocator hardening for memory safety |
| [`detect-toctou-races`](Skills/exploit-dev/detect-toctou-races/SKILL.md) | 2 | `offensive-toctou` | TOCTOU and race-window hardening |
| [`triage-crashes-defensively`](Skills/exploit-dev/triage-crashes-defensively/SKILL.md) | 2 | `offensive-crash-analysis` | Exploitability triage of crashes for defenders |
| [`verify-exploit-mitigations`](Skills/exploit-dev/verify-exploit-mitigations/SKILL.md) | 2 | `offensive-mitigations` | Audit that mitigations are present and effective |

### Fuzzing & Vulnerability Triage

`Skills/fuzzing/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`integrate-fuzzing-sdlc`](Skills/fuzzing/integrate-fuzzing-sdlc/SKILL.md) | 2 | `offensive-fuzzing`, `offensive-fuzzing-course` | Fuzz your own code in CI, triage findings |
| [`triage-vuln-classes`](Skills/fuzzing/triage-vuln-classes/SKILL.md) | 2 | `offensive-bug-identification`, `offensive-vuln-classes` | Classify and prioritize discovered bug classes |

### Exposure Management

`Skills/recon/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`monitor-external-attack-surface`](Skills/recon/monitor-external-attack-surface/SKILL.md) | 1 | `offensive-osint-methodology` | KEV exposure checks and external-surface monitoring |
| [`reduce-osint-exposure`](Skills/recon/reduce-osint-exposure/SKILL.md) | 2 | `offensive-osint` | Shrink leaked data, exposed services, and employee footprint |

### API Security

`Skills/api/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-api-business-logic-abuse`](Skills/api/detect-api-business-logic-abuse/SKILL.md) | 2 | `offensive-api-abuse` | BOLA/IDOR monitoring, rate and sequence anomaly |
| [`harden-api-security`](Skills/api/harden-api-security/SKILL.md) | 2 | `offensive-api-security` | AuthZ, schema validation, gateway controls across REST/gRPC/WebSocket |

### Container & Kubernetes

`Skills/container/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-container-escape`](Skills/container/detect-container-escape/SKILL.md) | 2 | `offensive-container-escape` | Runtime escape detection, seccomp and capability monitoring |
| [`harden-k8s`](Skills/container/harden-k8s/SKILL.md) | 2 | `offensive-k8s-attacks` | RBAC least privilege, admission control, audit-log detection |

### CI/CD & Pipeline

`Skills/cicd/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-cicd-secret-exposure`](Skills/cicd/detect-cicd-secret-exposure/SKILL.md) | 2 | `offensive-cicd-secrets` | Secret scanning and rotation, pipeline leak detection |
| [`harden-cicd-pipeline`](Skills/cicd/harden-cicd-pipeline/SKILL.md) | 2 | `offensive-cicd-pipeline` | OIDC federation, runner isolation, workflow-injection prevention |

### Cryptography

`Skills/crypto/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`harden-crypto-implementations`](Skills/crypto/harden-crypto-implementations/SKILL.md) | 2 | `offensive-crypto-attacks` | Fix padding, nonce reuse, and weak-primitive misuse |
| [`harden-tls`](Skills/crypto/harden-tls/SKILL.md) | 2 | `offensive-tls-attacks` | Cipher and protocol hardening, config scanning |

### Privilege Escalation

`Skills/privesc/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-linux-privesc`](Skills/privesc/detect-linux-privesc/SKILL.md) | 2 | `offensive-linux-privesc` | SUID, capability, and sudo-abuse detection and hardening |
| [`detect-windows-privesc`](Skills/privesc/detect-windows-privesc/SKILL.md) | 2 | `offensive-windows-privesc` | Token, service, and UAC-bypass detection and hardening |

### Post-Exploitation

`Skills/post-exploitation/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-data-exfiltration`](Skills/post-exploitation/detect-data-exfiltration/SKILL.md) | 1 | `offensive-data-exfiltration` | DNS and HTTPS exfil detection, egress volume anomaly |
| [`detect-ncentral-post-exploitation`](Skills/post-exploitation/detect-ncentral-post-exploitation/SKILL.md) | 1 | `offensive-persistence` | Service persistence, masquerading, and tunnel detection from the N-central case |
| [`detect-lateral-movement`](Skills/post-exploitation/detect-lateral-movement/SKILL.md) | 2 | `offensive-lateral-movement` | Remote-exec, Pass-the-Hash and tunneling signals |

### Forensics & C2

`Skills/forensics/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-anti-forensics`](Skills/forensics/detect-anti-forensics/SKILL.md) | 2 | `offensive-anti-forensics` | Log-clear (1102), timestomp, and artifact-wipe detection |
| [`detect-c2-beaconing`](Skills/forensics/detect-c2-beaconing/SKILL.md) | 2 | `offensive-c2-frameworks` | Beacon jitter, JA3, and tunnel-service detection |

### Supply Chain

`Skills/supply-chain/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-supply-chain-compromise`](Skills/supply-chain/detect-supply-chain-compromise/SKILL.md) | 1 | `offensive-supply-chain` | Compromised-package and tampered-artifact detection, MSP RMM risk |
| [`detect-dependency-confusion`](Skills/supply-chain/detect-dependency-confusion/SKILL.md) | 2 | `offensive-dependency-confusion` | Namespace-takeover and resolver-order monitoring |

### Social Engineering

`Skills/social-engineering/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`defend-social-engineering`](Skills/social-engineering/defend-social-engineering/SKILL.md) | 2 | `offensive-social-engineering` | Awareness, vishing and physical controls, process hardening |
| [`detect-phishing`](Skills/social-engineering/detect-phishing/SKILL.md) | 2 | `offensive-phishing` | Consent-phishing detection from the OAuth writeup; email-phishing controls next |

### Network

`Skills/network/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`detect-l2-l3-attacks`](Skills/network/detect-l2-l3-attacks/SKILL.md) | 2 | `offensive-network-attacks` | ARP, LLMNR, and DNS poisoning detection, DHCP snooping |

### AI Security

`Skills/ai/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`defend-ai-agents`](Skills/ai/defend-ai-agents/SKILL.md) | 1 | `offensive-ai-security` | Securing tool-calling agents, least-privilege tool scopes, injection containment |
| [`defend-llm-top-10`](Skills/ai/defend-llm-top-10/SKILL.md) | 1 | `offensive-ai-security` | OWASP LLM Top 10 for defenders: prompt injection, RAG poisoning, output handling |

### Utility

`Skills/utility/`

| Skill | Tier | Answers claude-red | Defensive focus |
|---|:-:|---|---|
| [`defensive-fast-triage`](Skills/utility/defensive-fast-triage/SKILL.md) | 2 | `offensive-fast-checking` | Fast blue-team triage checklist, from the Blue Team Mapper |
| [`defensive-reporting`](Skills/utility/defensive-reporting/SKILL.md) | 2 | `offensive-reporting` | Detection and incident reporting, every claim tied to a source |
<!-- skill-index:end -->

---

## Roadmap

| Phase | Focus | Status |
|---|---|---|
| 1 | Full mirror of claude-red, one defensive skill per offensive skill | Complete |
| 2 | Validator, manifest generator, and rule sync in CI | Complete |
| 3 | Promote Tier 2 skills to Tier 1 as UMBRASEC writeups and rules land, starting with identity, cloud, and web | In progress |
| 4 | Claude Code plugin marketplace packaging | Planned |
| 5 | Track new claude-red skills as they ship, keeping the pairing complete | Ongoing |

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## Contributing

Contributions and corrections are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the skill format, the tier rules, and the review process. Found a detection that misbehaves or a wrong citation? [Open an issue](https://github.com/umbrasec-labs/umbra-blue/issues). Corrections are credited.

## License

[MIT](LICENSE). The research the Tier 1 skills derive from is published free to read at [umbrasec.dev](https://umbrasec.dev/research/).

## Acknowledgements

- **Author:** [UMBRASEC](https://umbrasec.dev), an independent defensive security practice.
- **Public rule sources** referenced by Tier 2 skills: [SigmaHQ](https://github.com/SigmaHQ/sigma), [MITRE ATT&CK](https://attack.mitre.org/), and [MITRE D3FEND](https://d3fend.mitre.org/).

---

<div align="center">

*Attackers improve. Defenders should too.*

[umbrasec.dev](https://umbrasec.dev) &bull; [Research](https://umbrasec.dev/research/) &bull; [sigma-pack](https://umbrasec.dev/tools/sigma-pack/) &bull; [GitHub](https://github.com/umbrasec-labs)

</div>
