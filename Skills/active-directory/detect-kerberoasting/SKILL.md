---
name: detect-kerberoasting
description: "Detection and response methodology for Kerberoasting in Active Directory (MITRE ATT&CK T1558.003, Credential Access). Covers the RC4 service-ticket downgrade signal, SPN request fan-out, and the honeypot-SPN tripwire - three layered Sigma detections keyed off Windows Security Event ID 4769 on domain controllers, each with tuning, false-positive notes, and gMSA/AES mitigations. Use when investigating suspicious Kerberos service-ticket activity, writing or reviewing Kerberoasting detections, hunting for SPN enumeration, triaging 4769 alerts, or hardening service accounts against offline password cracking."
---

# Kerberoasting - Detection and Response

Kerberoasting lets any authenticated domain user request a service ticket for an account that has a Service Principal Name, then crack the service account's password offline. It needs no special privileges, produces no failed logons, and trips no lockout. That is why it is still one of the most common post-compromise techniques. This skill is defensive: it explains the technique only as far as detection and mitigation require, and ships no roasting or cracking tooling.

## TL;DR for defenders

Enable **Audit Kerberos Service Ticket Operations** on every domain controller, then watch **Event ID 4769** for two things: service-ticket requests using **RC4** (`TicketEncryptionType 0x17`) in a domain that should be AES, and a single account requesting tickets for an unusual number of distinct SPNs. A decoy **honeypot SPN** turns anomaly-hunting into a near-zero-false-positive alarm and is the highest-value, lowest-effort detection here. Layer all three rules below; none is a silver bullet alone.

## Why it still matters in 2026

The attack abuses how Kerberos is meant to work, so there is no patch that removes it. Microsoft is retiring RC4 in phases across supported domain controllers: the January 2026 updates added KDC audit events 201-209 flagging RC4 use, and the April 2026 updates switched the DC default to AES-only for accounts with no explicit `msDS-SupportedEncryptionTypes`. But any account whose `msDS-SupportedEncryptionTypes` still includes RC4 keeps getting RC4 service tickets, and those tend to be the old, over-privileged service accounts an attacker wants. The weak encryption that makes roasting fast still sits on some accounts, so detection still matters.

Why RC4 is the dangerous case: an RC4-HMAC ticket (`etype 0x17`, decimal 23) derives its key straight from the account's unsalted NT hash, fast to attack on a GPU. A single RTX 4090 running Hashcat 7.0.0 benchmarks about 3.4 billion guesses per second against an RC4 TGS-REP (hash-mode 13100), enough that a short or dictionary service-account password falls in minutes to hours. AES tickets (`0x11`/`0x12`) are roughly hundreds to a thousand times slower to attack because the key comes from salted PBKDF2. So roasting tooling deliberately downgrades to RC4 - and that downgrade is your single best signal.

## Log sources required

Everything here keys off one event generated on **domain controllers**: **Event ID 4769**, "A Kerberos service ticket was requested."

- Enable **Audit Kerberos Service Ticket Operations (Success)** via Group Policy: Computer Configuration, Policies, Windows Settings, Security Settings, Advanced Audit Policy, Account Logon.
- Ship the Security log from **every** DC. A roasting request can be serviced by any DC, so a gap on one DC is a blind spot.
- Expect volume. 4769 fires constantly in normal operation, which is why the filtering below matters as much as the matching.

Fields you will lean on in each 4769 event:

| Field | Why it matters |
|---|---|
| `TicketEncryptionType` | `0x17` = RC4, the downgrade signal. `0x12` = AES-256, `0x11` = AES-128. |
| `ServiceName` / `ServiceSid` | The account whose ticket was requested, the roast target. Names ending in `$` are computer accounts, usually benign. |
| `TargetUserName` | The principal that made the request, the account you would investigate. |
| `TicketOptions` | Roasting tools often produce recognizable flags, commonly `0x40810000`, but this varies and should not be relied on alone. |
| `Status` | `0x0` = the ticket was issued successfully. |

## Detection

Three layered detections, highest precision first. This mirrors MITRE ATT&CK's own detection strategy for the technique (DET0157). Canonical copies of these rules live in the UMBRASEC [sigma-pack](https://umbrasec.dev/tools/sigma-pack/); the writeup explains each in full.

### 1. RC4 ticket requested in an AES environment (high precision)

If your domain and accounts support AES, legitimate clients should almost never request RC4, so an RC4 4769 is a strong signal. Computer accounts (`$`) and `krbtgt` generate benign RC4 traffic and are excluded.

```yaml
# kerberoasting-rc4-service-ticket.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: Kerberoasting - RC4 Service Ticket Requested
id: 8f1e2c33-6a4b-4d9e-9a1f-2b7c0d5e4a10
status: experimental
description: >
    A Kerberos TGS (Event 4769) was issued using RC4-HMAC encryption.
    In AES-capable domains this is a common indicator of Kerberoasting,
    where tooling downgrades to RC4 to ease offline cracking.
references:
    - https://attack.mitre.org/techniques/T1558/003/
    - https://umbrasec.dev/research/detecting-kerberoasting.html
author: UMBRASEC
date: 2026-06-10
modified: 2026-10-25
tags:
    - attack.credential-access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'   # RC4-HMAC
        # TicketOptions: '0x40810000'  # OFF by default: roasting tools vary this flag, so
                                       # ANDing it here misses them. Opt-in tightening filter
                                       # only - see the writeup tuning note before enabling.
        Status: '0x0'                   # only count successfully issued tickets
    filter_machine:
        ServiceName|endswith: '$'
    filter_krbtgt:
        ServiceName: 'krbtgt'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legacy applications or appliances that genuinely require RC4
    - Some Linux/macOS or third-party Kerberos clients
    - Accounts whose msDS-SupportedEncryptionTypes still allow only RC4
level: medium
```

### 2. One account, many service principals (velocity / fan-out)

Roasting frameworks often pull tickets for every SPN they can find in one burst. A normal user touches a handful of services a day; an account requesting dozens of distinct SPNs in minutes is anomalous regardless of encryption type. Expressed as a Sigma correlation, or the equivalent `stats` query in your SIEM.

```yaml
# kerberoasting-spn-fanout.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: Kerberoasting - High Volume of Distinct SPN Requests
id: 1c9d4b77-2e55-4f01-bb3a-6d8e9f0a1b22
status: experimental
description: >
    A single account requested Kerberos service tickets (4769) for an
    unusually large number of distinct service principals in a short
    window - consistent with bulk Kerberoasting enumeration.
references:
    - https://attack.mitre.org/techniques/T1558/003/
    - https://umbrasec.dev/research/detecting-kerberoasting.html
author: UMBRASEC
date: 2026-06-10
modified: 2026-10-25
tags:
    - attack.credential-access
    - attack.t1558.003
correlation:
    type: value_count
    rules:
        - kerberoasting_4769_base
    group-by:
        - TargetUserName
    timespan: 5m
    condition:
        gte: 15
        field: ServiceName
falsepositives:
    - Vulnerability scanners and monitoring accounts that request tickets for many services in a burst - allowlist them
    - Busy legitimate accounts above the default threshold - run it report-only first and set gte above your noisiest legitimate account
level: medium
---
title: Kerberoasting 4769 base
id: 2d0e5c88-3f66-4012-cc4b-7e9f0a1b2c33
name: kerberoasting_4769_base
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        Status: '0x0'
    filter_machine:
        TargetUserName|endswith: '$'
    condition: selection and not filter_machine
```

### 3. The honeypot SPN (near-zero false positives)

The highest-value, lowest-effort detection here. Create a decoy service account, give it a tempting SPN so it appears in any SPN enumeration (for example `MSSQLSvc/sql-prod-01.corp.example:1433`), make sure nothing legitimately uses it, and give it a long random password and minimal privileges. Any 4769 naming that account is suspicious by construction, because no honest workload ever requests its ticket. This converts a fuzzy anomaly into a binary alarm.

```yaml
# kerberoasting-honeypot-spn.yml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)
title: Kerberoasting - Honeypot SPN Ticket Requested
id: 3e1f6d99-4a77-4123-dd5c-8f0a1b2c3d44
status: experimental
description: >
    A Kerberos service ticket (4769) was requested for a decoy service
    account that no legitimate workload uses. Any hit is high-confidence
    evidence of SPN enumeration / Kerberoasting.
references:
    - https://attack.mitre.org/techniques/T1558/003/
    - https://umbrasec.dev/research/detecting-kerberoasting.html
author: UMBRASEC
date: 2026-06-10
modified: 2026-10-25
tags:
    - attack.credential-access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        ServiceName: 'svc-honeypot-sql'   # <-- your decoy sAMAccountName
    condition: selection
falsepositives:
    - A misconfigured scanner that was pointed at the decoy (investigate anyway)
level: high
```

## Tuning and false positives

- **Rule 1 (`TicketOptions`).** The rule ships with the `TicketOptions: '0x40810000'` line commented out. Enabled, it tightens precision but misses tools that vary their flags. Start without it to measure your baseline of RC4 requests, identify the legitimate RC4-only accounts, add those to `filter_machine` as an allowlist, then decide whether the `TicketOptions` constraint earns its keep.
- **Rule 2 (threshold and window).** `gte: 15` over `5m` are starting points. Run it in report-only mode for a week, look at your top talkers - vulnerability scanners and monitoring accounts will appear, allowlist them - and set the threshold above your noisiest legitimate account.
- **Rule 3 (honeypot).** Replace `svc-honeypot-sql` with your decoy's `sAMAccountName`. A hit should be near-binary; the only benign cause is a scanner pointed at the decoy, which is still worth investigating.

## Threat hunt

For the low-and-slow attacker who pulls a single high-value ticket and waits, the velocity rule will not fire. Hunt instead:

1. Over a long window, list every 4769 with `TicketEncryptionType 0x17` and `Status 0x0`, excluding `$` and `krbtgt`.
2. Join the target `ServiceName` to its account's `msDS-SupportedEncryptionTypes`. An RC4 ticket for an account that is supposed to be AES-only is the anomaly.
3. Rank targets by privilege: a lone RC4 request for a Domain Admin-tier service account outweighs any volume signal.

## Mitigation

Detection buys time; these changes shrink the attack surface. Microsoft's October 2024 guidance is the authoritative reference. Mappings below follow the control codes used in the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html); a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Group Managed Service Accounts (gMSAs) | 120-character auto-rotated passwords that are not practically crackable | - | A.5.17 Authentication information | PR.AA-01 |
| Enforce AES-only (`msDS-SupportedEncryptionTypes`) | Removes the RC4 downgrade path, after rule 1 finds what still needs RC4 | - (configuration; the 2026 RC4 phase-out ships via *Patch operating systems*) | A.8.24 Use of cryptography | PR.PS |
| Fix weak service-account passwords | Long and random; AES raises cost but a short password still falls | - | A.5.17 Authentication information | PR.AA-01 |
| Audit SPNs and privilege | Remove SPNs from accounts that do not need them; strip over-granted admin rights | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 Least privilege |

## Honest limitations

A low-and-slow attacker who requests one high-value ticket and waits will sail past the velocity rule, and if the target is legitimately RC4-only may not stand out in rule 1 either. That is the reason the honeypot exists and why mitigation matters as much as detection. Layer all three rules, and pair them with non-crackable passwords so a stolen ticket is useless even if it slips through. Test every rule in report-only mode and baseline your own environment before enforcing; the thresholds are dials.

## ATT&CK and references

- MITRE ATT&CK: [T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/); Detection Strategy DET0157.
- UMBRASEC writeup: [Detecting Kerberoasting: A Practical Walkthrough with Sigma](https://umbrasec.dev/research/detecting-kerberoasting.html) (2026-06-10).
- Microsoft Support KB5073381 - managing Kerberos KDC RC4 usage for service-account ticket issuance, CVE-2026-20833 (Jan 2026).
- Microsoft Tech Community - Phase 2 of Kerberos RC4 hardening, April 2026 update.
- Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos (Feb 2026).
- Microsoft Security Blog - Guidance to help mitigate Kerberoasting (Oct 2024).
- CrowdStrike 2023 Threat Hunting Report; IBM 2024 X-Force Threat Intelligence Index.
- hashcat Forum - RTX 4090 benchmark, Hashcat 7.0.0 (Aug 2025).

**Scope note.** This is a defensive skill. It explains the technique only to the depth needed to detect and mitigate it and deliberately provides no roasting tooling or cracking instructions. UMBRASEC publishes defense, not offense.
