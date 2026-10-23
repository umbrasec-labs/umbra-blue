---
name: triage-vuln-classes
description: "Defensive triage methodology for classifying and prioritizing bug classes, the blue-team answer to offensive bug identification. Unremediated or mis-ranked vulnerabilities are what an adversary turns into Exploit Public-Facing Application (MITRE ATT&CK T1190) and the exploitation family (T1203, T1068, T1210, T1212, T1211), after recon and vuln sourcing (T1595.002, T1588.006). Works over your vulnerability data: scanner findings, SAST/DAST/SCA output (Semgrep, CodeQL, Trivy/Grype), and pentest reports, enriched with NVD CVSS v4.0, FIRST EPSS, the CISA KEV catalog, CWE, and CISA SSVC. Gives a classify-then-rank method that survives findings with no CVE, a hunt pivoting top classes to active-exploitation evidence, and remediation hardening mapped to ISO 27001 and NIST CSF 2.0. Use when triaging scanner or pentest findings, building a prioritization or SLA policy, deciding what to patch first, or reconciling CVSS against EPSS and KEV."
---

# Discovered Bug Classes - Triage and Prioritization Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's classification and prioritization method, the data sources and signals, the hunt, and the hardening, and points to public, maintained rule sources by URL. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR for defenders

Triage is a ranking discipline, not a scan. You already have more findings than you can fix; the job is to put them in the right order and defend that order. Classify every finding by its bug class (map it to a CWE and to the exploit primitive it grants, for example memory corruption to code execution, injection to data or command control, broken access control to privilege escalation), then rank by a combination of exploitability and exposure, not by vendor severity alone. The single most useful rule: a vulnerability that is in the **CISA KEV catalog** or has a high **EPSS** probability **and** sits on an internet-facing asset outranks a higher-CVSS bug that is internal-only and has no known exploit. Score CVE-bearing findings with CVSS v4.0, EPSS, and KEV; score first-party findings that have **no CVE** (authz flaws, business logic, SSRF in your own code) with CWE class severity and a CISA SSVC decision, because EPSS and KEV simply do not cover them. Then feed your top-ranked classes to detection so you are watching for exploitation of exactly the bugs you have not closed yet.

## What it looks like, defender view

The offensive counterpart to this skill is a bug hunter or operator sorting what they found into classes and picking the one that pays: which flaw gives reliable code execution, which authz gap reaches the most data, which injection point is actually reachable without auth. You are doing the inverse sort over the same facts. Your inputs are a deduplicated backlog of findings from scanners, code analysis, SBOM/SCA, and human testing; your output is a ranked, asset-aware remediation queue plus a short list of classes to watch in telemetry. In the defender's view a bad triage is invisible until it is not: a CVE sat in the backlog at "medium" because its CVSS base was 6.5, it was quietly added to KEV, an unauthenticated exploit shipped, and the first real signal is anomalous child processes under the web service or outbound traffic from a host that should never initiate it. Good triage moves that CVE to the top on the day KEV lists it, before the exploitation telemetry ever appears. No offensive how-to is needed to do any of this; you are ordering risk, not reproducing it.

## Log sources and signals

Triage runs on vulnerability data feeds, not host event logs. Name them so the gaps and the authoritative fields are visible:

- **Scanner findings.** Tenable Nessus / Tenable.io (`pluginID`, `cve`, `cvss3_base_score`, VPR), Qualys VMDR (`QID`, `SEVERITY`, `CVSS`), Rapid7 InsightVM (`vulnerabilityId`, `cvssV3Score`, Real Risk Score), OpenVAS/Greenbone (`oid`, `nvt`). Each finding carries the affected asset (IP/hostname/CPE) and, for CVE-mapped findings, the CVE ID.
- **Code and dependency analysis.** Semgrep (`check_id`, mapped `cwe`), GitHub CodeQL SARIF (`ruleId`, `security-severity`), GitHub Dependabot / GitHub Advisory Database (`GHSA` ID, `cve`, `cwe`, severity, fixed version), Trivy and Grype (`VulnerabilityID`, `Severity`, `FixedVersion`), OWASP Dependency-Check. SCA findings pair a component (purl/CPE) to a CVE or GHSA.
- **Human testing.** Pentest and bug-bounty reports. These are the ones without a CVE: a CWE class, a reachability note, and a repro. They are frequently under-triaged because the CVE-centric feeds say nothing about them.
- **Enrichment feeds (join keys for prioritization).** NVD CVE records (CVSS v3.1 and v4.0 vectors, authoritative CWE mapping); FIRST **EPSS** (`epss` exploitation probability and `percentile`, refreshed daily); CISA **KEV** catalog (`cveID`, `dateAdded`, `knownRansomwareCampaignUse`, `dueDate`); the MITRE **CWE** taxonomy and the CWE Top 25 for class weighting; CISA **SSVC** decision points (Exploitation, Automatable, Technical Impact, Mission and Well-being) for a stakeholder-specific decision.
- **Exposure context.** Asset inventory and CMDB (internet-facing vs internal, data classification, business criticality) and external attack-surface data. Exposure is the multiplier that turns a raw score into a priority; without it CVSS base is just a lab number.

What normal looks like: a steady inflow of findings, most of them medium-CVSS library issues with a fix available, EPSS near zero, not in KEV, on internal assets. The anomalies worth jumping the queue are KEV additions, EPSS spikes, and any high-impact class landing on an exposed, high-value asset.

## Detection approach

Two layers, and both are prose logic, not a shipped rule.

**Layer 1, classify.** For each finding, assign the CWE if the feed did not (NVD, GHSA, and Semgrep already carry one; pentest findings you map by hand). Collapse the CWE to its exploit primitive so non-specialists can reason about it: memory-safety classes (CWE-787 out-of-bounds write, CWE-416 use-after-free, CWE-121 stack overflow) grant code execution; injection classes (CWE-89 SQLi, CWE-78 OS command, CWE-79 XSS) grant data or session or command control; broken access control and auth classes (CWE-862 missing authorization, CWE-269 improper privilege management, CWE-287 improper authentication) grant privilege escalation or data exposure; SSRF (CWE-918) and deserialization (CWE-502) are high-leverage because they commonly chain to the above. Deduplicate: the same underlying flaw often appears as one CVE across many assets and as several scanner plugin IDs; rank the flaw once, then fan out to assets.

**Layer 2, rank.** Combine four factors, highest first:
1. **Known exploited.** In CISA KEV, or with a public exploit and EPSS percentile above your chosen line (start around the 90th percentile and tune). KEV `dueDate` is a hard deadline for federal systems and a sane default for everyone.
2. **Exposure.** Internet-facing and unauthenticated beats internal and authenticated. Reachability is decisive: an unreachable code path is a lower priority than its CVSS suggests.
3. **Impact and asset value.** The exploit primitive crossed with the asset's data classification and criticality. Code execution on a crown-jewel system outranks information disclosure on a lab box even at equal CVSS.
4. **Base severity.** CVSS v4.0 base as the tie-breaker, never the sole input. Use the v4.0 Threat metrics (Exploit Maturity) and Environmental metrics so the score reflects your environment, not NVD's default assumptions.

For findings with **no CVE** (your own authz, business-logic, and SSRF bugs from pentest and bounty), EPSS and KEV are blank by definition, so do not let the rank collapse to zero. Score those with CWE class severity plus a CISA **SSVC** walk (is it exploitable now, is exploitation automatable, what is the technical impact, what is the mission impact) and treat a confirmed reachable missing-authorization or auth-bypass finding as top-tier regardless of any CVSS.

Then close the loop with runtime detection of the classes you have not fixed: feed your top-ranked CVEs and classes to the SIEM/IDS so exploitation attempts surface. Point at public, maintained rules rather than inventing one: SigmaHQ CVE-specific exploitation rules under `rules-emerging-threats/` by year ([github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats](https://github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats)), generic web and proxy exploitation patterns under `rules/web/` ([github.com/SigmaHQ/sigma/tree/master/rules/web](https://github.com/SigmaHQ/sigma/tree/master/rules/web)), the CISA KEV catalog as a prioritization feed ([cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)), FIRST EPSS ([first.org/epss](https://www.first.org/epss/)), and MITRE D3FEND for the countermeasure mapping ([d3fend.mitre.org](https://d3fend.mitre.org/)). A tuned UMBRASEC rule is not shipped for this methodology; these are the public sources to use.

## Threat hunt

Hypothesis: a top-ranked, still-unpatched vulnerability class is already being exploited on an exposed asset. Steps:

1. Pull the top of the ranked queue: every finding that is in KEV, or has EPSS percentile above your line, **and** sits on an internet-facing asset. This is usually a short list.
2. For each, take the affected asset list from the scanner/SCA data and the exploit primitive from the classification. Build the hunt query from the primitive: for a code-execution class, look for anomalous child processes under the vulnerable service account and new outbound connections from a host that normally only receives; for an injection class, look in web access logs (W3CIISLog, Apache/Nginx access, WAF `CommonSecurityLog`) for the payload shape on the vulnerable endpoint plus a change in response size or a `200` where errors are normal; for a missing-authorization finding, look for a low-privilege principal reaching a high-privilege object.
3. Pivot from any hit to the asset's wider timeline: new local accounts, scheduled tasks or services, credential access, lateral movement outbound. One confirmed success reclassifies the finding from "to be patched" to "active incident" and should trigger your IR process.
4. Record the negative result too. A clean hunt on a top finding is evidence for the patch SLA decision, not proof of safety; re-run when KEV or EPSS changes for that CVE.

## Hardening

Triage decides the order; these controls shrink the backlog and the window so the order matters less. The codes below are grounded in the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html) mapping table; a cell is left blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Know what you own (asset inventory, exposure, data classification) | Supplies the exposure and value inputs that triage ranks on; you cannot prioritize what you cannot see | Assumed prerequisite | A.5.9 Inventory of assets | ID.AM Asset Management |
| Patch on a schedule, prioritized by this triage | Closes the ranked backlog; a tiered SLA (shorter for KEV and internet-facing) is the point of triaging at all | Patch applications; Patch operating systems | A.8.8 Technical vulnerabilities | ID.RA; PR.PS Platform Security |
| Restrict administrative privileges | Compensating control that lowers the impact factor for a class you cannot patch yet | Restrict administrative privileges | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Application control | Blocks execution of unapproved code, blunting code-execution classes while they sit in the queue | Application control | A.8.19 Software on systems | PR.PS Platform Security |

Patch SLA tiers (days to remediate) are dials, not law: set a short window for KEV and internet-facing high-impact, a longer one for internal and low-EPSS, and measure your patch latency against your own policy so the backlog is governed, not just listed.

## Honest limitations

Triage is a model of likelihood and exposure, not a guarantee. EPSS is a probability over a 30-day horizon, not a verdict, and it says nothing about your specific environment. KEV lags first exploitation by definition, so a fresh in-the-wild bug can outrank where your queue has it until CISA lists it. CVSS base over-weights theoretical severity and ignores reachability; a 9.8 on an unreachable code path is not your biggest problem. The CVE-centric feeds (EPSS, KEV, NVD) cover only CVEs, so a backlog built from them alone silently drops every first-party authz, business-logic, and SSRF finding that has a CWE but no CVE; those must be scored by class and SSVC or they vanish from the ranking. You can only triage what was discovered, so a gap in scanning or testing coverage is a gap in the queue. And any threshold here, the EPSS percentile line and the SLA days, is a starting point to baseline and tune against your own environment, not a fixed number.

## ATT&CK and D3FEND

- MITRE ATT&CK (the techniques unremediated bug classes enable): [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/), [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/), [T1210 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/), [T1212 Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212/), [T1211 Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/); and the adversary's own acquisition and recon, [T1588.006 Vulnerabilities](https://attack.mitre.org/techniques/T1588/006/) and [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/).
- MITRE D3FEND: D3FEND does not model vulnerability triage itself; it models the remediation that triage drives. The ranked queue feeds [D3-SU Software Update](https://d3fend.mitre.org/technique/d3f:SoftwareUpdate/), and the exposure inputs come from [D3-AI Asset Inventory](https://d3fend.mitre.org/technique/d3f:AssetInventory/).
- Public rule and feed sources: [SigmaHQ emerging-threat rules](https://github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats), [SigmaHQ web rules](https://github.com/SigmaHQ/sigma/tree/master/rules/web), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/), [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc), [MITRE CWE](https://cwe.mitre.org/).

**Scope note.** This is a defensive skill. It explains bug classes only to the depth needed to classify, prioritize, detect, and remediate them, and ships no exploitation or proof-of-concept tooling. UMBRASEC publishes defense, not offense.
