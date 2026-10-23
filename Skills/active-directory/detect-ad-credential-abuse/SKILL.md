---
name: detect-ad-credential-abuse
description: "Detection, hunting, and hardening methodology for Active Directory credential abuse that follows initial foothold: AS-REP Roasting (MITRE ATT&CK T1558.004), DCSync directory replication theft (T1003.006), ACL and group manipulation (T1098), and Kerberos delegation abuse (T1098 setup, T1550.003 use). Primary log sources are Windows domain controller Security events (4768, 4662, 5136, 4738, 4742, 4728/4732/4756) plus Microsoft Defender for Identity alerts and network DRSUAPI replication traffic. The skill gives the defender view of each technique, the exact events and object GUIDs to key off, a hypothesis-driven hunt, and framework-mapped hardening. Use when triaging an MDI DCSync or delegation alert, hunting for replication from a non-domain-controller, investigating accounts with Kerberos pre-authentication disabled, reviewing who holds DS-Replication rights, chasing writes to ntSecurityDescriptor or msDS-AllowedToActOnBehalfOfOtherIdentity, or hardening AD against post-foothold credential abuse."
---

# Active Directory Credential Abuse - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the log sources and signals, and the hardening, and points to public rule sources. Promotion to Tier 1 (a sourced, tuned UMBRASEC rule) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Four distinct abuses share one root cause: an attacker with a foothold turns existing AD rights and protocol features into credential material. Turn on **Directory Service Access** and **Directory Service Changes** auditing on every domain controller so Events **4662** and **5136** actually fire, keep **4768** and the account-change events, and feed **Microsoft Defender for Identity** if you have it. The four highest-value signals are: a **DCSync** (replication control-access rights pulled by a principal that is not a domain controller), a **DACL write** that grants those rights or adds delegation attributes, a **TGT request with pre-authentication type 0** (AS-REP Roasting), and any **DRSUAPI replication from a non-DC source IP**. None is a silver bullet; layer them and pair with least privilege on who can replicate.

## What it looks like, defender view

- **AS-REP Roasting (T1558.004).** An account that has "Do not require Kerberos pre-authentication" set hands back an AS-REP that is encrypted with the account's key before any password is proven. In telemetry this is a **4768** (TGT requested) with **Pre-Authentication Type 0** and, typically, RC4 (`0x17`) encryption, for a user account. No failed logon, no lockout.
- **DCSync (T1003.006).** The attacker asks a DC to replicate secrets using the directory replication protocol (DRSUAPI `DsGetNCChanges`), exactly as a real DC would, so no LSASS touch and no Mimikatz on the DC. The tell is *who* is asking: a workstation or non-DC server exercising replication rights it should never hold.
- **ACL and group manipulation (T1098).** Rights such as full control, write-DACL, write-owner, or write-member over a user, group, or the domain object are abused to grant the attacker replication rights, reset a password, or add to a privileged group. The tell is a modification to `ntSecurityDescriptor` or a sensitive group's membership by an unexpected principal.
- **Delegation abuse (T1098 setup, T1550.003 use).** The attacker writes `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer (resource-based constrained delegation), adds an SPN plus `msDS-AllowedToDelegateTo` (constrained delegation), or flips the `TRUSTED_FOR_DELEGATION` bit (unconstrained). The setup is an attribute write; the payoff is impersonating a privileged user to that service.

## Log sources and signals

Enable on every domain controller, via Group Policy Advanced Audit Policy: **Audit Directory Service Access (Success)**, **Audit Directory Service Changes (Success)**, **Audit Kerberos Authentication Service (Success and Failure)**, and **Audit User/Computer Account Management**. Ship the Security log from *every* DC, because any DC can service these requests.

| Event ID | Source | Signal it carries |
|---|---|---|
| **4768** | DC Security | TGT requested. For AS-REP Roasting: `Pre-Authentication Type` = `0`, often `Ticket Encryption Type` `0x17` (RC4). |
| **4662** | DC Security | An operation on a directory object. For DCSync, the `Properties`/`Access Mask` names the replication control-access-right GUIDs below. Requires a SACL on the domain naming context. |
| **5136** | DC Security | A directory object was modified. Watch `ntSecurityDescriptor` (DACL change), `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-AllowedToDelegateTo`, and `userAccountControl`. |
| **4738 / 4742** | DC Security | User / computer account changed. `userAccountControl` flips to `DONT_REQ_PREAUTH` (AS-REP exposure) or `TRUSTED_FOR_DELEGATION`; `msDS-AllowedToDelegateTo` set on a computer. |
| **4728 / 4732 / 4756** | DC Security | A member was added to a global / local / universal security group - the "added self to Domain Admins" step of an ACL abuse chain. |

The three DCSync control-access-right GUIDs that appear in **4662**:

- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` - DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` - DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c` - DS-Replication-Get-Changes-In-Filtered-Set

Network signal: DRSUAPI `DsGetNCChanges` RPC (part of the `E3514235-4B06-11D1-AB04-00C04FC2DCD2` interface) seen on the wire *from a source that is not a domain controller* is high-fidelity DCSync. A network sensor (Zeek DCE-RPC logging, or MDI's DC traffic inspection) catches it even when host auditing is incomplete.

What normal looks like: legitimate replication is DC-to-DC only, so the set of principals that should ever hold replication rights or request `DsGetNCChanges` is small and knowable. Pre-authentication is enabled on essentially all modern accounts; a `DONT_REQ_PREAUTH` account is rare and worth an inventory.

## Detection approach

Alert on the smallest trustworthy set first, then widen with hunts.

- **DCSync.** Alert on any **4662** whose accessed property set includes DS-Replication-Get-Changes or DS-Replication-Get-Changes-All where the requesting `SubjectUserName` is not a domain controller computer account and not a known tier-0 service (for example Entra Connect / AD sync). The strongest form correlates this with the network DRSUAPI-from-non-DC signal. SigmaHQ ships a maintained rule for this pattern under `rules/windows/builtin/security/` in [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma); use the community rule rather than a hand-rolled one, and allowlist your real sync servers.
- **AS-REP Roasting.** Alert on **4768** with `Pre-Authentication Type` 0 for user (non-computer) accounts, and separately on **4738/4742/5136** that sets `DONT_REQ_PREAUTH`. The first catches use; the second catches an attacker enabling the exposure. SigmaHQ carries rules for both the AS-REP request pattern and preauth-disabled changes in the same repository.
- **ACL and delegation changes.** Alert on **5136** writes to `ntSecurityDescriptor` on tier-0 objects (the domain head, AdminSDHolder, privileged groups) and on writes to `msDS-AllowedToActOnBehalfOfOtherIdentity` / `msDS-AllowedToDelegateTo` / `TRUSTED_FOR_DELEGATION` by any principal outside a tiny change-management allowlist. These attributes change rarely in a healthy domain, so the rule is low-volume.
- **Microsoft Defender for Identity.** If licensed, MDI raises **"Suspected DCSync attack (replication of directory services)"** and **"Suspicious additions to sensitive groups"** natively from DC traffic, and its identity posture assessments flag accounts with **"Do not require Kerberos preauthentication"** set and **unsecure Kerberos delegation**. Treat these as first-class alerts and route them to the SOC; see the MDI alert catalog on Microsoft Learn for the current list. A tuned UMBRASEC rule for these techniques is not yet shipped.

## Threat hunt

Hypothesis: a principal that is not a DC has acquired replication rights, or an account has been made AS-REP-roastable, since the last known-good baseline.

1. **Who can replicate?** Enumerate principals with DS-Replication-Get-Changes / -All on the domain naming context (the ACE set on the domain head). Diff against the expected tier-0 list (DCs, Enterprise/Domain Admins, Entra Connect). Anything else is the finding.
2. **Did anyone replicate who should not?** Over a long window, pull every **4662** touching those GUIDs, drop DC computer accounts and known sync accounts, and investigate the remainder. Cross-check against DRSUAPI-from-non-DC network events for the same source.
3. **What is roastable?** Query AD for `userAccountControl` containing `DONT_REQ_PREAUTH` (`(userAccountControl:1.2.840.113556.1.4.803:=4194304)`). Rank by privilege; a preauth-disabled service or admin account is the priority. Then list **4768** preauth-type-0 events for those accounts.
4. **What can delegate?** Enumerate accounts with `TRUSTED_FOR_DELEGATION`, non-empty `msDS-AllowedToDelegateTo`, or a populated `msDS-AllowedToActOnBehalfOfOtherIdentity`, and confirm each is intended. Join to recent **5136** writes on those attributes to find a newly introduced one.

## Hardening

Shrink the surface so the abuse has nowhere to land. Mappings follow the control framing of the UMBRASEC [identity and access guide](https://umbrasec.dev/guide/identity-and-access.html) and [detection and response guide](https://umbrasec.dev/guide/detection-and-response.html); a cell is blank where no single control maps cleanly.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Restrict and tier who holds replication / write-DACL rights on tier-0 | Removes the DCSync and ACL-abuse path at the source | Restrict administrative privileges (ML2+) | A.8.2 Privileged access rights | PR.AA-05 Least privilege |
| Remove `DONT_REQ_PREAUTH` and set strong, random passwords on any account that must keep it | Kills AS-REP exposure, and makes any captured AS-REP uncrackable | - | A.5.17 Authentication information | PR.AA-01 |
| Eliminate unconstrained delegation; constrain and review the rest; mark tier-0 accounts "sensitive, cannot be delegated" | Removes the delegation impersonation path | Restrict administrative privileges (ML2+) | A.5.16 Identity management; A.8.2 | PR.AA-05 |
| Phishing-resistant MFA on privileged roles | Raises the cost of reaching a position to run these abuses | Multi-factor authentication (ML2+) | A.8.5 Secure authentication | PR.AA-03 |
| Turn on and retain DS Access / DS Changes auditing | Without it, 4662 and 5136 never fire and the rest is blind | ML2/ML3 event-log requirements | A.8.15 Logging | DE.CM Continuous monitoring |

## Honest limitations

DCSync detection depends on a SACL on the domain naming context and on DS Access auditing being on; without it, 4662 is silent and only the network signal remains. A legitimate directory-sync product (Entra Connect) replicates by design and must be allowlisted, which an attacker who compromises that same account can hide behind. AS-REP preauth-type-0 can appear for genuinely preauth-disabled legacy accounts, so the signal is only as clean as your inventory. Delegation and ACL writes done before your baseline will not show as a *change*; the posture hunt in step 1 and step 4, not the event stream, is what finds those. Test every alert in report-only mode and baseline your own tier-0 before enforcing.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1558.004 AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/); [T1003.006 OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/); [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/); [T1550.003 Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/).
- MITRE D3FEND: [Domain Account Monitoring (D3-DAM)](https://d3fend.mitre.org/technique/d3f:DomainAccountMonitoring/); [Strong Password Policy (D3-SPP)](https://d3fend.mitre.org/technique/d3f:StrongPasswordPolicy/) for AS-REP; [Multi-factor Authentication (D3-MFA)](https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication/).
- Public rule sources: SigmaHQ Windows Security rules - [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (`rules/windows/builtin/security/`); Microsoft Defender for Identity alert reference on Microsoft Learn.

**Scope note.** This is a defensive skill. It explains these techniques only to the depth needed to detect and mitigate them, ships no offensive tooling, and provides no steps for performing roasting, DCSync, or delegation abuse. UMBRASEC publishes defense, not offense.
