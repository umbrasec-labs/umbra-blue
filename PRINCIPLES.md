# umbra-blue principles

Every skill in this library follows these rules. The validator enforces the ones that can be checked automatically; the rest are review gates.

## Two tiers

umbra-blue mirrors every claude-red skill, so it ships in two clearly labeled tiers. The tier is visible in each skill before a reader trusts it.

- **Tier 1, sourced.** Derived from a published UMBRASEC writeup or tool, ships a runnable detection or hunt inline (any rule is reused from the UMBRASEC sigma-pack byte for byte), and ties every claim to a primary source. Rules 1 to 9 below apply in full.
- **Tier 2, methodology.** Gives the defender's method, the log sources and signals, the hunt, and the hardening, but ships **no** bespoke rule. It says so in a banner at the top, points to public rule sources such as SigmaHQ by URL, and never fabricates a rule or claims UMBRASEC authored one. A Tier 2 skill is promoted to Tier 1 when its writeup and rule land; [COVERAGE.md](COVERAGE.md) tracks that.

The one rule no tier may break: never invent a rule or a citation. Tier 2 is honest about the absence of a bespoke rule; it does not hide it.

1. **Defensive only.** Explain a technique only to the depth a defender needs to detect and mitigate it. No offensive tooling, no exploit code, no cracking or evasion instructions.

2. **Ship the artifact, not just the method.** Each skill carries at least one runnable detection or hunt inline - a Sigma rule, a KQL/SPL query, a YARA rule, or an explicit hunt procedure. A skill that only describes how to write detections does not belong here.

3. **Tie every claim to a primary source.** Vendor advisories, CVE records, MITRE ATT&CK, RFCs, or first-party incident data. No unsourced assertions. List sources at the foot of the skill.

4. **Derive from a published writeup.** Each skill names the UMBRASEC research writeup it comes from. If there is no writeup yet, write the research first. The `articles.json` slug it cites must exist.

5. **Map precisely.** Give the MITRE ATT&CK technique ID, the required log source, and the specific event IDs or fields the detection keys off. Vague "monitor for suspicious activity" is not a mapping.

6. **Always include tuning and false positives.** State the baseline behaviour, the knobs to turn, and what benign activity will trip the rule. A detection with no false-positive profile is not finished.

7. **State confidence, end with the defender's call.** Lay out the evidence and what it does and does not prove. Advise; do not tell the reader the verdict is certain or that an automated action should fire unattended.

8. **Align to frameworks where it helps.** For hardening and governance skills, map recommendations to the ASD Essential Eight, ISO 27001:2022, and NIST CSF 2.0.

9. **Be honest about limits.** Every detection has blind spots. Name them. A low-and-slow attacker, a legitimate RC4 account, a log source you may not have - say so.
