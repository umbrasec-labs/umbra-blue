# Security Policy

`umbra-blue` is a defensive security library. Its skills describe how to detect, hunt, and mitigate attack techniques, and ship no exploit code or offensive tooling.

## Intended Use

These skills are intended for:

- Security operations, alert triage, and incident response
- Detection engineering and threat hunting
- Hardening reviews and control assessments
- Purple team exercises and defender training

Detections and hunts should be tested in report-only mode and baselined against your own environment before enforcement. Treat every hit as a lead to triage, not a verdict.

## Reporting a Vulnerability in umbra-blue Itself

If you find a security issue in this repository, such as offensive content that slipped in, a credential or personal data in an example, an unsafe default in `install.sh`, or a detection that could be abused to blind defenders, please report it privately rather than opening a public issue.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Please include the affected file and commit, a description of the issue and its impact, and a suggested fix if you have one. Reports are acknowledged as quickly as possible and confirmed issues are fixed promptly.

## Reporting a Detection That Misbehaves

A rule that is noisy, misses its target, or cites the wrong source is a correctness bug, not a security issue. [Open an issue](https://github.com/umbrasec-labs/umbra-blue/issues). Fixes to Tier 1 rule logic land in the [UMBRASEC sigma-pack](https://umbrasec.dev/tools/sigma-pack/) first and are then synced here.

## Supply Chain Integrity

Install from the upstream repository at `github.com/umbrasec-labs/umbra-blue`. Skills are plain Markdown, and `install.sh` only copies files into your skills directory. Read it before running it. If you receive an umbra-blue archive from a third party, verify it against the upstream repository first.

## Scope

| In scope | Out of scope |
|---|---|
| Repository content: skills, tooling, install logic | Vulnerabilities in third-party products named in skills |
| Offensive content or unsafe instructions in a skill | The Claude platform itself (report to Anthropic) |
| Credentials or personal data in examples | Issues in your own deployment of a detection |
| Unsafe installer behavior | Findings made using these skills; follow the vendor's disclosure process |

## Acknowledgements

Researchers who report issues responsibly are credited in the [CHANGELOG](CHANGELOG.md). Say if you would prefer to remain anonymous.
