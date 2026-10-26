#!/usr/bin/env python3
"""Generate the umbra-blue index files from Skills/ and tools/pairs.json.

Writes:
  claude-skills.json   machine-readable manifest of every skill
  COVERAGE.md          the claude-red to umbra-blue coverage matrix
  MINDMAP.md           a Mermaid map of the library
  README.md            the badges, category table, and skill index blocks

Usage:
  python3 tools/build_manifest.py           # regenerate
  python3 tools/build_manifest.py --check   # exit 1 if any generated file is stale
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from urllib.parse import quote

from _common import ROOT, iter_skills, load_pairs, parse_frontmatter, tier_of

VERSION = "0.1.0"
HOMEPAGE = "https://github.com/umbrasec-labs/umbra-blue"
# The Blue Team Mapper serves one stable page per skill at <MAPPER>/skills/<name>.
MAPPER = "https://umbrasec-labs.github.io/BlueTeamMapper"


def mapper_url(name: str) -> str:
    return f"{MAPPER}/skills/{quote(name)}"

# Same folder names and order as claude-red, with a defensive title and focus.
CATEGORIES = [
    ("web", "Web Application", "Detection and hardening for the OWASP Top 10 and advanced web vulnerability classes"),
    ("auth", "Auth & Identity", "JWT validation hardening, OAuth and OIDC consent-grant detection"),
    ("active-directory", "Active Directory", "Kerberoasting, AS-REP roasting, DCSync, and ACL abuse detection"),
    ("wireless", "Wireless", "802.11, WPA2/3, EAP, WPS, BLE, Zigbee, Z-Wave, LoRa, and sub-GHz detection and hardening"),
    ("cloud", "Cloud", "Control-plane and IAM attack-path detection across AWS, Azure, and GCP"),
    ("mobile", "Mobile", "Android and iOS application hardening"),
    ("iot", "IoT & Embedded", "Firmware, hardware-interface, RTOS, and ICS/OT hardening"),
    ("infrastructure", "Infrastructure & Endpoint", "Initial access, EDR tampering, injection, and red-team TTP detection, Windows hardening"),
    ("exploit-dev", "Exploit Mitigation", "Memory-safety hardening and exploit-mitigation verification"),
    ("fuzzing", "Fuzzing & Vulnerability Triage", "Fuzzing in the SDLC and bug-class triage"),
    ("recon", "Exposure Management", "External attack surface monitoring and OSINT exposure reduction"),
    ("api", "API Security", "API abuse detection and gateway hardening"),
    ("container", "Container & Kubernetes", "Container-escape detection and cluster hardening"),
    ("cicd", "CI/CD & Pipeline", "Pipeline hardening and secret-exposure detection"),
    ("crypto", "Cryptography", "TLS and cryptographic implementation hardening"),
    ("privesc", "Privilege Escalation", "Linux and Windows privilege-escalation detection"),
    ("post-exploitation", "Post-Exploitation", "Lateral movement, persistence, and exfiltration detection"),
    ("forensics", "Forensics & C2", "Anti-forensics and command-and-control beaconing detection"),
    ("supply-chain", "Supply Chain", "Compromised-package and dependency-confusion detection"),
    ("social-engineering", "Social Engineering", "Phishing detection and human-layer controls"),
    ("network", "Network", "Layer 2 and 3 poisoning and MITM detection"),
    ("ai", "AI Security", "OWASP LLM Top 10 and tool-calling agent defenses"),
    ("utility", "Utility", "Fast defensive triage and evidence-backed reporting"),
]
CAT_TITLE = {c: t for c, t, _ in CATEGORIES}
UPSTREAM = "https://github.com/SnailSploit/claude-red/blob/main/Skills"


def anchor(title: str) -> str:
    return re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")


def collect():
    pairs = load_pairs()
    by_blue = defaultdict(list)
    for p in pairs["pairs"]:
        by_blue[p["blue"]].append(p)
    skills = []
    for category, name, path, text in iter_skills():
        fm = parse_frontmatter(text)
        skills.append({
            "name": fm.get("name", name),
            "category": category,
            "path": str(path.relative_to(ROOT)),
            "tier": tier_of(text),
            "answers": [p["red"] for p in by_blue.get(name, [])],
            "focus": by_blue[name][0]["focus"] if by_blue.get(name) else "",
            "description": fm.get("description", ""),
            "mapper": mapper_url(fm.get("name", name)),
        })
    return pairs, skills


def build_manifest(skills) -> str:
    cats = defaultdict(list)
    for s in skills:
        cats[s["category"]].append(s["name"])
    manifest = {
        "name": "umbra-blue",
        "version": VERSION,
        "license": "MIT",
        "homepage": HOMEPAGE,
        "upstream": "https://github.com/SnailSploit/claude-red",
        "categories": {c: cats[c] for c, _, _ in CATEGORIES if c in cats},
        "skills": [{k: s[k] for k in ("name", "category", "path", "tier", "answers", "description", "mapper")} for s in skills],
        "skill_count": len(skills),
        "category_count": len(cats),
        "tier_counts": {"1": sum(s["tier"] == 1 for s in skills), "2": sum(s["tier"] == 2 for s in skills)},
    }
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def build_coverage(pairs, skills) -> str:
    sk = {s["name"]: s for s in skills}
    n1 = sum(s["tier"] == 1 for s in skills)
    n2 = len(skills) - n1
    upstream = pairs["upstream"]
    total = upstream["skill_count"]
    answered = len({(p["category"], p["red"]) for p in pairs["pairs"]})
    unanswered = upstream.get("unanswered", [])
    covers = f"all {total}" if answered == total else f"{answered} of the {total}"
    out = [
        "# Coverage matrix",
        "",
        "Each skill in [claude-red](https://github.com/SnailSploit/claude-red) that umbra-blue answers, paired to its defensive counterpart. "
        "Each offensive technique implies the detection, hunt, or hardening that counters it, in the spirit of MITRE D3FEND.",
        "",
        "<!-- Generated by tools/build_manifest.py from tools/pairs.json. Do not edit by hand. -->",
        "",
        f"{len(pairs['pairs'])} pairings cover {covers} claude-red skills, "
        f"answered by {len(skills)} umbra-blue skills: {n1} Tier 1 and {n2} Tier 2. "
        "A few red skills map to more than one blue skill, and a few blue skills answer more than one red skill.",
        "",
    ]
    if unanswered:
        out += ["Not answered yet, each needs a new umbra-blue skill:", ""]
        out += [
            f"- [`{u['red']}`]({UPSTREAM}/{u['category']}/{u['red']}/SKILL.md) ({CAT_TITLE[u['category']]}): {u['needs']}"
            for u in unanswered
        ]
        out.append("")
    out += [
        "| Tier | Meaning |",
        "|---|---|",
        "| 1 | Sourced. Built from a published UMBRASEC writeup or tool and cites primary sources. Ships a runnable detection or hunt; any rule is reused byte for byte from the UMBRASEC sigma-pack. |",
        "| 2 | Methodology. Gives the defender's method, log sources, hunt, and hardening, and points to public rule sources. Carries a banner saying no bespoke UMBRASEC rule ships yet. Never fabricates a rule or a citation. |",
        "",
        "A Tier 2 skill is promoted to Tier 1 when its UMBRASEC writeup and tuned rule land.",
        "",
        f"The Mapper column opens each skill's page in the [Blue Team Mapper]({MAPPER}/). "
        "It shows the skill's ATT&CK techniques and any UMBRASEC rules for them. "
        "Where those techniques are in the mapper matrix, it also shows the matrix rows, "
        "the response flow chains they lead to, and your own coverage rating.",
        "",
    ]
    by_cat = defaultdict(list)
    for p in pairs["pairs"]:
        by_cat[p["category"]].append(p)
    for c, title, _ in CATEGORIES:
        if c not in by_cat:
            continue
        out += [f"## {title}", "", "| claude-red | umbra-blue | Defensive focus | Tier | Mapper |", "|---|---|---|---|---|"]
        for p in by_cat[c]:
            s = sk[p["blue"]]
            out.append(
                f"| [`{p['red']}`]({UPSTREAM}/{p['category']}/{p['red']}/SKILL.md) | [`{s['name']}`]({s['path']}) "
                f"| {p['focus']} | {s['tier']} | [map]({s['mapper']}) |"
            )
        out.append("")
    return "\n".join(out)


# Domains group the categories in MINDMAP.md; every category in CATEGORIES must sit in one.
DOMAINS = [
    ("Application", ["web", "api", "auth", "ai"]),
    ("Identity & Infrastructure", ["active-directory", "infrastructure", "network", "privesc", "post-exploitation", "forensics"]),
    ("Cloud & Delivery", ["cloud", "container", "cicd", "supply-chain"]),
    ("Devices & Radio", ["wireless", "mobile", "iot"]),
    ("Exploit Engineering", ["exploit-dev", "fuzzing", "crypto"]),
    ("Exposure & People", ["recon", "social-engineering"]),
    ("Utility", ["utility"]),
]
MINDMAP_THEME = """%%{init: {"theme": "base", "themeVariables": {
  "fontFamily": "ui-monospace, SFMono-Regular, Menlo, monospace",
  "fontSize": "14px",
  "cScale0": "#1f2937", "cScaleLabel0": "#f9fafb",
  "cScale1": "#1d4ed8", "cScaleLabel1": "#ffffff",
  "cScale2": "#0f766e", "cScaleLabel2": "#ffffff",
  "cScale3": "#7c3aed", "cScaleLabel3": "#ffffff",
  "cScale4": "#b45309", "cScaleLabel4": "#ffffff",
  "cScale5": "#be123c", "cScaleLabel5": "#ffffff",
  "cScale6": "#4d7c0f", "cScaleLabel6": "#ffffff",
  "cScale7": "#0369a1", "cScaleLabel7": "#ffffff"
}}}%%"""


def build_mindmap(skills) -> str:
    cats = defaultdict(list)
    for s in skills:
        cats[s["category"]].append(s)
    placed = [c for _, cs in DOMAINS for c in cs]
    missing = [c for c in cats if c not in placed]
    if missing:
        raise SystemExit(f"categories missing from DOMAINS: {', '.join(missing)}")
    title = {c: CAT_TITLE[c].replace("&", "and") for c in CAT_TITLE}
    ordered = {c: sorted(cats[c], key=lambda x: (x["tier"], x["name"])) for c in cats}
    domains = [(d, [c for c in cs if c in cats]) for d, cs in DOMAINS]
    domains = [(d, cs) for d, cs in domains if cs]
    n1 = sum(s["tier"] == 1 for s in skills)
    star = lambda s: "\u2605 " if s["tier"] == 1 else ""
    nav = " \u00b7 ".join(["[Full map](#full-map)", "[Tier 1](#tier-1)"] + [f"[{d}](#{anchor(d)})" for d, _ in domains])
    out = [
        "# umbra-blue \u00b7 Library Mindmap",
        "",
        "Every skill in the library, grouped by domain and category. **\u2605** marks Tier 1 skills.",
        "",
        "<!-- Generated by tools/build_manifest.py. Do not edit by hand. -->",
        "",
        f"**{len(skills)} skills** \u00b7 **{len(cats)} categories** \u00b7 **{n1} Tier 1**",
        "",
        nav,
        "",
        "## Full map",
        "",
        "Hexagons are domains, rounded nodes are categories, leaves are skills. \u2605 marks Tier 1.",
        "",
        "```mermaid",
        MINDMAP_THEME,
        "mindmap",
        f"  root((**umbra-blue**<br/>{len(skills)} skills \u00b7 {len(cats)} categories))",
    ]
    for d, cs in domains:
        out.append(f"    {{{{{d}}}}}")
        for c in cs:
            out.append(f"      ({title[c]} \u00b7 {len(cats[c])})")
            out += [f"        {star(s)}{s['name']}" for s in ordered[c]]
    out += ["```", "", "## Tier 1", "", "| Skill | Category |", "| --- | --- |"]
    out += [f"| `{s['name']}` | {title[c]} |" for _, cs in domains for c in cs for s in ordered[c] if s["tier"] == 1]
    for d, cs in domains:
        out += ["", f"## {d}", "", "| Category | # | Skills |", "| --- | ---: | --- |"]
        for c in cs:
            names = " \u00b7 ".join(f"{star(s)}`{s['name']}`" for s in ordered[c])
            out.append(f"| **{title[c]}** | {len(cats[c])} | {names} |")
    out.append("")
    return "\n".join(out)


def replace_block(text: str, key: str, body: str) -> str:
    pattern = re.compile(rf"<!-- {key}:start -->.*?<!-- {key}:end -->", re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(f"README.md is missing the {key} markers")
    return pattern.sub(lambda m: f"<!-- {key}:start -->\n{body}\n<!-- {key}:end -->", text)


def build_readme(readme: str, skills) -> str:
    cats = defaultdict(list)
    for s in skills:
        cats[s["category"]].append(s)
    n1 = sum(s["tier"] == 1 for s in skills)
    badges = (
        "[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)\n"
        f"[![Skills](https://img.shields.io/badge/skills-{len(skills)}-1d4ed8.svg)](#skill-index)\n"
        f"[![Categories](https://img.shields.io/badge/categories-{len(cats)}-0f172a.svg)](#categories)\n"
        f"[![Tier 1](https://img.shields.io/badge/tier_1-{n1}-38bdf8.svg)](#two-tiers)\n"
        f"[![Tier 2](https://img.shields.io/badge/tier_2-{len(skills) - n1}-64748b.svg)](#two-tiers)\n"
        "[![Stars](https://img.shields.io/github/stars/umbrasec-labs/umbra-blue?style=social)](https://github.com/umbrasec-labs/umbra-blue)"
    )
    table = ["| Category | Skills | Tier 1 | Focus |", "|---|---:|---:|---|"]
    for c, title, focus in CATEGORIES:
        if c in cats:
            table.append(f"| [{title}](#{anchor(title)}) | {len(cats[c])} | {sum(s['tier'] == 1 for s in cats[c])} | {focus} |")
    index = []
    for c, title, _ in CATEGORIES:
        if c not in cats:
            continue
        index += [f"### {title}", "", f"`Skills/{c}/`", "", "| Skill | Tier | Answers claude-red | Defensive focus | Mapper |", "|---|:-:|---|---|:-:|"]
        for s in sorted(cats[c], key=lambda x: (x["tier"], x["name"])):
            ans = ", ".join(f"`{a}`" for a in s["answers"]) or "-"
            index.append(f"| [`{s['name']}`]({s['path']}) | {s['tier']} | {ans} | {s['focus']} | [map]({s['mapper']}) |")
        index.append("")
    readme = replace_block(readme, "badges", badges)
    readme = replace_block(readme, "categories", "\n".join(table))
    readme = replace_block(readme, "skill-index", "\n".join(index).rstrip())
    return readme


def main() -> int:
    check = "--check" in sys.argv[1:]
    pairs, skills = collect()
    readme_path = ROOT / "README.md"
    outputs = {
        ROOT / "claude-skills.json": build_manifest(skills),
        ROOT / "COVERAGE.md": build_coverage(pairs, skills),
        ROOT / "MINDMAP.md": build_mindmap(skills),
        readme_path: build_readme(readme_path.read_text(encoding="utf-8"), skills),
    }
    stale = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != content:
            stale.append(path.name)
            if not check:
                path.write_text(content, encoding="utf-8")
    if check:
        if stale:
            print("Stale generated files: " + ", ".join(stale) + ". Run: python3 tools/build_manifest.py", file=sys.stderr)
            return 1
        print(f"Generated files are current ({len(skills)} skills).")
        return 0
    print(f"Built index for {len(skills)} skills across {len({s['category'] for s in skills})} categories. Updated: {', '.join(stale) or 'nothing'}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
