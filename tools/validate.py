#!/usr/bin/env python3
"""Validate every umbra-blue skill against the library rules.

Checks:
  - every skill is a Skills/<category>/<skill>/SKILL.md, and no skill name is
    used in two categories (install.sh flattens categories into one folder)
  - frontmatter has exactly `name` and `description`; name matches its folder
    and the Agent Skills naming rules and has no reserved word; description is
    not empty, fits the length limit and has no angle brackets
  - no em-dashes or en-dashes in any file a skill ships, no stray HTML entities
  - Tier 2 skills carry no rule code blocks and never claim a canonical rule
  - every inlined canonical rule names its sigma-pack file, and, when
    --sigma-pack is given, matches that file byte for byte
  - every relative link resolves to a file inside the repository
  - every skill appears in tools/pairs.json and every pair points at a real skill

Usage:
  python3 tools/validate.py
  python3 tools/validate.py --sigma-pack ../umbrasec.dev/tools/sigma-pack
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from _common import RULE_BLOCK_RE, ROOT, SKILLS_DIR, canonical_blocks, iter_skills, load_pairs, normalize, parse_frontmatter, rule_files, tier_of

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
RESERVED_WORDS = ("claude", "anthropic")
FRONTMATTER_KEYS = {"name", "description"}
DESC_MAX = 1024
DASH_RE = re.compile("[\u2013\u2014]")
ENTITY_RE = re.compile(r"&(?:amp|lt|gt|quot|#\d+);")
LINK_RE = re.compile(r"\]\(([^)\s]+)")
# URLs (https:, mailto:) and in-page anchors are not files to check.
NOT_A_FILE_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|#)", re.IGNORECASE)


def layout_errors() -> list[str]:
    """Skill folders the tools would silently skip: no SKILL.md, or a SKILL.md at the wrong depth."""
    errors = []
    for skill_md in sorted(SKILLS_DIR.rglob("SKILL.md")):
        if len(skill_md.relative_to(SKILLS_DIR).parts) != 3:
            errors.append(f"{skill_md.relative_to(ROOT)}: not at Skills/<category>/<skill>/SKILL.md")
    # Same folders install.sh visits: directories only, dot-folders skipped (glob("*/*/") also
    # returns files before Python 3.11, such as a Finder .DS_Store).
    for folder in sorted(p for p in SKILLS_DIR.glob("*/*") if p.is_dir() and not p.name.startswith(".")):
        if not (folder / "SKILL.md").is_file():
            errors.append(f"{folder.relative_to(ROOT)}: skill folder has no SKILL.md")
    return errors


def bundled_file_errors(skill_dir: Path) -> list[str]:
    """install.sh copies the whole skill folder, so the dash rule covers every text file in it."""
    errors = []
    for f in sorted(skill_dir.rglob("*")):
        if not f.is_file() or f.name == "SKILL.md":
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if DASH_RE.search(text):
            errors.append(f"{f.relative_to(ROOT)}: contains an em-dash or en-dash")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-pack", type=Path, help="path to a checkout of umbrasec.dev/tools/sigma-pack for byte-identity checks")
    args = ap.parse_args()

    errors: list[str] = layout_errors()
    canon: dict[str, str] = {}
    if args.sigma_pack:
        if not args.sigma_pack.is_dir():
            print(f"error: {args.sigma_pack} is not a directory", file=sys.stderr)
            return 2
        # Skills name a rule by file name only, so two rules with one name would be ambiguous.
        for f in rule_files(args.sigma_pack):
            if f.name in canon:
                errors.append(f"sigma-pack: {f.name} appears more than once; skills could not tell the copies apart")
            canon[f.name] = normalize(f.read_text(encoding="utf-8"))

    names: set[str] = set()
    category_of: dict[str, str] = {}
    tiers = {1: 0, 2: 0}
    rules_checked = 0

    for category, folder, path, text in iter_skills():
        rel = path.relative_to(ROOT)
        fm = parse_frontmatter(text)
        name, desc = fm.get("name", ""), fm.get("description", "")
        names.add(folder)
        if folder in category_of:
            errors.append(
                f"{rel}: skill name '{folder}' is used in more than one category "
                f"({category_of[folder]}, {category}); install.sh would install only one"
            )
        category_of.setdefault(folder, category)
        if not fm:
            errors.append(f"{rel}: missing or malformed frontmatter")
        for key in sorted(set(fm) - FRONTMATTER_KEYS):
            errors.append(f"{rel}: frontmatter key '{key}' is not allowed; use only name and description")
        if name != folder:
            errors.append(f"{rel}: name '{name}' does not match folder '{folder}'")
        if not NAME_RE.match(name) or len(name) > 64:
            errors.append(f"{rel}: name must be lowercase letters, digits, and single hyphens, at most 64 characters")
        for word in RESERVED_WORDS:
            if word in name:
                errors.append(f"{rel}: name contains the reserved word '{word}'")
        if not desc.strip():
            errors.append(f"{rel}: empty description")
        elif len(desc) > DESC_MAX:
            errors.append(f"{rel}: description is {len(desc)} characters, limit is {DESC_MAX}")
        if re.search(r"[<>]", desc):
            errors.append(f"{rel}: description contains angle brackets")
        if DASH_RE.search(text):
            errors.append(f"{rel}: contains an em-dash or en-dash")
        errors.extend(bundled_file_errors(path.parent))
        if ENTITY_RE.search(text):
            errors.append(f"{rel}: contains an HTML entity")

        tier = tier_of(text)
        tiers[tier] += 1
        blocks = list(canonical_blocks(text))
        if tier == 2:
            if RULE_BLOCK_RE.search(text):
                errors.append(f"{rel}: Tier 2 skill contains a rule code block")
            if blocks:
                errors.append(f"{rel}: Tier 2 skill claims a canonical rule")
        for fn, header, body, _ in blocks:
            if not fn:
                errors.append(f"{rel}: canonical rule header names no file: {header[:60]}")
                continue
            if canon:
                rules_checked += 1
                if fn not in canon:
                    errors.append(f"{rel}: canonical rule {fn} not found in sigma-pack")
                elif normalize(body) != canon[fn]:
                    errors.append(f"{rel}: inlined {fn} differs from sigma-pack; run tools/sync_rules.py")

        for link in LINK_RE.findall(text):
            if NOT_A_FILE_RE.match(link):
                continue
            target = link.split("#", 1)[0]
            resolved = (path.parent / target).resolve()
            if not resolved.is_relative_to(ROOT):
                errors.append(f"{rel}: relative link {link} points outside the repository")
            elif not resolved.exists():
                errors.append(f"{rel}: broken relative link {link}")

    pairs = load_pairs()["pairs"]
    paired = {p["blue"] for p in pairs}
    for missing in sorted(names - paired):
        errors.append(f"tools/pairs.json: skill '{missing}' has no claude-red pairing")
    for ghost in sorted(paired - names):
        errors.append(f"tools/pairs.json: pairing points at missing skill '{ghost}'")

    for e in errors:
        print(e, file=sys.stderr)
    summary = f"{len(names)} skills ({tiers[1]} Tier 1, {tiers[2]} Tier 2)"
    if canon:
        summary += f", {rules_checked} inlined rules checked against sigma-pack"
    if errors:
        print(f"FAIL: {len(errors)} problem(s) across {summary}.", file=sys.stderr)
        return 1
    print(f"OK: {summary}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
