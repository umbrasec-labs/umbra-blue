#!/usr/bin/env python3
"""Validate every umbra-blue skill against the library rules.

Checks:
  - frontmatter has `name` and `description`; name matches its folder and the
    Agent Skills naming rules; description fits the length limit
  - no em-dashes or en-dashes, no stray HTML entities
  - Tier 2 skills carry no rule code blocks and never claim a canonical rule
  - every inlined canonical rule names its sigma-pack file, and, when
    --sigma-pack is given, matches that file byte for byte
  - every relative link resolves
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

from _common import RULE_BLOCK_RE, ROOT, canonical_blocks, iter_skills, load_pairs, normalize, parse_frontmatter, tier_of

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
DESC_MAX = 1024
DASH_RE = re.compile("[\u2013\u2014]")
ENTITY_RE = re.compile(r"&(?:amp|lt|gt|quot|#\d+);")
LINK_RE = re.compile(r"\]\(((?:\.\./|\./)[^)#\s]+)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-pack", type=Path, help="path to a checkout of umbrasec.dev/tools/sigma-pack for byte-identity checks")
    args = ap.parse_args()

    canon: dict[str, str] = {}
    if args.sigma_pack:
        if not args.sigma_pack.is_dir():
            print(f"error: {args.sigma_pack} is not a directory", file=sys.stderr)
            return 2
        for f in list(args.sigma_pack.rglob("*.yml")) + list(args.sigma_pack.rglob("*.kql")):
            canon[f.name] = normalize(f.read_text(encoding="utf-8"))

    errors: list[str] = []
    names: set[str] = set()
    tiers = {1: 0, 2: 0}
    rules_checked = 0

    for category, folder, path, text in iter_skills():
        rel = path.relative_to(ROOT)
        fm = parse_frontmatter(text)
        name, desc = fm.get("name", ""), fm.get("description", "")
        names.add(folder)
        if not fm:
            errors.append(f"{rel}: missing or malformed frontmatter")
        if name != folder:
            errors.append(f"{rel}: name '{name}' does not match folder '{folder}'")
        if not NAME_RE.match(name) or len(name) > 64:
            errors.append(f"{rel}: name must be lowercase letters, digits, and single hyphens, at most 64 characters")
        if not desc.strip():
            errors.append(f"{rel}: empty description")
        elif len(desc) > DESC_MAX:
            errors.append(f"{rel}: description is {len(desc)} characters, limit is {DESC_MAX}")
        if DASH_RE.search(text):
            errors.append(f"{rel}: contains an em-dash or en-dash")
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
            if not (path.parent / link).resolve().exists():
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
