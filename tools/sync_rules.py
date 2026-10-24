#!/usr/bin/env python3
"""Re-sync every inlined canonical rule from a sigma-pack checkout.

Tier 1 skills inline UMBRASEC sigma-pack rules byte for byte. When a rule
changes upstream, run this to refresh every copy, then run validate.py.

Usage:
  python3 tools/sync_rules.py --sigma-pack ../umbrasec.dev/tools/sigma-pack
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _common import RULE_BLOCK_RE, ROOT, CANONICAL_MARK, iter_skills, rule_files

import re


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-pack", type=Path, required=True)
    args = ap.parse_args()
    files: dict[str, Path] = {}
    for f in rule_files(args.sigma_pack):
        if f.name in files:
            print(f"error: {f.name} appears more than once in {args.sigma_pack}; skills could not tell the copies apart", file=sys.stderr)
            return 2
        files[f.name] = f
    if not files:
        print(f"error: no rules found under {args.sigma_pack}", file=sys.stderr)
        return 2

    changed, missing = 0, []
    for _, _, path, text in iter_skills():
        def refresh(m: re.Match) -> str:
            nonlocal changed
            lines = m.group(2).splitlines()
            if not lines or CANONICAL_MARK not in lines[0]:
                return m.group(0)
            fn = re.search(r"([\w.-]+\.(?:yml|yaml|kql))", lines[0])
            if not fn or fn.group(1) not in files:
                missing.append(f"{path.relative_to(ROOT)}: {lines[0][:60]}")
                return m.group(0)
            body = lines[0] + "\n" + files[fn.group(1)].read_text(encoding="utf-8").rstrip("\n") + "\n"
            if body != m.group(2):
                changed += 1
            return f"```{m.group(1)}\n{body}```"

        new = RULE_BLOCK_RE.sub(refresh, text)
        if new != text:
            path.write_text(new, encoding="utf-8")

    for m in missing:
        print(f"not found in sigma-pack: {m}", file=sys.stderr)
    print(f"Refreshed {changed} inlined rule(s).")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
