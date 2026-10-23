"""Shared helpers for the umbra-blue tooling. Standard library only."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "Skills"
PAIRS_FILE = ROOT / "tools" / "pairs.json"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
TIER2_MARKER = "**Tier 2 - methodology skill.**"
RULE_BLOCK_RE = re.compile(r"```(yaml|yml|kql|kusto)\n(.*?)```", re.DOTALL)
CANONICAL_MARK = "canonical copy"


def parse_frontmatter(text: str) -> dict[str, str]:
    """Parse the simple `key: value` frontmatter used by every skill.

    Values may be double-quoted. Uses PyYAML when available for full fidelity.
    """
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    block = m.group(1)
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(block)
        return {str(k): str(v) for k, v in (data or {}).items()}
    except ImportError:
        pass
    out: dict[str, str] = {}
    for line in block.splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            key, _, val = line.partition(":")
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] == '"':
                val = val[1:-1]
            out[key.strip()] = val
    return out


def tier_of(text: str) -> int:
    """Tier 2 skills carry the methodology banner near the top; all others are Tier 1."""
    return 2 if TIER2_MARKER in text[:3000] else 1


def iter_skills():
    """Yield (category, name, path, text) for every Skills/<category>/<name>/SKILL.md."""
    for skill_md in sorted(SKILLS_DIR.glob("*/*/SKILL.md")):
        yield skill_md.parent.parent.name, skill_md.parent.name, skill_md, skill_md.read_text(encoding="utf-8")


def load_pairs() -> dict:
    return json.loads(PAIRS_FILE.read_text(encoding="utf-8"))


def normalize(text: str) -> str:
    """Normalize for byte-identity comparison: strip trailing whitespace per line and outer blank lines."""
    return "\n".join(line.rstrip() for line in text.strip("\n").splitlines())


def canonical_blocks(text: str):
    """Yield (filename, header_line, body, match) for each inlined canonical sigma-pack rule."""
    for m in RULE_BLOCK_RE.finditer(text):
        lines = m.group(2).splitlines()
        if lines and CANONICAL_MARK in lines[0]:
            fn = re.search(r"([\w.-]+\.(?:yml|yaml|kql))", lines[0])
            yield (fn.group(1) if fn else None), lines[0], "\n".join(lines[1:]), m
