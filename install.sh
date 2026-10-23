#!/usr/bin/env bash
# umbra-blue installer
# Installs defensive security skills where Claude Code discovers them.
#
# Claude Code loads skills from <skills-dir>/<skill-name>/SKILL.md, one level
# deep, so this script flattens Skills/<category>/<skill>/ into
# <target>/<skill>/. Each installed skill gets a .umbra-blue marker so that
# updates and uninstall only ever touch umbra-blue's own folders.
#
# Usage:
#   ./install.sh                         # all skills into ~/.claude/skills
#   ./install.sh --project               # into ./.claude/skills of the current directory
#   ./install.sh --target DIR            # into an explicit skills directory
#   ./install.sh --category web          # one category only (repeatable)
#   ./install.sh --tier 1                # only Tier 1 (sourced) skills
#   ./install.sh --force                 # overwrite same-named skills not installed by umbra-blue
#   ./install.sh --uninstall             # remove every umbra-blue skill from the target
#   ./install.sh --list                  # list categories and counts
#   ./install.sh --dry-run               # show what would happen

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$SCRIPT_DIR/Skills"
MARKER=".umbra-blue"
TIER2_MARK='**Tier 2 - methodology skill.**'

TARGET="${HOME}/.claude/skills"
CATEGORIES=()
TIER=""
FORCE=0
DRY_RUN=0
UNINSTALL=0
LIST_ONLY=0

usage() {
  sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

list_categories() {
  echo "Available categories:"
  for d in "$SKILLS_DIR"/*/; do
    [ -d "$d" ] || continue
    printf "  %-20s %s skill(s)\n" "$(basename "$d")" "$(find "$d" -name SKILL.md | wc -l | tr -d ' ')"
  done
}

skill_tier() {
  if head -c 3000 "$1" | grep -qF "$TIER2_MARK"; then echo 2; else echo 1; fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --target)    TARGET="$2"; shift 2 ;;
    --project)   TARGET="$PWD/.claude/skills"; shift ;;
    --category)  CATEGORIES+=("$2"); shift 2 ;;
    --tier)      TIER="$2"; shift 2 ;;
    --force)     FORCE=1; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --list)      LIST_ONLY=1; shift ;;
    -h|--help)   usage 0 ;;
    *)           echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

[ -d "$SKILLS_DIR" ] || { echo "Error: Skills directory not found at $SKILLS_DIR" >&2; exit 1; }
if [ "$LIST_ONLY" -eq 1 ]; then list_categories; exit 0; fi
case "$TIER" in ""|1|2) ;; *) echo "Error: --tier must be 1 or 2" >&2; exit 1 ;; esac

if [ "$UNINSTALL" -eq 1 ]; then
  removed=0
  for marker in "$TARGET"/*/"$MARKER"; do
    [ -f "$marker" ] || continue
    dir="$(dirname "$marker")"
    if [ "$DRY_RUN" -eq 1 ]; then echo "[dry-run] would remove $dir"; else rm -rf -- "$dir"; fi
    removed=$((removed + 1))
  done
  echo "Removed $removed umbra-blue skill(s) from $TARGET"
  exit 0
fi

if [ "${#CATEGORIES[@]}" -eq 0 ]; then
  for d in "$SKILLS_DIR"/*/; do [ -d "$d" ] && CATEGORIES+=("$(basename "$d")"); done
fi
for c in "${CATEGORIES[@]}"; do
  [ -d "$SKILLS_DIR/$c" ] || { echo "Error: category '$c' not found." >&2; list_categories >&2; exit 1; }
done

echo "Target: $TARGET"
[ "$DRY_RUN" -eq 1 ] || mkdir -p "$TARGET"

installed=0; updated=0; skipped=0
for c in "${CATEGORIES[@]}"; do
  for skill_dir in "$SKILLS_DIR/$c"/*/; do
    [ -f "$skill_dir/SKILL.md" ] || continue
    name="$(basename "$skill_dir")"
    if [ -n "$TIER" ] && [ "$(skill_tier "$skill_dir/SKILL.md")" != "$TIER" ]; then continue; fi
    dest="$TARGET/$name"
    if [ -e "$dest" ] && [ ! -f "$dest/$MARKER" ] && [ "$FORCE" -eq 0 ]; then
      echo "skip   $name (a skill with this name already exists and was not installed by umbra-blue; use --force)"
      skipped=$((skipped + 1)); continue
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "[dry-run] $name -> $dest"
    else
      [ -e "$dest" ] && { rm -rf -- "$dest"; updated=$((updated + 1)); } || installed=$((installed + 1))
      mkdir -p "$dest"
      cp -R "$skill_dir/." "$dest/"
      echo "$c" > "$dest/$MARKER"
    fi
  done
done

if [ "$DRY_RUN" -eq 1 ]; then exit 0; fi
echo
echo "Installed $installed, updated $updated, skipped $skipped. Claude Code picks them up in new sessions."
