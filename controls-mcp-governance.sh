#!/usr/bin/env bash
# Negative controls for the MCP-governance change (classifier + hook suites).
#
# A check that cannot fail is not a check. Each control reintroduces ONE specific
# defect into a FRESH copy of the plugin, re-runs the suites against it, and
# asserts the suite goes RED. The unmutated tree must be green first.
#
# HARNESS RULES (each learned the hard way in this project):
#   * A FRESH COPY per control. Reusing one copy let a mutated file survive a
#     restore and produced a verdict about source that no longer existed.
#   * Every mutation asserts it actually applied before its verdict is believed.
#     A sed that matched nothing would "pass" by not mutating anything.
#   * The copy must resolve `openclaw`. A plugin test that dies on
#     MODULE_NOT_FOUND is a broken harness, not a control — hence the symlink.
#   * Old/new text is passed as SEPARATE ARGUMENTS, never joined by a sentinel.
#     An earlier version used a NUL separator and bash silently dropped the NUL,
#     so every mutation reported "anchor missing" — a harness bug wearing the
#     costume of six correct refusals.
#
# Run: bash controls-mcp-governance.sh
set -uo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
OPENCLAW_PKG="$SRC/node_modules/openclaw"
LOGDIR="$(mktemp -d /tmp/ox88_mcp_controls.XXXXXX)"
KEEP="${KEEP:-}"
cleanup() { [ -n "$KEEP" ] || rm -rf "$LOGDIR"; }
trap cleanup EXIT

pass=0; fail=0
verdict() { # name expected(red|green) suite_rc
  local name="$1" want="$2" rc="$3"
  local got; [ "$rc" -eq 0 ] && got=green || got=red
  if [ "$got" = "$want" ]; then
    pass=$((pass+1)); printf '  PASS  %s -> %s\n' "$name" "$got"
  else
    fail=$((fail+1)); printf '  FAIL  %s -> %s (expected %s)\n' "$name" "$got" "$want"
  fi
}

fresh_copy() {
  local t; t="$(mktemp -d /tmp/ox88_mcp_tree.XXXXXX)"
  # Copy EVERY local module, not a hand-picked list. The published tree's
  # classifier imports ./policies.js and its index imports ./audit-chain.js; a
  # copy missing one dies on MODULE_NOT_FOUND, which is a broken harness wearing
  # the costume of a passing control (both baselines go red for the wrong reason).
  cp -a "$SRC"/*.js "$SRC"/*.mjs "$t/" 2>/dev/null
  mkdir -p "$t/node_modules"
  ln -s "$OPENCLAW_PKG" "$t/node_modules/openclaw"
  printf '%s' "$t"
}

# Mutate a file; refuse loudly if the anchor is absent or ambiguous. A no-op
# mutation is not a control.
mutate() { # file  old  new
  python3 - "$1" "$2" "$3" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1]); src = p.read_text(); old, new = sys.argv[2], sys.argv[3]
n = src.count(old)
if n != 1:
    print(f"ANCHOR NOT UNIQUE ({n})", file=sys.stderr); sys.exit(2)
p.write_text(src.replace(old, new))
PY
}

run_suite() { # dir  suitefile  logfile
  ( cd "$1" && node "$2" ) >"$3" 2>&1; return $?
}

echo "=== BASELINE (unmutated copy must be GREEN) ==="
T="$(fresh_copy)"
run_suite "$T" test-classifier.mjs "$LOGDIR/base_c.log"; verdict "baseline classifier" green $?
run_suite "$T" test-hook.mjs       "$LOGDIR/base_h.log"; verdict "baseline hook"       green $?
tail -1 "$LOGDIR/base_c.log"; tail -1 "$LOGDIR/base_h.log"
rm -rf "$T"

# Each control: mutate ONE thing, assert RED.
control() { # letter label file old new suite suitefile
  local letter="$1" label="$2" file="$3" old="$4" new="$5" suite="$6" sfile="$7"
  local T; T="$(fresh_copy)"
  if mutate "$T/$file" "$old" "$new"; then
    run_suite "$T" "$sfile" "$LOGDIR/$letter.log"; local rc=$?
    verdict "$letter: $label" red "$rc"
    sed -n '1,3p' "$LOGDIR/$letter.log" | sed 's/^/        /'
  else
    printf '  ERROR  %s: anchor missing/ambiguous in %s\n' "$letter" "$file"
    fail=$((fail+1))
  fi
  rm -rf "$T"
}

echo
echo "=== CONTROLS (each must go RED) ==="

# A — re-introduce the matcher. THE original defect: MCP tool names are not in
# the list, so the handler never runs for them at all.
control A "matcher restored (MCP never reaches handler)" index.js \
  '        priority: 50,' \
  '        matcher: ["exec"],
        priority: 50,' \
  hook test-hook.mjs

# B — make an unclassifiable MCP call ALLOW instead of CONFIRM (fail-open).
control B "unknown MCP tool allows (fail open)" classifier.js \
  'return { action: CONFIRM, reason: `MCP tool ${toolName} has no path-shaped argument${serverNote}` };' \
  'return { action: ALLOW, reason: `MCP tool ${toolName} has no path-shaped argument${serverNote}` };' \
  classifier test-classifier.mjs

# C — break the name parse so MCP names are never recognised. Reproduces the
# original gap end to end: MCP calls fall through to the core-tool allow.
control C "MCP names unrecognised (fall through to allow)" classifier.js \
  '  if (i < 0) return null;' \
  '  if (i < 0 || true) return null;' \
  classifier test-classifier.mjs

# D — make the MCP class session-trustable (a blanket grant on an unknown
# third-party capability).
control D "mcp-unknown made session-trustable" classifier.js \
  '  "confirm-read",' \
  '  "confirm-read",
  "mcp-unknown",' \
  classifier test-classifier.mjs

# E — treat every server as configured, so an unrecognised server earns a silent
# allow on a permitted path.
control E "unrecognised server treated as configured" classifier.js \
  '  const serverKnown = known.has(String(parts.serverHalf).toLowerCase());' \
  '  const serverKnown = true;' \
  classifier test-classifier.mjs

# F — drop the MCP prompt fix, so the approval description renders a blank
# "Command: " and the operator approves something illegible.
control F "MCP prompt names nothing (blank command)" index.js \
  '        const isMcp = !!splitMcpToolName(event.toolName);' \
  '        const isMcp = false;' \
  hook test-hook.mjs

echo
if [ "$fail" -eq 0 ] && [ "$pass" -ge 8 ]; then
  echo "CONTROLS ALL CORRECT (baseline green, A-F red)"
  exit 0
fi
echo "CONTROLS NOT CORRECT: $pass correct, $fail wrong"
exit 1
