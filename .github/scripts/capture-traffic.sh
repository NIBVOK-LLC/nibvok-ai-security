#!/usr/bin/env bash
#
# Capture GitHub traffic into permanent CSV history.
#
# GitHub retains traffic data for only 14 days. An uncaptured day is gone for
# good, which is the entire reason this runs daily.
#
# WHY IT READS THE PER-DAY ARRAY, NOT THE TOTALS
# /traffic/views and /traffic/clones return a rolling 14-day window: the
# top-level `.count` and `.uniques` are PERIOD TOTALS, not today's numbers.
# Recording those once a day would build a history of overlapping rolling
# windows — every row quietly restating the last 14 days, so a one-day spike
# would appear to have lasted a fortnight. The true per-day breakdown is in the
# `.views[]` / `.clones[]` arrays, so this reads those and merges by date.
#
# A useful side effect: the merge is self-healing. If a run is missed, the next
# one backfills the gap from the array — as long as it happens within 14 days.
# Past 14 days the data is gone and the gap is permanent.
#
# Required env: GH_TOKEN, GITHUB_REPOSITORY   (skipped with TRAFFIC_SKIP_FETCH=1)
set -euo pipefail

RAW_DIR="traffic/raw"
mkdir -p "$RAW_DIR" traffic

api() {
  curl -sSf \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/traffic/$1"
}

# TRAFFIC_SKIP_FETCH=1 runs the merge against files already in $RAW_DIR with no
# network. That seam exists so the merge can be tested offline against fixtures:
# a merge only ever exercised by a live daily cron is one nobody has seen work.
if [ "${TRAFFIC_SKIP_FETCH:-0}" = "1" ]; then
  echo "== TRAFFIC_SKIP_FETCH=1 — using existing raw files in ${RAW_DIR} =="
else
  : "${GH_TOKEN:?GH_TOKEN is required}"
  : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
  echo "== Fetching traffic for ${GITHUB_REPOSITORY} =="
  api views             > "${RAW_DIR}/views.json"
  api clones            > "${RAW_DIR}/clones.json"
  api popular/referrers > "${RAW_DIR}/referrers.json"
  api popular/paths     > "${RAW_DIR}/paths.json"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Merge rows keyed on the date in column 1.
#   $1 = history file   $2 = header line   stdin = candidate rows
# Existing dates are dropped, so re-running is idempotent and a backfill adds
# only what is missing. Writes to a temp file then moves it — never reads and
# appends the same path at once.
merge_by_date() {
  local hist="$1" header="$2" newrows tmp
  newrows="$(mktemp)"
  cat > "$newrows"

  [ -f "$hist" ] || printf '%s\n' "$header" > "$hist"

  tmp="$(mktemp)"
  {
    cat "$hist"
    sort -u -t, -k1,1 "$newrows" \
      | awk -F, 'NR==FNR { seen[$1]=1; next } !($1 in seen)' "$hist" -
  } > "$tmp"
  mv "$tmp" "$hist"
  rm -f "$newrows"
}

# Referrers and paths have no daily breakdown, so they are dated SNAPSHOTS: a
# re-run on the same day replaces that day's rows instead of duplicating them.
snapshot() { # $1 = rows, $2 = history, $3 = header
  local rows="$1" hist="$2" header="$3" keep tmp
  keep="$(mktemp)"; tmp="$(mktemp)"

  if [ -f "$hist" ]; then
    grep -v "^\"${TODAY}\"" "$hist" > "$keep" || true
  else
    printf '%s\n' "$header" > "$keep"
  fi

  { cat "$keep"; cat "$rows"; } > "$tmp"
  mv "$tmp" "$hist"
  rm -f "$keep" "$rows"
}

TODAY="$(date -u +%F)"
ROWS="$(mktemp -d)"
trap 'rm -rf "$ROWS"' EXIT

node "${HERE}/traffic-rows.mjs" views  "${RAW_DIR}/views.json" \
  | merge_by_date traffic/views.csv "date,views,views_uniques"

node "${HERE}/traffic-rows.mjs" clones "${RAW_DIR}/clones.json" \
  | merge_by_date traffic/clones.csv "date,clones,clones_uniques"

node "${HERE}/traffic-rows.mjs" referrers "${RAW_DIR}/referrers.json" "$TODAY" \
  > "${ROWS}/referrers"
snapshot "${ROWS}/referrers" traffic/referrers.csv "date,referrer,count,uniques"

node "${HERE}/traffic-rows.mjs" paths "${RAW_DIR}/paths.json" "$TODAY" \
  > "${ROWS}/paths"
snapshot "${ROWS}/paths" traffic/paths.csv "date,path,count,uniques"

echo "== Traffic captured =="
for f in traffic/views.csv traffic/clones.csv traffic/referrers.csv traffic/paths.csv; do
  printf '  %-24s %s rows\n' "$f" "$(( $(wc -l < "$f") - 1 ))"
done
