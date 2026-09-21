#!/usr/bin/env node
//
// Emit CSV rows from a GitHub traffic payload, for capture-traffic.sh.
//
// Node rather than jq deliberately: jq is present on the runner, but node is
// present BOTH on the runner and on the machine where this was written — so the
// merge can be exercised locally against fixtures instead of first running for
// real in a daily cron nobody is watching.
//
// Payload shapes (GitHub REST, api-version 2022-11-28):
//
//   views.json      { count, uniques, views:  [{ timestamp, count, uniques }] }
//   clones.json     { count, uniques, clones: [{ timestamp, count, uniques }] }
//   referrers.json  [ { referrer, count, uniques } ]   <- 14-day SNAPSHOT
//   paths.json      [ { path, count, uniques } ]       <- 14-day SNAPSHOT
//
// For views/clones the top-level count/uniques are ROLLING 14-DAY TOTALS and are
// deliberately ignored; only the per-day array is emitted.
//
// Usage: node traffic-rows.mjs <views|clones|referrers|paths> <file> [date]
import { readFileSync } from "node:fs";

const [, , kind, file, date] = process.argv;

if (!kind || !file) {
  console.error("usage: traffic-rows.mjs <views|clones|referrers|paths> <file> [date]");
  process.exit(2);
}

let data;
try {
  data = JSON.parse(readFileSync(file, "utf8"));
} catch (err) {
  console.error(`cannot read ${file}: ${err.message}`);
  process.exit(1);
}

const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
const rows = [];

// Shape validation. Without this, a payload whose expected key is missing or
// renamed yields zero rows and the script exits 0 — the job reports success and
// silently records nothing, forever. That is INCIDENTS.md #8 (a success flag
// that lies), and for a metrics job it is worse than a crash: a crash is
// noticed. So an unexpected shape is a hard error, not an empty result.
function requireArray(value, what) {
  if (!Array.isArray(value)) {
    console.error(
      `unexpected payload for ${what}: expected an array, got ${JSON.stringify(value)?.slice(0, 120)}`,
    );
    console.error("(The GitHub traffic API shape may have changed. Refusing to record nothing silently.)");
    process.exit(3);
  }
  return value;
}

switch (kind) {
  case "views":
  case "clones":
    // A repo with no traffic returns `{count:0,uniques:0,views:[]}` — a real
    // empty array. A MISSING key is a different thing and must fail.
    for (const d of requireArray(data[kind], `data.${kind}`)) {
      rows.push([String(d.timestamp).slice(0, 10), d.count, d.uniques].map(q).join(","));
    }
    break;

  case "referrers":
    for (const r of requireArray(data, "referrers")) {
      rows.push([date, r.referrer, r.count, r.uniques].map(q).join(","));
    }
    break;

  case "paths":
    for (const p of requireArray(data, "paths")) {
      rows.push([date, p.path, p.count, p.uniques].map(q).join(","));
    }
    break;

  default:
    console.error(`unknown kind: ${kind}`);
    process.exit(2);
}

process.stdout.write(rows.length ? rows.join("\n") + "\n" : "");
