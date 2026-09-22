// Regression: running the hook suites must not touch the REAL audit logs.
//
// The defect (INCIDENTS.md #25): both hook suites drive the real handler via
// `plugin.register(fakeApi)`, so the real `audit()` runs. With no override the
// fixtures were appended to the production log — 24 rows per bare
// `node test-hook.mjs` — and a log a test writes to is not evidence of anything.
//
// This asserts the property directly: each protected log's line count is
// identical before and after the suites run. It measures the FILE, not a claim
// about the code.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// The real logs a bare test run must never write to. Absolute on purpose: these
// are the observed contamination sites, not a computed default.
const PROTECTED = [
  "/root/.openclaw/workspace/governance-audit.log",
  `${process.env.HOME || "/root"}/.openclaw/nibvok-ai-security-audit.log`,
];

const SUITES = ["test-hook.mjs", "test-session-trust.mjs"];

// Non-empty lines, matching how the chain verifier counts entries: a trailing
// newline is not an extra row.
function lineCount(file) {
  return readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "").length;
}

const before = new Map();
for (const f of PROTECTED) if (existsSync(f)) before.set(f, lineCount(f));

if (!before.size) {
  console.error("SKIPPED (exit 3): no protected audit log present to measure.");
  process.exit(3);
}

// Run each suite the way a developer does — bare `node <suite>`, from this
// directory, with the audit-log override REMOVED. Removing it is the point: the
// suite must isolate itself, not rely on the caller's environment.
let skipped = false;
for (const suite of SUITES) {
  const env = { ...process.env };
  delete env.NIBVOK_AI_SECURITY_AUDIT_LOG;
  let rc = 0;
  try {
    execFileSync(process.execPath, [join(HERE, suite)], { cwd: HERE, env, stdio: "pipe" });
  } catch (err) {
    rc = err.status ?? 1;
  }
  if (rc === 3) { skipped = true; continue; }
  if (rc !== 0) {
    console.error(`FAIL: ${suite} exited ${rc}; the isolation claim is untested.`);
    process.exit(1);
  }
}

let bad = 0;
for (const [f, n] of before) {
  const now = lineCount(f);
  const ok = now === n;
  if (!ok) bad++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${f}: ${n} -> ${now} lines`);
}

if (bad) {
  console.error(`\nFAIL: ${bad} protected log(s) changed while the suites ran.`);
  process.exit(1);
}
if (skipped) {
  console.error("SKIPPED (exit 3): a suite could not run here, so isolation is unproven.");
  process.exit(3);
}
console.log(`\n${before.size} protected log(s) unchanged by the hook suites.`);
