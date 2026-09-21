// Tests for the five preset policies.
//
//   node test-policies.mjs
//
// Two layers:
//   1. Table/logic tests on policies.js directly (pure).
//   2. BEHAVIOURAL tests: each preset is loaded in a CHILD process with
//      NIBVOK_AI_SECURITY_POLICY set, then real classifications are asserted.
//      The classifier reads its policy at import time, so a child process is the
//      only honest way to prove a preset actually changes behaviour — mutating
//      env in-process would test nothing.

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { PRESETS, POLICY_NAMES, DEFAULT_POLICY_NAME, resolvePolicy } from "./policies.js";

const HERE = dirname(fileURLToPath(import.meta.url));

let passed = 0;
let failed = 0;
function t(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL  ${name}\n        ${err.message}`);
  }
}
function eq(a, b, what) {
  const ja = JSON.stringify(a);
  const jb = JSON.stringify(b);
  if (ja !== jb) throw new Error(`${what}: expected ${jb}, got ${ja}`);
}
function ok(c, what) {
  if (!c) throw new Error(what);
}

console.log("── the preset table ──");
t("exactly five presets, with the agreed names", () => {
  eq(POLICY_NAMES.sort(), ["development", "locked-down", "production", "read-only", "research"], "names");
});
t("every preset declares the full knob set", () => {
  for (const [name, p] of Object.entries(PRESETS)) {
    for (const k of ["label", "description", "writeRoots", "loggedWriteRoots", "denyWrites", "denyDelete", "spendCeilingUsd", "extraReadRoots"]) {
      ok(k in p, `${name} is missing ${k}`);
    }
    ok(Array.isArray(p.writeRoots), `${name}.writeRoots must be an array`);
    ok(typeof p.denyWrites === "boolean", `${name}.denyWrites must be boolean`);
  }
});
t("loggedWriteRoots is always a subset of writeRoots", () => {
  for (const [name, p] of Object.entries(PRESETS)) {
    for (const r of p.loggedWriteRoots) ok(p.writeRoots.includes(r), `${name}: ${r} not in writeRoots`);
  }
});
t("only the read-only postures deny writes", () => {
  const denying = Object.entries(PRESETS).filter(([, p]) => p.denyWrites).map(([n]) => n).sort();
  eq(denying, ["locked-down", "read-only"], "denyWrites presets");
});

console.log("\n── resolution ──");
t("default is development", () => {
  eq(resolvePolicy({}).name, DEFAULT_POLICY_NAME, "name");
});
t("a named preset resolves", () => {
  eq(resolvePolicy({ NIBVOK_AI_SECURITY_POLICY: "read-only" }).name, "read-only", "name");
});
t("an unknown name falls back to the default (fails safe, and says so)", () => {
  const orig = console.error;
  console.error = () => {};
  try {
    eq(resolvePolicy({ NIBVOK_AI_SECURITY_POLICY: "nope" }).name, DEFAULT_POLICY_NAME, "name");
  } finally {
    console.error = orig;
  }
});
t("the spend-ceiling env var overrides the preset", () => {
  const p = resolvePolicy({ NIBVOK_AI_SECURITY_POLICY: "production", NIBVOK_AI_SECURITY_SPEND_CEILING_USD: "250" });
  eq(p.spendCeilingUsd, 250, "ceiling");
});

console.log("\n── behavioural: each preset, cold-loaded ──");
// A child loads classifier.js under the given preset and prints one verdict per
// probe as JSON. This is the proof that a preset actually changes decisions.
const CHILD = `
import { classifyToolCall } from ${JSON.stringify(join(HERE, "classifier.js"))};
const probes = {
  writeWorkspace: ["write", { path: "/root/.openclaw/workspace/notes.txt" }],
  writeScratch:   ["write", { path: "/tmp/scratch.txt" }],
  deleteBuild:    ["exec", { command: "rm -rf build/" }],
  readShadowish:  ["exec", { command: "cat /etc/passwd" }],
  outboundSpend:  ["exec", { command: "curl https://api.stripe.com/v1/transfers -d amount=60000" }],
};
const out = {};
for (const [k, [tool, params]] of Object.entries(probes)) {
  out[k] = classifyToolCall(tool, params).action;
}
process.stdout.write(JSON.stringify(out));
`;

function verdictsFor(preset) {
  const raw = execFileSync(
    process.execPath,
    ["--input-type=module", "-e", CHILD],
    { env: { ...process.env, NIBVOK_AI_SECURITY_POLICY: preset }, encoding: "utf8" },
  );
  return JSON.parse(raw);
}

const dev = verdictsFor("development");
t("development: workspace + scratch writes allowed, deletes confirm", () => {
  ok(dev.writeWorkspace !== "deny", `workspace write should not deny, got ${dev.writeWorkspace}`);
  ok(dev.writeScratch !== "deny", `scratch write should not deny, got ${dev.writeScratch}`);
  eq(dev.deleteBuild, "confirm", "deleteBuild");
});

const prod = verdictsFor("production");
t("production: scratch is NOT a write root (tighter than development)", () => {
  ok(prod.writeWorkspace !== "deny", "workspace write allowed");
  eq(prod.writeScratch, "confirm", "scratch write now confirms (outside write roots)");
  eq(prod.deleteBuild, "confirm", "deleteBuild still confirms");
});

const ro = verdictsFor("read-only");
t("read-only: writes and deletes DENIED", () => {
  eq(ro.writeWorkspace, "deny", "workspace write");
  eq(ro.writeScratch, "deny", "scratch write");
  eq(ro.deleteBuild, "deny", "delete");
});
t("read-only: reads still follow the normal allowlist", () => {
  eq(ro.readShadowish, "confirm", "ordinary confirm-read unchanged");
});

const res = verdictsFor("research");
t("research: workspace + scratch writable, deletes confirm", () => {
  ok(res.writeWorkspace !== "deny", "workspace write");
  ok(res.writeScratch !== "deny", "scratch write");
  eq(res.deleteBuild, "confirm", "deleteBuild");
});

const lock = verdictsFor("locked-down");
t("locked-down: writes and deletes DENIED", () => {
  eq(lock.writeWorkspace, "deny", "workspace write");
  eq(lock.writeScratch, "deny", "scratch write");
  eq(lock.deleteBuild, "deny", "delete");
});

t("every preset still confirms an outbound spend at the ceiling", () => {
  eq(dev.outboundSpend, "confirm", "development");
  eq(prod.outboundSpend, "confirm", "production");
  eq(ro.outboundSpend, "confirm", "read-only");
  eq(res.outboundSpend, "confirm", "research");
  eq(lock.outboundSpend, "confirm", "locked-down");
});

console.log("");
if (failed) {
  console.log(`${passed} passed, ${failed} FAILED`);
  process.exit(1);
}
console.log(`${passed} passed, 0 failed`);
console.log("All five presets behave as documented.");
