// Tests for the hash-chained audit trail. Pure — no Gateway, no SDK.
//
//   node test-audit-chain.mjs
//
// The important test is the tamper one: a modified entry MUST break the chain.
// A verifier that passes everything would be worse than no verifier, so each
// tamper case below asserts a specific failure code, not merely "not ok".

import { GENESIS, canonical, entryHash, chainPayload, lastHashOfText, verifyChain }
  from "./audit-chain.js";

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
function eq(actual, expected, what) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) throw new Error(`${what}: expected ${e}, got ${a}`);
}
function ok(cond, what) {
  if (!cond) throw new Error(what);
}

/** Build a chained log of `n` entries; returns {text, records}. */
function build(n) {
  let prev = GENESIS;
  const records = [];
  const lines = [];
  for (let i = 0; i < n; i++) {
    const rec = {
      ts: `2026-09-21T19:0${i}:00.000Z`,
      product: "nibvok",
      action: "deny",
      tool: "exec",
      reason: `test reason ${i}`,
      cmd: `echo entry ${i}`,
    };
    const hash = entryHash(rec, prev);
    const line = { ...rec, prev_hash: prev, hash };
    records.push(line);
    lines.push(JSON.stringify(line));
    prev = hash;
  }
  return { text: lines.join("\n") + "\n", records };
}

/** Replace line `i` (0-based) with `repl` (object or string). */
function withLine(text, i, repl) {
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  lines[i] = typeof repl === "string" ? repl : JSON.stringify(repl);
  return lines.join("\n") + "\n";
}

console.log("── canonical form ──");
t("key order does not change the hash", () => {
  const a = { b: 1, a: 2 };
  const c = { a: 2, b: 1 };
  eq(canonical(a), canonical(c), "canonical");
  eq(entryHash(a, GENESIS), entryHash(c, GENESIS), "hash");
});
t("chain fields are excluded from the payload", () => {
  const rec = { a: 1, prev_hash: "x", hash: "y" };
  eq(chainPayload(rec), { a: 1 }, "payload");
});
t("nested objects and arrays are canonicalised", () => {
  eq(canonical({ z: { b: [2, 1], a: 1 } }), '{"z":{"a":1,"b":[2,1]}}', "canonical");
});

console.log("\n── a well-formed chain verifies ──");
t("5 clean entries verify", () => {
  const { text } = build(5);
  const r = verifyChain(text);
  eq(r.ok, true, "ok");
  eq(r.chained, 5, "chained");
  eq(r.errors.length, 0, "errors");
});
t("empty log verifies (nothing to break)", () => {
  const r = verifyChain("");
  eq(r.ok, true, "ok");
  eq(r.chained, 0, "chained");
});
t("lastHashOfText returns the tail hash, GENESIS when empty", () => {
  const { text, records } = build(3);
  eq(lastHashOfText(text), records[2].hash, "tail");
  eq(lastHashOfText(""), GENESIS, "empty");
});

console.log("\n── TAMPER: a modified entry must break the chain ──");
t("editing a middle entry's content is detected", () => {
  const { text, records } = build(5);
  const tampered = { ...records[2], cmd: "echo TAMPERED" };
  const r = verifyChain(withLine(text, 2, tampered));
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.line === 3 && e.code === "hash-mismatch"),
    `expected hash-mismatch at line 3, got ${JSON.stringify(r.errors)}`);
});
t("editing the FIRST entry is detected", () => {
  const { text, records } = build(5);
  const r = verifyChain(withLine(text, 0, { ...records[0], reason: "changed" }));
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.line === 1 && e.code === "hash-mismatch"), "line 1 mismatch");
});
t("editing the LAST entry is detected", () => {
  const { text, records } = build(5);
  const r = verifyChain(withLine(text, 4, { ...records[4], cmd: "echo x" }));
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.line === 5), "line 5 flagged");
});
t("rewriting a stored hash is detected", () => {
  const { text, records } = build(5);
  const r = verifyChain(withLine(text, 1, { ...records[1], hash: "f".repeat(64) }));
  eq(r.ok, false, "ok");
  // Its own hash no longer matches, and the next entry's prev_hash no longer matches.
  ok(r.errors.some((e) => e.line === 2), "line 2 flagged");
  ok(r.errors.some((e) => e.line === 2 && e.code === "hash-mismatch") ||
     r.errors.some((e) => e.line === 3 && e.code === "prev-mismatch"), "mismatch surfaced");
});
t("rewriting a prev_hash is detected", () => {
  const { text, records } = build(5);
  const r = verifyChain(withLine(text, 2, { ...records[2], prev_hash: "a".repeat(64) }));
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.line === 3 && e.code === "prev-mismatch"), "prev-mismatch at line 3");
  ok(r.errors.some((e) => e.line === 3 && e.code === "hash-mismatch"), "hash-mismatch at line 3");
});
t("REMOVING an entry is detected", () => {
  const { text } = build(5);
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  lines.splice(2, 1); // drop the middle entry
  const r = verifyChain(lines.join("\n") + "\n");
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.code === "prev-mismatch"), "continuity broken");
});
t("REORDERING two entries is detected", () => {
  const { text } = build(5);
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  [lines[1], lines[2]] = [lines[2], lines[1]];
  const r = verifyChain(lines.join("\n") + "\n");
  eq(r.ok, false, "ok");
  ok(r.errors.length > 0, "some error");
});
t("INSERTING a forged entry is detected", () => {
  const { text, records } = build(5);
  const forged = { ts: "x", product: "nibvok", action: "allow", prev_hash: records[1].hash, hash: "0".repeat(64) };
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  lines.splice(2, 0, JSON.stringify(forged));
  const r = verifyChain(lines.join("\n") + "\n");
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.line === 3), "forged line flagged");
});
t("appending a forged tail entry is detected", () => {
  const { text } = build(3);
  const forged = JSON.stringify({ ts: "z", product: "nibvok", action: "deny", prev_hash: GENESIS, hash: "1".repeat(64) });
  const r = verifyChain(text + forged + "\n");
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.line === 4 && e.code === "prev-mismatch"), "tail prev-mismatch");
});
t("truncating the log is NOT a chain break (a prefix still verifies)", () => {
  // Honest limitation: dropping trailing entries leaves a valid prefix. Only an
  // external anchor can detect truncation. Documented, and asserted so the
  // behaviour is pinned rather than assumed.
  const { text } = build(5);
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  const r = verifyChain(lines.slice(0, 3).join("\n") + "\n");
  eq(r.ok, true, "ok");
  eq(r.chained, 3, "chained");
});

console.log("\n── malformed input ──");
t("a non-JSON line is reported, not silently skipped", () => {
  const { text } = build(3);
  const r = verifyChain(text + "not json\n");
  eq(r.ok, false, "ok");
  ok(r.errors.some((e) => e.code === "malformed"), "malformed reported");
});
t("pre-chain (legacy) lines are allowed only as a prefix", () => {
  const legacy = JSON.stringify({ ts: "old", product: "nibvok", action: "allow" });
  const { text } = build(3);
  const prefix = verifyChain(legacy + "\n" + text);
  eq(prefix.ok, true, "legacy prefix ok");
  eq(prefix.legacy, 1, "legacy count");
  const mid = verifyChain(text + legacy + "\n");
  eq(mid.ok, false, "legacy after chain rejected");
  ok(mid.errors.some((e) => e.code === "no-chain-field"), "no-chain-field reported");
});

console.log("");
if (failed) {
  console.log(`${passed} passed, ${failed} FAILED`);
  process.exit(1);
}
console.log(`${passed} passed, 0 failed`);
console.log("Audit chain is tamper-evident.");
