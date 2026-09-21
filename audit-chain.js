// Hash-chained audit trail — pure logic, no imports, unit-testable.
//
// The audit log is append-only JSONL. "Append-only" is a promise about how the
// writer behaves, NOT a property of the file: nothing stops an editor from
// changing a line after the fact. This module makes tampering DETECTABLE without
// a blockchain or any external service.
//
// Each entry carries two extra fields:
//
//   prev_hash   the `hash` of the previous entry (GENESIS for the first)
//   hash        SHA-256 over this entry's content AND prev_hash
//
// So every entry commits to the one before it. Change any content, any hash, or
// any ordering, and every entry after it fails to verify.
//
// WHAT THIS PROVES AND WHAT IT DOES NOT
//
// It proves the log is internally consistent: nothing was edited, reordered,
// removed, or inserted after the fact WITHOUT the chain noticing. It does NOT
// prove authenticity against an attacker who can rewrite the WHOLE file and
// recompute every hash from GENESIS — that needs a signature or an external
// anchor, which this module deliberately does not invent. Stated here rather
// than implied, because a tamper-evidence claim that overreaches is the exact
// failure this project exists to catch.
//
// The separate `verify-audit-chain.mjs` CLI walks a log file and reports the
// result; `test-audit-chain.mjs` proves that a modified entry breaks the chain.

import { createHash } from "node:crypto";

/** The `prev_hash` of the first entry: 64 hex zeros. */
export const GENESIS = "0".repeat(64);

/**
 * Deterministic JSON for hashing: object keys sorted lexicographically at every
 * depth. Without this, two runs could serialise the same record differently
 * (key order is not guaranteed) and the chain would look broken when it is not.
 */
export function canonical(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(canonical).join(",") + "]";
  }
  if (value && typeof value === "object") {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + canonical(value[k]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

/**
 * The two fields the chain adds. They are excluded from the hashed content, so
 * they can be recomputed by a verifier.
 */
const CHAIN_FIELDS = ["prev_hash", "hash"];

/** The record content that the hash commits to (chain fields stripped). */
export function chainPayload(record) {
  const out = {};
  for (const k of Object.keys(record)) {
    if (!CHAIN_FIELDS.includes(k)) out[k] = record[k];
  }
  return out;
}

/** SHA-256 of `prevHash + "\n" + canonical(payload)`, hex. */
export function entryHash(record, prevHash) {
  return createHash("sha256")
    .update(String(prevHash) + "\n" + canonical(chainPayload(record)))
    .digest("hex");
}

/**
 * The `hash` of the last entry in a log's text, or GENESIS when there is none.
 *
 * Used to continue a chain across process restarts: a fresh process reads the
 * tail so the next entry still commits to the previous one.
 */
export function lastHashOfText(text) {
  const lines = String(text).split("\n").filter((l) => l.trim() !== "");
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const rec = JSON.parse(lines[i]);
      if (typeof rec.hash === "string" && rec.hash) return rec.hash;
    } catch {
      // malformed line — keep walking back to the last valid chained entry
    }
  }
  return GENESIS;
}

/**
 * Walk a log's text and verify the chain.
 *
 * Returns:
 *   ok       true when every chained entry verifies and continuity holds
 *   total    number of non-empty lines
 *   chained  number of entries carrying a hash
 *   legacy   number of PRE-CHAIN entries (no hash) — allowed only as a prefix
 *   errors   [{line, code, detail}] — empty when ok
 *
 * Codes: "malformed" (unparseable), "no-chain-field" (an unchained line after
 * the chain started), "prev-mismatch", "hash-mismatch".
 */
export function verifyChain(text) {
  const lines = String(text).split("\n").filter((l) => l.trim() !== "");
  const errors = [];
  let prev = GENESIS;
  let chained = 0;
  let legacy = 0;
  let started = false;

  lines.forEach((line, idx) => {
    const lineNo = idx + 1;
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      errors.push({ line: lineNo, code: "malformed", detail: "not valid JSON" });
      return;
    }
    if (typeof rec.hash !== "string" || !rec.hash) {
      if (started || chained > 0) {
        errors.push({
          line: lineNo,
          code: "no-chain-field",
          detail: "entry has no `hash` after the chain started",
        });
      } else {
        legacy++;
      }
      return;
    }
    started = true;
    chained++;
    if (rec.prev_hash !== prev) {
      errors.push({
        line: lineNo,
        code: "prev-mismatch",
        detail: `expected prev_hash ${prev.slice(0, 12)}…, found ${String(
          rec.prev_hash,
        ).slice(0, 12)}…`,
      });
    }
    const want = entryHash(rec, rec.prev_hash);
    if (want !== rec.hash) {
      errors.push({
        line: lineNo,
        code: "hash-mismatch",
        detail: `expected ${want.slice(0, 12)}…, found ${rec.hash.slice(0, 12)}…`,
      });
    }
    prev = rec.hash;
  });

  return { ok: errors.length === 0, total: lines.length, chained, legacy, errors };
}
