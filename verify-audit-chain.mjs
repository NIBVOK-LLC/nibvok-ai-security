#!/usr/bin/env node
// verify-audit-chain.mjs — walk a NIBVOK audit log and confirm nothing was altered.
//
// Usage:
//   node verify-audit-chain.mjs [path-to-audit.log]
//
// Default path matches the plugin's default:
//   $NIBVOK_AI_SECURITY_AUDIT_LOG, else $HOME/.openclaw/nibvok-ai-security-audit.log
//
// Exit codes:
//   0  chain verified
//   1  chain BROKEN (tamper or corruption detected)
//   2  file not found / unreadable
//
// It reports what it proves (internal consistency) and what it does not
// (a full rewrite with recomputed hashes), rather than implying more.

import { readFileSync } from "node:fs";
import { verifyChain } from "./audit-chain.js";

const DEFAULT_LOG =
  process.env.NIBVOK_AI_SECURITY_AUDIT_LOG ||
  `${process.env.HOME || "/root"}/.openclaw/nibvok-ai-security-audit.log`;

const file = process.argv[2] || DEFAULT_LOG;

let text;
try {
  text = readFileSync(file, "utf8");
} catch (err) {
  console.error(`verify-audit-chain: cannot read ${file}: ${err.message}`);
  process.exit(2);
}

const res = verifyChain(text);

console.log(`file     : ${file}`);
console.log(`lines    : ${res.total}`);
console.log(`chained  : ${res.chained}`);
console.log(`pre-chain: ${res.legacy}`);
console.log("");

if (res.ok) {
  console.log(`OK — chain verified across ${res.chained} entries.`);
  if (res.legacy) {
    console.log(
      `     ${res.legacy} pre-chain line(s) had no hash (written before chaining).`,
    );
  }
  console.log(
    "     Proves: no entry was edited, reordered, removed or inserted after the fact.",
  );
  console.log(
    "     Does NOT prove authenticity against a full rewrite from GENESIS.",
  );
  process.exit(0);
}

console.error(`BROKEN — ${res.errors.length} problem(s):`);
for (const e of res.errors) {
  console.error(`  line ${e.line}: ${e.code} — ${e.detail}`);
}
process.exit(1);
