// Focused test: "Allow for this session" as a CLASS-scoped session policy.
//
// Proves, per approval class:
//   (a) the dialog offers allow-always,
//   (b) choosing it suppresses later prompts of the SAME class in that session,
//   (c) a DIFFERENT class still prompts,
//   (d) another session is unaffected,
//   (e) classes excluded from session trust stay one-shot,
//   (f) DENY never offers an approval path at all.
//
// Imports `index.js` (via the plugin), so it needs the host-provided OpenClaw
// plugin SDK. A bare clone has no such module and Node does not search the global
// root; the raw error is an ERR_MODULE_NOT_FOUND from inside index.js, which looks
// like a plugin bug. Exit 3 = environment could not run it, distinct from 1 =
// a real test failure, so "could not run" is never read as a result.
let plugin, confirmClass, SESSION_TRUSTABLE_CLASSES;
try {
  plugin = (await import("./index.js")).default;
  ({ confirmClass, SESSION_TRUSTABLE_CLASSES } = await import("./classifier.js"));
} catch (err) {
  if (err?.code === "ERR_MODULE_NOT_FOUND" && /'openclaw'/.test(err.message)) {
    console.error("SKIPPED (exit 3): the OpenClaw plugin SDK is not resolvable here.");
    console.error('  index.js does: import ... from "openclaw/plugin-sdk/plugin-entry"');
    console.error("  which the OpenClaw host supplies. To run this suite from a clone:");
    console.error("    mkdir -p node_modules");
    console.error("    ln -sfn /usr/lib/node_modules/openclaw node_modules/openclaw");
    console.error("  (test-classifier.mjs needs none of this and always runs.)");
    process.exit(3);
  }
  throw err;
}

const registered = [];
plugin.register({ on: (name, fn, opts) => registered.push({ name, fn, opts }) });
const h = registered.find((r) => r.name === "before_tool_call").fn;

let ok = 0, bad = 0;
const check = (label, cond) => {
  cond ? ok++ : bad++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
};

// One representative command per confirm class.
const CMDS = {
  delete: "rm -rf /root/.openclaw/workspace/project/build",
  git: "git push --force origin main",
  db: "sqlite3 a.db 'DROP TABLE u'",
  "outside-write": "echo x > /root/other/f.txt",
  "confirm-read": "cat /etc/passwd",
  spend: "curl https://api.stripe.com/v1/charges -d amount=60000",
};

const evt = (cls, sessionKey) => ({
  toolName: "exec",
  params: { command: CMDS[cls] },
  sessionKey,
});
const decisionsOf = (r) => (r?.requireApproval?.allowedDecisions || []).join(",");

const SESS = "sess-A";
const OTHER = "sess-B";

console.log("── class model ──");
for (const cls of Object.keys(CMDS)) {
  const { classifyToolCall } = await import("./classifier.js");
  const r = classifyToolCall("exec", { command: CMDS[cls] });
  check(`reason->class: ${cls}`, confirmClass(r.reason) === cls);
}
check("unknown reason fails closed (null class)", confirmClass("something new") === null);

console.log("\n── (a) every trustable class offers allow-always ──");
for (const cls of Object.keys(CMDS)) {
  const r = h(evt(cls, SESS), { sessionKey: SESS });
  if (cls === "spend") {
    check(`spend is NOT session-trustable (one-shot only)`,
      decisionsOf(r) === "allow-once,deny");
  } else {
    check(`${cls} offers allow-always`,
      decisionsOf(r) === "allow-once,allow-always,deny");
  }
}

console.log("\n── (b) grant one class -> same class stops prompting ──");
for (const cls of Object.keys(CMDS)) {
  if (!SESSION_TRUSTABLE_CLASSES.has(cls)) continue;
  const r = h(evt(cls, SESS), { sessionKey: SESS });
  r.requireApproval.onResolution("allow-always");
  const after = h(evt(cls, SESS), { sessionKey: SESS });
  check(`${cls} no longer prompts after grant`, !after?.requireApproval);
}

console.log("\n── (c) a NEW class still prompts ──");
// delete/git/db/outside-write/confirm-read are all trusted in SESS now.
check("spend still prompts (not trustable)",
  !!h(evt("spend", SESS), { sessionKey: SESS })?.requireApproval);

console.log("\n── (c2) trust is per-class, not per-session-blanket ──");
const S2 = "sess-C";
const r2 = h(evt("git", S2), { sessionKey: S2 });
check("fresh session: git prompts", !!r2?.requireApproval);
r2.requireApproval.onResolution("allow-always");
check("fresh session: git now silent",
  !h(evt("git", S2), { sessionKey: S2 })?.requireApproval);
check("fresh session: delete STILL prompts",
  !!h(evt("delete", S2), { sessionKey: S2 })?.requireApproval);

console.log("\n── (d) another session is unaffected ──");
check("sess-B delete still prompts",
  !!h(evt("delete", OTHER), { sessionKey: OTHER })?.requireApproval);
check("sess-B git still prompts",
  !!h(evt("git", OTHER), { sessionKey: OTHER })?.requireApproval);

console.log("\n── (e) allow-once must NOT create session trust ──");
const S3 = "sess-D";
const r3 = h(evt("db", S3), { sessionKey: S3 });
r3.requireApproval.onResolution("allow-once");
check("allow-once leaves the class prompting",
  !!h(evt("db", S3), { sessionKey: S3 })?.requireApproval);

console.log("\n── (f) DENY has no approval path ──");
const denyEvt = { toolName: "exec", params: { command: "openclaw config set tools.deny '[]'" }, sessionKey: SESS };
const rd = h(denyEvt, { sessionKey: SESS });
check("config set is blocked, never offered approval",
  !!rd?.block && !rd?.requireApproval);
const accEvt = { toolName: "exec", params: { command: "openclaw plugins install x --accept-capabilities" }, sessionKey: SESS };
const ra = h(accEvt, { sessionKey: SESS });
check("--accept-capabilities is blocked, never offered approval",
  !!ra?.block && !ra?.requireApproval);

console.log(`\n${ok} passed, ${bad} failed`);
process.exit(bad ? 1 : 0);
