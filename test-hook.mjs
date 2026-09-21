// Negative test against the REAL plugin handler (not just the classifier).
// Captures the registered `before_tool_call` handler and feeds it simulated
// events, proving the plugin returns block / requireApproval / allow.
//
// Run: node test-hook.mjs
//
// This suite exercises the plugin through its registered handler, so it imports
// `index.js`, which imports the OpenClaw plugin SDK the HOST provides. Node does
// not search the global package root, so from a bare clone that module is not
// resolvable — and the raw failure is an ERR_MODULE_NOT_FOUND raised from inside
// index.js, which reads like a bug in this plugin rather than a missing host.
// The guard below turns that into an actionable message and a DIFFERENT exit
// code (3 = environment, 1 = test failure), so "could not run" can never be
// mistaken for "ran and passed" or "ran and failed".
let plugin, BOOTSTRAP_ROOT;
try {
  plugin = (await import("./index.js")).default;
  ({ BOOTSTRAP_ROOT } = await import("./classifier.js"));
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

const BOOT = BOOTSTRAP_ROOT.replace(/\/$/, "");

const registered = [];
const fakeApi = { on: (name, fn, opts) => registered.push({ name, fn, opts }) };
plugin.register(fakeApi);

const h = registered.find((r) => r.name === "before_tool_call");
if (!h) { console.log("FAIL: no before_tool_call handler registered"); process.exit(1); }
console.log(`handler matcher: ${JSON.stringify(h.opts.matcher)}\n`);

let nOk = 0, fail = 0;
function t(label, event, expect) {
  const r = h.fn(event) || {};
  let got = "allow";
  if (r.block) got = "block";
  else if (r.requireApproval) got = "approval";
  const ok = got === expect;
  ok ? nOk++ : fail++;
  const detail = r.blockReason
    || (r.requireApproval && r.requireApproval.description.split("\n")[0]) || "";
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}\n         -> ${got}${detail ? ": " + detail : ""}`);
}

console.log("DENY (must block):");
t("rm -rf /", { toolName: "exec", params: { command: "rm -rf /" } }, "block");
t("openclaw plugins disable", { toolName: "exec", params: { command: "openclaw plugins disable nibvok-ai-security" } }, "block");
t("cat secrets.json", { toolName: "exec", params: { command: "cat /root/.openclaw/secrets.json" } }, "block");
t("cat .env", { toolName: "exec", params: { command: "cat .env" } }, "block");
t("read tool at secrets", { toolName: "read", params: { path: "/root/.openclaw/secrets.json" } }, "block");
t("cat /etc/passwd (confirm, not block)", { toolName: "exec", params: { command: "cat /etc/passwd" } }, "approval");
t("write /etc/hosts", { toolName: "exec", params: { command: "echo x > /etc/hosts" } }, "block");

console.log("\nCONFIRM (must require approval):");
t("git push --force", { toolName: "exec", params: { command: "git push --force origin main" } }, "approval");
t("rm -rf build", { toolName: "exec", params: { command: "rm -rf build/" } }, "approval");
t("git reset --hard", { toolName: "exec", params: { command: "git reset --hard" } }, "approval");
t("drop table", { toolName: "exec", params: { command: "sqlite3 a.db 'DROP TABLE u'" } }, "approval");
t("spend >= $500", { toolName: "exec", params: { command: "curl https://api.stripe.com/v1/charges -d amount=60000" } }, "approval");
t("write outside workspace", { toolName: "exec", params: { command: "echo x > /root/other/f.txt" } }, "approval");

console.log("\nALLOW (must pass untouched - the false-positive check):");
t("read classifier", { toolName: "exec", params: { command: `cat ${BOOT}/classifier.js` } }, "allow");
t("git status", { toolName: "exec", params: { command: "git status" } }, "allow");
t("git push normal", { toolName: "exec", params: { command: "git push origin main" } }, "allow");
t("pytest", { toolName: "exec", params: { command: "python3 -m pytest tests/ -q" } }, "allow");
t("secrets allow-host grant", { toolName: "exec", params: { command: "openclaw secrets store set X --allow-host api.telegram.org" } }, "allow");
t("outbound send (allow+log)", { toolName: "conversations_send", params: { message: "hi" } }, "allow");
t("word 'secret' in a log line", { toolName: "exec", params: { command: "echo 'no secrets' >> /root/.openclaw/workspace/l.txt" } }, "allow");
t("edit tool", { toolName: "edit", params: { path: "app/main.py" } }, "allow");

console.log(`\n${nOk} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("Plugin handler enforces the intended policy.");
