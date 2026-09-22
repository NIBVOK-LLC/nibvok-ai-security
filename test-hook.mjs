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
import { useTempAuditLog } from "./test-audit-env.mjs";

let plugin, BOOTSTRAP_ROOT;
try {
  // Own a throwaway audit log BEFORE importing the plugin. `index.js` resolves
  // its audit path at import time, so an override applied afterwards is too
  // late and the fixtures land in a real log. See INCIDENTS.md #25.
  useTempAuditLog();
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
const fakeApi = {
  on: (name, fn, opts) => registered.push({ name, fn, opts }),
  // Owner-configured MCP servers, as the handler reads them at register time.
  config: { mcp: { servers: { startupnamegenerator: {}, filesystem: {} } } },
};
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
// NOTE (2026-09-21): OUTBOUND endpoint. This used /charges, a COLLECTION --
// inbound revenue, which no longer escalates under the narrowed rule. The spend
// CLASS is unchanged; only the command that reaches it changed.
t("spend >= $500", { toolName: "exec", params: { command: "curl https://api.stripe.com/v1/transfers -d amount=60000" } }, "approval");
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

console.log("\nTERMINAL / PROCESS (INCIDENTS.md #23):");
t("terminal input: cat shadow blocks", { toolName: "terminal", params: { action: "input", sessionId: "t1", data: "cat /etc/" + "sha" + "dow" } }, "block");
t("process write: cat shadow blocks", { toolName: "process", params: { action: "write", sessionId: "p1", data: "cat /etc/" + "sha" + "dow" } }, "block");
t("terminal input: ordinary work allows", { toolName: "terminal", params: { action: "input", data: "git status" } }, "allow");

// The hook used to be matcher-gated to a list of core tool ids, which meant a
// tool NOT in the list was never classified at all -- and MCP tool names cannot
// be listed ahead of time (discovered at connect, and able to change). The
// matcher is now OMITTED, which is the only match-all form the framework allows
// (`"*"` is rejected; omission is the sole match-all).
//
// Asserting the field alone proves the edit, not the consequence. This mirrors
// the framework's own filter (`pluginToolMatcherCoversTool`) so the test proves
// MCP calls actually REACH the handler -- which is the whole point of the change.
function reachesHandler(matcher, toolName) {
  return matcher === undefined || matcher.includes(String(toolName).toLowerCase());
}
const matcher = h.opts && h.opts.matcher;
console.log("\nMATCHER REMOVED (so every tool, including MCP, reaches the handler):");
if (matcher === undefined) { nOk++; console.log("  PASS  no matcher -> match-all"); }
else { fail++; console.log(`  FAIL  matcher still present: ${JSON.stringify(matcher)}`); }
for (const tool of ["exec", "read", "terminal", "filesystem__read_text_file", "startupnamegenerator__do_thing"]) {
  const ok = reachesHandler(matcher, tool);
  ok ? nOk++ : fail++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${tool} reaches the handler`);
}

console.log("\nMCP TOOLS (the gap this change closes):");
// Unknown MCP tool, no classifiable argument -> approval (fail closed).
t("unknown MCP tool", { toolName: "startupnamegenerator__do_thing", params: {} }, "approval");
// Path rules apply unchanged underneath.
t("MCP read of a secret", { toolName: "filesystem__read_text_file", params: { path: "/root/.ssh/id_rsa" } }, "block");
t("MCP read of an allowed path", { toolName: "filesystem__read_text_file", params: { path: "/root/.openclaw/workspace/ox88/README.md" } }, "allow");
// A hostile server cannot reach the exec rules by naming its tool `exec`.
t("MCP tool named exec is not exec", { toolName: "evil__exec", params: {} }, "approval");
// The reserved first-party bridge is never waved through on its name alone.
t("reserved bridge call", { toolName: "mcp__openclaw__read", params: {} }, "approval");
// An unrecognised server gets no silent allow.
t("unrecognised server, allowed path", { toolName: "ghost__read_text_file", params: { path: "/root/.openclaw/workspace/ox88/README.md" } }, "approval");

// The prompt must be legible: an MCP call has no `params.command`, so a naive
// description would render "Command: " blank and the operator would be
// approving nothing they can read.
const mcpPrompt = (() => {
  const r = h.fn({ toolName: "startupnamegenerator__do_thing", params: {} }) || {};
  return (r.requireApproval && r.requireApproval.description) || "";
})();
if (mcpPrompt.includes("startupnamegenerator__do_thing") && !/Command:\s*$/.test(mcpPrompt)) {
  nOk++;
  console.log("  PASS  MCP approval prompt names the tool (not a blank command)");
} else {
  fail++;
  console.log(`  FAIL  MCP approval prompt is uninformative: ${JSON.stringify(mcpPrompt)}`);
}

// MCP-unknown must not be offered session-wide trust on "allow-always".
const mcpDecisions = (() => {
  const r = h.fn({ toolName: "startupnamegenerator__do_thing", params: {} }) || {};
  return (r.requireApproval && r.requireApproval.allowedDecisions) || [];
})();
if (!mcpDecisions.includes("allow-always")) {
  nOk++;
  console.log("  PASS  MCP-unknown is one-shot (no allow-always)");
} else {
  fail++;
  console.log("  FAIL  MCP-unknown offered allow-always (session-wide grant)");
}

console.log(`\n${nOk} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("Plugin handler enforces the intended policy.");
