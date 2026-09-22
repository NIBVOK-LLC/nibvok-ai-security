// Test prelude: own a throwaway audit log BEFORE the plugin is imported.
//
// Both hook suites call `plugin.register(fakeApi)`, which runs the REAL
// `before_tool_call` handler and therefore the REAL `audit()`. `index.js`
// resolves its audit path ONCE, when it is first evaluated — so an override
// applied after importing it is too late: every fixture row has already been
// appended to the log the module already chose. That is exactly how synthetic
// rows ended up in the production log (INCIDENTS.md #25).
//
// So the order is load-bearing:
//
//   import { useTempAuditLog } from "./test-audit-env.mjs";
//   useTempAuditLog();
//   plugin = (await import("./index.js")).default;

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Redirect the audit log to a fresh temp file and return its path.
 *
 * Unconditional on purpose: an inherited `NIBVOK_AI_SECURITY_AUDIT_LOG` must
 * never be able to point a test run at a real log. The directory is removed on
 * process exit.
 */
export function useTempAuditLog() {
  const dir = mkdtempSync(join(tmpdir(), "ox88-hook-audit-"));
  const log = join(dir, "audit.log");
  process.env.NIBVOK_AI_SECURITY_AUDIT_LOG = log;
  process.on("exit", () => {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  return log;
}
