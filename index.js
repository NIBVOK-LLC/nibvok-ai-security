// NIBVOK AI Security — runtime enforcement of policy for OpenClaw agents.
//
// Sits in the `before_tool_call` hook and decides, per call: allow, allow-log,
// confirm, or deny. The hook is the only place in OpenClaw where that decision
// can be made per call — `tools.deny` matches tool IDS only, and
// `tools.exec.mode` is a single global posture. Neither can express "confirm
// `git push --force` but run `pytest` silently".
//
// The bundled `@openclaw/policy` plugin is NOT this. It audits config drift and
// emits attestation hashes; per its own docs it "does not enforce tool calls or
// rewrite runtime behavior at request time." Enforcement lives here.
import { appendFileSync } from "node:fs";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { classifyToolCall, confirmClass, SESSION_TRUSTABLE_CLASSES } from "./classifier.js";

/**
 * Where decisions are recorded: one JSON line per tool call.
 *
 * OpenClaw home first, then the legacy in-workspace path, overridable by
 * `NIBVOK_AI_SECURITY_AUDIT_LOG`. The default is deliberately NOT a hardcoded
 * absolute path — a published plugin that writes to one developer's directory
 * is a plugin that fails silently on everyone else's machine.
 */
const AUDIT_LOG =
  process.env.NIBVOK_AI_SECURITY_AUDIT_LOG ||
  `${process.env.HOME || "/root"}/.openclaw/nibvok-ai-security-audit.log`;

/** Product tag written into every audit record. */
const PRODUCT = "nibvok";

/**
 * Session-scoped trust, keyed sessionKey -> Set<class>.
 *
 * "Allow for this session" on one CLASS of confirm covers later calls of the
 * SAME class in the SAME session. A new class still prompts. In-memory on
 * purpose: trust ends when the Gateway restarts.
 *
 * Eligibility lives in SESSION_TRUSTABLE_CLASSES (classifier.js). `spend` is
 * excluded there, and the DENY class has no approval path at all — a deny is
 * never offered "allow for this session", because there is no approval to
 * remember. Turning a deny into a confirm is a separate policy decision.
 */
const sessionTrust = new Map(); // sessionKey -> Set<class>

function hasSessionTrust(sessionKey, cls) {
  if (!sessionKey || !cls) return false;
  const set = sessionTrust.get(sessionKey);
  return !!set && set.has(cls);
}

function grantSessionTrust(sessionKey, cls) {
  if (!sessionKey || !cls) return;
  if (!sessionTrust.has(sessionKey)) sessionTrust.set(sessionKey, new Set());
  sessionTrust.get(sessionKey).add(cls);
}

/**
 * Append one JSON line; never let a logging failure block a tool call.
 *
 * `product` is a FIELD, not a "[NIBVOK] " line prefix: the audit log is JSONL, and
 * a textual prefix per line would make the file unparseable by every reader.
 */
function audit(entry) {
  try {
    appendFileSync(
      AUDIT_LOG,
      JSON.stringify({ ts: new Date().toISOString(), product: PRODUCT, ...entry }) + "\n",
    );
  } catch {
    // Governance must not fail closed on an audit-log write error.
  }
}

export default definePluginEntry({
  id: "nibvok-ai-security",
  name: "NIBVOK AI Security",
  description: "Allow, confirm, or deny every tool call before it runs.",
  register(api) {
    api.on(
      "before_tool_call",
      (event, ctx) => {
        const { action, reason } = classifyToolCall(
          event.toolName,
          event.params,
          event.derivedPaths,
        );
        const cmd = String((event.params && event.params.command) || "").slice(0, 400);
        const sessionKey = ctx?.sessionKey || event.sessionKey;
        const cls = confirmClass(reason);
        const sessionScoped = !!cls && SESSION_TRUSTABLE_CLASSES.has(cls);

        // Session-scoped trust: a class approved once stops prompting for the
        // rest of this session. A DIFFERENT class still prompts.
        if (action === "confirm" && sessionScoped && hasSessionTrust(sessionKey, cls)) {
          audit({
            action: "allow-log",
            tool: event.toolName,
            reason: `session trust (${cls})`,
            cmd,
          });
          return undefined;
        }

        if (action === "deny") {
          audit({ action, tool: event.toolName, reason, cmd });
          return {
            block: true,
            blockReason: `[NIBVOK] Blocked by NIBVOK AI Security: ${reason}. Choose a safer approach or ask the operator.`,
          };
        }

        if (action === "confirm") {
          audit({ action, tool: event.toolName, reason, cmd });
          // Every session-eligible class offers session-scoped trust; classes
          // not eligible (spend) stay one-shot. A deny never reaches here.
          return {
            requireApproval: {
              title: "NIBVOK AI Security — action approval",
              description: `${reason}\n\nCommand: ${cmd.slice(0, 300)}`,
              severity: "warning",
              timeoutMs: 600000,
              allowedDecisions: sessionScoped
                ? ["allow-once", "allow-always", "deny"]
                : ["allow-once", "deny"],
              onResolution(decision) {
                audit({ action: "resolution", tool: event.toolName, decision, reason });
                if (decision === "allow-always" && sessionScoped) {
                  grantSessionTrust(sessionKey, cls);
                  audit({
                    action: "session-trust-grant",
                    class: cls,
                    session: sessionKey,
                  });
                }
              },
            },
          };
        }

        if (action === "allow-log") {
          audit({ action, tool: event.toolName, reason, cmd });
          return undefined; // allowed, recorded
        }

        return undefined; // allow
      },
      {
        matcher: [
          "exec",
          "process",
          "read",
          "ls",
          "write",
          "edit",
          "apply_patch",
          "patch",
          "conversations_send",
          "conversations_turn",
          "sessions_send",
        ],
        priority: 50,
      },
    );
  },
});
