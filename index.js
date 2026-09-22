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
import { appendFileSync, readFileSync } from "node:fs";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { classifyToolCall, confirmClass, SESSION_TRUSTABLE_CLASSES, splitMcpToolName } from "./classifier.js";
import { GENESIS, entryHash, lastHashOfText } from "./audit-chain.js";

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

/**
 * The owner-configured MCP server names (`mcp.servers`), read at register time.
 *
 * The classifier validates a call's SERVER half against this set. It is the one
 * half an untrusted server cannot choose, so it is the only half that may select
 * policy. Only NAMES are read — never server URLs, headers or credentials.
 *
 * Deliberately NO reload registration: `api.registerReload` takes a descriptor
 * object (`restartPrefixes`/`hotPrefixes`/`noopPrefixes`), not a callback, and
 * passing the wrong shape can throw inside `register()` — which would take the
 * whole governance layer offline. Adding a server needs a Gateway restart, and
 * an unknown server fails CLOSED in the meantime (see classifyMcpCall), so the
 * failure mode is a prompt rather than a silent allow.
 */
let mcpServerNames = [];

function refreshMcpServers(api) {
  try {
    const servers = api?.config?.mcp?.servers;
    mcpServerNames = servers && typeof servers === "object" ? Object.keys(servers) : [];
  } catch {
    mcpServerNames = [];
  }
}

function configuredMcpServers(api) {
  if (!mcpServerNames.length) refreshMcpServers(api);
  return mcpServerNames;
}

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
 *
 * Every entry is HASH-CHAINED: it carries `prev_hash` (the previous entry's
 * `hash`) and its own `hash`, so an edit, reorder, removal or insertion anywhere
 * in the file is detectable after the fact. See `audit-chain.js` for what the
 * chain proves and what it does not. `lastHash` is seeded from the existing
 * file tail so the chain continues across a Gateway restart.
 */
function readLastHash(file) {
  try {
    return lastHashOfText(readFileSync(file, "utf8"));
  } catch {
    return GENESIS;
  }
}

let lastHash = readLastHash(AUDIT_LOG);

function audit(entry) {
  try {
    const record = { ts: new Date().toISOString(), product: PRODUCT, ...entry };
    const prev_hash = lastHash;
    const hash = entryHash(record, prev_hash);
    appendFileSync(AUDIT_LOG, JSON.stringify({ ...record, prev_hash, hash }) + "\n");
    lastHash = hash;
  } catch {
    // Governance must not fail closed on an audit-log write error.
  }
}

export default definePluginEntry({
  id: "nibvok-ai-security",
  name: "NIBVOK AI Security",
  description: "Allow, confirm, or deny every tool call before it runs.",
  register(api) {
    refreshMcpServers(api);
    api.on(
      "before_tool_call",
      (event, ctx) => {
        const { action, reason } = classifyToolCall(
          event.toolName,
          event.params,
          event.derivedPaths,
          configuredMcpServers(api),
        );
        // Text that identifies WHAT is being acted on. `exec` carries `command`;
        // an MCP call carries neither a command nor a path in that field, so the
        // tool name is used instead — otherwise every MCP prompt would render
        // "Command: " blank and the operator would approve nothing legible.
        const isMcp = !!splitMcpToolName(event.toolName);
        const cmd = isMcp
          ? `MCP tool ${event.toolName}`
          : String((event.params && event.params.command) || "").slice(0, 400);
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
        // NO matcher. Omission is the only match-all form (the framework rejects
        // `"*"`), and MCP tool names cannot be listed ahead of time: they are
        // discovered from the remote server at connect time and can change
        // between connects. Omitting the matcher is what lets this handler see
        // MCP calls at all — until 2026-09-22 it did not, and every MCP tool call
        // was executed ungoverned. See INCIDENTS.md and MCP-GAP.md.
        priority: 50,
      },
    );
  },
});
