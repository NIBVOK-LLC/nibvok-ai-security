# MCP Tool-Name Governance Gap

**Status:** confirmed — findings only, no code changes
**Date:** 2026-09-22
**Build:** OpenClaw 2026.9.4 (`3a9d69d`)
**Scope:** `before_tool_call` dispatch for MCP-server tools
**Governed plugin:** `ai-security-force` (`/root/.openclaw/workspace/ox88/governance-plugin/index.js`)

## Summary

MCP tools are dispatched through the **same** `before_tool_call` hook as core tools.
They never reach the governance classifier, because the hook is **matcher-gated before
the handler runs**, and the plugin's matcher is an exact-name allowlist of 12 core tool
ids that contains no MCP name.

This is a **binding gap**, not a classification gap. The `{ action: ALLOW }` fall-through
in `classifyToolCall` is not what lets MCP calls through — `classifyToolCall` is never
invoked for them.

## 1. MCP tools use the same hook path

MCP server tools are projected into ordinary agent tools, keyed by a generated name:

- `dist/agent-bundle-mcp-materialize-Df1MHkc-.mjs:158` — `const safeToolName = buildSafeToolName({...})`
- `dist/agent-bundle-mcp-materialize-Df1MHkc-.mjs:166` — `name: safeToolName,`

The generic tool-execution adapter then runs the hook for **any** tool, core or MCP:

- `dist/agent-tool-definition-adapter-DhccrrY9.mjs:204` — `const normalizedName = normalizeToolPolicyName(name);`
- `dist/agent-tool-definition-adapter-DhccrrY9.mjs:247-248` — `const hookOutcome = await runBeforeToolCallHook({ toolName: name, ... })`

There is no separate MCP execution path for Gateway-hosted runs.

## 2. Dispatch is matcher-gated before the handler

```
dist/hook-runner-global-BhDCl4qm.mjs:806
  const hooks = getHooksForName(registry, hookName, void 0, matcherToolName);

dist/hook-runner-global-BhDCl4qm.mjs:1185
  }, event.toolName);            // ← matcherToolName is event.toolName

dist/hook-runner-global-BhDCl4qm.mjs:490
  ... .filter((hook) => toolName === void 0 || pluginToolMatcherCoversTool(hook.matcher, toolName))

dist/hook-runner-global-BhDCl4qm.mjs:55-58
  function pluginToolMatcherCoversTool(matcher, toolName) {
    const normalizedMatcher = normalizePluginToolMatcher(matcher);
    return normalizedMatcher === void 0 || normalizedMatcher.includes(normalizeLowercaseStringOrEmpty(toolName));
  }
```

Matching is **exact lowercase set membership**. There is no glob, prefix, or pattern form:

- `dist/hook-runner-global-BhDCl4qm.mjs:32` — *"Omission is the only match-all form; explicit matcher values must stay bounded."*
- `dist/hook-runner-global-BhDCl4qm.mjs:37` — `if (canonicalToolName === "*") throw new TypeError("tool hook matcher wildcard entries are not supported");`

The plugin registers a 12-name matcher:

- `governance-plugin/index.js:130-145` (identical at `packages/nibvok-ai-security/index.js:166-180`)

```
exec, process, terminal, read, ls, write, edit,
apply_patch, patch, conversations_send, conversations_turn, sessions_send
```

No MCP-generated name equals any of these, so the hook is filtered out and the handler
never runs.

## 3. Exact `event.toolName` format for an MCP tool

```
<safeServerName>__<sanitizedToolName>
```

**Two underscores.** Neither half is the advertised MCP name.

Built at `dist/agent-bundle-mcp-names-38ksiKnf.mjs:52-64`:

```js
function buildSafeToolName(params) {
  const cleanedToolName = sanitizeToolName(params.toolName);
  const maxToolChars = Math.max(1, TOOL_NAME_MAX_TOTAL - params.serverName.length - 2);
  const truncatedToolName = cleanedToolName.slice(0, maxToolChars);
  let candidateToolName = truncatedToolName || "tool";
  let candidate = `${params.serverName}__${candidateToolName}`;
  ...
}
```

Transformations applied before the name is formed:

| Transform | Source | Effect |
|---|---|---|
| Unsafe-char replacement | `:8` `/[^A-Za-z0-9_-]/g` → `-` | `read text file!` → `read-text-file-` |
| Server-name sanitize | `:18-28` `sanitizeServerName` | non-alnum → `-`; fallback `mcp` |
| Truncation | `:5-6` `TOOL_NAME_MAX_PREFIX=30`, `TOOL_NAME_MAX_TOTAL=64` | server ≤30; server+tool ≤64 |
| Collision suffix | `:58-63` | duplicate name → `-2`, `-3`, … |

**Live confirmation** (throwaway stdio server, since removed):

```bash
$ openclaw mcp doctor probe2 --probe
[bundle-mcp] tool "weird tool name!" from server "probe2" registered as
             "probe2__weird-tool-name-" to keep the tool name provider-safe.
```

Byte-exact (`od -c`): `p r o b e 2 _ _ w e i r d - t o o l - n a m e -`

Note the sanitization: the model-facing name is **not** the advertised name. A rule keyed
on advertised names (`weird tool name!`) would never fire.

`event.toolName` is additionally lowercased in the hook path:

- `dist/agent-tools.before-tool-call-WtmCO7BO.mjs:2633` — `const toolName = normalizeToolPolicyName(args.toolName || "tool");`
- `dist/tool-policy-shared-BJ7_ouvf.mjs:47-50` — `normalizeToolPolicyName` lowercases and maps aliases (`bash`→`exec`, …)

## 4. Spoofing analysis

**Canonical-name collision is structurally impossible.** Every MCP name contains `__`,
and no core tool id does. `x` + `y` always yields `x__y`, so an MCP tool can never
present as bare `exec`, `read`, or `ls`. A malicious server cannot expand its own reach
by naming a tool.

Two real risks remain:

1. **Wildcard/pattern matching would reintroduce spoofing.** The server controls the
   *tool* half of the name; only the owner controls the *server* half (it is the
   `mcp.servers` config key). Any pattern that matches on the tool half alone — or on a
   prefix/suffix — is nameable by an untrusted server. The matcher must key on the exact
   normalized event name.
2. **Partial parsing.** A classifier that splits on `__` and keys on the tool half only
   can be steered by the server-supplied half. Parse the server half against the
   owner-configured `mcp.servers` set; treat the tool half as untrusted input.

Also exclude `mcp__openclaw__*` — the reserved first-party bridge prefix. A permissive
`mcp__*` rule would sweep in OpenClaw's own tooling alongside untrusted servers.

## 5. Corroborating evidence

Plugin audit log (`/root/.openclaw/nibvok-ai-security-audit.log`), distinct `tool` values:

```
1991  exec
  44  read
  44  conversations_send
  13  terminal
  13  process
```

**Zero MCP entries** — consistent with the hook never firing for MCP calls. (Zero grep
hits for `mcp` and for `mcp__` in the gateway logs likewise.)

## 6. Caveat / not determined

A live end-to-end MCP *tool_call* event through the hook was **not** captured. The
configured `startupnamegenerator` server is unreachable
(`Streamable HTTP error: Error POSTing to endpoint`), and MCP tools are not in this
session's surface, so no in-session invocation was possible. The format above rests on a
live *registration* capture plus the explicit code path
registered name → `runBeforeToolCallHook({ toolName: name })` → `event.toolName` →
matcher. An event-level capture would be belt-and-braces confirmation of the same chain.

## 7. Native-harness note

Native harnesses (Codex-style relay) use a different convention — `mcp__<server>__<tool>`
(`dist/native-hook-relay-DeUTHcYk.mjs:593,608`). The relay merges the same
`getGlobalToolHookMatcherScope("before_tool_call")` (`:994`), so the identical blind spot
applies there.
