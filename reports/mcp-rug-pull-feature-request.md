# Feature Request — plugin-facing MCP catalog / tool-schema read

**Status:** DRAFTED, **not filed** — no GitHub identity or `gh` CLI is available on this host, and the
repo has no configured remote. Needs a human to file (or a GitHub connection in Agent Settings).
**Date:** 2026-09-22
**Target:** OpenClaw (upstream), version 2026.9.4 (`3a9d69d`)
**Proposed title:** Expose an MCP tool catalog / schema read to `before_tool_call` plugins

---

## Summary

A `before_tool_call` plugin can see an MCP tool call's **name and arguments**, but cannot see the
server's **tool list or schemas**. That makes one class of MCP attack undetectable from the plugin
layer: the **rug pull**, where a server changes a tool's definition after the agent has learned it.

Two related asks follow — a schema read (for fingerprinting) and a reliable server-name helper (see
§4.2 of `reports/mcp-classifier-profile-scope.md`).

## What is requested

**Primary.** A plugin-facing, read-only way to obtain, for a session/run, the advertised MCP catalog:
per server, the tool names and their input schemas (and, if available, annotations).

Candidate shapes (any one would do):

- a `before_tool_call` event field carrying the tool's server/tool/schema, or
- a plugin API method (e.g. `api.mcp.listCatalog(...)`), or
- a `openclaw/plugin-sdk/*` subpath exporting the existing catalog readers.

**Secondary.** A supported helper to map an `mcp.servers` config key to its **runtime safe server
name** — i.e. an exported form of the `sanitizeServerName` / `assignSafeServerNames` algorithm
currently internal.

## Why it matters

Without the catalog read, a policy layer can enforce *"is this call allowed right now?"* but not
*"is this the same tool I approved yesterday?"*. The second question is the whole of MCP rug-pull
defence, and today it is unanswerable from a plugin.

Without the safe-name helper, a plugin must **re-implement a framework algorithm** (sanitization +
truncation + collision suffixing over the declared set in declaration order). That is a correctness
hazard: two implementations drift, and a drifted policy is a silently unenforced policy.

## Current state (evidence, OpenClaw 2026.9.4)

- The `before_tool_call` event carries `toolName`, `params`, `derivedPaths`, `toolKind`,
  `toolInputKind`, session/agent identity — **no schema**
  (`agent-tools.before-tool-call-*.mjs:2842-2849`).
- Catalog readers exist but are internal
  (`agent-bundle-mcp-manager-api-*.mjs`: `getAdvertisedScopedMcpCatalog`, `peekSessionMcpRuntime`,
  `mergeMcpToolCatalogs`) and are **not** re-exported through any `openclaw/plugin-sdk/*` subpath
  (checked against the 338-entry export map; the only MCP-ish subpath, `plugin-sdk/codex-mcp-projection`,
  is Codex-harness-specific and exposes no catalog read).
- Name construction is internal (`agent-bundle-mcp-names-*.mjs:52-64` `buildSafeToolName`,
  `:38-45` `assignSafeServerNames`).

## Prior art in-repo

- `agent-bundle-mcp-harness-*.mjs` already consults the advertised catalog per session, so the data
  exists at the right lifecycle point — the gap is **exposure**, not availability.
- `dist/mcp-codex-tool-approval-*.mjs` already consumes annotations for approval decisions, which
  shows annotations survive to a policy-adjacent layer.

## Alternatives considered

- **Read the catalog out-of-process** (CLI/IPC). Rejected for a per-call policy: adds latency and a
  second trust boundary, and the catalog is session-scoped, not global.
- **Re-implement the naming algorithm in the plugin.** Works, but is the drift hazard in §"Why it
  matters" — acceptable only as a stopgap (which is what we plan).
- **Use annotations as the authorization basis.** Rejected outright: annotations are server-supplied.

## Notes for triage

- Requested capability is **read-only** and needs no new write surface.
- It is **not** the same as `registerMcpServerConnectionResolver` (that binds a *declared* server's
  transport; it is not a catalog read).
- If the maintainers prefer not to expose the raw catalog, an **event-field** carrying just the
  calling tool's schema would satisfy the primary ask.

## Interim position (what we ship without it)

Documented as a limitation: MCP tools are governed **by name and arguments at call time**, and
**not** by definition-change over time. See `MCP-GAP.md` §7. Rug-pull detection is deferred until the
framework exposes the surface — explicitly **not** built on a private/internal API, which would break
on upgrade.
