# MCP Classifier Extension — Scope (Task A)

**Status:** SCOPE ONLY — **do not build until reviewed (A and B together)**
**Date:** 2026-09-22
**Build:** OpenClaw 2026.9.4 (`3a9d69d`)
**Depends on:** `reports/mcp-tool-name-governance-gap.md`, `reports/mcp-scope-matcher-and-classifier.md`
**Owner decisions applied:** matcher omitted (match-all); classify in handler; server half validated
against owner-controlled `mcp.servers`.

---

## 1. Which servers?

**One is configured on this Gateway: `startupnamegenerator`** (`mcp.servers`, transport
`streamable-http`). No `config/mcporter.json` exists, so there are no mcporter servers.

**It is currently unreachable** — `openclaw mcp probe` fails
(`Streamable HTTP error: Error POSTing to endpoint`). Its tool list therefore **cannot be
enumerated**, and no live MCP call can be captured.

**Scoping consequence:** the profile cannot be authored per-server for this Gateway. It must be
**generic** — driven by the name format and the parameter shape, not by a table of known tools —
with an **optional owner-extensible per-server override** for deployments that do know their servers.

## 2. Which tools? — the profile is name-driven, not tool-list-driven

Because tool lists are discovered at connect time and can change between connects, the classifier
**cannot** hold a list of MCP tool names. It must decide from:

1. the **server half** — validated against owner-controlled config (trustworthy), and
2. the **tool half + `params`** — both attacker-influenced (untrusted).

### 2.1 Detecting an MCP call

An MCP call is a tool name matching `<safeServer>__<rest>` where `<safeServer>` is a
**runtime safe server name**. Two hard requirements, both from the framework's own algorithms:

- **Replicate `sanitizeServerName`, not the config key.** The runtime name is sanitized
  (`[^A-Za-z0-9_-]` → `-`), truncated to **30** chars, and **collision-suffixed** (`-2`, `-3`)
  (`agent-bundle-mcp-names-38ksiKnf.mjs:18-36`).
- **Replicate the declared-set + declaration-order assignment.** `assignSafeServerNames` walks the
  **full declared server set in declaration order** (`:38-45`), so a server's safe name depends on
  its siblings, not on itself. Deriving the name from one config key in isolation is **wrong** when
  two servers sanitize to the same base.

Deriving this in the plugin means reproducing a framework algorithm — a **coupling liability**.
Mitigation: derive once at `register()` and on reload, from `api.config.mcp.servers`; tolerate drift
by failing **closed** (unknown-looking `<x>__<y>` → CONFIRM, never ALLOW).

Two structural facts that make detection safe:

- **No core or plugin tool id contains `__`.** Verified across `dist/*.mjs` — zero matches. So a
  `__`-bearing name is an MCP name with no ambiguity.
- **`mcp__openclaw__*` is reserved** for the first-party bridge (`tool-policy-BFGCxo1a.mjs:5`,
  `cli-shared-B1D4oyOO.mjs:42`). Rule it explicitly rather than letting it fall into the generic path.

### 2.2 Containment: does the classifier trust the name at all?

**No.** The server half selects *which policy applies*; it is never sufficient to authorize a call.
Concretely: a config-listed server is *configured*, not *trusted*. Validation answers "is this a real
configured server?", **not** "is this call safe?".

### 2.3 Parameter shapes — what can actually be classified

MCP arguments are arbitrary structured JSON, differing per server (the existing
`MCP-GUARD-SCOPING.md` Appendix A works this out for the filesystem server). Two tiers:

| Tier | Detection | Verdict |
|---|---|---|
| **Path-bearing arguments** | a string argument that is path-shaped, or an array of them | reuse `classifyReadPath` / `classifyWritePath` unchanged |
| **No path-shaped argument** | anything else (SQL, dates, opaque blobs) | **not classifiable** → default-CONFIRM (Task B) |

The existing path corpus (`ALLOWED_READ_ROOTS`, `DENIED_READ_PATTERNS`, `CONFIRM_READ_PARENTS`,
`classifyWritePath`) is **reusable as-is**. The new work is the tool→class map and path extraction,
not new path rules.

**Path extraction must cover arrays and multiple fields**, mirroring the shell `mv` lesson: e.g.
`move_file(source, destination)` classifies **both**; `read_multiple_files(paths[])` classifies
**every element** with one denied path denying the call. First-element-only is a bypass.

### 2.4 Classification direction (per argument, per tool)

| Direction | Basis |
|---|---|
| read-shaped | the tool's *name/params* suggest reading — never its `readOnlyHint` |
| write-shaped | suggests mutation — never its `destructiveHint` |
| unknown | neither is inferable → CONFIRM |

**Annotations are hints only.** `readOnlyHint`/`destructiveHint` may **raise** scrutiny and may
**never lower** it (owner decision 2; the same conclusion already reached in
`MCP-GUARD-SCOPING.md` §A.2.4).

## 3. Proposed profile — shape

Insert **before** the existing core-tool fall-through in `classifyToolCall`:

```
1. reserved:  name startsWith "mcp__openclaw__"   -> explicit rule (never ALLOW by accident)
2. MCP shape: /^(<safeServer>)__(.+)$/ with safeServer in runtime-safe set
     a. extract path-shaped args (strings + arrays)
     b. if any path      -> worstAction(paths.map(classify{Read,Write}Path))
     c. else if owner map has <server>.<tool> -> apply owner verdict
     d. else             -> CONFIRM  (Task B)
3. else -> existing core path (unchanged)
```

**Ordering matters.** The MCP branch must run before the `EXEC_PAYLOAD_TOOLS` fall-through at
`governance-plugin/classifier.js:1411-1413`, or MCP calls continue to hit `{action: ALLOW}`.

## 4. Owner-extensible override (optional but recommended)

A per-server tool map in plugin config, for deployments that know their servers (e.g. filesystem).

- **Blocker:** the manifest's `configSchema` is `{ "type": "object", "additionalProperties": false }`
  with **no properties** (`governance-plugin/openclaw.plugin.json`). Adding a knob requires a
  **schema change**, which is part of this work, not free.
- Keyed on **`<raw config server name>`** + **`<advertised tool name>`**, resolved to the runtime
  safe name via the same algorithm as §2.1. Never keyed on the model-facing name alone.
- Overrides may only **tighten** (allow is not a legal override value for a path-bearing tool).

## 5. Effort — Task A

| Piece | Effort | Notes |
|---|---|---|
| Safe-server-name derivation (port of framework algorithm) | **medium** | The single biggest correctness risk; depends on `api.config` shape at `register()` |
| MCP name detection + reserved-prefix rule | **trivial** | format is unambiguous |
| Path extraction (strings, arrays, multi-field) | **medium** | shape-driven, not tool-name-driven |
| Reuse of existing path rules | **~none** | corpus carries over |
| Owner override map + config-schema change | **medium** | manifest schema edit |
| Tests (spoof, collision, sanitize, truncation, array bypass) | **medium** | follows `test-classifier.mjs` shape |

**Task A total: medium.** No new rule *families*; the work is name-derivation correctness and
argument-shape extraction.

## 6. Open questions for review

1. **Safe-name derivation duplication** — accept the coupling, or ask the framework for a
   plugin-facing helper? (Feeds the Task C feature request.)
2. **Server half and requester scoping** — the runtime resolves servers per requester; should the
   profile be requester-aware, or config-global? (Leaning config-global + fail-closed.)
3. **Non-path MCP tools** — is default-CONFIRM acceptable as the steady state (many prompts), or do
   we require an owner override to enable a server at all? (Task B covers the switch point.)

## Not verified

- Live MCP `tool_call` event (no reachable server — see gap report §6).
- The exact `api.config` shape at `register()` for a plugin (config read is denied to the CLI here;
  read from type defs, not runtime).
