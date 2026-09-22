# MCP Matcher Extension + Classifier Profile — Scope

**Status:** scope only — **do not build until reviewed**
**Date:** 2026-09-22
**Build:** OpenClaw 2026.9.4 (`3a9d69d`)
**Depends on:** `reports/mcp-tool-name-governance-gap.md`
**Governed plugin:** `ai-security-force` (`/root/.openclaw/workspace/ox88/governance-plugin/index.js`)

---

## Bottom line

**The matcher cannot be extended with exact MCP tool names.** MCP tool names are
discovered from the remote server at connect time, are not present in config at plugin
registration, and can change between connects. An exact-name allowlist is therefore
unknowable at registration, and wildcards are rejected by the framework.

The workable shape is the inverse of the owner's initial framing:

1. **Matcher:** *omit* it (match-all), so the hook receives every tool call including MCP.
2. **Classifier:** key on the exact `<server>__<tool>` format **inside** the handler,
   validating the server half against the owner-controlled `mcp.servers` set.

The owner's "no wildcards / must key on the exact format" constraint is satisfied — but in
the classifier, not the matcher. The matcher has no format-matching capability at all.

---

## A. Matcher extension — findings and effort

### A1. Framework constraints (all verified)

| Constraint | Evidence |
|---|---|
| Exact lowercase set membership only | `hook-runner-global-BhDCl4qm.mjs:55-58` |
| `"*"` explicitly rejected | `hook-runner-global-BhDCl4qm.mjs:37` |
| Omission is the *only* match-all form | `hook-runner-global-BhDCl4qm.mjs:32` |
| Validated once at registration | `loader-runtime-load-DpX1CRjH.mjs:4104`, `:4107` |
| No matcher-mutation API | no `updateHookMatcher`/`setHookMatcher` in `dist/`; only `typedHooks.push` |
| Matcher is optional | `loader-runtime-load-DpX1CRjH.mjs:4104` — `opts?.matcher` |

### A2. Why exact names cannot work

MCP names are built at connect time from remote-advertised tool names:

- `agent-bundle-mcp-names-38ksiKnf.mjs:52-64` — `<safeServerName>__<sanitizedToolName>`
- `agent-bundle-mcp-materialize-Df1MHkc-.mjs:158-166` — name assigned during catalog projection

At `register()` time the plugin has `api.config` (including `config.mcp.servers`), so it can
enumerate **configured servers** — but never their **tool lists**, which arrive later over
the transport. Even the server half is not a plain config key: it is sanitized, truncated
to 30 chars, and collision-suffixed (`-2`, `-3`) at runtime.

**Conclusion:** a static exact matcher covering MCP tools is impossible. Enumerating
`<server>__*` requires wildcards, which the framework rejects.

### A3. Viable options

| Option | Mechanism | Trade-off |
|---|---|---|
| **A-omit (recommended)** | Drop `matcher`; classify by prefix in the handler | Hook fires for **every** tool call; classifier must stay fast and keep the ALLOW fall-through |
| A-dynamic (unproven) | Re-register hooks after MCP discovery | Needs a registry that accepts re-registration; `definePluginEntry` has `reload` + `api.registerReload`, but **no verified** path re-runs `register()` per connect |
| A-status-quo | Leave matcher as-is | MCP stays ungoverned — rejected |

### A4. Effort — A

- Remove the 12-name matcher from `governance-plugin/index.js:130-145` (and the mirror at
  `packages/nibvok-ai-security/index.js:166-180`): **trivial**.
- Confirm no behaviour regression from the wider hook surface (perf + classifier
  fall-through): **small** — the classifier already returns ALLOW for unknown names.
- Update `test-hook.mjs` matcher expectations: **small**.

**A total: small.** One file, one block, plus tests. The risk is not effort; it is
covering the widened surface safely (see B).

---

## B. MCP classifier profile — scope and effort

### B1. What the hook actually receives

The event carries `toolName`, `params`, `derivedPaths`, `toolKind`, `toolInputKind`, plus
session/agent identity (`agent-tools.before-tool-call-WtmCO7BO.mjs:2842-2849`). It does
**not** carry MCP server/tool metadata — `getPluginToolMeta(tool).mcp` is used by the
*diagnostic* path (`agent-tools.before-tool-call-WtmCO7BO.mjs:317-320`), not the plugin
event. `toolKind` is only set for code-mode exec (`code-mode-control-tools-Erzi_uv9.mjs:93-109`).

**Therefore the profile must reconstruct server and tool from `event.toolName` alone.**

### B2. Proposed profile logic

```
1. name = event.toolName (already lowercased by normalizeToolPolicyName)
2. If name starts with "mcp__openclaw__"  -> reserved first-party bridge; explicit rule
3. Else if name matches /^<safeServer>__<rest>$/ where safeServer is in the set of
   RUNTIME-safe server names derived from config.mcp.servers:
      a. tool half = untrusted input; never used as the sole discriminator
      b. apply path rules to params (carry over classifyReadPath / classifyWritePath)
      c. apply MCP tool classification (see B3)
4. Else -> existing behaviour (core tool sets, then ALLOW)
```

Key correctness points:

- **Validate the server half against owner-controlled config**, not against the name
  string. The server half is the only half an attacker does not choose.
- **Match the runtime *safe* server name**, not the raw config key — `sanitizeServerName`
  may transform it and collision-suffix it (`agent-bundle-mcp-names-38ksiKnf.mjs:18-28`).
- **Exclude `mcp__openclaw__*`** — reserved bridge prefix.

### B3. Tool-to-class map — the genuinely new work

This is net-new and cannot be inferred from the name. Options:

- **Annotation-driven:** MCP tools carry `readOnlyHint` / `destructiveHint` /
  `openWorldHint` (`mcp-codex-tool-approval-u1CcvKx0.mjs:25-26,38-40`). These are
  **server-supplied and therefore untrusted** — usable as a hint, never as authority.
- **Default-deny-unknown:** unknown MCP tools → CONFIRM, not ALLOW. This inverts the
  current fail-open `{action: ALLOW}` fall-through, which is the single most important
  change: an unclassified MCP tool must not be silently allowed.
- **Owner allowlist:** an explicit `mcpToolPolicy` map in plugin config.

**Recommendation:** default-CONFIRM for unknown MCP tools + optional owner allowlist. Do
not rely on server-supplied annotations for the verdict.

### B4. Rug-pull defense — feasibility

The requirement: fingerprint every tool on connect, compare to baseline.

What exists:
- The harness consults the advertised catalog per session
  (`agent-bundle-mcp-harness-D3882cvQ.mjs:1` imports `getAdvertisedScopedMcpCatalog`).
- Session overrides `mcpServers` / `mcpToolsDeny` are enforced *before* the hook
  (`agent-bundle-mcp-runtime-config-BV_S7nt7.mjs:54`, `effective-tool-policy`).

What is **not** established:
- **No plugin-facing API** was found to read the MCP catalog or tool schemas. The catalog
  helpers live in `agent-bundle-mcp-manager-api-*.mjs`, which is **not** exported to
  plugins, and `PluginRuntime` exposes no MCP catalog surface. `registerMcpServerConnectionResolver`
  binds a transport for a *declared* server; it is not a catalog read.
- The hook event carries no schema, so fingerprinting **cannot** be done from
  `before_tool_call` alone.

**Conclusion:** rug-pull fingerprinting needs an evidence source the plugin may not have
today. This is the highest-uncertainty item and needs a spike before it is scoped as
buildable. Do not design the profile assuming it is available.

### B5. Effort — B

| Piece | Effort | Confidence |
|---|---|---|
| Name-format parse + server validation | small | high |
| Path-rule carry-over (`read`/`write` semantics inside MCP params) | medium | medium — depends on each tool's param shape; MCP schemas are arbitrary |
| Default-CONFIRM for unknown MCP tools | small | high |
| Owner allowlist config + schema | medium | high |
| `mcp__openclaw__` exclusion rule | trivial | high |
| Rug-pull fingerprint + baseline | **unknown** | low — blocked on catalog access (B4) |
| Tests (spoof-resistance, collision, sanitize, truncation) | medium | high |

**B total: medium**, *excluding* rug-pull, which is **unscoped pending a catalog-access
spike**.

---

## Risks

1. **Fail-open is the core defect.** The classifier's `{action: ALLOW}` fall-through is
   correct for unknown *core* tools and wrong for unknown *MCP* tools. The profile must
   special-case MCP rather than relying on the default.
2. **Widened hook surface (option A-omit).** Every tool call now reaches the plugin. Keep
   the classifier path cheap and side-effect-free.
3. **Two copies.** `governance-plugin/` is the loaded plugin; `packages/nibvok-ai-security/`
   is the published copy. Any change must land in both, or they diverge.
4. **Server-half trust.** Only the owner-controlled config half is trustworthy; the tool
   half is attacker-choosable.
5. **Rug-pull may be unimplementable** without a new framework surface (B4).

## Recommendation

Proceed with A-omit + B2/B3 (default-CONFIRM for unknown MCP tools), which closes the
governance gap with bounded effort and no framework changes. Run a **spike on MCP catalog
access** before committing to rug-pull; treat it as a separate, framework-dependent item.

## Not verified

- Live end-to-end MCP `tool_call` event through the hook (no reachable server — see gap
  report §6). The event payload shape above is from code reading, not capture.
- Whether hooks can be re-registered post-discovery (A-dynamic).
- Whether any plugin API can read MCP tool schemas (B4) — not found, not proven absent.
