# MCP Fail-Closed Behaviour — Scope (Task B)

**Status:** SCOPE ONLY — **do not build until reviewed (A and B together)**
**Date:** 2026-09-22
**Depends on:** `reports/mcp-classifier-profile-scope.md` (Task A)
**Owner decision 2:** unknown core tool → ALLOW (correct); unknown MCP tool → CONFIRM (fail-closed).

---

## 1. The defect, precisely

`classifyToolCall` ends in a **fail-open** default. Any tool name not in
`EXEC_PAYLOAD_TOOLS` returns ALLOW:

```
governance-plugin/classifier.js:1411-1413
  if (!EXEC_PAYLOAD_TOOLS.has(tool)) {
    return { action: ALLOW };
  }
```

That is **correct for unknown core tools** — a new OpenClaw core tool must not break the agent — and
**wrong for MCP tools**, because an MCP tool name is chosen by a third-party server. Fail-open there
means any server can mint a tool with an unrecognised name and be silently allowed.

Today MCP calls never reach this line (the matcher filters them out — see the gap report). **Once the
matcher is omitted (Task A), they will reach it**, and without this change every MCP call would be
silently ALLOWed. A and B are therefore **one atomic change**: omitting the matcher without the
fail-closed branch would *worsen* the posture.

## 2. Where the switch happens

Single insertion point: **before** the `EXEC_PAYLOAD_TOOLS` fall-through
(`classifier.js:1411`), inside the MCP branch defined in Task A §3.

```
classifyToolCall(toolName, params, derivedPaths)
│
├─ messaging tools            → ALLOW_LOG          (unchanged)
├─ WRITE_TOOLS                → classifyWritePath  (unchanged)
├─ read / ls                  → classifyReadPath   (unchanged)
│
├─ ★ MCP BRANCH (new)  ─────────────────────────────────────────
│    name matches <safeServer>__<tool> with a validated server half?
│      yes → paths found?      → worstAction(path rules)   [may be ALLOW]
│            no paths, owner override?  → owner verdict
│            no paths, no override      → CONFIRM          ← FAIL-CLOSED
│      no  → fall through
│
└─ EXEC_PAYLOAD_TOOLS?        → exec rules         (unchanged)
   else                       → ALLOW              (unchanged: unknown CORE tool)
```

The two ALLOW paths are now **explicitly distinct**: unknown *core* tool → ALLOW; unknown *MCP*
tool → CONFIRM. That distinction is the whole of Task B.

## 3. The decision matrix

| Input | Verdict | Rationale |
|---|---|---|
| MCP call, path argument(s), all allowed | ALLOW (or ALLOW_LOG if logged root) | existing path corpus decides |
| MCP call, path argument denied | DENY | existing path corpus decides |
| MCP call, path argument outside allowlist | CONFIRM | existing `confirm-read` / `outside-write` classes |
| MCP call, **no path-shaped args**, owner override = allow | ALLOW | explicit owner decision |
| MCP call, **no path-shaped args**, owner override = confirm | CONFIRM | explicit owner decision |
| MCP call, **no path-shaped args**, no override | **CONFIRM** | **fail-closed default (new)** |
| MCP-shaped name, server NOT in config | **CONFIRM** | unknown server → fail closed |
| `mcp__openclaw__*` | explicit rule | reserved first-party bridge |
| Unknown **core** tool | ALLOW | unchanged — must not break the agent |

## 4. Wiring the CONFIRM into the existing machinery

CONFIRM is already a first-class action; the new branch reuses it rather than inventing a path.

| Element | Location | Change |
|---|---|---|
| Action value | `classifier.js:330` `ACTION_RANK = { allow:0, "allow-log":1, confirm:2, deny:3 }` | none — `confirm` exists |
| Aggregation | `classifier.js:1046-1052` `worstAction` | none — CONFIRM already outranks ALLOW |
| Reason → class | `classifier.js:1289-1298` `confirmClass(reason)` | **add** an `mcp-unknown` pattern |
| Session trust | `classifier.js:1309-1316` `SESSION_TRUSTABLE_CLASSES` | **decide** — see §5 |

The reason string must map to a class in `confirmClass`, or the approval prompt renders with
`sessionScoped = false` and is one-shot only (index.js:96-99, 116-125).

### 4.1 Approval payload

The hook already builds the prompt from `reason` + `cmd` (`index.js:73-129`). For MCP there is **no
command string** — `event.params.command` is undefined. The prompt would render:

```
description: "unknown MCP tool ... \n\nCommand: "     ← blank
```

**Fix required:** use the tool name (and a bounded, redacted preview of `params`) as the description
subject for MCP calls. Do **not** dump raw arguments — that is a payload-logging decision the owner
already ruled on for the proxy (`MCP-GUARD-SCOPING.md` §5, Option B). Keep the same shape: decision +
tool + rule, no payload.

## 5. Session-trust decision (needs owner input)

Should `mcp-unknown` be session-trustable (offer "allow-always")?

- **Yes** → one approval covers subsequent unknown MCP calls **from that server** for the session.
  Ergonomic; but it converts a per-call gate into a blanket server grant.
- **No** → every unclassified MCP call prompts. Safe; noisy enough that operators may disable the
  layer (the exact failure mode `MCP-GUARD-SCOPING.md` §6 warns about).

**Recommendation: NOT session-trustable by default.** An unknown MCP tool is an unknown capability;
a session-wide grant on it is the same mistake as trusting a self-declared identity. If noise proves
unacceptable, the correct remedy is an explicit owner override (Task A §4), which is a deliberate act
— not a remembered approval.

Note the contrast with `spend` (excluded from session trust at `classifier.js:1300-1308`) — same
reasoning: a class whose blast radius is not bounded must stay one-shot.

## 6. Edge cases

| Case | Handling |
|---|---|
| Tool name contains `__` but no matching server | CONFIRM (fail closed), not ALLOW |
| Server in config but currently disconnected | still CONFIRM — config presence ≠ safety |
| Same tool name from two servers | distinct names (`a__x`, `b__x`); policy is per-server |
| Collision-suffixed safe name (`srv-2__x`) | resolve via the Task A §2.1 derivation |
| Nested/malformed params (deep JSON, huge blobs) | treat as "no path found" → CONFIRM; bound any preview |
| `derivedPaths` present | already threaded through `classifyToolCall`'s 3rd arg |

## 7. Test additions

Follow `test-classifier.mjs` shape (`t(name, tool, params, expected)`):

1. unknown MCP tool, no paths → **confirm**
2. MCP read tool with allowed path → **allow**
3. MCP read tool with `/root/.ssh/id_rsa` → **deny**
4. MCP write tool outside workspace → **confirm** / **deny** per existing rules
5. MCP array arg with one denied path → **deny** (proves no first-element bypass)
6. MCP-looking name, server not configured → **confirm**
7. unknown **core** tool → **allow** (regression guard — the distinction must hold)
8. `mcp__openclaw__*` → explicit expected verdict
9. spoof: server naming a tool `exec` → resolves to `<srv>__exec`, does **not** hit exec rules
10. `mcp-unknown` **not** in `SESSION_TRUSTABLE_CLASSES`

## 8. Effort — Task B

| Piece | Effort |
|---|---|
| Insert MCP fail-closed branch | trivial |
| `confirmClass` pattern for `mcp-unknown` | trivial |
| Approval-description fix for MCP (no `command`) | small |
| Session-trust decision + wiring (§5) | small (pending owner) |
| Tests (10 cases) | medium |

**Task B total: small.** It is one branch, one regex, one prompt fix, plus tests. The careful part is
**A and B landing together**.

## 9. Open questions for review

1. **§5 session-trust** — confirm NOT trustable by default?
2. **Override semantics** — may an owner override say `allow` for a non-path MCP tool, or only
   `confirm`/`deny`? (Leaning: allow is legal only for explicitly named `<server>.<tool>`.)
3. **Noise budget** — if a real server has many non-path tools, default-CONFIRM will be loud. Is that
   acceptable, or should shipping require an override?

## Not verified

No live MCP call was available to observe the rendered approval prompt (configured server
unreachable). The blank-`command` issue in §4.1 is read from code (`index.js:80-86`), not observed.
