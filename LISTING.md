# NIBVOK AI Security

**Runtime policy enforcement for OpenClaw agents — every tool call is allowed,
confirmed, or denied *before* it runs.**

Version `0.1.0` · Plugin id `nibvok-ai-security` · Category `security`
Zero-config · One hook · 284 tests

---

## ClawHub listing fields

**Description** — 92 characters (limit 120):

> Runtime enforcement for OpenClaw agents. Allow, confirm, or deny every tool call. 284 tests.

> An earlier draft of this line ended *"Hash-chained audit trail."* **That claim
> is false and was removed.** There is no hash chain; see *What it honestly does
> not do* below. A listing that promises tamper-evidence the code does not
> provide is the kind of claim this project exists to catch.

**Search phrases** (ClawHub indexes the description for vector search):

`agent security` · `tool call enforcement` · `OpenClaw governance` ·
`AI guardrails` · `prevent agent damage` · `runtime policy engine` ·
`before_tool_call hook` · `human approval for agent actions`

---

## The problem

An agent with shell access is an agent that can delete a directory, force-push
over a branch, write outside its workspace, or spend money. The usual answer is
a prompt telling it to be careful — which is a request, not a control.

OpenClaw already ships two mechanisms that look like policy, and each stops one
step short:

- **`tools.deny`** matches **tool ids only**. It can block the `exec` tool
  outright. It cannot allow `pytest` while blocking `git push --force` — both
  are `exec`.
- **`tools.exec.mode`** is a **single global posture** (`deny` / `allowlist` /
  `ask` / `auto` / `full`). It applies to every command equally.

Neither can express the sentence that actually matters:

> *"Confirm `git push --force`, deny `rm -rf /`, and let `pytest` run silently."*

That requires reading the **command**, not just the tool name — and a
`before_tool_call` hook is the only place in the request path where that
decision can be made per call, before execution.

## What it does

NIBVOK AI Security registers one `before_tool_call` handler and classifies each
call into exactly one of four outcomes:

| Decision | Meaning |
|---|---|
| `allow` | run silently |
| `allow-log` | run, and write an audit line |
| `confirm` | block on a human approval dialog |
| `deny` | refuse outright, with a stated reason |

It is not a scanner, not a linter, and not a dashboard. It is an **enforcement
point**.

## What makes it different

**The decision is per call, not per tool.** The classifier reads the actual
command or path, so `pytest` can run silently while `git push --force` prompts
and `rm -rf /` is refused — within the same `exec` tool.

**Approval is scoped and bounded.** Confirming one *class* of action (say, a
destructive delete) can be remembered **for that session only**. A different
class still prompts. Trust is in-memory by design and ends when the gateway
restarts; it is never written to disk.

**A spend ceiling is enforced, not suggested.** Any transaction at or above
`$500` (configurable) requires confirmation. This is a hard floor in the
classifier, not a nudge in a prompt.

**Deny is terminal.** A denied call has no "allow this time" path. There is no
approval to remember, because there is nothing to approve — the only route is a
different approach.

**Refusals are recorded.** Every decision is appended to a JSON Lines audit
log, so the reasoning is reviewable after the fact rather than inferred.

## Proof

The behaviour is covered by **284 tests** across three suites:

| Suite | Tests | Covers |
|---|---|---|
| `test-classifier.mjs` | 236 | decision logic, path/host/spend classification, deny and confirm rules |
| `test-hook.mjs` | 21 | hook registration, decision mapping, approval and audit wiring |
| `test-session-trust.mjs` | 27 | session-scoped trust: grant, scope, and restart expiry |

Run them yourself:

```bash
node test-classifier.mjs
node test-hook.mjs
node test-session-trust.mjs
```

The package also ships **eighteen case studies** (`INCIDENTS.md`) — real
failures found while building and running this layer, each of which changed the
code or the process. They are kept because the *reasoning* is the reusable part.
Several are failures *of verification itself*: a policy that reported healthy
while unenforced, a test that compared a setting to itself, a deny list that
covered the verbs it named but not the effect of a synonym it did not.

## Install

```bash
openclaw plugins install <path-or-clawhub-spec>
```

The plugin activates on startup and needs **no configuration**. Optional
environment overrides exist for deployments whose paths differ from the
defaults:

| Variable | Purpose | Default |
|---|---|---|
| `ASF_WORKSPACE_ROOT` | the agent workspace | `/root/.openclaw/workspace/` |
| `NIBVOK_AI_SECURITY_PLUGIN_ROOT` | this plugin's own directory | resolved from its own module URL |
| `ASF_ARTIFACT_ROOT` | generated artifacts | `/var/asf/artifacts/` |
| `ASF_LOG_ROOT` | deployment logs | `/var/log/asf/` |
| `NIBVOK_AI_SECURITY_SPEND_CEILING_USD` | transaction ceiling | `500` |

## What it honestly does not do

- **The audit log is not tamper-evident.** It is append-only JSON Lines. There
  is no hash chain and no retention policy. Anything with write access to the
  log file can alter it — this is a record, not a notary.
- **Session trust does not survive a restart.** Deliberate: trust that
  outlives the process is trust nobody re-approved.
- **It sees the call, not the outcome.** The classifier judges a tool call
  before it runs. It cannot know that a command did something other than what
  it appeared to do.
- **It is a hook-only plugin.** That is a supported OpenClaw compatibility
  path, not an oversight; it has not migrated to explicit capability
  registration.

## Who it is for

Anyone running an OpenClaw agent that can touch a real system — a filesystem,
a git remote, a payment API — and who wants the dangerous calls to stop for a
human rather than depend on the model choosing well.

---

*Built and run in production on the author's own agent. The case studies are
published with it on purpose: a security layer that cannot show you its
failures is asking for trust instead of earning it.*
