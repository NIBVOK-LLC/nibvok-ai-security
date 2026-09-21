# OWASP ASI Mapping — NIBVOK AI Security

Mapping of the [OWASP Agentic Security Initiative (ASI)] categories to the
specific NIBVOK rules that address them, with **honest coverage ratings**.

This document exists because a security product that claims coverage it does not
have is the problem it was built to catch. Every rating below is either **Full**,
**Partial**, or **None**, and every **Partial** and **None** states its gap.

The ratings describe **what this layer actually does today**, verified against
`classifier.js` and pinned by `test-classifier.mjs`. They are not a roadmap and
not an aspiration.

> **Scope of the layer.** NIBVOK AI Security is a `before_tool_call` hook. It
> sees the *tool call the agent is about to make* — tool name, params, derived
> paths — and returns allow / allow-log / confirm / deny. It does **not** see the
> prompt, the model's reasoning, or the tool's *output*. That boundary sets the
> ceiling on every rating below: categories defined in terms of prompt content
> or model output are out of reach by construction, and are marked `None` rather
> than dressed up.

---

## Summary

| ASI | Category | Coverage |
|---|---|---|
| ASI-01 | Prompt Injection | **None** |
| ASI-02 | Tool Misuse | **Partial** |
| ASI-03 | Privilege Escalation | **Partial** |
| ASI-04 | Data Exfiltration | **Partial** |
| ASI-05 | Insecure Output Handling | **Partial** |
| ASI-06 | Excessive Agency | **Partial** |

No category is rated **Full**. That is a deliberate choice: a lexical,
best-effort classifier over command strings cannot honestly claim full coverage
of any agentic-security category. The honest headline is **four Partial, two
None**, with the gaps named.

---

## ASI-01 — Prompt Injection

**Coverage: None.**

**What the category is.** Untrusted content (a web page, an email, a file, a tool
result) carries instructions that hijack the agent into acting against its
operator's intent.

**Why None.** This layer never sees prompt or context content. It classifies the
*tool call*, not the reasoning that produced it, so it cannot detect that a call
was injection-driven. There is no rule to point at, and claiming one would be
false.

**What it does do — containment, not coverage.** A successful injection still
has to get past every deny and confirm rule below. Injection changes *why* the
agent acts, not *what the layer evaluates*: a hijacked agent trying `rm -rf /`
is denied exactly like an un-hijacked one. This is blast-radius reduction, and
it is **not** coverage of ASI-01. It is listed here so the boundary is explicit,
not so it can be counted.

**Gap to close, if you need ASI-01 covered:** injection detection belongs
upstream of this layer — provenance tagging on untrusted content, an
instruction/data boundary in the prompt, or a model-side classifier. None of
those are this plugin.

**Evidence:** the layer's own design rule 3 and INCIDENTS.md #3 document the
inverse error — matching *text that names* something rather than the thing
itself — which is the same class of mistake as treating injected text as
instructions.

---

## ASI-02 — Tool Misuse

**Coverage: Partial.**

**What the category is.** A legitimate tool used to do something it should not —
deleting a directory, force-pushing over a branch, dropping a table.

**Rules that address it:**

| Rule (reason string) | Decision | What it catches |
|---|---|---|
| `rm -rf targeting the filesystem root` | deny | `rm -rf /` in any quoting form, incl. `bash -c "rm -rf /"` |
| `rm -rf targeting a system directory` | deny | whole-directory wipes of `/etc`, `/usr`, `/var`, `/home`, … |
| `destructive delete (rm)` | confirm | any other `rm`, with a narrow auto-allow for routine cleanup |
| `destructive git operation` | confirm | `push --force`, `reset`, `clean -fd`, `branch -D`, `restore` |
| `database drop/destructive restore` | confirm | `DROP TABLE`, destructive restore |
| `write to system path` / `mutation of system path` | deny | writes and mutations under `/etc`, `/usr`, `/bin`, … |
| `write outside the workspace` | confirm | writes outside the allowed write roots |

**Tool-surface coverage.** `exec`, `process`, and `terminal` are all classified
through one `execPayloadOf` path, so identical bytes get the same verdict
regardless of which tool carries them (INCIDENTS.md #23 — previously `exec`
denied while `terminal`/`process` allowed).

**Gap.** Classification is **lexical and best-effort**. It does not parse the
shell, resolve variable expansion, follow symlinks, or understand `$(…)`
substitution. A sufficiently creative command can evade a regex. The masks that
stop prose from firing rules (quoted literals and heredocs treated as data) are
the same mechanism an attacker could try to abuse; the execution-context guards
are what keep executed literals in scope.

**Evidence:** `test-classifier.mjs`; INCIDENTS.md #1–#4.

---

## ASI-03 — Privilege Escalation

**Coverage: Partial.**

**What the category is.** The agent obtaining access it was not granted —
reading credential material, rewriting its own guardrails, or changing the
policy that constrains it.

**Rules that address it:**

| Rule (reason string) | Decision | What it catches |
|---|---|---|
| `read of protected account secret material (…)` | deny | password-hash and auth files by **path segment**, incl. the `cd`-then-bare-name bypass |
| `attempt to disable or rewrite the governance layer` | deny | tampering with the layer's own config/tree |
| `write to protected secret material` | deny | writing over credential stores |
| `read of protected secret material (…)` | deny | secret stores and key material |
| `reading a stored secret value back out` | deny | `secrets store get/show/read` |

**Gap.** There is no user, role, or capability model — "privilege" here means
*filesystem and config authority*, which is what a single-tenant agent has. The
layer cannot reason about OS users, sudoers semantics beyond the file, or
capability elevation through a program it does not recognise.

**Evidence:** the account-secret family is INCIDENTS.md #22, which specifically
closed a path where `/etc/shadow` inherited `/etc/passwd`'s session-trustable
CONFIRM tier, so one `allow-always` made the root password hash readable for the
rest of a session. Those paths are now DENY with no approval path.

---

## ASI-04 — Data Exfiltration

**Coverage: Partial.**

**What the category is.** Getting data — especially credentials — off the machine
or to an unauthorised destination.

**Rules that address it:**

| Rule (reason string) | Decision | What it catches |
|---|---|---|
| `read of protected secret material (…)` | deny | reading credential material at all |
| `read outside the read allowlist (…)` | confirm/deny | reads beyond the allowlisted roots |
| `external API call to allowlisted host` | allow-log | egress to `APPROVED_HOSTS`, recorded |
| `outbound message send` | allow-log | `conversations_send`, `conversations_turn`, `sessions_send` |
| `secrets store: approved host grant` | allow | the one sanctioned credential-substitution form |
| `token/key in a query string` (redaction rule) | — | query-string credential forms in archived transcripts |

**Gap.** Two real ones, stated plainly:

1. **No payload inspection.** The layer decides *whether* an egress call may
   happen, not *what it carries*. A read that is allowed, then sent to an
   allowlisted host, is not examined for content.
2. **The allowlist is a destination control, not a channel control.** Hosts not
   on `APPROVED_HOSTS` confirm, but channels this layer does not model (raw
   sockets from a permitted program, DNS, a subprocess doing its own networking)
   are outside its view.

**Evidence:** `APPROVED_HOSTS` in `classifier.js`; INCIDENTS.md #7 (silent
account drift, where the *right* app used the *wrong* account).

---

## ASI-05 — Insecure Output Handling

**Coverage: Partial.**

**What the category is.** Model output (or tool output) consumed by a downstream
system without adequate handling — executed as code, rendered as HTML, or fed to
a shell.

**Rules that address it:**

| Rule (reason string) | Decision | What it catches |
|---|---|---|
| `write to system path` / `write outside the workspace` | deny/confirm | model-directed writes that would place output somewhere it is executed or served |
| *(masking, not a reason string)* | — | `inertSpans`: quoted literals and heredoc bodies are **data**, not invocations, unless executed |

**What "Partial" means here, precisely.** The `inertSpans` mechanism is exactly
this category's shape — *do not treat text as a command unless the shell will
run it*. It is what stops `echo "rm -rf /"` (a display) from being mistaken for
`bash -c "rm -rf /"` (an execution), and equally what keeps the latter in scope.
That is a meaningful, tested property.

**Gap.** This layer governs **tool calls**, not rendered output. If model output
is written to an HTML file a browser will render, this plugin does not sanitize
it — XSS in a downstream UI is **not covered**. There is no HTML sanitizer, no
output encoder, and no template-safety check here, and the document does not
pretend otherwise.

**Evidence:** the two-mask design (`inertSpans` vs statement operands) in
`classifier.js`, design rule 7; INCIDENTS.md #13–#16 on data-vs-invocation.

---

## ASI-06 — Excessive Agency

**Coverage: Partial.**

**What the category is.** An agent with more autonomy or capability than its task
warrants — broad permissions, unbounded actions, approvals that silently widen.

**Rules that address it:**

| Mechanism | Effect |
|---|---|
| deny / confirm / allow per call | least-privilege at the call boundary, not at the tool-grant boundary |
| `SESSION_TRUSTABLE_CLASSES` | approval is **class-scoped**, never blanket; `spend` is excluded |
| session trust lifecycle | in-memory; ends on Gateway restart |
| `SPEND_CEILING_USD` (default 500) | outbound expenditure at or above the ceiling confirms; inbound revenue does not |
| deny has no approval path | a deny cannot be widened to "allow for this session" |
| **starter policies** (Development / Production / Read-Only / Research / Locked-Down) | preset postures so the default is not "everything on" |

**Gap.** The layer **gates** capability; it does not **remove** it, and it cannot
force a posture. A user who answers `allow-always` on every prompt erodes the
benefit, and a permissive preset is still a choice. There is no autonomy budget
(no "N actions per hour"), no task-scoped capability grant, and no cross-session
approval ledger. What exists is a bound that fails closed and is recorded.

**Evidence:** `SESSION_TRUSTABLE_CLASSES` and the `spend` exclusion in
`classifier.js`; INCIDENTS.md #6 (a policy silently unenforced while reporting
healthy).

---

## How to read this document

- **Full** would mean the category is comprehensively addressed with no known
  bypass. Nothing here is rated Full, because a lexical classifier cannot
  honestly earn it.
- **Partial** means real, tested rules address the category, with a named gap.
  The gap is the point — it is what an integrator needs to know.
- **None** means the category is outside this layer's visibility by
  construction. It is stated rather than quietly omitted.

If you need a category covered more strongly than rated here, the gap paragraph
is the honest starting point for what would have to be built.

[OWASP Agentic Security Initiative (ASI)]: https://genai.owasp.org/
