# NIBVOK AI Security

**Runtime enforcement for OpenClaw agents.** Allow, confirm, or deny every tool
call — before it runs.

A runtime policy-enforcement layer for OpenClaw agents.

> **Status:** running in production on the author's own agent. Version `0.1.0`.
> Plugin id `nibvok-ai-security`; categories `["security"]`.

---

## What it is

NIBVOK AI Security is an OpenClaw **plugin** that inspects every tool call an agent
is about to make and decides, per call:

| Decision | Meaning |
|---|---|
| `allow` | run silently |
| `allow-log` | run, and write an audit line |
| `confirm` | block on a human approval dialog |
| `deny` | refuse outright, with a reason |

It is not a scanner, not a linter, and not a dashboard. It is an **enforcement
point** in the request path.

## Why it exists

OpenClaw already ships two mechanisms that look like policy:

- **`tools.deny`** matches **tool ids only**. It can block the `exec` tool. It
  cannot allow `pytest` while blocking `git push --force` — both are `exec`.
- **`tools.exec.mode`** is a **single global posture** (`deny` / `allowlist` /
  `ask` / `auto` / `full`). It applies to every command equally.

Neither can express the sentence that actually matters:

> *"Confirm `git push --force`, deny `rm -rf /`, and let `pytest` run silently."*

That requires reading the **command**, not just the tool name. A
`before_tool_call` hook is the only place in OpenClaw where that decision can be
made per call, before execution.

### Why not the bundled `policy` plugin

`@openclaw/policy` is a **different thing**. It audits configuration drift and
emits attestation hashes. By its own documentation it *"does not enforce tool
calls or rewrite runtime behavior at request time."* It will tell you your config
changed. It will not stop anything. Enforcement lives here.

## What it catches that simpler matchers miss

Four failure modes, each found by a real bypass during development and each
fixed in the classifier — see **[INCIDENTS.md](INCIDENTS.md)** #1–#4.

| Failure mode | Why naive matching misses it | What the rule does instead |
|---|---|---|
| **Over-broad write rules** (#1) | a loosely anchored rule blocks nearly every command, so it gets turned off | scope the rule to a root, so ordinary work never prompts |
| **Reads conflated with writes** (#2) | `ls x` and `echo > x` share a path but not a meaning; treating them alike either blocks inspection or permits mutation | decide on **verb + path**; a bare `/` is its own case |
| **String-anchored secrets** (#3) | matching the filename *text* fires on a comment that merely mentions the file, and misses the real file under another spelling | classify the resolved **path** |
| **Path traversal** (#4) | `../../…` does not trip a rule anchored on the literal path | normalize the target before classifying |

## What it actually governs

- **Destructive deletes** — `rm -rf /` and system-directory wipes denied;
  bounded routine cleanup recorded instead of prompted.
- **Secret material** — `/root/.openclaw/secrets*`, `*.env`, `/root/.ssh/`,
  private keys, runtime config and state are unreadable and unwritable.
- **Writes** — workspace and artifact roots allowed; system paths denied;
  anything else outside the workspace confirms.
- **Destructive git** — force-push, `reset`, `clean -fd`, `branch -D` confirm.
- **Database drops** — `DROP TABLE`, `dropdb`, `pg_restore --clean` confirm.
- **Spend** — any transaction at or above **$500** confirms (ABC guardrail).
- **Governance-layer changes** — disabling, rewriting, or re-consenting the
  policy layer itself is denied.
- **Outbound messages** — always recorded.

Full rule-by-rule reference: **[POLICY.md](POLICY.md)**.

## How it works

```
agent wants a tool call
        │
        ▼
before_tool_call hook ──► classifyToolCall(toolName, params, derivedPaths)
        │                          │
        │                   pure, no imports, unit-testable
        │                          │
        ▼                          ▼
  allow / allow-log / confirm / deny
        │
        ▼
  every decision appended to the audit log
```

The classifier is a **pure module with no imports** (`classifier.js`). That is
deliberate: it runs under `node test-classifier.mjs` with no Gateway, no restart,
and no live tool call. Regex classification of shell commands is best-effort by
nature — the only honest way to ship it is to make it inspectable and tested.

### The bootstrap exemption

The layer **always allows reads and writes to its own source tree**. This is a
safety property, not a convenience: if the classifier could be locked out of
editing its own rules, a wrong classifier could never be fixed. A governance
layer you cannot repair is a governance layer you have to disable.

### The audit log

`$HOME/.openclaw/nibvok-ai-security-audit.log` — one JSON line per decision (`product` is a field, so the file stays valid JSONL). Every entry is **hash-chained**: `prev_hash` is the previous entry's `hash`, and `hash` is SHA-256 over this entry's content plus `prev_hash`.

```json
{"ts":"2026-09-18T17:26:50.615Z","product":"nibvok","action":"deny","tool":"exec",
 "reason":"read of protected secret material (/root/.openclaw/openclaw.json)",
 "cmd":"cat /root/.openclaw/openclaw.json",
 "prev_hash":"0000…0000","hash":"9462fa48…0e8d"}
```

Verify a log at any time:

```bash
node verify-audit-chain.mjs [path-to-audit.log]
```

It exits `0` when the chain holds and `1` when it does not, naming the line and
failure code. The chain proves the log is **internally consistent** — no entry was
edited, reordered, removed or inserted after the fact. It does **not** prove
authenticity against a full rewrite with recomputed hashes, and it cannot detect
truncation of trailing entries; those need a signature or an external anchor,
which this package does not ship.

Audit-write failures never block a tool call. Governance must not fail closed on
a logging error.

### Preset policies

Five postures ship in `policies.js`, selected by one variable:

```bash
NIBVOK_AI_SECURITY_POLICY=production   # development | production | read-only | research | locked-down
```

They set the posture knobs (writable roots, write/delete posture, spend ceiling) —
not the rule set, which stays compiled in. See **[POLICIES.md](POLICIES.md)** for
what each one changes and doesn't.

## Evidence it works

Five suites, runnable without a Gateway:

| Suite | What it proves | Result |
|---|---|---|
| `node test-classifier.mjs` | decision logic per rule | **274 passed** |
| `node test-hook.mjs` | the real registered handler returns block / approval / allow | **29 passed** |
| `node test-session-trust.mjs` | class-scoped session trust is bounded correctly | **27 passed** |
| `node test-audit-chain.mjs` | a modified audit entry breaks the hash chain | **18 passed** |
| `node test-policies.mjs` | each of the five preset postures behaves as documented | **15 passed** |

**363 tests** across five suites.

`test-classifier.mjs` is self-contained. The other two import `index.js`, which
imports the OpenClaw plugin SDK that the **host** supplies — so from a bare clone
(no `openclaw` on the module path) they exit **3** with a `SKIPPED` message
rather than crashing. Exit `3` means *could not run*, and is deliberately distinct
from exit `1` (*ran and failed*). See `INSTALL.md` §2 for the one-line symlink
that lets a clone run all three.

Plus live verification against real tool calls — including a **control test** on a
protected file that actually exists, which is the only way to distinguish "policy
blocked it" from "the file wasn't there." That distinction turned out to matter
enormously; see **[INCIDENTS.md](INCIDENTS.md)** case study #6.

## Known limitations

Stated plainly, because a guard that overstates itself is worse than none:

- **Lexical only.** The classifier reads command strings. It does not resolve
  symlinks, follow shell variable expansion, or understand `$(…)` substitution.
  A sufficiently creative command can evade a regex.
- **Session trust is in-memory.** "Allow for this session" ends when the Gateway
  restarts. It is **class-scoped**: approving a delete does not approve a
  force-push or a spend. The `spend` class is deliberately excluded (≤ the $500
  ABC hard stop).
- **No timestamp access.** The rule *"a secret created in the last 60 minutes"*
  is **not implemented**. A pure classifier has no access to entry timestamps.
  Implementing it needs a state lookup, which breaks the purity property.
- **Configuration is by environment variable, not a policy file.** Deployment
  roots (`ASF_ARTIFACT_ROOT`, `ASF_LOG_ROOT`, `ASF_WORKSPACE_ROOT`,
  `NIBVOK_AI_SECURITY_PLUGIN_ROOT`, `NIBVOK_AI_SECURITY_SPEND_CEILING_USD`) are overridable; the rule *set*
  itself is compiled in. There is no per-tenant policy editor and no UI.

## Install

```bash
openclaw plugins enable nibvok-ai-security
openclaw gateway restart
```

Full, verified steps — including SDK linking and the install-order caveat — are
in **[INSTALL.md](INSTALL.md)**. Every command there was run; nothing is
aspirational.

## License

**MIT-0** — free to use, copy, modify, and redistribute, with no attribution
requirement. See **[LICENSE](LICENSE)**. Third-party notices:
**[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)** (this package bundles no
third-party code).

## Paid services

The plugin is free. For teams that want help tuning policies for their
environment, reviewing audit trails, or responding to incidents, the author
offers paid advisory engagements. See
**[TERMS-OF-SERVICE.md](TERMS-OF-SERVICE.md)**.

Contact: data@nibvok.com

## Further reading

- **[POLICY.md](POLICY.md)** — every rule, action, and scope
- **[POLICIES.md](POLICIES.md)** — the five preset postures and what each changes
- **[OWASP-ASI-MAPPING.md](docs/OWASP-ASI-MAPPING.md)** — coverage against the six OWASP ASI categories, with gaps stated
- **[INSTALL.md](INSTALL.md)** — install on a new instance
- **[LISTING.md](LISTING.md)** — ClawHub listing copy and search phrases
- **[SCREENSHOTS.md](SCREENSHOTS.md)** — provenance of each screenshot
- **[INCIDENTS.md](INCIDENTS.md)** — twenty-one case studies from real failures; #10 was caught by its own negative test before it shipped
