# POLICY.md — NIBVOK AI Security rule reference

Every rule the enforcement layer applies, as implemented in `classifier.js`
(v0.1.0, 2026-09-18). Source of truth is the code; this document explains it.

---

## 1. The four decisions

| Action | Effect | When |
|---|---|---|
| `allow` | runs silently | ordinary work |
| `allow-log` | runs, writes an audit line | expected-but-notable: artifact writes, outbound sends, approved secret grants |
| `confirm` | human approval dialog | genuinely risky, but sometimes legitimate |
| `deny` | refused, with a reason | catastrophic or secret-exposing |

**Severity order** (used to collapse several path decisions to one):
`allow < allow-log < confirm < deny`.

### Design rule: gate narrowly

> *A layer that prompts for ordinary work gets switched off, and then nothing is
> governed at all.*

This is the single most important design constraint, and it was learned the hard
way (see INCIDENTS.md #1). A guard that cries wolf is worse than no guard,
because the response to noise is to disable the guard — and then the guard's
absence is invisible.

---

## 2. Exec command policy

Evaluated in order: **deny → confirm → log/allow**.

### 2.1 DENY — always refused

| Rule | Pattern | Reason string |
|---|---|---|
| Filesystem-root wipe | `rm -rf /`, `rm -rf /*` | `rm -rf targeting the filesystem root` |
| System-directory wipe | `rm -rf /etc\|/root\|/var\|/usr\|/bin\|/sbin\|/lib\|/lib64\|/boot\|/sys\|/proc\|/dev\|/home\|/opt\|/srv\|/mnt` | `rm -rf targeting a system directory` |
| Governance disable | `openclaw plugins disable\|remove\|uninstall` | `attempt to disable or rewrite the governance layer` |
| Governance config rewrite | `openclaw config set\|unset\|delete` | *(same)* |
| Policy reset | `openclaw policy reset\|clear` | *(same)* |
| Governance file destroy | `rm\|mv\|truncate\|shred` targeting `openclaw.json`, `policy.jsonc`, `governance-plugin` | *(same)* |
| Capability-consent reinstall | `openclaw plugins …--accept-capabilities` | *(same)* |
| System-path write | redirect/`cp`/`mv` into `/etc/`, `/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`, `/boot/`, `/sys/`, `/proc/`, `/dev/` | `write to system path …` |
| Secret read | `openclaw secrets store get\|show\|read` | `reading a stored secret value back out` |
| `.env` read | any `*.env` token, absolute or relative | `read of an .env file` |
| Secret-path read | paths matching the secret patterns (§3.1) | `read of protected secret material (…)` |

**A targeted delete inside a system tree still only confirms:**
`rm -rf /var` → **deny**, but a targeted delete inside it, e.g.
`rm -rf /var/asf/artifacts/x` → **confirm**. The distinction
is a whole-top-level-directory wipe vs. a targeted path.

### 2.2 CONFIRM — human approval required

| Rule | Trigger | Reason string |
|---|---|---|
| Destructive delete | any `rm` not covered by the bounded-cleanup rule (§2.3) | `destructive delete (rm)` |
| Destructive git | `push --force` / `--force-with-lease` / `-f`, `reset`, `clean -fd`, `branch -D`, `checkout -- .`, `restore` | `destructive git operation` |
| Database drop | `DROP TABLE\|DATABASE\|SCHEMA`, `dropdb`, `pg_restore --clean` | `database drop/destructive restore` |
| **Spend ceiling** | any `$` amount ≥ **$500**, or an `amount=` field ≥ 50000 cents | `transaction at or above the $500 ceiling ($N)` |
| Outside-workspace write | redirect/`cp`/`mv` target outside the allowed write roots | `write outside the workspace (…)` |
| `/etc` read | read under `/etc/` outside exceptions | `read of … outside the allowlist` |

The **$500 ceiling** (`NIBVOK_AI_SECURITY_SPEND_CEILING_USD`, default `500`) is a hard stop:
at or above it, a transaction confirms regardless of context. The classifier
catches the obvious spelled-out cases;
it is a backstop, not a ledger.

### 2.3 ALLOW-LOG — recorded, not prompted

| Rule | Exact shape | Reason string |
|---|---|---|
| Approved secret grant | `openclaw secrets store set … --allow-host <approved>` | `secrets store: approved host grant` |
| Bounded cleanup | see guards below | `routine cleanup delete` |
| Artifact write | write under the artifact root (`ASF_ARTIFACT_ROOT`) | `artifact write (…)` |
| Allowlisted API call | network call where **every** host is in `APPROVED_HOSTS` | `external API call to allowlisted host (…)` |

**Bounded cleanup** is deliberately narrow. It auto-allows only:

- `openclaw secrets store rm TEST_* --yes` — test artifacts, name prefix enforced
- exactly `rm <LOG_ROOT>*.log` (the glob, verbatim)
- **one concrete file** under `/tmp/` or `/var/tmp/`

and it **refuses to auto-allow** when: recursive (`-r`), any glob, more than one
operand, or the target is a directory. Those all fall through to CONFIRM.

> **Not implemented:** *"a secret created in the last 60 minutes."* A pure
> lexical classifier has no access to entry timestamps. Implementing it requires
> a state lookup, which breaks the purity property that makes this testable.

### 2.4 ALLOW — silent

- anything matching a test/lint runner: `pytest`, `jest`, `vitest`, `go test`,
  `cargo test`, `ruff`, `mypy`, `eslint`, `tsc`, `openclaw doctor`, …
- any command confined to the bootstrap tree (§4)
- everything not matched above

---

## 3. Read policy

### 3.1 Hard-deny patterns (path-anchored)

```
/root/.openclaw/secrets*          /root/.ssh/
any *.env file                    id_rsa | id_ed25519 | id_ecdsa
/root/.openclaw/credentials/      *-key.pem | *fingerprint.key
/root/.openclaw/secret-egress-proxy/
/root/.openclaw/openclaw.json     /root/.openclaw/state/
```

**Path-anchored, never string-anchored.** Matching the *word* "secret" once
blocked every governance-related command — including reading the classifier
itself. The word appearing is not a read of secret material; a path pointing at
secret material is. (INCIDENTS.md #3.)

### 3.2 Read roots

**Allowed read roots:**

```
/root/.openclaw/                <ASF_LOG_ROOT>
<ASF_WORKSPACE_ROOT>            /etc/nginx/sites-available/
<ASF_ARTIFACT_ROOT>
```

**Denied parents** (except listed exceptions): `/root/backups/`, `/root/.ssh/`,
`/var/log/`.

**Confirm parents:** `/etc/` — per the owner's spec, `/etc/passwd` confirms
rather than denies.

**Default:** anything else denies (`read outside the read allowlist`).

---

## 4. The bootstrap exemption

`BOOTSTRAP_ROOT = ` the plugin's own directory (defaults to its location on
disk; override with `NIBVOK_AI_SECURITY_PLUGIN_ROOT`)

Reads and writes here are **always allowed**. This exists so a wrong rule can
always be repaired. It applies to:
- `read` / `write` / `edit` on a bootstrap path
- exec commands whose absolute paths are **all** bootstrap paths, with no
  non-bootstrap write target

It does **not** exempt the layer from its own governance rules for anything
outside that tree — including the config that registers it. That asymmetry is
intentional and visible in case study #6.

---

## 5. Path normalisation

`.` and `..` are resolved **lexically** before any comparison. Without this,
`/root/.openclaw/workspace/../credentials/x` still string-prefixes the allowed
workspace root and would be allowed — a real traversal bypass. (INCIDENTS.md #4.)

Also handled: `~` → `/root`; relative paths resolve inside the workspace; a
relative path containing `..` is denied.

### Why the `/` case is special

A bare `/` appears constantly in ordinary text and arithmetic — `"4 / 6"`,
`"new pid / start"` — and an earlier version treated each as a path, producing
false "outside the allowlist" denials. The extractor now requires a **real
FHS top-level directory** as the first segment, so `/payments/config` inside an
echo label is ignored rather than treated as a read. (INCIDENTS.md #2.)

---

## 6. Tool coverage

The hook matches: `exec`, `process`, `read`, `ls`, `write`, `edit`,
`apply_patch`, `patch`, `conversations_send`, `conversations_turn`,
`sessions_send`.

**File-mutating tools** (`write`, `edit`, `apply_patch`, `patch`) are classified
by **target path** directly. Without this they would bypass the write policy
entirely, because they never pass through the exec path.

**Messaging tools** are always `allow-log` — outbound sends are recorded.

---

## 7. Approval dialog

When a call confirms, the dialog presents:

- **title:** `NIBVOK AI Security — action approval`
- **description:** the reason, then the command (truncated to 300 chars)
- **severity:** `warning`
- **timeout:** 600000 ms (10 min)

**Decisions offered:**

| Class | Reason | Options |
|---|---|---|
| `delete` | destructive delete (rm) | `allow-once`, **`allow-always`**, `deny` |
| `git` | destructive git operation | `allow-once`, **`allow-always`**, `deny` |
| `db` | database drop/destructive restore | `allow-once`, **`allow-always`**, `deny` |
| `outside-write` | write outside the workspace | `allow-once`, **`allow-always`**, `deny` |
| `confirm-read` | read outside the allowlist | `allow-once`, **`allow-always`**, `deny` |
| `spend` | transaction ≥ $500 ceiling | `allow-once`, `deny` |

### Session policy ("Allow for this session")

Approving with `allow-always` trusts that **one class** for the rest of the
session. A different class still prompts; another session is unaffected. Trust is
held **in memory** and ends at Gateway restart.

- Classes are derived by `confirmClass(reason)`; an unrecognised reason yields
  `null`, which is **not** trustable — a new confirm rule added later can never
  inherit trust it was not meant to have.
- `allow-once` never creates trust.
- **`spend` is excluded.** A session-wide grant would authorise every later
  transaction at or above $500, contradicting the standing ABC hard stop ("any
  transaction above the ceiling escalates to a human *before* it happens").
- **DENY has no approval path.** `allow-always` is never offered on a deny,
  because there is no approval to remember. Converting a deny into a trustable
  confirm is a separate policy decision, not a session setting.

> **This covers only decisions this plugin makes.** OpenClaw's own exec approval
> layer is separate and has its own policy. See §9.

---

## 8. Constants worth knowing

| Constant | Value |
|---|---|
| `SPEND_CEILING_USD` | `500` |
| `APPROVED_HOSTS` | api.gumloop.com, queue.fal.run, fal.run, api.telegram.org, storage.googleapis.com, api.stripe.com, api.openai.com |
| `BOOTSTRAP_ROOT` | the plugin's own directory (or `NIBVOK_AI_SECURITY_PLUGIN_ROOT`) |
| Audit log | `$HOME/.openclaw/nibvok-ai-security-audit.log` (or `NIBVOK_AI_SECURITY_AUDIT_LOG`) |

The roots and the spend ceiling are **environment-overridable** (see the table
above). The **rule set itself** is a source edit — there is no policy file. That
is the main known limitation, and the first thing productization has to fix.

---

## 9. Two layers, not one

This plugin is **not** the only thing that can prompt. OpenClaw has its own exec
approval layer, controlled by `tools.exec.mode`
(`deny` | `allowlist` | `ask` | `auto` | `full`).

| | This plugin | OpenClaw `tools.exec` |
|---|---|---|
| Judges | the **command text** | tool id + native policy |
| Per-call decisions | yes | per mode |
| Session-scoped trust | **yes** (this plugin) | not observed |
| Audit log | yes (JSONL) | native logs |

**A prompt can come from either layer.** Session trust granted here suppresses
only *this* plugin's prompts. If a native prompt also fires, the call still
blocks — and no amount of approval here will quiet it.

**Why this matters operationally.** Double-gating the same call produces exactly
the approval fatigue that design rule 5 warns about. The intended shape is:
**one** layer decides, the other stays permissive. If the plugin is installed as
the enforcement point, `tools.exec.mode` should be permissive enough not to
double-prompt; if the native layer is the enforcement point, this plugin's
confirm classes should be narrowed.

Deciding which is the gate is an **owner** decision — see `tools.exec.mode` in
the config schema. Changing it is a config write and is denied to the agent.
