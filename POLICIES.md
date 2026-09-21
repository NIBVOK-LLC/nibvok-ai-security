# POLICIES.md — the five preset postures

NIBVOK AI Security ships **five** starter policies, not seventy-five. Each is a
named posture selected by one environment variable:

```bash
NIBVOK_AI_SECURITY_POLICY=production
```

A policy is a bundle of **posture knobs**. The **rule set is not a knob** — the
deny/confirm/allow rules live in `classifier.js` and are compiled in. A preset
changes the shape of the deployment (where writes may go, whether writes happen
at all, whether deletes are refused), not the rule vocabulary.

That distinction is deliberate. A per-tenant policy *editor* is another thing to
get wrong, and a governance layer whose rules can be edited at runtime is one
whose rules can be edited at runtime.

---

## The five

| Name | Writes | Deletes | Spend ceiling | Read surface |
|---|---|---|---|---|
| `development` *(default)* | workspace, artifacts, `/tmp`, `/var/tmp` | confirm | $500 | standard allowlist |
| `production` | workspace, artifacts only | confirm | $500 | standard allowlist |
| `read-only` | **denied** | **denied** | $500 | standard allowlist |
| `research` | workspace, `/tmp` | confirm | $500 | allowlist **+** `/usr/share/doc`, `/usr/share/man` |
| `locked-down` | **denied** | **denied** | $500 | standard allowlist |

`development` is the default, and the posture every test in `test-classifier.mjs`
pins. Any other preset is opt-in.

### development

Everyday agent work. The workspace, the artifact root, and the shared scratch
roots (`/tmp`, `/var/tmp`) are writable; artifact writes are recorded
(`allow-log`). `rm` confirms — gated, but available, because a layer that blocks
routine cleanup gets switched off.

### production

Tighter than development in exactly one way: the shared scratch roots are **not**
writable. Only the workspace and the artifact root are. A write to `/tmp`
therefore confirms instead of running silently. Everything else matches
development.

Use it when the agent runs where other tenants share `/tmp`.

### read-only

Inspection only. **Every write is denied** and **every delete is denied** — not
confirmed, denied. The only writes that still succeed are the bootstrap
exemption (the layer may always repair its own source, or a wrong rule could
never be fixed).

Reads are unchanged: the ordinary allowlist still applies, and a read outside it
still confirms rather than being silently permitted. Read-only means *no
mutation*, not *no confirmation*.

### research

Wider **reading** — `/usr/share/doc/` and `/usr/share/man/` join the read
allowlist — with writes confined to the workspace and `/tmp`. Use it for an agent
that needs to consult reference material but should not be able to write into the
system documentation trees it reads.

### locked-down

Least capability. Writes denied, deletes denied, same as read-only. The two
presets exist separately because they mean different things operationally: a
`read-only` agent is one you expect to inspect and report; a `locked-down` agent
is one you do not fully trust and have deliberately starved of capability. That
distinction is in the operator's head, not in the enforcement, and the naming
should not pretend otherwise.

---

## What a preset does NOT change

- **The rule set.** Every deny/confirm rule in `POLICY.md` applies under every
  preset. `locked-down` does not add rules; it refuses two categories outright.
- **The spend ceiling with no override.** $500 is the ABC hard stop and is the
  same in all five. Override it explicitly with
  `NIBVOK_AI_SECURITY_SPEND_CEILING_USD` if a deployment genuinely needs
  otherwise — the preset is not the place to quietly move it.
- **Inbound revenue.** The ceiling gates *outbound* expenditure only, in every
  preset.
- **Coverage.** A preset is a posture, not a proof. See
  [OWASP-ASI-MAPPING.md](docs/OWASP-ASI-MAPPING.md) for what the layer does and
  does not cover.

## Resolution order

1. `NIBVOK_AI_SECURITY_POLICY` selects the preset (default `development`).
2. `NIBVOK_AI_SECURITY_SPEND_CEILING_USD` overrides the ceiling, if set.
3. Root paths are read from `ASF_WORKSPACE_ROOT`, `ASF_ARTIFACT_ROOT`, and
   `ASF_LOG_ROOT` when those are set, and default to neutral absolute paths.

An **unknown** preset name is reported on stderr and falls back to
`development`. A governance layer that failed open on a typo would be worse than
one that says so.

## Testing

```bash
node test-policies.mjs
```

Loads each preset in a **cold child process** — the classifier reads its policy
at import time, so a preset can only be honestly tested by starting fresh — and
asserts the write, delete, and spend behaviour of each.
