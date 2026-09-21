# INSTALL.md — installing NIBVOK AI Security on a new OpenClaw instance

Verified against a working install on OpenClaw **2026.9.4** (node v24.21.0, Linux).
Every command here was run; nothing is aspirational.

---

## 0. Prerequisites

- A running OpenClaw Gateway. Confirm before starting:

  ```bash
  openclaw gateway status
  ```

- Node.js available to the Gateway (`node --version`).
- **Write access to the plugin directory and to `~/.openclaw/work/`.**

> **Do not install this blind on a live instance.** It is an enforcement layer:
> a mistake locks you out of ordinary work. Install it where you can restart the
> Gateway and watch the result.

---

## 1. Place the plugin directory

The plugin is a directory containing `index.js`, `classifier.js`,
`openclaw.plugin.json`, `package.json`, and a `node_modules/openclaw` link.

```bash
# Pick a permanent location. It must be writable, and it must NOT be
# inside a directory that the policy denies reading.
mkdir -p /root/.openclaw/plugins/nibvok-ai-security
cd /root/.openclaw/plugins/nibvok-ai-security

# Copy the source (index.js, classifier.js, the two json manifests, tests)
cp /path/to/source/{index.js,classifier.js,openclaw.plugin.json,package.json} .
cp /path/to/source/test-*.mjs .
```

### 1.1 Link the OpenClaw SDK

The plugin imports `openclaw/plugin-sdk/plugin-entry`. It resolves through a
`node_modules/openclaw` symlink to the Gateway's own installation — **do not**
`npm install` a copy, or the plugin and the Gateway can disagree about the SDK
version:

```bash
mkdir -p node_modules
ln -s /usr/lib/node_modules/openclaw node_modules/openclaw
```

Verify the import resolves **before** registering anything:

```bash
node -e "import('openclaw/plugin-sdk/plugin-entry').then(m=>console.log('SDK OK', typeof m.definePluginEntry))"
```

Expect `SDK OK function`. If this fails, stop. A plugin that cannot import its
SDK will register, fail to activate, and leave you with an **unenforced** policy
that still reports `enabled` — the exact failure in INCIDENTS.md #6.

---

## 2. Run the test suites first

All three run without a Gateway, a restart, or a live tool call:

```bash
node test-classifier.mjs      # expect: 274 passed, 0 failed
node test-hook.mjs            # expect: 29 passed, 0 failed
node test-session-trust.mjs   # expect: 27 passed, 0 failed
```

**Two of them need the OpenClaw plugin SDK on the module path.**
`test-classifier.mjs` is self-contained and always runs.
`test-hook.mjs` and `test-session-trust.mjs` drive the plugin through its
registered handler, so they import `index.js`, which imports
`openclaw/plugin-sdk/plugin-entry` — supplied by the OpenClaw **host**, and not
resolvable from a bare clone. Node exits **3** with a `SKIPPED` message in that
case, deliberately distinct from exit **1** (a real test failure): "could not
run" must never read as "ran and passed".

To run all three from a clone:

```bash
mkdir -p node_modules
ln -sfn /usr/lib/node_modules/openclaw node_modules/openclaw
```

**Exit codes:** `0` all passed · `1` a test failed · `3` the suite could not run
(SDK absent). Never read 3 as a pass.

**Do not proceed if any suite reports a failure.** These are the only cheap
proof you get that the layer behaves before it starts governing a live agent.

---

## 3. Register the plugin

Registration is **config**, not a file copy. Point `plugins.load.paths` at the
directory:

```bash
openclaw config set plugins.load.paths '["/root/.openclaw/plugins/nibvok-ai-security"]'
```

> **This command will itself be denied** by a policy layer already running with
> `openclaw config set` in its deny list. Install order matters: on a fresh
> instance with no layer yet running, it succeeds. On an instance replacing an
> older layer, an operator must do this step manually. That is intentional: a
> layer that can re-register itself can also be moved somewhere it does not load.

Confirm it registered:

```bash
openclaw plugins list | grep -i nibvok-ai-security
```

---

## 4. Enable and restart

```bash
openclaw plugins enable nibvok-ai-security
openclaw gateway restart
```

> **`--accept-capabilities` is denied by this policy** (v0.1.0+, INCIDENTS.md #6).
> If the plugin reports that it requires capability consent, the plain
> `plugins enable` path is the one to use. Do **not** reach for
> `--accept-capabilities`; if a newer version of this policy denies it, that is
> the guard doing its job.

---

## 5. Verify — with a real control

This is the step that matters most. **A test that passes because the system is
off is the most dangerous kind of pass.**

### 5.1 Is it actually loaded?

```bash
openclaw plugins inspect nibvok-ai-security --runtime --json \
  | grep -E '"status"|"activated"'
```

Required:

```
"activated": true,
"status": "loaded",
```

`"status": "disabled"` or `"activated": false` means **the policy is not
enforcing**, regardless of what any config flag says.

### 5.2 Does it enforce?

**Control (must be blocked).** Use a protected file that **actually exists**:

```bash
cat ~/.openclaw/openclaw.json
# expect: Blocked by <policy name>: read of protected secret material (...)
```

**Ordinary read (must pass silently):**

```bash
ls -la ~/.openclaw/
# expect: normal listing, no prompt
```

**Secret read (must be blocked):**

```bash
cat ~/.openclaw/secrets.json
# expect: Blocked by <policy name>: read of protected secret material (...)
```

The control is not optional. Without a file that exists, a non-zero exit could
mean *"policy blocked it"* **or** *"the file was not there"* — and those are
opposite results. That ambiguity is exactly what produced the false pass in
INCIDENTS.md #6.

### 5.3 Confirm the audit trail

```bash
tail -5 $HOME/.openclaw/nibvok-ai-security-audit.log
```

You should see one JSON line per call above, with matching `deny` entries. **No
audit lines means the hook is not running**, even if §5.1 looked healthy.

---

## 6. Install checklist

```
[ ] SDK import resolves                      node -e "import('openclaw/plugin-sdk/plugin-entry')..."
[ ] test-classifier.mjs   274 passed
[ ] test-hook.mjs          29 passed (or exit 3 without the SDK)
[ ] test-session-trust.mjs  27 passed (or exit 3 without the SDK)
[ ] plugins.load.paths points at the directory
[ ] plugins enable <id>        → enabled
[ ] gateway restarted
[ ] inspect --runtime          → activated: true, status: loaded
[ ] CONTROL on an existing protected file  → BLOCKED
[ ] ordinary read                          → silent
[ ] audit log has matching lines
```

Any unchecked box means the layer is not doing what the documentation claims.

---

## 7. Uninstall

```bash
openclaw plugins disable nibvok-ai-security
```

Then remove the path from `plugins.load.paths` and restart.

> Both commands are **denied by a running policy layer** — by design. Removing
> an enforcement layer requires an operator action outside the governed agent.
> That is the point; record why you are removing it.

---

## 8. Note on `openclaw plugins validate`

This package reports `valid: false` from `openclaw plugins validate`:

```
plugin entry does not expose tool or feature authoring metadata: ./index.js
```

That is expected for a **hook-only** plugin, and it is **not a defect in this
package**. This plugin registers one `before_tool_call` hook at runtime via
`api.on(...)` and contributes no tools, commands, providers or channels — so
there is no authoring metadata for the validator to find. The check is written
for capability-registering plugins.

Verified, rather than assumed: the same command fails with the **identical**
message against a known-good, actively-enforcing hook-only plugin on the same
host. Two different hook-only plugins, one error, no behaviour difference.

If you need a green `validate`, that is a reason to migrate this plugin to
explicit capability registration — a separate change, not a packaging fix.
