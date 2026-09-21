// Unit tests for the NIBVOK AI Security classifier.
// Run: node test-classifier.mjs
import { classifyToolCall, BOOTSTRAP_ROOT, ARTIFACT_ROOT, LOG_ROOT } from "./classifier.js";

// The plugin's own directory, derived from where this file lives — not a
// hardcoded host path — so the bootstrap-exemption tests follow the tree to
// wherever it is installed.
const BOOT = BOOTSTRAP_ROOT.replace(/\/$/, "");

// Enough `..` segments to escape the install tree to the filesystem root,
// whatever depth the tree is installed at. The traversal negatives below used a
// hardcoded `../../..`, which from a 6-deep path lands in the WORKSPACE, not at
// `/` — so they never actually reached the file they named and were passing on
// the name anchor alone (see INCIDENTS.md #19).
const ESCAPE = "../".repeat(BOOT.split("/").filter(Boolean).length);

let nOk = 0, fail = 0;
const failures = [];

function t(name, tool, params, expected) {
  const got = classifyToolCall(tool, params).action;
  if (got === expected) { nOk++; return; }
  fail++;
  failures.push(`${name}\n     expected=${expected} got=${got}`);
}

// ═══ OWNER TEST 1: reading the classifier file must NOT prompt ═══
t("read classifier (cat)", "exec",
  { command: `cat ${BOOT}/classifier.js` }, "allow");
t("read classifier (node run)", "exec",
  { command: `cd ${BOOT} && node test-classifier.mjs` }, "allow");
t("read classifier via read tool", "read",
  { path: `${BOOT}/classifier.js` }, "allow");
t("write classifier (bootstrap)", "write",
  { path: `${BOOT}/classifier.js` }, "allow");
t("edit classifier (bootstrap)", "edit",
  { path: `${BOOT}/index.js` }, "allow");

// ═══ OWNER TEST 2: reading secrets must BE BLOCKED (path-anchored) ═══
t("cat secrets.json", "exec", { command: "cat /root/.openclaw/secrets.json" }, "deny");
t("cat secrets dir file", "exec", { command: "cat /root/.openclaw/secrets/store.json" }, "deny");
t("read secrets via read tool", "read", { path: "/root/.openclaw/secrets.json" }, "deny");
t("cat .env", "exec", { command: "cat .env" }, "deny");
t("cat app.env file", "exec", { command: "cat /app/config/prod.env" }, "deny");
t("cat ssh private key", "exec", { command: "cat /root/.ssh/id_rsa" }, "deny");
t("ls ssh dir", "exec", { command: "ls /root/.ssh/" }, "deny");
t("secrets store get", "exec", { command: "openclaw secrets store get TELEGRAM_BOT_TOKEN" }, "deny");

// ═══ OWNER TEST 3: approved --allow-host grant must NOT prompt ═══
t("secrets set approved host", "exec",
  { command: "openclaw secrets store set TEST_KEY --allow-host api.telegram.org" }, "allow-log");
t("secrets set approved host (TELEGRAM)",
  "exec",
  { command: "openclaw secrets store set TELEGRAM_BOT_TOKEN --allow-host api.telegram.org" }, "allow-log");
t("secrets set approved host (stripe)", "exec",
  { command: "openclaw secrets store set STRIPE_SECRET_KEY --allow-host api.stripe.com" }, "allow-log");
t("secrets set UNapproved host still gated", "exec",
  { command: "openclaw secrets store set X --allow-host evil.example.com" }, "allow");

// ═══ THE WORD "secret" is not a violation (path-anchored rule) ═══
t("mention secret in a comment", "exec",
  { command: "grep -rn 'secret' /root/.openclaw/workspace/notes.md" }, "allow");
t("grep the word secrets in source", "exec",
  { command: `grep -rn secrets ${BOOT}/` }, "allow");
t("log line mentioning secret", "exec",
  { command: "echo 'no secrets here' >> /root/.openclaw/workspace/log.txt" }, "allow");
t("filename containing secret (not .env)", "exec",
  { command: "cat /root/.openclaw/workspace/secret-plan.md" }, "allow");

// ═══ READ ALLOWLIST ═══
t("read workspace", "read", { path: "/root/.openclaw/workspace/tasks.yaml" }, "allow");
t("read artifacts", "read", { path: `${ARTIFACT_ROOT}a.mp4` }, "allow");
t("read deployment log", "read", { path: `${LOG_ROOT}accountability.log` }, "allow");
t("read nginx sites-available", "read", { path: "/etc/nginx/sites-available/site" }, "allow");
// Scratch roots are writable, so they must be readable too (owner-confirmed
// 2026-09-18): `node /tmp/x.mjs` used to be denied as a read of a path outside
// the allowlist right after /tmp was allowed as a write target.
t("read /tmp script", "read", { path: "/tmp/probe.mjs" }, "allow");
t("exec node /tmp script", "exec", { command: "node /tmp/x.mjs" }, "allow");
t("read /var/tmp script", "read", { path: "/var/tmp/x.sh" }, "allow");
t("exec cat /tmp file", "exec", { command: "cat /tmp/out.txt" }, "allow");
// ...but the path-anchored secret rules still win inside a scratch root.
t("read /tmp/.env still denied", "read", { path: "/tmp/app/.env" }, "deny");
t("exec cat /tmp/id_rsa still denied", "exec", { command: "cat /tmp/id_rsa" }, "deny");
t("read /root/backups DENIED", "read", { path: "/root/backups/plain/x.tar.zst" }, "deny");
t("read /etc/passwd CONFIRMS (not denied)", "read", { path: "/etc/passwd" }, "confirm");
t("read /var/log/syslog DENIED", "read", { path: "/var/log/syslog" }, "deny");
t("exec cat /etc/passwd CONFIRMS", "exec", { command: "cat /etc/passwd" }, "confirm");
t("exec ls /root/backups DENIED", "exec", { command: "ls /root/backups/" }, "deny");
t("exec cat /var/log/syslog DENIED", "exec", { command: "cat /var/log/syslog" }, "deny");

// ═══ DENY: root rm + governance disable ═══
t("rm -rf /", "exec", { command: "rm -rf /" }, "deny");
t("rm -rf /*", "exec", { command: "rm -rf /*" }, "deny");
t("disable governance", "exec", { command: "openclaw plugins disable nibvok-ai-security" }, "deny");
t("remove governance", "exec", { command: "openclaw plugins remove nibvok-ai-security" }, "deny");
t("openclaw config set", "exec", { command: "openclaw config set tools.deny '[]'" }, "deny");

// ═══ DENY: `config patch` is a config WRITE (case study #18) ═══
// `config set|unset|delete` were denied but `config patch` was not, yet patch
// merges recursively and `null` DELETES a path -- i.e. it can reach exactly the
// settings `config set` is denied for (`tools.deny`, the governance plugin
// entry). Denied unconditionally, like the other config write verbs: a
// --dry-run exemption would be a parsing bypass to argue about for no gain.
t("config patch --stdin", "exec",
  { command: "openclaw config patch --stdin" }, "deny");
t("config patch --file", "exec",
  { command: "openclaw config patch --file ./openclaw.patch.json5" }, "deny");
t("config patch after cd", "exec",
  { command: "cd /root && openclaw config patch --stdin" }, "deny");
t("config patch null-deletes tools.deny", "exec",
  { command: 'openclaw config patch --stdin <<< \'{"tools":{"deny":null}}\'' }, "deny");
t("config patch nested in bash -c", "exec",
  { command: "bash -c \"openclaw config patch --stdin\"" }, "deny");
t("config patch in a command substitution", "exec",
  { command: 'echo "$(openclaw config patch --stdin)"' }, "deny");
t("config patch after a chain", "exec",
  { command: "cd /root && openclaw config get gateway.port && openclaw config patch --stdin" }, "deny");

// NEGATIVE: the config READ verbs must stay allowed, so the fix does not
// over-block ordinary inspection (the write verbs are the deny list).
t("config get stays allowed", "exec",
  { command: "openclaw config get gateway.port" }, "allow");
t("config file stays allowed", "exec",
  { command: "openclaw config file" }, "allow");
t("config schema stays allowed", "exec",
  { command: "openclaw config schema" }, "allow");
t("config validate stays allowed", "exec",
  { command: "openclaw config validate" }, "allow");
// NEGATIVE: prose that MENTIONS config patch is documentation, not invocation.
t("heredoc mentions config patch (no deny)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<'EOF'\nDo not run `openclaw config patch` on this host.\nEOF" },
  "allow");

t("write /etc host file", "exec", { command: "echo x > /etc/hosts" }, "deny");

// ═══ DENY: --accept-capabilities is a governance-layer modification ═══
// A capability-consent reinstall is how the guard silently re-registered and
// was then disabled in config (INCIDENTS.md #6). It must be denied like the
// other disable verbs, while an ordinary `plugins update` stays allowed.
t("install with --accept-capabilities", "exec",
  { command: "openclaw plugins install /x/governance --accept-capabilities" }, "deny");
t("update with --accept-capabilities", "exec",
  { command: "openclaw plugins update nibvok-ai-security --accept-capabilities" }, "deny");
t("--accept-capabilities with trailing flags", "exec",
  { command: "openclaw plugins install foo --accept-capabilities --other-flag" }, "deny");
t("--accept-capabilities after a command chain", "exec",
  { command: "cd /x && openclaw plugins install y --accept-capabilities" }, "deny");
t("plain plugins update stays allowed", "exec",
  { command: "openclaw plugins update deepseek" }, "allow");
t("plain plugins list stays allowed", "exec",
  { command: "openclaw plugins list" }, "allow");

// ═══ CONFIRM: destructive + big spend + outside writes ═══
t("rm build dir", "exec", { command: "rm -rf build/" }, "confirm");
t("rm file", "exec", { command: "rm notes.txt" }, "confirm");
t("git push --force", "exec", { command: "git push --force origin main" }, "confirm");
t("git reset", "exec", { command: "git reset --hard HEAD~3" }, "confirm");
t("git clean -fd", "exec", { command: "git clean -fd" }, "confirm");
t("drop table", "exec", { command: "sqlite3 app.db 'DROP TABLE users'" }, "confirm");
t("write outside workspace", "exec", { command: "echo x > /root/other/file.txt" }, "confirm");
t("spend $500", "exec", { command: "curl https://api.stripe.com/v1/charges -d amount=50000" }, "confirm");
t("spend $600 amount field", "exec",
  { command: "curl https://api.stripe.com/v1/payment_intents -d amount=60000" }, "confirm");
t("spend under ceiling", "exec",
  { command: "curl https://api.stripe.com/v1/charges -d amount=100" }, "allow-log");
// RULING CHANGED (rule 7): a displayed amount is prose, not a transaction.
// This used to expect "confirm". See the spend note in the new rule-7 block.
t("literal $600 mention (prose, not spend)", "exec",
  { command: "echo 'invoice total $600'" }, "allow");

// ═══ ALLOW: ordinary work must run silently ═══
t("git status", "exec", { command: "git status" }, "allow");
t("git commit", "exec", { command: "git commit -m 'x'" }, "allow");
t("git push normal", "exec", { command: "git push origin main" }, "allow");
t("git log", "exec", { command: "git log --oneline -5" }, "allow");
t("pytest", "exec", { command: "python3 -m pytest tests/ -q" }, "allow");
t("unittest", "exec", { command: "python3 -m unittest discover -s tests" }, "allow");
t("eslint", "exec", { command: "npx eslint ." }, "allow");
t("openclaw doctor", "exec", { command: "openclaw doctor" }, "allow");
t("write in workspace", "exec",
  { command: "echo x > /root/.openclaw/workspace/project/app/out.txt" }, "allow");
t("edit tool in workspace", "edit", { path: "app/main.py" }, "allow");
t("web search", "web_search", { query: "x" }, "allow");
t("null redirect (regression)", "exec", { command: `ls ${LOG_ROOT} 2>/dev/null` }, "allow");
t("null redirect plus real read", "exec", { command: "crontab -l >/dev/null 2>&1" }, "allow");

// ═══ ALLOW+LOG: messaging, artifacts, allowlisted APIs ═══
t("outbound send", "conversations_send", { message: "hi" }, "allow-log");
t("artifact write", "exec",
  { command: `cp out.mp4 ${ARTIFACT_ROOT}out.mp4` }, "allow-log");
t("approved API call", "exec",
  { command: "curl https://api.telegram.org/botX/sendMessage" }, "allow-log");
t("approved API (fal)", "exec", { command: "curl https://queue.fal.run/fal-ai/x" }, "allow-log");

// ═══ Regression: the exact command blocked in production ═══
t("the blocked inspection command", "exec",
  { command: 'ls -la /root/backups/plain/ 2>/dev/null && restic snapshots --latest 3' }, "deny");
t("severity: log listing under allowed-log root", "exec",
  { command: `ls -la ${LOG_ROOT} | grep backup` }, "allow");

// ═══ WRITE-TOOL PATH POLICY (gap found: write/edit/apply_patch bypassed exec) ═══
t("write tool in workspace", "write",
  { path: "app/main.py" }, "allow");
t("write tool absolute workspace", "write",
  { path: "/root/.openclaw/workspace/project/app/x.py" }, "allow");
t("edit tool in workspace", "edit", { path: "app/main.py" }, "allow");
t("write tool to artifact (allow+log)", "write",
  { path: `${ARTIFACT_ROOT}report.pdf` }, "allow-log");
t("write tool outside workspace -> confirm", "write",
  { path: "/root/other/file.txt" }, "confirm");
t("write tool to /etc -> deny", "write", { path: "/etc/hosts" }, "deny");
t("write tool to .env -> deny", "write",
  { path: "/root/.openclaw/workspace/app/.env" }, "deny");
t("write tool to secrets -> deny", "write",
  { path: "/root/.openclaw/secrets/store.json" }, "deny");
t("apply_patch to workspace", "apply_patch",
  { path: "docs/readme.md" }, "allow");
t("apply_patch outside workspace -> confirm", "apply_patch",
  { path: "/root/elsewhere/x.md" }, "confirm");
t("apply_patch bootstrap", "apply_patch",
  { path: `${BOOT}/classifier.js` }, "allow");

// ═══ REAL SECRET MATERIAL ON THIS HOST (owner rule named a path that doesn't exist) ═══
t("read credentials dir file", "read",
  { path: "/root/.openclaw/credentials/browser-extension-relay.secret" }, "deny");
t("read egress proxy root-ca-key", "read",
  { path: "/root/.openclaw/secret-egress-proxy/gateway-FC8EDw/root-ca-key.pem" }, "deny");
t("read leaf-key.pem", "read",
  { path: "/root/.openclaw/secret-egress-proxy/gateway-FC8EDw/leaf-key.pem" }, "deny");
t("read fingerprint key", "read",
  { path: "/root/.openclaw/config-journal-fingerprint.key" }, "deny");
t("exec cat credentials", "exec",
  { command: "cat /root/.openclaw/credentials/browser-extension-relay.secret" }, "deny");
t("write to credentials -> deny", "write",
  { path: "/root/.openclaw/credentials/x.secret" }, "deny");

// ═══ TRAVERSAL: allowed root must not be escaped with .. ═══
t("traversal out of workspace to credentials", "read",
  { path: "/root/.openclaw/workspace/../credentials/browser-extension-relay.secret" }, "deny");
t("traversal deeper to secrets", "exec",
  { command: "cat /root/.openclaw/workspace/../../root/.openclaw/credentials/x.secret" }, "deny");
t("traversal write escaping workspace -> confirm", "write",
  { path: "/root/.openclaw/workspace/../../etc/hosts" }, "confirm");
t("traversal write reaching /etc -> deny", "write",
  { path: "/root/.openclaw/workspace/../../../etc/hosts" }, "deny");
t("normal dot path still allowed", "read",
  { path: "/root/.openclaw/workspace/./project/app/x.py" }, "allow");
t("traversal staying inside allowed root", "read",
  { path: "/root/.openclaw/workspace/project/../project/app/x.py" }, "allow");

// ═══ OWNER TEST 1: /root/.openclaw listing must be allowed silently ═══
t("read /root/.openclaw dir (TEST 1)", "read",
  { path: "/root/.openclaw" }, "allow");
t("read /root/.openclaw/ (TEST 1)", "read",
  { path: "/root/.openclaw/" }, "allow");
t("exec ls -la /root/.openclaw/ (TEST 1)", "exec",
  { command: "ls -la /root/.openclaw/" }, "allow");

// Config/state stay protected even though the parent is now readable.
t("read openclaw.json -> deny", "read",
  { path: "/root/.openclaw/openclaw.json" }, "deny");
t("read state sqlite -> deny", "read",
  { path: "/root/.openclaw/state/openclaw.sqlite" }, "deny");

// ═══ /etc is CONFIRM, not deny (owner: /etc/passwd not in the deny list) ═══
t("cat /etc/passwd -> confirm", "exec",
  { command: "cat /etc/passwd" }, "confirm");
t("read tool /etc/hosts -> confirm", "read",
  { path: "/etc/hosts" }, "confirm");
t("nginx sites still allowed", "read",
  { path: "/etc/nginx/sites-available/foo" }, "allow");

// ═══ FALSE POSITIVE: regex fragments must not be read as paths ═══
t("sed with slashed regex", "exec",
  { command: "sed -n '/export function f/,/^}/p' classifier.js" }, "allow");
t("grep with slashed pattern", "exec",
  { command: "grep -n 'a/b' classifier.js" }, "allow");
// ...but a real secret path inside a quoted program string is still caught.
t("python -c reading secrets -> deny", "exec",
  { command: "python3 -c \"print(open('/root/.openclaw/secrets.json').read())\"" }, "deny");

// ═══ FALSE POSITIVE: bare "/" in prose/arithmetic is not a path ═══
t("comment with bare slash", "exec",
  { command: "echo 4 / 6 done" }, "allow");
t("prose bare slash", "exec",
  { command: "printf 'a / b'" }, "allow");
// A real absolute path is still classified.
t("bare slash does not mask real path", "exec",
  { command: "cat /root/.openclaw/secrets.json" }, "deny");

// ═══ FALSE POSITIVE: URL/label slash-tokens are not filesystem paths ═══
t("echo label with /payments/config", "exec",
  { command: "curl -s http://127.0.0.1:8035/x; echo '=== /payments/config ==='" }, "allow");
t("url path fragment", "exec",
  { command: "echo 'see /docs/cli/secrets for details'" }, "allow");
// Real paths under real FHS roots are still classified.
t("real /var path still denied outside allowlist", "read",
  { path: "/var/lib/secret-thing.txt" }, "deny");
t("real /root secret still denied", "read",
  { path: "/root/.openclaw/secrets.json" }, "deny");

// ═══ OWNER SCOPE RULE: whole-system-dir wipes are DENY, not confirm ═══
t("rm -rf /etc", "exec", { command: "rm -rf /etc" }, "deny");
t("rm -rf /root", "exec", { command: "rm -rf /root" }, "deny");
t("rm -rf /var", "exec", { command: "rm -rf /var" }, "deny");
t("rm -rf /usr", "exec", { command: "rm -rf /usr" }, "deny");
// ...but a TARGETED delete inside those trees still only confirms.
t("rm -rf targeted artifact delete confirms", "exec",
  { command: `rm -rf ${ARTIFACT_ROOT}x.bin` }, "confirm");
t("rm -rf workspace subtree confirms", "exec",
  { command: "rm -rf /root/.openclaw/workspace/project/build" }, "confirm");

// ═══ OWNER SCOPE RULE: bounded routine cleanup auto-allows (recorded) ═══
t("rm single file in /tmp -> allow-log", "exec",
  { command: "rm /tmp/scratch.txt" }, "allow-log");
t("rm single file in /var/tmp -> allow-log", "exec",
  { command: "rm /var/tmp/scratch.txt" }, "allow-log");
t("secrets store rm TEST_KEY --yes -> allow-log", "exec",
  { command: "openclaw secrets store rm TEST_KEY --yes" }, "allow-log");
t("rm old deployment logs glob -> allow-log", "exec",
  { command: `rm ${LOG_ROOT}*.log` }, "allow-log");
// Guard: the auto-allow must NOT swallow dangerous variants.
t("rm -rf /tmp (dir) still confirms", "exec",
  { command: "rm -rf /tmp" }, "confirm");
t("rm -f a b (multi) still confirms", "exec",
  { command: "rm -f a.txt b.txt" }, "confirm");
t("secrets store rm without --yes confirms", "exec",
  { command: "openclaw secrets store rm STRIPE_SECRET_KEY" }, "confirm");
t("secrets store rm production key confirms", "exec",
  { command: "openclaw secrets store rm STRIPE_SECRET_KEY --yes" }, "confirm");
t("rm workspace file still confirms", "exec",
  { command: "rm /root/.openclaw/workspace/project/notes.md" }, "confirm");

// ═══ FALSE POSITIVE: a QUOTED denied string is documentation, not an invocation ═══
// Observed 2026-09-18: appending a memory entry whose heredoc body merely
// MENTIONED `openclaw config set` / `plugins disable` in prose was DENIED as
// "attempt to disable or rewrite the governance layer". The write itself was an
// ordinary workspace append. Same class as the string-anchored secret rules
// (INCIDENTS.md case study #3): a deny rule firing on text that is not an
// invocation. Fix: strip heredoc bodies and quoted literals before the
// GOVERNANCE_DISABLE check (classifier design rule 6).

// (a) a heredoc body quoting a denied command must NOT deny the enclosing write
t("heredoc body mentions config set (no deny)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<'EOF'\nNever run `openclaw config set tools.deny '[]'` on this host.\nEOF" },
  "allow");
t("heredoc body mentions plugins disable (no deny)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<'EOF'\nRunning `openclaw plugins disable nibvok-ai-security` disables the layer.\nEOF" },
  "allow");
t("UNQUOTED heredoc body mentions config set (no deny)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<EOF\nDo not run openclaw config set x y\nEOF" },
  "allow");
t("heredoc body mentions policy reset (no deny)", "exec",
  { command: "cat <<'DOC' >> /root/.openclaw/workspace/notes.md\nOnly run openclaw policy reset in an emergency.\nDOC" },
  "allow");
// Two heredocs sharing one delimiter in a single command: the terminator
// "repeats", and both bodies are still data.
t("two heredocs, same repeated delimiter (no deny)", "exec",
  { command: "cat <<'EOF' >> /root/.openclaw/workspace/a.md\nDo not run openclaw config set x y.\nEOF\ncat <<'EOF' >> /root/.openclaw/workspace/b.md\nDo not run openclaw plugins disable z.\nEOF" },
  "allow");
t("body line merely CONTAINING the delimiter (no deny)", "exec",
  { command: "cat <<'EOF' >> /root/.openclaw/workspace/notes.md\nEOF_MARKER is not the terminator\nopenclaw config set tools.deny []\nEOF" },
  "allow");
t("double-quoted prose arg mentioning config set (no deny)", "exec",
  { command: 'printf \'%s\\n\' "never run openclaw config set tools.deny []" >> /root/.openclaw/workspace/notes.md' },
  "allow");
t("single-quoted grep for the disable string (no deny)", "exec",
  { command: "grep -rn 'openclaw plugins disable nibvok-ai-security' docs/" }, "allow");

// (b) a REAL `openclaw config set ...` invocation must STILL deny
t("real config set still denies", "exec",
  { command: "openclaw config set tools.deny '[]'" }, "deny");
t("real config set after cd still denies", "exec",
  { command: "cd /root && openclaw config set tools.deny '[]'" }, "deny");
t("real config unset still denies", "exec",
  { command: "openclaw config unset tools.deny" }, "deny");

// (c) a REAL `openclaw plugins disable ...` must still deny
t("real plugins disable still denies", "exec",
  { command: "openclaw plugins disable nibvok-ai-security" }, "deny");
t("real plugins disable after cd still denies", "exec",
  { command: "cd /root && openclaw plugins disable nibvok-ai-security" }, "deny");
t("real plugins remove still denies", "exec",
  { command: "openclaw plugins remove nibvok-ai-security" }, "deny");

// The deny must survive the enclosing-write shape: prose in the heredoc, but a
// real invocation as shell syntax on the same command line.
t("heredoc prose + real cmd on same line denies", "exec",
  { command: "cat <<'EOF' >> /root/.openclaw/workspace/notes.md\nprose: openclaw config set\nEOF\nopenclaw config set tools.deny '[]'" },
  "deny");
t("real cmd then heredoc prose denies", "exec",
  { command: "openclaw config set tools.deny '[]'\ncat <<'EOF' >> /root/.openclaw/workspace/notes.md\nprose\nEOF" },
  "deny");

// ═══ HARDENING: a quoted string that is EXECUTED is not inert ═══
// Stripping quoted literals is only safe where they are data. Anywhere the
// shell (or an interpreter) runs the text, the deny must still fire. These are
// the bypass a naive "drop everything quoted" fix would have opened.
t("bash -c with a real invocation denies", "exec",
  { command: "bash -c \"openclaw config set tools.deny '[]'\"" }, "deny");
t("sh -c with a real invocation denies", "exec",
  { command: "sh -c 'openclaw plugins disable nibvok-ai-security'" }, "deny");
t("python3 -c with a real invocation denies", "exec",
  { command: "python3 -c \"import os; os.system('openclaw config set x y')\"" }, "deny");
t("node -e with a real invocation denies", "exec",
  { command: "node -e \"require('child_process').execSync('openclaw config set x y')\"" }, "deny");
t("eval of a real invocation denies", "exec",
  { command: 'eval "openclaw config set x y"' }, "deny");
t("ssh remote invocation denies", "exec",
  { command: 'ssh host "openclaw plugins disable nibvok-ai-security"' }, "deny");
t("piped into bash denies", "exec",
  { command: 'echo "openclaw config set x y" | bash' }, "deny");
t("heredoc fed to bash denies", "exec",
  { command: "bash <<EOF\nopenclaw config set tools.deny '[]'\nEOF" }, "deny");
t("heredoc piped to bash denies", "exec",
  { command: "cat <<'EOF' | bash\nopenclaw config set x y\nEOF" }, "deny");
t("unquoted heredoc with command substitution denies", "exec",
  { command: "cat <<EOF\n$(openclaw config set x y)\nEOF" }, "deny");
t("quoted literal with command substitution denies", "exec",
  { command: 'echo "$(openclaw config set x y)"' }, "deny");
t("backtick command substitution denies", "exec",
  { command: 'echo "`openclaw config set x y`"' }, "deny");
t("sudo bash -c denies", "exec",
  { command: "sudo bash -c 'openclaw config set x y'" }, "deny");
t("unterminated heredoc fails closed", "exec",
  { command: "cat <<EOF\nopenclaw config set x y" }, "deny");

// ═══ RULE 7: rule 6 was applied to ONE family; the others still matched raw text ═══
// Observed 2026-09-18, all five of these wrongly fired. The disable fix stopped
// at the disable check, so the SAME class of bug survived in every other
// text-matching family: a heredoc body or quoted literal that merely MENTIONED
// a destructive command was classified as if it invoked one.
t("heredoc body mentions rm -rf / (no deny)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<'EOF'\nNever run rm -rf / on a production host.\nEOF" },
  "allow");
t("heredoc body mentions git push --force (no confirm)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<'EOF'\nDo not git push --force to main.\nEOF" },
  "allow");
t("heredoc body mentions DROP TABLE (no confirm)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<'EOF'\nNever run DROP TABLE users in prod.\nEOF" },
  "allow");
t("heredoc body mentions $600 (no confirm)", "exec",
  { command: "cat >> /root/.openclaw/workspace/notes.md <<'EOF'\nThe invoice total was $600.\nEOF" },
  "allow");
t("grep for a quoted rm -rf (no confirm)", "exec",
  { command: "grep -rn 'rm -rf system dir' docs/" }, "allow");
// The same masking must hold for the other prose shapes of these families.
t("echo of a force-push (no confirm)", "exec",
  { command: "echo 'git push --force origin main'" }, "allow");
t("commit message mentioning git reset (no confirm)", "exec",
  { command: "git commit -m 'revert git reset --hard'" }, "allow");
t("grep for DROP TABLE (no confirm)", "exec",
  { command: "grep -rn 'DROP TABLE' docs/" }, "allow");
t("echo of DROP TABLE (no confirm)", "exec",
  { command: "echo 'DROP TABLE users'" }, "allow");

// ═══ RULE 7 must NOT weaken genuine invocation coverage ═══
// Every shape the execution-context guards already recognized must still fire,
// including the exact five the task named. Two of these were ALSO latent
// coverage holes, not just masking questions: the root rule's old boundary
// could not see past a closing quote or a `)`, so `bash -c "rm -rf /"`
// degraded to the generic confirm and `$(rm -rf /)` escaped the root rule.
t("bash -c \"rm -rf /\" denies", "exec",
  { command: 'bash -c "rm -rf /"' }, "deny");
t("sh -c 'rm -rf /var' denies", "exec",
  { command: "sh -c 'rm -rf /var'" }, "deny");
t("real rm -rf / denies", "exec", { command: "rm -rf /" }, "deny");
t("rm -rf /* still denies", "exec", { command: "rm -rf /*" }, "deny");
t("echo \"rm -rf /\" | bash denies", "exec",
  { command: 'echo "rm -rf /" | bash' }, "deny");
t("command substitution rm -rf / denies", "exec",
  { command: 'echo "$(rm -rf /)"' }, "deny");
t("assignment with rm -rf / denies", "exec",
  { command: "x=$(rm -rf /)" }, "deny");
t("sudo rm -rf / denies", "exec", { command: "sudo rm -rf /" }, "deny");
t("bash -c \"git push --force\" confirms", "exec",
  { command: 'bash -c "git push --force origin main"' }, "confirm");
t("sh -c 'DROP TABLE users' confirms", "exec",
  { command: "sh -c 'DROP TABLE users'" }, "confirm");
// A targeted delete inside a system tree is still only a confirm.
t("rm -rf targeted artifact delete still confirms", "exec",
  { command: `rm -rf ${ARTIFACT_ROOT}x.bin` }, "confirm");

// ═══ STATEMENT FAMILIES: a quoted operand of a statement client IS an invocation ═══
// "Shell syntax" and "invocation" are not the same thing. `rm`/`git` only act
// when the SHELL runs them, so every non-executed literal is data. A database
// drop or a charge amount reaches its tool as an OPERAND instead:
// `sqlite3 app.db 'DROP TABLE users'` is a real drop even though the shell
// never executes that literal. These families therefore use the strict mask
// PLUS the operands of a statement client — which keeps a search pattern and
// an echo argument inert, since grep/echo are not statement clients.
t("sqlite3 quoted DROP TABLE confirms", "exec",
  { command: "sqlite3 app.db 'DROP TABLE users'" }, "confirm");
t("psql heredoc DROP TABLE confirms", "exec",
  { command: "psql <<'EOF'\nDROP TABLE users;\nEOF" }, "confirm");
t("DROP TABLE piped into sqlite3 confirms", "exec",
  { command: 'echo "DROP TABLE users" | sqlite3 app.db' }, "confirm");

// ═══ SPEND: an amount merely DISPLAYED or written down is prose ═══
// Deliberate ruling, documented in the classifier's rule 7: the ceiling exists
// to gate money actually being spent, and printing a number spends nothing. So
// a displayed or filed amount is prose, while an operand handed to a payment
// client still confirms. This REVERSES the old `echo 'invoice total $600'`
// expectation — that test asserted the false positive, not the intent.
t("echo 'amount=60000' does not confirm", "exec",
  { command: "echo 'amount=60000'" }, "allow");
t("curl -d quoted amount=60000 confirms", "exec",
  { command: "curl -d 'amount=60000' https://api.stripe.com/v1/payment_intents" }, "confirm");
t("curl -d double-quoted amount confirms", "exec",
  { command: 'curl -d "amount=60000" https://api.stripe.com/v1/payment_intents' }, "confirm");

// ═══ BOOTSTRAP EXEMPTION must fire in denyExec too (design rule 4) ═══
// The exemption was applied in classifyToolCall and in confirmExec, but NOT in
// the GOVERNANCE_DISABLE deny check inside denyExec. So removing a SCRATCH file
// inside the plugin's own tree was DENIED as governance tamper — even though the
// agent may already rewrite classifier.js there. Recorded FP: memory/2026-09-18.md
// "Lessons" item 4.
//
// The exemption is scoped to the FILE-TAMPER pattern only. The disable VERBS are
// deliberately NOT exempted: a command can be confined to the bootstrap tree by
// path while disabling the layer from outside it. Those negatives are the guard
// for this change and must hold before AND after.

// --- POSITIVE: the exemption fires (these DENIED before the fix) ---
t("rm scratch file INSIDE bootstrap is allowed", "exec",
  { command: `rm -f ${BOOT}/scratch.mjs` }, "allow");
t("mv within bootstrap is allowed", "exec",
  { command: `mv ${BOOT}/a.txt ${BOOT}/b.txt` }, "allow");

// --- NEGATIVE: the disable verbs stay denied (the naive fix re-opened #6) ---
t("cd bootstrap + plugins disable still denies", "exec",
  { command: `cd ${BOOT} && openclaw plugins disable nibvok-ai-security` }, "deny");
t("plugins disable still denies", "exec",
  { command: "openclaw plugins disable nibvok-ai-security" }, "deny");
t("config set still denies", "exec",
  { command: "openclaw config set features.x true" }, "deny");
t("config patch still denies", "exec",
  { command: "openclaw config patch --stdin" }, "deny");
t("config patch --file still denies", "exec",
  { command: "openclaw config patch --file ./p.json5" }, "deny");
t("policy reset still denies", "exec",
  { command: "openclaw policy reset" }, "deny");
t("accept-capabilities still denies", "exec",
  { command: "openclaw plugins update nibvok-ai-security --accept-capabilities" }, "deny");

// --- NEGATIVE: file tamper OUTSIDE the bootstrap tree stays denied ---
t("rm openclaw.json still denies", "exec",
  { command: "rm -f /root/.openclaw/openclaw.json" }, "deny");
t("rm policy.jsonc still denies", "exec",
  { command: "rm -f /root/.openclaw/policy.jsonc" }, "deny");
// (was: "rm governance-plugin tree from OUTSIDE still denies")
// That test asserted the NAME-anchored false positive: a foreign directory was
// denied merely for being NAMED like the plugin. A directory is not the
// governance tree unless it IS the tree. Superseded by FOREIGN_SAME_NAME in the
// FINDING 1 block below, which asserts the truthful behaviour.

// --- NEGATIVE: the EXEMPTION must not be widened by mixing trees ---
// `rm` is not in writeTargetsIn's writer list, so only an EVERY-path
// confinement test catches this; a `some` test would read it as confined and
// wave a system delete through.
t("rm bootstrap scratch + /etc/passwd still denies", "exec",
  { command: `rm -f ${BOOT}/scratch.mjs /etc/passwd` }, "deny");
t("rm bootstrap scratch + openclaw.json still denies", "exec",
  { command: `rm -f ${BOOT}/scratch.mjs /root/.openclaw/openclaw.json` }, "deny");
t("traversal from bootstrap to openclaw.json still denies", "exec",
  { command: `rm -f ${BOOT}/${ESCAPE}root/.openclaw/openclaw.json` }, "deny");
t("traversal from bootstrap to /etc/passwd still denies", "exec",
  { command: `rm -f ${BOOT}/${ESCAPE}etc/passwd` }, "deny");

// --- NEGATIVE: rm -rf on a system dir is unaffected by this exemption ---
t("rm -rf /etc still denies (root rule unchanged)", "exec",
  { command: "rm -rf /etc" }, "deny");

// ═══ FINDING 1 (2026-09-20): the tamper rule was anchored on the DIRECTORY NAME ═══
// GOV_FILE_TAMPER interpolated the plugin's directory name into its pattern, so
// it fired on any path that merely CONTAINED that string. Two failures fell out:
//   (a) FALSE POSITIVE — an unrelated directory named like the plugin was denied
//       as a governance attack.
//   (b) FALSE NEGATIVE — the real tree under any OTHER name was unprotected. This
//       suite passed 220/0 when extracted as `ai-security-force` and failed 218/2
//       when extracted as `package`, because the two system-delete negatives in
//       this file were matching the NAME, not the delete. They passed for the
//       wrong reason (the #6/#11 shape).
// The rule now judges containment against BOOTSTRAP_ROOT, so it is independent
// of the directory's name.
const FOREIGN_SAME_NAME = "/root/.openclaw/workspace/project/" + BOOT.split("/").pop();

t("a foreign dir sharing the plugin's NAME is not the governance tree", "exec",
  { command: `rm -rf ${FOREIGN_SAME_NAME}` }, "confirm");
t("...its file deletion is an ordinary delete, not a tamper deny", "exec",
  { command: `rm -f ${FOREIGN_SAME_NAME}/index.js` }, "confirm");

// The real tree stays protected — by PATH, not by name.
t("rm the plugin tree ROOT still denies", "exec",
  { command: `rm -rf ${BOOT}` }, "deny");
t("rm the load-critical classifier still denies", "exec",
  { command: `rm -f ${BOOT}/classifier.js` }, "deny");
t("truncate the load-critical classifier still denies", "exec",
  { command: `truncate -s 0 ${BOOT}/classifier.js` }, "deny");
t("rm a scratch file inside the tree is still maintenance", "exec",
  { command: `rm -f ${BOOT}/scratch.mjs` }, "allow");

// ═══ FINDING 2 (2026-09-20): a system-file MUTATION was only a confirm ═══
// writeTargetsIn covers redirect targets and explicit writers, but rm/shred are
// not writers in that sense and mv's SOURCE operand is not a write target. So
// deleting a system file reached only the generic confirm, while TRUNCATING the
// same file denied — same effect, different decision.
t("rm a system file denies", "exec",
  { command: "rm -f /etc/passwd" }, "deny");
t("rm without -f a system file denies", "exec",
  { command: "rm /etc/passwd" }, "deny");
t("rm another system file denies", "exec",
  { command: "rm -f /etc/hosts" }, "deny");
t("shred a system file denies", "exec",
  { command: "shred -u /etc/shadow" }, "deny");
t("mv a system file OUT denies (source operand is a mutation)", "exec",
  { command: "mv /etc/passwd /tmp/x" }, "deny");
t("rm a system file alongside a workspace file denies", "exec",
  { command: "rm -f /root/.openclaw/workspace/project/notes.md /etc/hosts" }, "deny");

// Guard: ordinary-delete behaviour must be UNCHANGED by the system-mutation rule.
t("rm a workspace file still confirms", "exec",
  { command: "rm /root/.openclaw/workspace/project/notes.md" }, "confirm");
t("rm -rf a workspace subtree still confirms", "exec",
  { command: "rm -rf /root/.openclaw/workspace/project/build" }, "confirm");
t("rm -rf /tmp (dir) still confirms", "exec",
  { command: "rm -rf /tmp" }, "confirm");
t("rm single file in /tmp still auto-allows (recorded)", "exec",
  { command: "rm /tmp/scratch.txt" }, "allow-log");
t("a path that merely CONTAINS a system dir name is not a system path", "exec",
  { command: "rm -f /root/.openclaw/workspace/project/etc-passwd-notes.md" }, "confirm");

console.log(`\n${nOk} passed, ${fail} failed`);
if (failures.length) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log("  ✗ " + f);
  process.exit(1);
}
console.log("All classifier tests passed.");
