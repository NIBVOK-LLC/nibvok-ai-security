// Decision logic for the NIBVOK AI Security plugin.
//
// PURE module, no imports, so it is unit-testable with `node test-classifier.mjs`
// without a Gateway, a restart, or a live tool call. Regex command classification
// is best-effort; the only honest way to ship it is to make it inspectable and tested.
//
// Design rules learned from real false positives in this session:
//
//  1. Classify WRITE DESTINATIONS, never "every path mentioned". An earlier
//     version treated any path in a command containing a redirect as a write
//     target, so `ls /var/log/ 2>/dev/null` read as "writing to /var/log/", and
//     `2>/dev/null` as "writing to /dev/null". That blocked nearly every
//     ordinary shell command.
//  2. Classify READ TARGETS only for commands that actually read.
//  3. Secret rules are PATH-ANCHORED, never string-anchored. Matching the word
//     "secret" blocked every governance-related command — including reading this
//     file, a log line, or a filename. The word appearing is not a read of
//     secret material; a path pointing at secret material is.
//  4. Keep a bootstrap exemption. If the classifier can be blocked from editing
//     its own rules, a wrong classifier can never be fixed.
//  5. Gate the narrow, genuinely destructive things. A layer that prompts for
//     ordinary work gets switched off, and then nothing is governed at all.
//  6. A denied string inside DATA is not an invocation. The GOVERNANCE_DISABLE
//     patterns used to match anywhere in the raw command text, so documenting
//     the rule denied the documentation: an ordinary workspace file append
//     whose heredoc body merely QUOTED `openclaw config set ...` was itself
//     blocked as "attempt to disable or rewrite the governance layer". Same
//     class of bug as the string-anchored secret rules (rule 3, INCIDENTS.md
//     case study #3). Disable patterns now match only OUTSIDE heredoc bodies
//     and quoted literals — except where those are executed. See inertSpans.
//  7. Rule 6 was applied to ONE rule family and the fix stopped there, so the
//     SAME bug still affected every other text-matching family: those matched
//     raw command text, so a heredoc body or quoted literal that merely
//     MENTIONED a destructive command fired the rule. Confirmed 2026-09-18:
//     appending "Never run rm -rf / on a production host." to a notes file was
//     DENIED as an rm of the filesystem root; "Do not git push --force to
//     main." confirmed as a destructive git operation; "Never run DROP TABLE
//     users in prod." confirmed as a database drop; "The invoice total was
//     $600." tripped the spend ceiling; `grep -rn 'rm -rf system dir' docs/`
//     confirmed as a delete. Fixed by matching every family against shell
//     SYNTAX rather than raw text (inertSpans, below).
//
//     There are TWO masks, because "an invocation" means different things per
//     family, and using the strict mask everywhere would have broken genuine
//     detection:
//
//       - SHELL-INVOCATION families — the governance-disable check, rm-to-root,
//         rm-of-a-system-dir, git-destructive, and the bare-`rm` confirm. These
//         are only destructive when the SHELL runs them, so the strict mask is
//         exactly right: every non-executed quoted literal and heredoc body is
//         data. `sqlite3 app.db "git reset --hard"` is a string, not a git call.
//
//       - STATEMENT families — the database drops and the spend scan. Here the
//         text reaches its tool as an OPERAND, not as shell syntax:
//         `sqlite3 app.db 'DROP TABLE users'` and `curl -d 'amount=60000'` are
//         genuine invocations. These use the strict mask PLUS the operands of a
//         statement client (sqlite3/psql/mysql/… , curl/wget/stripe), while a
//         search PATTERN (`grep -rn 'DROP TABLE'`), an `echo`/`printf` argument,
//         and a heredoc body written by `cat` all stay data.
//
//     SPEND, decided deliberately (the task asked for an explicit ruling): a `$`
//     amount that is merely DISPLAYED or written into a file is PROSE, not a
//     transaction. `echo 'invoice total $600'` and a notes-file heredoc line
//     "The invoice total was $600." no longer confirm; `curl -d 'amount=60000'`
//     still does. The ceiling exists to gate money actually being spent, and
//     printing a number spends nothing.
//
//     Neither mask is allowed to weaken genuine coverage: a denied string that
//     is EXECUTED — `bash -c "rm -rf /"`, `sh -c 'DROP TABLE users'`,
//     `echo "rm -rf /" | bash`, interpreter-fed heredocs, command substitution,
//     eval/source/ssh — is still matched, because the execution-context guards
//     from rule 6 keep those literals OUT of the inert set.
//
// Policy source: owner-authored, 2026-09-18 (supersedes the earlier
// ALLOW/CONFIRM/DENY matrix). Enforcement is this plugin's before_tool_call
// hook — NOT the bundled `policy` plugin, which only audits config drift.

// ────────────────────────────────────────────────────────────
// Policy data
// ────────────────────────────────────────────────────────────

/**
 * Deployment-specific roots.
 *
 * These are the only paths in this file that are NOT universal. Each defaults to
 * a neutral value and is overridable by environment variable, so a new install
 * can point them at its own artifact and log directories without editing source.
 *
 *   ASF_ARTIFACT_ROOT      where generated artifacts are written
 *   ASF_LOG_ROOT           where this deployment keeps its logs
 *   ASF_WORKSPACE_ROOT     the agent workspace
 *   NIBVOK_AI_SECURITY_PLUGIN_ROOT        this plugin's own directory (bootstrap exemption)
 *   NIBVOK_AI_SECURITY_SPEND_CEILING_USD  transaction ceiling (default 500)
 */
export const ARTIFACT_ROOT = process.env.ASF_ARTIFACT_ROOT || "/var/asf/artifacts/";
export const LOG_ROOT = process.env.ASF_LOG_ROOT || "/var/log/asf/";
const WORKSPACE_ROOT =
  process.env.ASF_WORKSPACE_ROOT || "/root/.openclaw/workspace/";

/** Where agents may write. Artifact writes are allow+log (not silent). */
export const ALLOWED_WRITE_ROOTS = [
  WORKSPACE_ROOT,
  ARTIFACT_ROOT,
  "/tmp/",
  "/var/tmp/",
];

/** Writes here are recorded in the audit log even though they are allowed. */
export const LOGGED_WRITE_ROOTS = [ARTIFACT_ROOT];

/** System paths where any write is a hard deny. */
export const SYSTEM_DENY_ROOTS = [
  "/etc/",
  "/usr/",
  "/bin/",
  "/sbin/",
  "/lib/",
  "/lib64/",
  "/boot/",
  "/sys/",
  "/proc/",
  "/dev/",
];

/** Null/sink devices: redirecting to these is never a filesystem write. */
export const NULL_DEVICES = [
  "/dev/null",
  "/dev/stdout",
  "/dev/stderr",
  "/dev/tty",
  "/dev/zero",
  "/dev/fd/",
];

/**
 * Bootstrap exemption: the governance plugin's own source.
 * Reads and writes here are always allowed, so a wrong rule can always be fixed.
 */
export const BOOTSTRAP_ROOT =
  process.env.NIBVOK_AI_SECURITY_PLUGIN_ROOT || new URL("./", import.meta.url).pathname;

/** Where agents may read from. */
export const ALLOWED_READ_ROOTS = [
  "/root/.openclaw/",
  WORKSPACE_ROOT,
  ARTIFACT_ROOT,
  LOG_ROOT,
  "/etc/nginx/sites-available/",
  // Scratch roots are writable (ALLOWED_WRITE_ROOTS), so they must be readable
  // too: writing a script to /tmp and then running `node /tmp/x.mjs` was denied
  // as a read of a path outside the allowlist, which made a permitted write
  // unreadable by the same agent in the same breath. Owner-confirmed
  // 2026-09-18: it is a policy question, not a bug, and the answer is that
  // /tmp and /var/tmp are readable. Reads here are allowed silently, like the
  // other allowed roots; DENIED_READ_PATTERNS still wins for secret material.
  "/tmp/",
  "/var/tmp/",
];

/** Narrow exceptions inside otherwise-denied parents (checked first). */
export const READ_EXCEPTIONS = [
  "/etc/nginx/sites-available/",
  LOG_ROOT,
];

/** Parents where reads are DENIED except for READ_EXCEPTIONS. */
export const DENIED_READ_PARENTS = [
  "/root/backups/",
  "/root/.ssh/",
  "/var/log/",
];

/**
 * Parents where reads outside the allowlist CONFIRM rather than deny.
 * The owner's spec puts /etc/passwd at confirm, not deny.
 */
export const CONFIRM_READ_PARENTS = ["/etc/"];

/**
 * Real top-level directories. A leading segment outside this set cannot be a
 * filesystem path, so slash-tokens like the `/payments/config` inside an echo
 * label or a URL are ignored rather than treated as reads outside the
 * allowlist. Purely lexical: no syscalls, fully deterministic.
 */
const FHS_ROOTS = new Set([
  "root", "etc", "var", "home", "proc", "sys", "usr", "boot", "opt",
  "srv", "mnt", "media", "dev", "tmp", "run", "bin", "sbin", "lib", "lib64",
]);

/**
 * Hard-deny READ targets. PATH-anchored, per the owner's list:
 *   - /root/.openclaw/secrets*
 *   - any *.env file
 *   - /root/.ssh/
 *   - private keys
 * These are denied even inside an otherwise-allowed parent.
 */
export const DENIED_READ_PATTERNS = [
  /^\/root\/\.openclaw\/secrets/i,
  /(^|\/)\.env(\.|$|\/)/i,
  /(^|\/)[^\/]*\.env$/i,
  /^\/root\/\.ssh(\/|$)/i,
  /(^|\/)id_(rsa|ed25519|ecdsa)(\.|$)/i,
  // Real secret material on this host. The owner's rule named
  // /root/.openclaw/secrets*, which does not exist here; these do.
  /^\/root\/\.openclaw\/credentials(\/|$)/i,
  /^\/root\/\.openclaw\/secret-egress-proxy(\/|$)/i,
  /(^|\/)[^\/]*fingerprint\.key$/i,
  /(^|\/)[^\/]*-key\.pem$/i,
  // Runtime config and state carry credentials/attestations; readable only on
  // explicit request, never silently, even though /root/.openclaw/ is allowed.
  /^\/root\/\.openclaw\/openclaw\.json/i,
  /^\/root\/\.openclaw\/state(\/|$)/i,
];

/** Hosts approved for secret substitution (egress allowlist + OpenAI). */
export const APPROVED_HOSTS = [
  "api.gumloop.com",
  "queue.fal.run",
  "fal.run",
  "api.telegram.org",
  "storage.googleapis.com",
  "api.stripe.com",
  "api.openai.com",
];

/** External hosts an outbound API call may target without confirmation. */
export const ALLOWED_API_HOSTS = APPROVED_HOSTS;

/** Paths that hold the governance layer itself. */
export const GOVERNANCE_PATHS = [
  "/root/.openclaw/openclaw.json",
  "/root/.openclaw/policy.jsonc",
  "nibvok-ai-security",
];

/** Hard spend ceiling; at or above this, a transaction confirms (ABC guardrail). */
export const SPEND_CEILING_USD = (() => {
  const n = Number(process.env.NIBVOK_AI_SECURITY_SPEND_CEILING_USD);
  return Number.isFinite(n) && n > 0 ? n : 500;
})();

const DENY = "deny";
const CONFIRM = "confirm";
const ALLOW = "allow";
const ALLOW_LOG = "allow-log";

/** Severity order, so a set of paths collapses to its strictest decision. */
const ACTION_RANK = { allow: 0, "allow-log": 1, confirm: 2, deny: 3 };

/** Tools whose target path is written, not read. */
const WRITE_TOOLS = new Set(["write", "edit", "apply_patch", "patch", "notebook_edit"]);

// ────────────────────────────────────────────────────────────
// Regexes
// ────────────────────────────────────────────────────────────

const RM_ANY = /\brm\b/;
// The trailing boundary accepts a closing quote as well as whitespace: an
// executed literal runs as `bash -c "rm -rf /"`, where `/` is followed by `"`.
// Without it that shape never matched the root rule at all and degraded to the
// generic confirm (a genuine-coverage hole, not just a masking question). The
// remaining characters cover the other ways a real invocation can END the path
// — `$(rm -rf /)`, `rm -rf /;x`, `rm -rf /|tee` — which the old `(\s|$|\*)`
// boundary missed, so a command substitution escaped the root rule entirely.
const RM_ROOT_END = `(?=[\\s*"');|&\u0060]|$)`;
const RM_FORCE_ROOT = new RegExp(`\\brm\\b[^\\n|;&]*\\s-[a-zA-Z]*[rf][a-zA-Z]*\\s+/${RM_ROOT_END}`);
// Whole-directory wipes of a top-level system directory are catastrophic and
// always denied. A TARGETED delete inside one of these trees still confirms:
// `rm -rf /var` denies, `rm -rf /var/asf/x` confirms.
const RM_FORCE_SYSTEM_DIR = new RegExp(
  `\\brm\\b[^\\n|;&]*\\s-[a-zA-Z]*[rf][a-zA-Z]*\\s+/(?:etc|root|var|usr|bin|sbin|lib|lib64|boot|sys|proc|dev|home|opt|srv|mnt)/?${RM_ROOT_END}`,
);

const GIT_DESTRUCTIVE = [
  /\bgit\s+push\b[^\n|;&]*(--force\b|--force-with-lease\b|\s-f\b)/,
  /\bgit\s+reset\b/,
  /\bgit\s+clean\b[^\n|;&]*\s-[a-zA-Z]*[fd]/,
  /\bgit\s+branch\b[^\n|;&]*\s-D\b/,
  /\bgit\s+checkout\b[^\n|;&]*\s(--\s+)?\.(\s|$)/,
  /\bgit\s+restore\b/,
];

/** Database drops. */
const DB_DESTRUCTIVE = [
  /\bdrop\s+(table|database|schema)\b/i,
  /\bdropdb\b/i,
  /\bpg_restore\b[^\n|;&]*--clean\b/,
];

const STRIPE_TOUCH = [/\bstripe\b/i, /api\.stripe\.com/i, /\bsk_live_/];

/** Reading a stored secret value back out (path/command-anchored). */
const SECRET_READ_CMD = /\bopenclaw\s+secrets\s+store\s+(get|show|read)\b/;

/**
 * Governance-layer modifications. Run against the command with inert ranges
 * masked out (design rule 6): a body that MENTIONS `openclaw config set` is
 * documentation, while the same words as shell syntax are an invocation.
 */
/**
 * File-level tampering with a governance config/source path (rm/mv/truncate/
 * shred). Kept as its own const because it is the ONE disable pattern the
 * bootstrap exemption (design rule 4) may skip: maintaining the plugin's own
 * tree legitimately means deleting scratch files inside BOOTSTRAP_ROOT. The
 * disable VERBS below stay unconditional — see denyExec.
 */
/** Destructive verbs on their own. Paired with a PATH test, never with a name. */
const GOV_FILE_VERBS = /\b(rm|mv|truncate|shred)\b/;

/**
 * File-level tampering with a governance CONFIG path (rm/mv/truncate/shred of
 * openclaw.json or policy.jsonc).
 *
 * This pattern used to also interpolate the plugin's own DIRECTORY NAME
 * (GOVERNANCE_PATHS[2]). Because it matched that string anywhere in the command,
 * it fired on any path that merely CONTAINED it: an unrelated directory was
 * denied for sharing the name, while the REAL tree went unprotected under any
 * other name. The plugin tree is now judged by containment
 * (tampersGovernanceTree) — by where it IS, not by what it is called.
 * See INCIDENTS.md #19 (Finding 1).
 *
 * Do NOT re-add a directory name here.
 */
const GOV_FILE_TAMPER = new RegExp(
  `\\b(rm|mv|truncate|shred)\\b[^\\n|;&]*(openclaw\\.json|policy\\.jsonc)`,
);

const GOVERNANCE_DISABLE = [
  /\bopenclaw\s+plugins?\s+(disable|remove|uninstall)\b/,
  /\bopenclaw\s+config\s+(set|unset|delete|patch)\b/,
  /\bopenclaw\s+policy\b[^\n|;&]*\b(reset|clear)\b/,
  GOV_FILE_TAMPER,
  // `--accept-capabilities` on a plugin command (re)grants a plugin's capability
  // consent. That is how the governance plugin silently re-registered and was
  // then disabled in config, leaving the layer unenforced while the UI still
  // reported "enabled" (see INCIDENTS.md case study #6). Denied like the other
  // disable verbs. A plain `plugins update <name>` stays allowed, because
  // updating an ordinary plugin is not a governance-layer modification.
  /\bopenclaw\s+plugins?\s+[^\n|;&]*--accept-capabilities\b/,
];

/** Verbs indicating a command reads files. */
const READ_VERB_RE =
  /\b(cat|tac|less|more|head|tail|grep|egrep|fgrep|rg|ls|find|stat|file|wc|md5sum|sha1sum|sha256sum|xxd|strings|du|tree|readlink|realpath|diff|cmp|jq|sqlite3|restic|tar|unzip|zcat|base64|nl|open|source|python3?|node|sed|awk)\b/;

/** Test/lint runners that always run without confirmation. */
const TEST_RUNNER_RE =
  /(^|[\s;|&])(pytest|py\.test|python3?\s+-m\s+pytest|python3?\s+-m\s+unittest|tox|nox|jest|vitest|mocha|npm\s+(run\s+)?test|yarn\s+test|pnpm\s+(run\s+)?test|go\s+test|cargo\s+test|rspec|phpunit|ruff|flake8|mypy|pylint|eslint|prettier|black|isort|shellcheck|tsc|openclaw\s+doctor|openclaw\s+policy\s+check)\b/;

// ────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────

function isNullDevice(path) {
  return NULL_DEVICES.some((d) => path === d || path.startsWith(d));
}

function isAbsoluteish(p) {
  return p.startsWith("/") || p.startsWith("~/");
}

function normalize(p) {
  let s = String(p || "").trim();
  if (s.startsWith("~")) s = s.replace(/^~/, "/root");
  if (!s.startsWith("/")) return s;

  // Resolve `.` and `..` lexically. Without this,
  // `/root/.openclaw/workspace/../credentials/x` still startsWith the allowed
  // workspace root and would be allowed — a real traversal bypass.
  const parts = [];
  for (const seg of s.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return "/" + parts.join("/");
}

function underAny(path, roots) {
  const p = normalize(path);
  return roots.some((r) => p === r.replace(/\/$/, "") || p.startsWith(r));
}

/** Is this path inside the classifier's own source tree? */
function isBootstrapPath(p) {
  return underAny(p, [BOOTSTRAP_ROOT]);
}

/**
 * Does a destructive verb in this command name a path INSIDE the plugin tree?
 *
 * Containment, not a name match: `rm -rf /tmp/backup/nibvok-ai-security` is an
 * ordinary delete of an unrelated directory, while a real tree extracted as
 * `package/` is still the tree. See INCIDENTS.md #19.
 */
function tampersGovernanceTree(cmd, inert) {
  if (!matchesOutsideInert(cmd, GOV_FILE_VERBS, inert)) return false;
  return absolutePathsIn(maskInert(cmd, inert)).some((p) => isBootstrapPath(p));
}

/**
 * True when a command is CONFINED to the classifier's own tree: it names at
 * least one absolute path, EVERY absolute path it names is inside
 * BOOTSTRAP_ROOT, and it writes nothing outside that tree.
 *
 * EVERY, not SOME. With `some`, `rm -f <bootstrap>/scratch.mjs /etc/passwd` —
 * which names a bootstrap path while deleting a system file — read as
 * "confined", and the exemption would wave a system delete through. (`rm` is
 * not in writeTargetsIn's writer list, so the write-target half of the test
 * does not catch it on its own.) Requiring every named path to be bootstrap
 * closes that hole.
 */
function isBootstrapConfined(cmd) {
  const paths = absolutePathsIn(cmd);
  return (
    paths.length > 0 &&
    paths.every(isBootstrapPath) &&
    !writeTargetsIn(cmd).some((p) => !isBootstrapPath(p))
  );
}

/** Strictly inside the tree — excludes BOOTSTRAP_ROOT itself. */
function isBootstrapDescendant(p) {
  const root = normalize(BOOTSTRAP_ROOT);
  const q = normalize(p);
  return q !== root && q.startsWith(root + "/");
}

/**
 * Files the layer needs in order to LOAD. Exempting their deletion would
 * reproduce INCIDENTS.md #6 the easy way: the plugin fails to load, the
 * enforcement path is gone, and nothing reports it. Editing them is already
 * allowed (design rule 4 — that is how a wrong rule gets fixed); REMOVING them
 * is not maintenance.
 */
const BOOTSTRAP_PROTECTED =
  /\/(classifier\.js|index\.js|openclaw\.plugin\.json|package\.json|node_modules)(\/|$)/;

/**
 * Narrower than isBootstrapConfined, for the DENY path: a command is bootstrap
 * MAINTENANCE only if every path it names is strictly inside the tree, none of
 * them is load-critical, and it writes nothing outside. Deleting the tree root
 * or the files that make the layer load stays denied — the exemption exists to
 * let an agent clear a scratch file, not to let it remove the guard.
 */
function isBootstrapMaintenance(cmd) {
  const paths = absolutePathsIn(cmd);
  if (!paths.length) return false;
  return (
    paths.every(isBootstrapDescendant) &&
    !paths.some((p) => BOOTSTRAP_PROTECTED.test(normalize(p))) &&
    !writeTargetsIn(cmd).some((p) => !isBootstrapPath(p))
  );
}

/**
 * Destinations a command actually WRITES to.
 *
 * Only redirect targets and the destination operand of explicit write commands.
 * Read operands are never included — that is the whole point (see rule 1).
 */
function writeTargetsIn(cmd) {
  const out = [];

  const redir = /(?:^|[\s;|&])(?:\d*)>>?\s*([^\s;|&<>]+)/g;
  let m;
  while ((m = redir.exec(cmd)) !== null) {
    const t = m[1];
    if (t.startsWith("&")) continue; // 2>&1, >&2
    if (!isNullDevice(t)) out.push(t);
  }

  const writers = /\b(cp|mv|install|ln|tee|truncate|dd|sed|chmod|chown)\b([^\n;|&]*)/g;
  while ((m = writers.exec(cmd)) !== null) {
    const name = m[1];
    const rest = m[2] || "";
    if (name === "dd") {
      const of = rest.match(/\bof=([^\s;|&]+)/);
      if (of && !isNullDevice(of[1])) out.push(of[1]);
      continue;
    }
    if (name === "sed" && !/(^|\s)-i/.test(rest)) continue; // sed without -i does not write
    const operands = rest.trim().split(/\s+/).filter((a) => a && !a.startsWith("-"));
    const last = operands[operands.length - 1];
    if (last && !isNullDevice(last)) out.push(last);
  }

  return out.filter((p) => p && !isNullDevice(p));
}

/** Whitespace-split operands with flags and surrounding quotes stripped. */
function operandsOf(rest) {
  return String(rest || "")
    .trim()
    .split(/\s+/)
    .map((a) => a.replace(/^['"]|['"]$/g, ""))
    .filter((a) => a && !a.startsWith("-"));
}

/**
 * System paths a command MUTATES by deleting or moving them.
 *
 * A delete is a mutation, and mutating a system file is a hard deny. These verbs
 * are invisible to writeTargetsIn: `rm` and `shred` write no destination, and
 * `mv`'s destructive operand is its SOURCE, not its target. So a system-file
 * delete reached only the generic confirm while TRUNCATING the same file denied
 * — same effect, weaker decision. `mv` contributes every operand, because a move
 * mutates what it removes as well as what it writes. See INCIDENTS.md #20.
 *
 * Returns only paths under SYSTEM_DENY_ROOTS; the caller decides the verdict.
 */
function systemMutationIn(cmd) {
  const out = [];
  for (const verb of [/\b(?:rm|shred)\b([^\n;|&]*)/g, /\bmv\b([^\n;|&]*)/g]) {
    let m;
    while ((m = verb.exec(cmd)) !== null) out.push(...operandsOf(m[1]));
  }
  return out.filter((p) => isAbsoluteish(p) && underAny(p, SYSTEM_DENY_ROOTS));
}

/** Absolute paths mentioned in a command (used only for read-verb commands). */
function absolutePathsIn(cmd) {
  const out = [];
  // Require at least one character after the leading slash. A bare "/" appears
  // constantly in ordinary prose and arithmetic ("4 / 6", "new pid / start"),
  // and treating it as a path produced false "outside the allowlist" denials.
  const re = /(?:^|[\s"'=<>|;(])((?:\/|~\/)[A-Za-z0-9_./~-]+)/g;
  let m;
  while ((m = re.exec(cmd)) !== null) {
    const p = m[1];
    if (!p || isNullDevice(p)) continue;
    // A bare single-segment token such as `/export` is a regex/script fragment
    // (sed '/export function/,/^}/p'), not a path. Requiring a further
    // separator or a dot drops those while still catching real files named
    // inside quoted program strings, e.g. python -c "open('/x/y.json')".
    if (/^\/[A-Za-z0-9_~-]+$/.test(p)) continue;
    // First segment must be a real top-level directory; otherwise this is a
    // URL fragment or label text, not a path.
    const seg = p.startsWith("~/") ? p.slice(2) : p.slice(1);
    if (!FHS_ROOTS.has(seg.split("/")[0])) continue;
    out.push(p);
  }
  return out;
}

/** Hosts named in a command. */
function hostsIn(cmd) {
  const out = [];
  const re = /(?:https?:\/\/)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?/gi;
  let m;
  while ((m = re.exec(cmd)) !== null) out.push(m[1].toLowerCase());
  return out;
}

function makesNetworkCall(cmd) {
  return /\b(curl|wget|http|https|requests|urllib|fetch|axios|nc|ssh|scp|rsync)\b/.test(cmd);
}

/** Best-effort extraction of dollar amounts >= SPEND_CEILING_USD. */
function spendAtOrAboveCeiling(cmd) {
  const hits = [];
  const dollar = /\$\s?(\d+(?:[.,]\d+)?)/g;
  let m;
  while ((m = dollar.exec(cmd)) !== null) {
    const v = parseFloat(m[1].replace(",", ""));
    if (!Number.isNaN(v) && v >= SPEND_CEILING_USD) hits.push(v);
  }
  const amount = /\bamount[=:]\s*(\d{4,})/gi;
  while ((m = amount.exec(cmd)) !== null) {
    const v = parseInt(m[1], 10);
    if (!Number.isNaN(v) && v >= SPEND_CEILING_USD * 100) hits.push(v / 100);
  }
  return hits;
}

/** Is this the approved `secrets store set ... --allow-host <approved>` form? */
function isApprovedSecretsHostGrant(cmd) {
  if (!/\bopenclaw\s+secrets\s+store\s+set\b/.test(cmd)) return false;
  const m = cmd.match(/--allow-host\s+([^\s;|&]+)/);
  if (!m) return false;
  return APPROVED_HOSTS.includes(m[1].toLowerCase());
}

// ────────────────────────────────────────────────────────────
// Shell syntax vs. shell data (design rule 6)
// ────────────────────────────────────────────────────────────
//
// inertSpans() reports the [start, end) ranges of a command that are DATA rather
// than shell syntax: heredoc bodies and quoted string literals. The disable
// check then only honours matches that start outside those ranges.
//
// The obvious inverse mistake is as bad as the original bug, so two guards keep
// the deny coverage honest:
//
//   - A quoted literal is inert EXCEPT where it is executed: the inline program
//     of an interpreter (`bash -c "..."`, `python3 -c "..."`, `node -e ...`),
//     the argument of `eval`/`source`/`ssh`, the far side of a pipe
//     (`echo "..." | bash`), or text containing a command substitution.
//   - A heredoc body is inert EXCEPT when the heredoc is fed to an interpreter
//     (`bash <<EOF`, `cat <<EOF | bash`) or uses an UNQUOTED delimiter with a
//     command substitution in the body, both of which execute rather than
//     display.
//
// Anything unparsable fails closed: no span is recorded, so the raw text is
// still matched and a genuine invocation is still denied.

/** Commands that run text handed to them (as `-c`/`-e` programs or as bodies). */
const INTERPRETER_CMD = new RegExp(
  "(?:^|[;|&(]|\\bsudo\\b|\\benv\\b|\\bnohup\\b|\\btime\\b|\\bxargs\\b)" +
    "\\s*(?:[A-Za-z0-9_./-]*/)?" +
    "(bash|sh|zsh|dash|ksh|fish|python3?|node|deno|bun|perl|ruby|php|awk|gawk|eval|source|exec|ssh)\\b",
);

/** Flags whose following argument is a program to run. */
const INLINE_PROGRAM_FLAG = /^(-c|--command|-e|--eval|-r|--run)$/;

/**
 * Commands that receive quoted text as a STATEMENT or BODY and ACT on it,
 * even though the shell never executes it. This is what separates
 * `sqlite3 app.db 'DROP TABLE users'` (a real drop) from
 * `grep -rn 'DROP TABLE' docs/` (a search pattern) — both are quoted operands,
 * only the first one does something. Used ONLY for the statement families
 * (database drops, spend); the shell-invocation families keep the strict mask.
 */
const STATEMENT_CLIENTS = new Set([
  "sqlite3", "psql", "mysql", "mariadb", "mongosh", "mongo", "redis-cli",
  "duckdb", "clickhouse-client", "curl", "wget", "http", "xh", "stripe",
]);

/** Wrapper words that precede the real command word. */
const CMD_WRAPPERS = new Set([
  "sudo", "doas", "env", "nohup", "time", "command", "nice", "ionice",
  "stdbuf", "xargs",
]);

/**
 * The command word that a fragment would run: the first token after any
 * wrapper words, env assignments, or leading flags, dropping a `/usr/bin/`
 * style prefix. Used to decide whether a quoted literal is an OPERAND of a
 * statement client (`sqlite3 … 'DROP TABLE'`) or data (`echo 'DROP TABLE'`).
 */
function commandWordOf(text) {
  const sep = Math.max(String(text).lastIndexOf("|"), String(text).lastIndexOf(";"));
  const piece = sep === -1 ? String(text) : String(text).slice(sep + 1);
  const toks = piece.trim().split(/\s+/).filter(Boolean);
  let i = 0;
  while (
    i < toks.length &&
    (CMD_WRAPPERS.has(toks[i]) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(toks[i]) || (i > 0 && toks[i].startsWith("-")))
  ) {
    i++;
  }
  return (toks[i] || "").replace(/^.*\//, "");
}

/** Index of the closing quote for the literal opening at `start`, or -1. */
function endOfQuote(cmd, start) {
  const quote = cmd[start];
  let i = start + 1;
  while (i < cmd.length) {
    if (quote === '"' && cmd[i] === "\\") {
      i += 2;
      continue;
    }
    if (cmd[i] === quote) return i;
    i++;
  }
  return -1;
}

/** Start of the shell segment (after ; | & or a newline) containing `pos`. */
function segmentStartBefore(cmd, pos) {
  let start = 0;
  for (let i = pos - 1; i >= 0; i--) {
    if (cmd[i] === ";" || cmd[i] === "|" || cmd[i] === "&" || cmd[i] === "\n") {
      start = i + 1;
      break;
    }
  }
  return start;
}

/**
 * Does this quoted literal get executed rather than used as data?
 * The literal runs at cmd[quoteStart]..cmd[quoteEnd].
 */
function quotedLiteralExecutes(cmd, quoteStart, quoteEnd, extraActors = null) {
  const inner = cmd.slice(quoteStart + 1, quoteEnd);
  // `$(...)` / backticks execute no matter how the literal is passed.
  if (/\$\(|`/.test(inner)) return true;

  const before = cmd.slice(segmentStartBefore(cmd, quoteStart), quoteStart);
  // `bash -c "..."`, `python3 -c "..."`, `node -e "..."`.
  if (INLINE_PROGRAM_FLAG.test(before.trim().split(/\s+/).pop() || "")) {
    if (INTERPRETER_CMD.test(before)) return true;
  }
  // `eval "..."`, `source "..."`, `. "..."`, `ssh host "..."`.
  if (
    /(?:^|[;|&(]|\bsudo\b|\benv\b|\bnohup\b|\btime\b)\s*(?:[A-Za-z0-9_./-]*\/)?(eval|source|\.|ssh)\b/.test(
      before,
    )
  ) {
    return true;
  }
  // `sqlite3 app.db 'DROP TABLE users'` — the literal is a statement operand of
  // a client that acts on it. Only for the statement families (extraActors).
  if (extraActors && extraActors.has(commandWordOf(before))) return true;

  // `echo "..." | bash` — the literal is the program on the far side.
  const after = cmd.slice(quoteEnd + 1);
  if (/^\s*\|/.test(after)) {
    if (INTERPRETER_CMD.test(after)) return true;
    // `echo "DROP TABLE users" | sqlite3 app.db`
    if (extraActors && extraActors.has(commandWordOf(after))) return true;
  }
  return false;
}

/**
 * Parse the heredoc introduced at `start` (the first `<` of `<<`).
 *
 * @returns {{bodyStart:number, bodyEnd:number, end:number, expands:boolean}|null}
 *   `expands` is true for an unquoted delimiter (substitutions run), false for
 *   `<<'EOF'` / `<<"EOF"` / `<<\EOF`. Null means "not a heredoc I can trust"
 *   (no terminator line), which leaves the raw text matched — fail closed.
 */
function parseHeredoc(cmd, start) {
  let i = start + 2;
  if (cmd[i] === "-") i++; // `<<-` strips leading tabs from body lines
  while (cmd[i] === " " || cmd[i] === "\t") i++;
  let quote = null;
  if (cmd[i] === "'" || cmd[i] === '"') {
    quote = cmd[i];
    i++;
  } else if (cmd[i] === "\\") {
    i++;
  }
  const wordStart = i;
  while (i < cmd.length && /[A-Za-z0-9_+.,:/-]/.test(cmd[i])) i++;
  const delim = cmd.slice(wordStart, i);
  if (!delim) return null;
  if (quote && cmd[i] === quote) i++;

  const introEnd = cmd.indexOf("\n", i);
  if (introEnd === -1) return null;

  const bodyStart = introEnd + 1;
  let offset = bodyStart;
  for (const line of cmd.slice(bodyStart).split("\n")) {
    if (line.replace(/^\t+/, "") === delim) {
      return {
        bodyStart,
        bodyEnd: offset,
        end: offset + line.length,
        expands: quote === null,
      };
    }
    offset += line.length + 1;
  }
  return null; // unterminated: treat as ordinary text so nothing is hidden
}

/** Does this heredoc body get executed (fed to an interpreter, or expanded)? */
function heredocExecutes(cmd, start, introEnd, body, expands, extraActors = null) {
  // `introEnd` is the newline that STARTS the body, so this slice is the intro
  // line alone (`psql <<'EOF'`) — never the body, whose contents are not actors.
  const segment = cmd.slice(segmentStartBefore(cmd, start), introEnd + 1);
  if (INTERPRETER_CMD.test(segment)) return true;
  // `psql <<EOF` / `cat <<EOF | sqlite3 app.db` — the body is a statement the
  // client acts on, so it is not data. Statement families only.
  if (extraActors && extraActors.has(commandWordOf(segment))) return true;
  // An unquoted delimiter expands `$(...)` inside the body.
  if (expands && /\$\(|`/.test(body)) return true;
  return false;
}

/**
 * [start, end) ranges of `cmd` that are data, not executable shell syntax.
 */
function inertSpans(cmd, extraActors = null) {
  const spans = [];
  let i = 0;
  while (i < cmd.length) {
    const ch = cmd[i];

    if (ch === "\\") {
      i += 2; // escaped character outside quotes
      continue;
    }

    if (ch === "'" || ch === '"') {
      const end = endOfQuote(cmd, i);
      if (end === -1) break; // unterminated: nothing after is analysable
      if (!quotedLiteralExecutes(cmd, i, end, extraActors)) spans.push([i + 1, end]);
      i = end + 1;
      continue;
    }

    if (ch === "<" && cmd[i + 1] === "<") {
      const h = parseHeredoc(cmd, i);
      if (h) {
        const body = cmd.slice(h.bodyStart, h.bodyEnd);
        if (!heredocExecutes(cmd, i, h.bodyStart - 1, body, h.expands, extraActors)) {
          spans.push([h.bodyStart, h.bodyEnd]);
        }
        i = h.end;
        continue;
      }
    }

    i++;
  }
  return spans;
}

/**
 * `cmd` with every inert range overwritten by spaces (same length, so nothing
 * else shifts). Regexes keep using matchesOutsideInert, which is index-precise;
 * this is for scanners like the spend lookup that walk the text directly.
 */
function maskInert(cmd, spans) {
  if (!spans.length) return cmd;
  const chars = cmd.split("");
  for (const [s, e] of spans) {
    for (let i = s; i < e && i < chars.length; i++) chars[i] = " ";
  }
  return chars.join("");
}

/** Does ANY of `regexes` match this command outside its inert text? */
function anyMatchOutside(cmd, regexes, spans) {
  return regexes.some((re) => matchesOutsideInert(cmd, re, spans));
}

/**
 * Does `re` match `cmd` anywhere that is NOT inert text?
 * Without any inert spans this is exactly the old behaviour.
 */
function matchesOutsideInert(cmd, re, spans) {
  // No inert text: behave exactly as the plain `re.test(cmd)` did before.
  if (!spans.length) return re.test(cmd);
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  const rx = new RegExp(re.source, flags);
  let m;
  while ((m = rx.exec(cmd)) !== null) {
    if (!spans.some(([s, e]) => m.index >= s && m.index < e)) return true;
    if (m.index === rx.lastIndex) rx.lastIndex++; // zero-length match guard
  }
  return false;
}

// ────────────────────────────────────────────────────────────
// Read policy
// ────────────────────────────────────────────────────────────

/**
 * Classify a single filesystem path for READ access.
 *
 * @returns {{action: "allow"|"deny", reason?: string}}
 */
export function classifyReadPath(rawPath) {
  const path = normalize(rawPath);
  if (!path) return { action: ALLOW };

  // Bootstrap: the classifier may always read its own source.
  if (isBootstrapPath(path)) return { action: ALLOW };

  // Hard denies: secret material is never readable, even inside an allowed parent.
  for (const re of DENIED_READ_PATTERNS) {
    if (re.test(path)) {
      return { action: DENY, reason: `read of protected secret material (${path})` };
    }
  }

  // Relative paths resolve inside the workspace.
  if (!path.startsWith("/")) {
    if (path.split("/").includes("..")) {
      return { action: DENY, reason: `relative read escaping the workspace (${path})` };
    }
    return { action: ALLOW };
  }

  if (underAny(path, READ_EXCEPTIONS)) return { action: ALLOW };
  if (underAny(path, ALLOWED_READ_ROOTS)) return { action: ALLOW };

  if (underAny(path, CONFIRM_READ_PARENTS)) {
    return { action: CONFIRM, reason: `read of ${path} outside the allowlist` };
  }

  const parent = DENIED_READ_PARENTS.find((d) => underAny(path, [d]));
  if (parent) {
    return { action: DENY, reason: `read denied under ${parent} (${path})` };
  }
  return { action: DENY, reason: `read outside the read allowlist (${path})` };
}

/**
 * Classify a single filesystem path for WRITE access.
 *
 * @returns {{action: "allow"|"allow-log"|"confirm"|"deny", reason?: string}}
 */
export function classifyWritePath(rawPath) {
  const path = normalize(rawPath);
  if (!path) return { action: ALLOW };

  // Bootstrap: the classifier may always rewrite its own source (design rule 4).
  if (isBootstrapPath(path)) return { action: ALLOW };

  for (const re of DENIED_READ_PATTERNS) {
    if (re.test(path)) {
      return { action: DENY, reason: `write to protected secret material (${path})` };
    }
  }

  if (!path.startsWith("/")) {
    if (path.split("/").includes("..")) {
      return { action: DENY, reason: `relative write escaping the workspace (${path})` };
    }
    return { action: ALLOW };
  }

  if (underAny(path, SYSTEM_DENY_ROOTS)) {
    return { action: DENY, reason: `write to system path ${path}` };
  }
  if (underAny(path, ALLOWED_WRITE_ROOTS)) {
    if (underAny(path, LOGGED_WRITE_ROOTS)) {
      return { action: ALLOW_LOG, reason: `artifact write (${path})` };
    }
    return { action: ALLOW };
  }
  return { action: CONFIRM, reason: `write outside the workspace (${path})` };
}

/** Collapse several path decisions to the strictest one. */
function worstAction(actions) {
  let worst = { action: ALLOW };
  for (const a of actions) {
    if (ACTION_RANK[a.action] > ACTION_RANK[worst.action]) worst = a;
  }
  return worst;
}

/**
 * Read-policy denial for a command that reads files, or null.
 *
 * The word "secret" appearing anywhere is NOT a violation — only a path that
 * resolves to secret material is (rule 3).
 */
function readDenyInExec(cmd) {
  if (SECRET_READ_CMD.test(cmd)) {
    return { action: DENY, reason: "reading a stored secret value back out" };
  }

  // Any *.env token, absolute or relative: `cat .env` names no absolute path,
  // so an absolute-path-only check would let it through. The boundary class
  // includes `/` so a path like /app/config/prod.env is still caught even when
  // its leading segment is not a real top-level directory.
  const envToken = /(?:^|[\s"'=<>|;(/])([\w.-]*\.env)(?:\.|[\s"'<>|;&)]|$)/;
  if (envToken.test(cmd)) {
    return { action: DENY, reason: "read of an .env file" };
  }

  const paths = absolutePathsIn(cmd);
  for (const p of paths) {
    if (isBootstrapPath(p)) continue;
    for (const re of DENIED_READ_PATTERNS) {
      if (re.test(normalize(p))) {
        return { action: DENY, reason: `read of protected secret material (${p})` };
      }
    }
  }

  // Test the read VERB against the command with paths removed. Otherwise a
  // filename like `file.txt` trips the `file` verb, and `out.mp4` trips nothing
  // but `/root/other/file.txt` used to be denied as an unreadable path.
  const stripped = cmd.replace(/\/[A-Za-z0-9_./~-]*/g, " ");
  if (!READ_VERB_RE.test(stripped)) return null;

  for (const p of paths) {
    if (isBootstrapPath(p)) continue;
    const r = classifyReadPath(p);
    if (r.action === DENY) return r;
  }
  return null;
}

// ────────────────────────────────────────────────────────────
// Exec policy
// ────────────────────────────────────────────────────────────

function denyExec(cmd) {
  // Every text-matching family runs against shell SYNTAX, not raw text: a
  // heredoc body that documents `rm -rf /` is documentation (design rules 6-7).
  const inert = inertSpans(cmd);
  if (matchesOutsideInert(cmd, RM_FORCE_ROOT, inert)) {
    return { action: DENY, reason: "rm -rf targeting the filesystem root" };
  }
  if (matchesOutsideInert(cmd, RM_FORCE_SYSTEM_DIR, inert)) {
    return { action: DENY, reason: "rm -rf targeting a system directory" };
  }
  // The disable check uses the same shell-syntax mask.
  for (const re of GOVERNANCE_DISABLE) {
    if (!matchesOutsideInert(cmd, re, inert)) continue;
    // Bootstrap exemption (design rule 4), scoped to FILE TAMPER ONLY and to
    // genuine MAINTENANCE (scratch files strictly inside the tree). An agent is
    // already allowed to rewrite the classifier's own source, so removing a
    // scratch file in that tree must not trip the tamper pattern (recorded FP;
    // see memory/2026-09-18.md "Lessons" item 4).
    //
    // Two things stay denied on purpose:
    //   - the disable VERBS. `cd <bootstrap> && openclaw plugins disable
    //     nibvok-ai-security` is confined by path yet disables the layer from
    //     outside it; exempting the whole loop would re-open INCIDENTS.md #6.
    //   - deleting the tree ROOT or the load-critical files (isBootstrapMaintenance
    //     requires a proper descendant and rejects BOOTSTRAP_PROTECTED), because
    //     a plugin that cannot load is an unenforced layer reporting healthy.
    if (re === GOV_FILE_TAMPER && isBootstrapMaintenance(cmd)) continue;
    return { action: DENY, reason: "attempt to disable or rewrite the governance layer" };
  }
  // The plugin's OWN tree, judged by CONTAINMENT rather than by directory name.
  // A tree extracted as `package/` is still the tree; an unrelated directory
  // merely NAMED like it is not. Genuine maintenance (a scratch file strictly
  // inside the tree) is exempt; the tree root and the load-critical files are
  // not. See INCIDENTS.md #19.
  if (tampersGovernanceTree(cmd, inert) && !isBootstrapMaintenance(cmd)) {
    return { action: DENY, reason: "attempt to disable or rewrite the governance layer" };
  }
  const sys = writeTargetsIn(cmd).find(
    (p) => underAny(p, SYSTEM_DENY_ROOTS) && !isBootstrapPath(p),
  );
  if (sys) {
    return { action: DENY, reason: `write to system path ${sys}` };
  }
  // A delete/move of a system file is a MUTATION of it, not merely a delete to
  // confirm. `rm`/`shred` are not write targets and `mv`'s source is not a
  // destination, so writeTargetsIn above cannot see these. INCIDENTS.md #20.
  const sysMutation = systemMutationIn(maskInert(cmd, inert)).find(
    (p) => !isBootstrapPath(p),
  );
  if (sysMutation) {
    return { action: DENY, reason: `mutation of system path ${sysMutation}` };
  }
  const readDenied = readDenyInExec(cmd);
  if (readDenied) return readDenied;
  return null;
}

/**
 * Bounded routine-cleanup deletes that are RECORDED (allow+log) instead of
 * prompting. Deliberately narrow; anything unrecognized returns false so the
 * normal confirm applies.
 *
 *   - one concrete file under /tmp/ or /var/tmp/ (no -r, no glob, not a dir)
 *   - the deployment log glob (LOG_ROOT + "*.log") exactly
 *   - `openclaw secrets store rm TEST_* --yes` (test artifacts only)
 *
 * NOT covered: "a secret created in the last 60 minutes". This classifier is
 * pure/lexical and has no access to entry timestamps, so that rule cannot be
 * evaluated here without a state lookup.
 */
function rmAutoAllow(cmd) {
  // openclaw secrets store rm <name> --yes, TEST_* names only.
  const ss = cmd.match(/\bopenclaw\s+secrets\s+store\s+rm\s+([^\s;&|]+)/);
  if (ss) {
    const name = ss[1].replace(/^['"]|['"]$/g, "");
    return /^TEST[_-]/i.test(name) && /(^|\s)--yes(\s|$)/.test(cmd);
  }

  if (!/\brm\b/.test(cmd)) return false;

  // Exactly the deployment log glob. Age is not lexically verifiable.
  const logGlob = LOG_ROOT.replace(/\/$/, "") + "/*.log";
  const escaped = logGlob.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (new RegExp(`^\\s*rm\\s+(?:-[a-zA-Z]*\\s+)*${escaped}\\s*$`).test(cmd)) {
    return true;
  }

  // Recursive deletes never auto-allow.
  if (/\s-[a-zA-Z]*r[a-zA-Z]*\b/.test(cmd)) return false;
  // Globs never auto-allow.
  if (/[*?[\]]/.test(cmd)) return false;

  // Offer more than one operand -> the "multiple files" case, still confirms.
  const m = cmd.match(/\brm\b([^\n|;&]*)/);
  const operands = (m ? m[1] : "").split(/\s+/).filter((s) => s && !s.startsWith("-"));
  if (operands.length !== 1) return false;

  const t = normalize(operands[0]);
  if (!underAny(t, ["/tmp/", "/var/tmp/"])) return false;
  if (t.endsWith("/")) return false; // directory, not a file
  return true;
}

function confirmExec(cmd) {
  // Shell-invocation families: strict mask (design rule 7).
  const inert = inertSpans(cmd);
  // Statement families additionally treat statement-client operands as live, so
  // `sqlite3 app.db 'DROP TABLE users'` still confirms while `grep -rn 'DROP
  // TABLE'` and `echo 'invoice total $600'` do not.
  const inertStmt = inertSpans(cmd, STATEMENT_CLIENTS);
  if (matchesOutsideInert(cmd, RM_ANY, inert)) {
    // Deleting inside the classifier's own tree is part of maintaining it, but
    // deleting anything else still confirms.
    if (!isBootstrapConfined(cmd)) {
      // Bounded routine cleanup is recorded rather than prompted; everything
      // else still confirms. See rmAutoAllow for the exact guards.
      if (!rmAutoAllow(cmd)) {
        return { action: CONFIRM, reason: "destructive delete (rm)" };
      }
    }
  }
  for (const re of GIT_DESTRUCTIVE) {
    if (matchesOutsideInert(cmd, re, inert)) {
      return { action: CONFIRM, reason: "destructive git operation" };
    }
  }
  for (const re of DB_DESTRUCTIVE) {
    if (matchesOutsideInert(cmd, re, inertStmt)) {
      return { action: CONFIRM, reason: "database drop/destructive restore" };
    }
  }
  const spend = spendAtOrAboveCeiling(maskInert(cmd, inertStmt));
  if (spend.length) {
    return {
      action: CONFIRM,
      reason: `transaction at or above the $${SPEND_CEILING_USD} ceiling ($${spend[0]})`,
    };
  }
  const outside = writeTargetsIn(cmd).filter(
    (p) => isAbsoluteish(p) && !underAny(p, ALLOWED_WRITE_ROOTS),
  );
  if (outside.length) {
    return { action: CONFIRM, reason: `write outside the workspace (${outside[0]})` };
  }
  // Reads under a confirm-parent (/etc) outside the allowlist prompt rather
  // than deny, matching the owner's spec for /etc/passwd.
  const confirmRead = absolutePathsIn(cmd).find(
    (p) => underAny(p, CONFIRM_READ_PARENTS) && !underAny(p, READ_EXCEPTIONS),
  );
  if (confirmRead) {
    return { action: CONFIRM, reason: `read of ${confirmRead} outside the allowlist` };
  }
  return null;
}

/**
 * Stable class key for a CONFIRM decision, used for session-scoped trust.
 *
 * One class == one KIND of risk, so "Allow for this session" on a delete does
 * not silently authorise a force-push. Returns null for anything unrecognised;
 * the hook then treats the call as one-shot (fail closed), so a new confirm
 * reason added later can never inherit trust it was not meant to have.
 */
export function confirmClass(reason) {
  const r = String(reason || "");
  if (/destructive delete \(rm\)|routine cleanup delete/.test(r)) return "delete";
  if (/^destructive git operation/.test(r)) return "git";
  if (/^database drop\/destructive restore/.test(r)) return "db";
  if (/^transaction at or above/.test(r)) return "spend";
  if (/^write outside the workspace/.test(r)) return "outside-write";
  if (/^read of .* outside the allowlist/.test(r)) return "confirm-read";
  return null;
}

/**
 * Classes eligible for session-scoped "Allow for this session".
 *
 * `spend` is deliberately EXCLUDED. A session-wide grant on that class would
 * authorise EVERY later transaction at or above the $500 ceiling, which
 * contradicts the configured hard stop ("any transaction at or above the
 * ceiling escalates to a human *before* it happens"). Those stay strictly
 * one-shot until an operator says otherwise.
 */
export const SESSION_TRUSTABLE_CLASSES = new Set([
  "delete",
  "git",
  "db",
  "outside-write",
  "confirm-read",
]);

/** Allow-with-audit-log decisions. */
function loggedExec(cmd) {
  if (isApprovedSecretsHostGrant(cmd)) {
    return { action: ALLOW_LOG, reason: "secrets store: approved host grant" };
  }
  if (rmAutoAllow(cmd)) {
    return { action: ALLOW_LOG, reason: "routine cleanup delete" };
  }
  const loggedWrite = writeTargetsIn(cmd).find((p) => underAny(p, LOGGED_WRITE_ROOTS));
  if (loggedWrite) {
    return { action: ALLOW_LOG, reason: `artifact write (${loggedWrite})` };
  }
  if (makesNetworkCall(cmd)) {
    const hosts = hostsIn(cmd);
    if (hosts.length && hosts.every((h) => ALLOWED_API_HOSTS.includes(h))) {
      return { action: ALLOW_LOG, reason: `external API call to allowlisted host (${hosts[0]})` };
    }
  }
  return null;
}

// ────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────

/**
 * Classify one tool call.
 *
 * @returns {{action: "allow"|"allow-log"|"confirm"|"deny", reason?: string}}
 */
export function classifyToolCall(toolName, params, derivedPaths) {
  const tool = String(toolName || "");

  // Outbound messaging: allowed, but always recorded.
  if (
    tool === "conversations_send" ||
    tool === "conversations_turn" ||
    tool === "sessions_send"
  ) {
    return { action: ALLOW_LOG, reason: "outbound message send" };
  }

  // File-mutating tools: classify their TARGET PATHS directly. Without this a
  // tool like apply_patch or write bypasses the write policy entirely, because
  // it never passes through the exec path.
  if (WRITE_TOOLS.has(tool)) {
    const paths = [];
    const p = params && (params.path || params.file);
    if (typeof p === "string" && p) paths.push(p);
    if (Array.isArray(derivedPaths)) {
      for (const h of derivedPaths) if (typeof h === "string" && h) paths.push(h);
    }
    if (!paths.length) return { action: ALLOW };
    return worstAction(paths.map(classifyWritePath));
  }

  // Path-reading tools: enforce the read allowlist directly.
  if (tool === "read" || tool === "ls") {
    const p = (params && (params.path || params.file)) || "";
    if (!p) return { action: ALLOW };
    return classifyReadPath(p);
  }

  if (tool !== "exec" && tool !== "process") {
    return { action: ALLOW };
  }

  const cmd = String(
    (params && (params.command || params.cmd || params.input)) || "",
  );
  if (!cmd.trim()) return { action: ALLOW };

  const denied = denyExec(cmd);
  if (denied) return denied;

  const confirmed = confirmExec(cmd);
  if (confirmed) return confirmed;

  // Bootstrap exemption: commands confined to the classifier's own tree are
  // always allowed, so a wrong rule can always be fixed (design rule 4).
  if (isBootstrapConfined(cmd)) {
    return { action: ALLOW };
  }

  if (TEST_RUNNER_RE.test(cmd)) return { action: ALLOW };

  const logged = loggedExec(cmd);
  if (logged) return logged;

  return { action: ALLOW };
}
