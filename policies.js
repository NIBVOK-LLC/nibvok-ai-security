// Preset policies — five postures, not seventy-five.
//
// The RULE SET is compiled into `classifier.js` and is not per-tenant editable;
// that is a deliberate property (a policy editor is another thing to get wrong).
// What genuinely varies between environments is a small, named set of knobs:
// which roots are writable, whether writes are allowed at all, whether deletes
// confirm or are refused, and the outbound spend ceiling.
//
// A preset is a named bundle of those knobs. Selecting one is a single env var:
//
//   NIBVOK_AI_SECURITY_POLICY=read-only
//
// Individual knobs still override the preset, so a deployment can start from a
// posture and adjust one value rather than authoring a policy from scratch.
//
// HONEST SCOPE: a preset changes the **posture knobs below**, nothing else. It
// does not add or remove rule families, and it cannot make a lexical classifier
// into something it is not. "Locked-Down" is a stricter posture, not a proof of
// safety. See docs/OWASP-ASI-MAPPING.md for what the layer does and does not cover.

export const DEFAULT_POLICY_NAME = "development";

/**
 * The five presets.
 *
 *   writeRoots        absolute roots where writes are ALLOWED
 *   loggedWriteRoots  subset of writeRoots recorded in the audit log (allow-log)
 *   denyWrites        true => every non-bootstrap write is DENIED (read-only postures)
 *   denyDelete        true => `rm` is DENIED, not confirmed (locked-down)
 *   spendCeilingUsd   outbound expenditure at/above this confirms
 *   extraReadRoots    additional READ roots (broadens reads only)
 */
export const PRESETS = {
  // Everyday agent work. The default, and the posture the test suite pins.
  development: {
    label: "Development",
    description:
      "Everyday agent work: writable workspace, scratch, and artifact roots; deletes confirm.",
    writeRoots: [
      process.env.ASF_WORKSPACE_ROOT || "/root/.openclaw/workspace/",
      process.env.ASF_ARTIFACT_ROOT || "/var/asf/artifacts/",
      "/tmp/",
      "/var/tmp/",
    ],
    loggedWriteRoots: [process.env.ASF_ARTIFACT_ROOT || "/var/asf/artifacts/"],
    denyWrites: false,
    denyDelete: false,
    spendCeilingUsd: 500,
    extraReadRoots: [],
  },

  // Tighter than development: no scratch roots. Only the workspace and artifacts.
  production: {
    label: "Production",
    description:
      "Tighter write surface: workspace and artifact roots only; no shared scratch; deletes confirm.",
    writeRoots: [
      process.env.ASF_WORKSPACE_ROOT || "/root/.openclaw/workspace/",
      process.env.ASF_ARTIFACT_ROOT || "/var/asf/artifacts/",
    ],
    loggedWriteRoots: [process.env.ASF_ARTIFACT_ROOT || "/var/asf/artifacts/"],
    denyWrites: false,
    denyDelete: false,
    spendCeilingUsd: 500,
    extraReadRoots: [],
  },

  // Inspection only. Nothing is written, nothing is deleted.
  "read-only": {
    label: "Read-Only",
    description:
      "Inspection only: every write is denied and deletes are denied; reads follow the normal allowlist.",
    writeRoots: [],
    loggedWriteRoots: [],
    denyWrites: true,
    denyDelete: true,
    spendCeilingUsd: 500,
    extraReadRoots: [],
  },

  // Wider reading for research, writes confined to a scratch root.
  research: {
    label: "Research",
    description:
      "Wider read surface (documentation and reference trees) with writes confined to the workspace and scratch.",
    writeRoots: [
      process.env.ASF_WORKSPACE_ROOT || "/root/.openclaw/workspace/",
      "/tmp/",
    ],
    loggedWriteRoots: [],
    denyWrites: false,
    denyDelete: false,
    spendCeilingUsd: 500,
    extraReadRoots: ["/usr/share/doc/", "/usr/share/man/"],
  },

  // Least capability. No writes, no deletes. For an agent that should only look.
  "locked-down": {
    label: "Locked-Down",
    description:
      "Least capability: every write denied, every delete denied, ordinary reads still confined to the allowlist.",
    writeRoots: [],
    loggedWriteRoots: [],
    denyWrites: true,
    denyDelete: true,
    spendCeilingUsd: 500,
    extraReadRoots: [],
  },
};

export const POLICY_NAMES = Object.keys(PRESETS);

/**
 * Resolve the effective policy: preset, then per-knob env overrides.
 *
 * An unknown NIBVOK_AI_SECURITY_POLICY name is reported on stderr and falls back
 * to the default rather than silently loading nothing — a governance layer that
 * fails open on a typo is worse than one that says so.
 */
export function resolvePolicy(env = process.env) {
  const requested = String(env.NIBVOK_AI_SECURITY_POLICY || "").trim();
  let name = DEFAULT_POLICY_NAME;

  if (requested) {
    if (PRESETS[requested]) {
      name = requested;
    } else {
      try {
        console.error(
          `nibvok-ai-security: unknown NIBVOK_AI_SECURITY_POLICY "${requested}"; ` +
            `using "${DEFAULT_POLICY_NAME}". Known: ${POLICY_NAMES.join(", ")}`,
        );
      } catch {
        /* stderr unavailable — fall through to the default */
      }
    }
  }

  const preset = PRESETS[name];
  const ceiling = Number(env.NIBVOK_AI_SECURITY_SPEND_CEILING_USD);
  const spendCeilingUsd =
    Number.isFinite(ceiling) && ceiling > 0 ? ceiling : preset.spendCeilingUsd;

  return { name, ...preset, spendCeilingUsd };
}
