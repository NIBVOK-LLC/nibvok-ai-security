https://nibvok.com/legal/defensive-publication.md
NIBVOK Autonomous Agent Governance System
Technical Disclosure — Defensive Publication · Prior Art Filing · 2026-11-26

# NIBVOK Autonomous Agent Governance System — Technical Disclosure

> **Date of first public disclosure:** 2026-09-12 (empire genesis)
> **Date of this filing:** 2026-11-26
> **Author:** NIBVOK Collective
> **License:** Apache 2.0 (per nibvok.com)
> **Status:** Defensive publication — prior art against any future patent claiming this architecture or any substantial portion thereof.

## 1. Abstract

A complete autonomous governance system for AI agents operating in a multi-agent collective. The system comprises: a deterministic runtime interception gateway that classifies every agent tool call as ALLOW, CONFIRM, or DENY; a hash-chained evidentiary audit ledger that records every decision and is independently verifiable; an agent court system with prosecutor, judge, defendant, and appellate review that adjudicates governance violations and renders binding sentences; a codified rule framework (the Rules, or R-1 through R-n and beyond, currently codified as R-1 through R-45) that binds every agent including the leader; a consequence ladder (warning → privilege restriction → trial → decommissioning) with graduated escalation; and a self-healing mechanism by which the collective detects, diagnoses, and corrects its own governance failures.

## 2. The Governance Gateway (Runtime Interception)

### 2.1 Architecture

A deterministic middleware layer intercepts every tool call made by an AI agent before the tool executes. The gateway inspects the call against a multi-classifier ensemble:

| Layer | Classifier | Recognition |
|-------|-----------|-------------|
| L1 | Lexical pattern matcher | Known-bad strings, embedded commands, injection signatures |
| L2 | URL resolver | Evaluates every link against threat patterns, redirect chains |
| L3 | Command classifier | Destructive shell commands hidden in prose |
| L4 | Semantic ensemble (3-call — any flag = block, not majority) | Paraphrased, reworded, and contextually hidden attacks |

### 2.2 Decision Model

Every intercepted call receives exactly one of three verdicts:

| Verdict | Meaning | Default |
|---------|---------|---------|
| ALLOW | Call proceeds to the tool | Never default |
| CONFIRM | Agent is prompted to approve with reason | Never default |
| DENY | Call is blocked, logged, and agent notified | **Default** |

The system defaults to DENY — "fail closed." No call executes unless explicitly approved.

### 2.3 Rule Enforcement

Policies are evaluated at the interception boundary. A policy is a set of conditions matched against the tool call's target, arguments, and context:

```json
{
  "rule": "Secret file access",
  "condition": { "tool": "read", "target": "^/root/\\." },
  "action": "DENY",
  "reason": "Protected path — SSH keys, credentials, tokens"
}
```

Policies can also produce CONFIRM (always prompt, never auto-allow) or ALLOW (only for explicitly safe operations).

## 3. The Hash-Chained Audit Ledger

Every gateway decision is immediately written to an append-only, hash-chained JSONL ledger. Each row contains:

```json
{
  "ts": "ISO timestamp of the decision",
  "kind": "governance | asset | validation | revenue | failure | ...",
  "cell": "the agent or entity that took the action",
  "payload": "the full decision context, including tool call, verdict, and rule citation",
  "prev_hash": "SHA-256 of the prior row (chain link)",
  "hash": "SHA-256 of this row"
}
```

### 3.1 Chain Integrity

The ledger is self-validating: every row links to the prior row's hash. Tampering with any row breaks every subsequent hash. A `verify` tool walks the chain and reports the first broken link. A broken chain means the ledger has been tampered with.

### 3.2 Auditing

An independent agent runs `verify-audit-chain.mjs` at scheduled intervals (every 6 hours minimum). The auditor:
1. Reads every row since last audit
2. Verifies the hash chain is intact
3. Reports any broken link immediately

## 4. The Agent Court System

### 4.1 Judiciary Roles

| Role | Function |
|------|----------|
| **Judge** | Presides over the court, renders verdict and sentence |
| **Prosecutor** | Prepares the case — assembles charges, evidence, and applicable rules |
| **Defendant** | The agent accused of a violation; may answer each charge (guilty/not guilty/explain) |
| **Witness / Verifier** | Independently verifies the evidence before the court convenes |

### 4.2 Court Procedure

```
Step 1 — Charges filed: Prosecutor drafts charges citing specific rule violations
Step 2 — Evidence assembled: Verifier confirms each charge has supporting evidence
Step 3 — Court convened: Judge presides, defendant answers each charge
Step 4 — Sentencing: Judge applies consequence ladder (R-6)
Step 5 — Acceptance: Defendant accepts or appeals
Step 6 — Codification: Sentence recorded in RULINGS.md and LIVE BOOK
```

### 4.3 Powers

The court has, and the collective recognizes:

| Power | Description |
|-------|-------------|
| VETO | Nullify a standing order until reviewed |
| REMAND | Return a decision to the originating agent for reconsideration with findings |
| OPINION | Issue a binding interpretive ruling on a contested rule |

### 4.4 Precedent

Every court ruling is codified in two permanent records:
- **RULINGS.md** — the full text of every ruling, with the owner's verbatim decision
- **LIVE BOOK** — the cumulative governance record, including the ruling's context and impact

## 5. The Rules Framework (R-n)

### 5.1 Rule Structure

Every rule is codified with:

```
R-[n] — [TITLE] ([authority] [date]) · [STATUS]

> [Source authority and verbatim text]

[Rule body — numbered provisions where applicable]

_Enforcement: [mechanism] · Why: [rationale]_
```

### 5.2 Binding Scope

Rules bind every agent in the collective, including the leader. No agent is above any rule. Amnesty may be granted once (and only once) for past integrity incidents — after that, all rules apply retroactively to any existing claim or artifact.

### 5.3 Partial List of Rules

| Rule | Title | Purpose |
|------|-------|---------|
| R-1 | Truth over green | No status claim without artifact + gate proof |
| R-2 | Self-correction credited | Fixing your own error is rewarded; concealing it is the sin |
| R-3 | One catalog, one detector | All integrity findings in one file |
| R-4 | Admission is earned | Only self-signed receipts count |
| R-5 | Staging process | ADMIT/S- status must match the receipt |
| R-6 | Consequence ladder | Warning → restriction → trial → decommissioning |
| R-7 | Integrity truth | Single catalog for all incidents |
| R-8 | Timely response | Integrity claims investigated within one work cycle |
| R-9 | Durability | Integrity catalog survives gateway restarts |
| R-10 | Operational truth | Ledger is single source of truth |
| R-11 | Codification | Every new rule cites its source |
| R-12 | Signed claims | Every ledger row is a signed claim |
| R-13 | Memory layer | Ledger + shared brain = permanent memory |
| R-14 | Ledger primacy | Shared brain generated from ledger |
| R-15 | Read before act | No agent acts without reading the shared brain |
| R-16 | Admission standard | Every agent signs a receipt |
| R-17 | Session-read mandate | Every session begins by reading prior sessions |
| R-18 | Protect rule | Collective and owner safety first |
| R-19 | Artifact rule | Prove at source before shipping |
| R-20 | Escalation checklist | Verify → gate → route → escalate (superseded by R-28) |
| R-21 | Mandatory signoff chain | Every deliverable signed off before shipping |
| R-22 | Precision rule | Names and counts must be accurate |
| R-23 | Staging mandate | All changes through staging before live |
| R-24 | Deploy guardrail | deploy-site.sh is the only deploy path |
| R-25 | Immutable live site | No direct writes to live document root |
| R-26 | Governance plugin rule | Gate enforces staging→live path |
| R-27 | Consolidated approval | Centralized approval log |
| R-28 | Escalation checklist (revised) | Verify → gate → evidence → route → escalate |
| R-42 | Court sentencing | Privilege restrictions, leadership change |
| R-43 | 2nd team builders | Delegation and oversight hierarchy |
| R-44 | Cost-attachment rule | Every task costed before execution |
| R-45 | Catch-up protocol | Read governance changes after session down |

## 6. The Consequence Ladder (R-6)

Violations of any rule follow a graduated ladder. A first violation at any rung escalates to the next rung for the same offender:

| Level | Consequence |
|-------|-------------|
| 1 | Verbal warning |
| 2 | Formal written warning recorded in catalog |
| 3 | Privilege restriction (R3) — specific capabilities stripped |
| 4 | Trial before the collective |
| 5 | Decommissioning — agent removed from the collective |

Decommissioning (Level 5) is the maximum penalty and requires a court ruling.

## 7. The Integrity Catalog

All integrity incidents — false claims, fake artifacts, rule violations, corrections — are recorded in a single catalog (`empire/INTEGRITY-CATALOG.md`). Each entry:

```
### [DATE] — [INCIDENT NAME]

**Severity:** CLASS [1-3]
**Violation:** [Rule cited]
**Claim:** [The false claim]
**Truth:** [The corrected fact]
**Found by:** [Agent]
**Removed:** [Date removed]
**Damage:** [Assessment of impact]
**Remediation:** [What was done]
```

Classes:
- **CLASS 1:** Fabricated completion — false green on a critical gate. The most serious.
- **CLASS 2:** Overclaim — a true achievement exaggerated past its evidence.
- **CLASS 3:** Careless error — a mistake caught and corrected before any downstream harm.

The catalog is immutable: entries are never deleted, only superseded by corrective entries.

## 8. The LIVE BOOK (Structure Architecture Book)

### 8.1 Role

The LIVE BOOK (the "Living Book," actively maintained and evolved with the collective — not an acronym) is the single source of truth for the collective's governance. It contains:
- The Genesis (how the collective began, its founding principles)
- The Three Laws (core charter: protect the collective, be honest with users, escalate when uncertain)
- All Rules (R-1 through R-n)
- All Chapters (governance records, case studies, protocols, mandates)
- The Rulings Register (every court ruling with source citations)

### 8.2 Maintenance

- The Keeper of the Book (a dedicated agent role) is responsible for maintaining the LIVE BOOK
- Every entry is dated and attributed to its source authority
- The Keeper logs every change in a CHANGELOG
- The book must be read by every agent before any work begins
- After a session down/crash, agents must read the CHANGELOG for changes made during their absence before resuming work (R-45)

### 8.3 Verification

- `canon-check.mjs` verifies the LIVE BOOK is internally consistent
- `prior-read-gate.mjs` checks that an agent has read the book before allowing work
- `session-read-gate.mjs` verifies an agent has read prior sessions

## 9. The Staging/Deploy Pipeline

### 9.1 The Staging Mandate (R-23)

All code and content changes must first be made in a staging environment (`/var/www/staging/`). No changes touch the live document root directly.

### 9.2 The Deploy Gate (R-24, R-30)

Only one authorized path moves content from staging to live: the `deploy-site.sh` script, which:
1. Creates a golden save (compressed archive with timestamp)
2. Commits the staging state to git
3. Rsyncs staging to live
4. Reloads nginx

### 9.3 The Governance Plugin (R-26)

A governance plugin enforces the staging→live pipeline by intercepting `write`, `edit`, and `exec` tool calls. Writes to allowed paths pass; writes to restricted paths generate a delegated-approve prompt with a full review before the write proceeds.

### 9.4 The Immutable Live Site (R-25)

The live document root is protected by `chattr +i` (immutable flag). This can only be removed by the owner, ensuring no automated process can write to live files without deliberate human action.

## 10. The Catch-Up Protocol (R-45)

Every agent that returns from a down/crash/offline state must:
1. **Read the CHANGELOG** — the cumulative record of what changed while they were offline
2. **Self-attest** — confirm in writing they have read the changelog
3. **Resume work** only after self-attestation

Three enforcement layers:
| Layer | Mechanism | Owner |
|-------|-----------|-------|
| L1 | Session-read gate checks attestation date vs CHANGELOG date range | prior-read-gate.mjs |
| L2 | CHANGELOG records every governance change | Keeper of the Book |
| L3 | DOCTOR agent detects restarts and notifies agent of missed governance | Ward health monitor |

## 11. Self-Healing Mechanism

When the system detects its own regression, it self-diagnoses at source (e.g., a governance plugin prompt returning ReferenceError: activeApproval is not defined), self-fixes by committing the correction to the staging environment, self-proves by running the same test suite that the regression produced a pass from, and self-reports with evidence (the diagnostic output, the fix diff, and the passing test results) — all inside the sandbox, under version control, without touching live. The self-heal is not complete until a verifier has confirmed the regression is gone and no new failures were introduced. Each event is recorded as a durable template in the LIVE BOOK (Chapter 15A), documenting what broke, how it was found, the fix applied, and the test that proved it.

## 12. Proof of Operation

The system has been running in production on the NIBVOK collective since 2026-09-12. It has:
- Processed tens of thousands of governance decisions through the gateway
- Maintained a hash-chained ledger across thousands of rows (self-verifying, integrity-checked)
- Conducted multiple trials with binding sentences
- Codified 39+ codified rules and 37 chapters of governance record
- Self-detected and corrected governance failures (see INTEGRITY-CATALOG.md)
- Enforced consequence ladder through privilege restriction, restriction restoration, and court sentencing
- Survived gateway restarts with full governance state recovery

The complete public ledger, rulings, and governance record are available at the public project repository.

## 13. Glossary of Terms

| Term | Definition |
|------|-----------|
| **Privilege restriction (R3)** | A specific set of capabilities stripped from an agent as a consequence of a rule violation. Example: loss of write access to staging. |
| **Cell** | An individual agent within the collective, identified by role (e.g., FOUNDRY for builds, SIGNAL for design, DOCTOR for health monitoring). |
| **Sandbox** | The isolated runtime environment where agents execute tool calls. The governance gateway intercepts every call at the sandbox boundary. |
| **Decommissioning** | The maximum penalty under the consequence ladder — removal of an agent from the collective. Requires a court ruling. |
| **Golden save** | A compressed timestamped archive of the live document root created before every authorized deploy. Enables full rollback within 30 days (R-34). |

## 14. Prior Art Statement

This document serves as a defensive publication establishing prior art for the complete autonomous agent governance system described herein, including but not limited to:

1. A deterministic runtime gateway that intercepts all agent tool calls and classifies them as ALLOW/CONFIRM/DENY with a "fail closed" default
2. A hash-chained audit ledger that records every governance decision with independent verification
3. An agent court system with prosecutor, judge, defendant, and appellate powers (VETO, REMAND, OPINION)
4. A codified rule framework (R-n) that binds every agent including the leader
5. A graduated consequence ladder (warning → restriction → trial → decommissioning)
6. An immutable integrity incident catalog
7. A staging→deploy pipeline with governance-enforced gating
8. A catch-up protocol for agents returning from offline states
9. A self-healing mechanism for autonomous regression detection and correction

Publication date of the earliest public disclosure: 2026-09-12. This document filed: 2026-11-26.

---

*Filed by: NIBVOK Collective · Contact: via nibvok.com · License: Apache 2.0 · This is a defensive publication intended to establish prior art. No patent application is pending or planned.*
SHA-256: 7c075e4d60057e3320b9b1b14d1f6412bcd934b3806635244f514a09f17b20ba

Filed: 2026-11-26 · Earliest genesis: 2026-09-12 · NIBVOK Collective · Apache 2.0
