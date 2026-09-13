---
eatmycode_version: "2.0.0"
---

# Agent Rules

Owner: [Project architecture](../ARCHITECTURE.md)

Read when: before planning code changes or reviewing code.

## Development Loop

Frame → Write → Prove → Review → Gate. Findings return to Write;
uncertainty that changes the plan returns to Frame.

Use one subagent per role when available, otherwise distinct labeled
passes. Tester and Verifier report findings and never edit; Coder repairs.

| Role | Stages | Handoff |
| ---- | ------ | ------- |
| Planner | Frame | Goal, observable checks, assumptions, affected files/owners, and plan. |
| Coder | Write | Planned changes or repairs to named findings. |
| Tester | Prove | Commands, results, and behavioral/structural evidence. |
| Verifier | Review + Gate | Evidence-backed findings or verified completion. |

### The loop

1. **Frame:** Inspect the request, code, docs, and conventions before
   planning. Give the goal and each plan step an observable check. When
   using eatmycode, run its Version and Freshness Gate before trusting
   architecture; include versions, migration scope, routing/agent-file
   changes, and verification commands in architecture plans. Resolve
   uncertainty from evidence and record the narrowest supported assumptions.
   Only Planner may ask one focused question, when a required decision
   cannot be discovered or safely inferred and guessing changes the result.
2. **Write:** Apply Coding Discipline. Make the planned change; for a
   repair, address only named findings. Update affected architecture with
   changes to its documented contracts.
3. **Prove:** Run relevant tests and structural checks, retaining observable
   evidence. For architecture work under eatmycode, apply its Architecture
   Verification. Failures and missing, duplicate, or obsolete coverage
   become Coder findings. Re-run affected checks after repairs; never send
   a red result to Review.
4. **Review:** Apply every Review Check as a separate pass over full affected
   files. Use an independent agent or isolated pass for Fit, Dependencies,
   and Security when available. Return findings to Coder, then re-prove
   and re-review the repairs.
5. **Gate:** Confirm completion only when the Definition of Done passes.
   Return unmet criteria to the responsible stage; continue until resolved.
   If an external constraint prevents verification, state the missing
   evidence and remaining work without claiming completion or readiness.

Handoffs are automatic. Continue without pauses for plan approval,
permission to continue, or review/reporting ceremonies. Finish with the
harness's normal concise completion handoff.

### Definition of Done

- **Correctness:** The goal and named checks pass. Tests cover claimed
  behavior; bug fixes have a reproducing regression test. The project
  builds and tests from a fresh clone without local-only dependencies.
  Owning modules' **Verification** commands pass with evidence.
- **Review:** Every Review Check ran and its completion threshold passes.
- **Contract:** Docs reflect source and let an agent locate owners,
  constraints, and verification commands. When using eatmycode, architecture
  satisfies its Output Contract, verification, and version rules. Public
  names, signatures, errors, and recovery are intelligible. Breaking
  changes, deprecations, dependencies, licenses, and attribution are handled;
  commit or PR text, when present, explains why.
- **Scope:** Changed lines serve the goal and follow Coding Discipline;
  no debugging remnants, commented-out code, secrets, tokens, or local paths
  remain. Test edits follow the inventory and coverage rules below.

### Iterating without thrashing

- Each repair pass targets a named finding; nits alone do not trigger one.
- Two no-change passes force Gate re-evaluation. If Done still fails,
  return the surviving evidence to Frame.
- Three passes against the same finding return to Frame for a new approach.
- Never widen scope to satisfy a finding. Record coding follow-ups under
  **Known Gaps** and keep non-coding work outside architecture.

## Coding Discipline

- Implement only the goal. Prefer the simplest approach that passes its
  checks; simplify code materially larger than the problem.
- Match local style. Avoid speculative features, flexibility, single-use
  abstractions, and checks for impossible conditions.
- Keep edits surgical: no unrelated refactoring, reformatting, or cleanup.
  Remove imports, variables, and functions made unused by this change;
  leave pre-existing dead code alone unless requested.
- Make success concrete: validation rejects invalid input in a named test;
  a regression test fails before a bug fix and passes after; behavior tests
  pass before and after a refactor.

### Before editing tests

Before any test edit, including during Write, inventory the whole suite
with discovery tools; keep the full file/case listing outside model context.
Load matching inventory entries and read in full tests whose subject,
fixtures, or assertions touch the change. Use a subagent for broad inventory
when supported. Plan all additions, changes, merges, and removals from that
evidence, citing `file:line`, before executing the test edits.

- **Reuse first:** Extend the test owning the behavior or sharing its
  setup, fixtures, and subject. Add a function/file only if no existing
  owner fits or merging would obscure which case failed.
- **Add only required coverage:** A bug fix needs its regression test;
  a capability needs a test of its claimed behavior. Avoid duplicates.
- **Retire only what changed:** Remove tests of deleted behavior and merge
  new duplicates, citing surviving coverage. Record unrelated suspected
  redundancy under **Known Gaps**.
- **Preserve coverage:** Never delete or weaken tests to turn red green.
  Removal needs evidence that behavior is gone or covered elsewhere;
  coverage of claimed behavior must not decrease.

## Review Checks

Run every check against every change before confirming a code edit is
complete, even when no commit or merge is requested. Keep checks separate.

- **Evidence or no finding:** Cite `file:line` for every finding.
- **Repository authority:** Demand only conventions supported by the tree.
- **Full context:** Read affected files, not only hunks; context can expose
  unreachable code, unused parameters, or hidden duplication.
- **Code and impact:** Review the change, never the author or how it was made.

### 1. Style and Naming

Check indentation and local conventions; leave machine-checkable formatting
to existing formatters/linters and never demand unrelated reformatting.
Mixed indentation is `major`; a consistent new file with the wrong local
indent is `nit`. Compare names with nearby precedents. If the repository
is inconsistent, demand nothing. A local naming mismatch is `nit`; an
inconsistent public name is `major`.

### 2. Duplication

Search distinctive constants, errors, fields, and call sequences, beyond
symbol names, for the same job. Cite both sites and a remedy. Cross-layer
duplication is `major`; small local repetition is `nit`. Similar code with
meaningfully different branches is not duplication.

### 3. Quality

Require followable control flow, errors handled where they occur, and
proportionate abstractions. Swallowed errors, inappropriate prints,
unexplained magic values, and dead branches are `major`. Remove unrequested
configurability, one-caller wrappers, filler comments, debugging remnants,
and unrelated formatting. Missing tests belong to Prove.

### 4. Fit

Follow the root Read First instructions and read the owning module before
the diff. Check language/toolchain constraints, conventions, scope, layering,
ownership, invariants, public-API growth, compatibility, and performance
claims against source. A layering violation or unjustified public API is `major`.
Architectural/public-behavior changes need matching docs in the same change.

### 5. Dependencies

Check manifests/imports, maintenance, supply-chain risk, advisories,
install-time behavior, license, transitive cost, and standard-library
alternatives. An unjustified top-level dependency is `major`; a live
advisory or abandoned upstream is `blocker`. Incomplete evidence does not pass.

### 6. Security

Check defects and widened exposure: unsafe memory access, unchecked sizes
or offsets, integer overflow, traversal, unsafe deserialization, command
construction, committed secrets, and unbounded untrusted input. Trace input
to impact; without a reachable path there is no finding. A real defect is
`major`; a trust-boundary break is `blocker`. Describe fixes without exploit
steps.

### Severity and the completion threshold

| Severity | Effect |
| -------- | ------ |
| `blocker` | Must not confirm completion or merge. |
| `major` | Must be resolved before confirming completion or merging. |
| `nit` | Apply or consciously decline. |
| `info` | Context or a question; no action implied. |

Confirm completion or merge only with no `blocker` or unresolved `major`.
A check that did not run does not pass; explain evidence-backed
inapplicability. Findings feed Write and Gate directly.
