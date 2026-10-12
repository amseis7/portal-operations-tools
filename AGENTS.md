# AGENTS.md

## Purpose

This repository contains an existing internal production application.

AI agents must preserve existing behavior, architecture, security controls, and operational workflows unless a task explicitly requires changing them.

The goal is to make small, controlled, reviewable improvements without introducing unnecessary architectural changes.

---

# 1. General Working Rules

Before modifying code:

1. Understand the requested change.
2. Identify the subsystem affected.
3. Inspect the existing implementation.
4. Read the relevant documentation under `docs/`.
5. Identify dependencies and side effects.
6. Prefer the smallest change that satisfies the requirement.
7. Preserve existing patterns unless there is a documented reason to change them.
8. Validate the result before considering the task complete.

Do not assume documentation is always current.

When documentation and code disagree, treat the code as the current implementation and report the inconsistency.

---

# 2. Existing Application

This is an existing Flask application.

The application is already functional and contains multiple operational tools.

Do not redesign or rewrite working systems unless explicitly requested.

Prefer incremental evolution over large refactors.

---

# 3. Protected Areas

Agents must not read, modify, expose, summarize, or include data from:

- `.env`
- `instance/`
- database files
- credential files
- KeePass databases
- certificates or private keys
- runtime secrets
- production data
- log files containing sensitive information

These areas may only be inspected when the user explicitly requests it and the task cannot reasonably be completed without doing so.

Never include secrets in generated documentation, source code, logs, examples, commits, or responses.

---

# 4. Ignore Generated and Runtime Content

Do not use the following directories as architectural context unless the task specifically concerns them:

- `venv/`
- `__pycache__/`
- `build/`
- `dist/`
- `.git/`
- `.opencode/node_modules/`

Avoid indexing or reading generated dependencies when application source code is sufficient.

---

# 5. Architecture Preservation

Before introducing a new abstraction, library, service, or architectural pattern:

1. Check whether an equivalent mechanism already exists.
2. Reuse existing application conventions where reasonable.
3. Explain why a new mechanism is necessary.
4. Avoid duplicate utilities or overlapping implementations.

Do not introduce a new framework or replace an existing dependency without explicit approval.

---

# 6. Scope Control

Only modify files related to the requested change.

Do not perform unrelated:

- refactors
- formatting changes
- renames
- dependency upgrades
- architecture migrations
- code cleanup

If an unrelated issue is discovered, report it separately.

Do not silently fix it.

---

# 7. Database Changes

Database schema changes must use the project's existing SQLAlchemy and migration workflow.

Never modify an existing production database directly.

For schema changes:

1. Modify the relevant model.
2. Create a migration.
3. Review the migration.
4. Ensure both upgrade and downgrade behavior are reasonable.
5. Consider compatibility with existing data.

Do not delete or rewrite historical migrations unless explicitly required.

---

# 8. Security

Security-related behavior must not be weakened for convenience.

Preserve existing:

- authentication
- authorization
- CSRF protection
- permission checks
- encryption
- credential handling
- input validation

External input must be treated as untrusted.

Do not expose secrets, tokens, credentials, internal paths, or sensitive exception data to users.

---

# 9. External APIs

When modifying external API integrations, consider:

- authentication
- timeouts
- retries
- rate limits
- partial failures
- provider errors
- invalid responses
- logging
- background execution

Do not add uncontrolled retry loops.

Do not assume external services are always available.

---

# 10. Background Work

Long-running or external operations should follow the existing project's background-processing patterns.

Do not move expensive operations into synchronous HTTP request handlers unless explicitly justified.

When changing background jobs, consider:

- failure recovery
- duplicate execution
- application restarts
- partial completion
- job state persistence

---

# 11. Dependencies

Prefer existing dependencies.

Before adding a new dependency:

1. Confirm that existing libraries cannot reasonably solve the problem.
2. Explain why the dependency is required.
3. Consider maintenance and security impact.
4. Add it through the project's existing dependency-management mechanism.

Do not add a dependency for trivial functionality.

---

# 12. Change Planning

For non-trivial changes, produce a short change plan before implementation.

The plan should identify:

- objective
- affected subsystem
- files likely to change
- database impact
- external API impact
- security impact
- expected risks
- validation strategy

Do not produce large speculative plans for simple changes.

---

# 13. Validation

Before considering a change complete:

1. Check for syntax errors.
2. Run relevant automated tests if available.
3. Validate affected routes or flows.
4. Verify authorization behavior.
5. Verify error handling.
6. Review the diff for unrelated changes.

If automated tests do not exist for the affected behavior, state this explicitly.

Do not claim a change is safe or working if it has not been validated.

---

# 14. Documentation

Documentation must describe the current implementation, not intended future behavior.

Use:

- `docs/systems/` for current subsystem behavior
- `docs/decisions/` for architectural decisions
- `docs/generated/` for automatically generated project information
- `docs/technical-debt/` for known problems and limitations
- `docs/superpowers/specs/` for proposed or designed future behavior
- `docs/superpowers/plans/` for implementation plans

Do not confuse a specification with the current system state.

If code changes make documentation incorrect, update the relevant documentation.

---

# 15. Source of Truth

When determining how the system currently works, use this priority:

1. Current application code
2. Database models and migrations
3. Current automated tests
4. `docs/systems/`
5. `docs/generated/`
6. Architecture and decision documentation
7. Historical specifications and plans

Specifications and old plans describe intent and may not reflect the current implementation.

---

# 16. Git and Existing Work

Do not discard, overwrite, revert, or modify unrelated uncommitted user changes.

Before making changes, inspect the working tree.

Assume that existing uncommitted changes may represent active work.

Do not use destructive Git commands unless explicitly requested.

Never run commands such as:

```bash
git reset --hard
git clean -fd
git checkout -- .
```

without explicit user authorization.

---

# 17. Agent Behavior

Agents should prefer evidence over assumptions.

If uncertain:

1. inspect the relevant code,
2. inspect relevant documentation,
3. identify what remains unknown.

Do not invent project conventions.

Do not infer architecture solely from filenames.

Do not claim a component exists unless it has been verified.

When discovering inconsistencies between documentation and implementation, report them.

---

# 18. Efficiency and Context

Do not read the entire repository for every task.

Use progressive context loading:

1. Read this file.
2. Identify the affected subsystem.
3. Read the subsystem documentation.
4. Inspect only relevant source files and dependencies.
5. Expand context only when necessary.

Avoid loading unrelated modules.

The objective is to reduce token consumption while preserving enough context to make correct changes.

---

# 19. Review Policy

Reviews must be proportional to the risk and scope of the change.

The default review mode is a focused single-pass review. Multi-agent or multi-angle review is reserved for broad or high-risk changes where additional independent perspectives are likely to materially improve safety.

## 19.1 Normal Changes

This includes:

- UX changes
- templates
- isolated backend changes
- ordinary bug fixes
- tests
- documentation
- small refactors explicitly required by the task

For these changes:

1. Do not fork review agents by default.
2. Do not run multi-angle or multi-agent review automatically.
3. Perform one focused review pass.
4. Verify findings directly against the current code before acting on them.
5. Run relevant tests during implementation.
6. Run the full test suite once before completion when appropriate.
7. Do not reopen implementation for style, naming, minor duplication, speculative maintainability, micro-performance, or YAGNI findings unless explicitly requested.

## 19.2 Security-Sensitive Changes

This includes changes involving:

- authentication
- authorization
- Vault or secrets
- encryption
- credential handling
- migrations that may lose or corrupt data
- filesystem security
- upload validation
- security boundaries
- rollback or partial-persistence guarantees

For these changes:

1. Start with one focused security review.
2. Use multi-agent review only when the change is broad enough to justify it.
3. When multi-agent review is justified, use at most 3 review agents unless the user explicitly approves more.
4. Do not automatically retry stalled agents.
5. Retry at most one failed or stalled review angle, and only when that angle is necessary to determine safety.
6. Consolidate and verify findings before launching additional analysis.
7. Do not run repeated full review rounds unless a real blocker was found and fixed.

## 19.3 Blocker Definition

A finding should reopen implementation only when it can plausibly cause one or more of:

- secret or sensitive-data disclosure
- authentication or authorization bypass
- data loss or corruption
- partial persistence or rollback failure
- unsafe migration behavior
- filesystem safety failure
- regression of an explicitly documented security invariant
- regression of stable object identity where that identity protects correctness or confidentiality

The following are non-blockers by default unless the task explicitly targets them:

- style
- naming
- minor duplication
- simplification opportunities
- speculative future callers
- micro-performance
- test scaffolding polish
- hypothetical abstractions
- YAGNI concerns

Report such findings separately without automatically expanding the implementation scope.

## 19.4 Review Stop Conditions

A task is ready to close when:

1. relevant tests pass,
2. affected subsystem tests pass when available,
3. the full suite passes when appropriate,
4. one focused review finds no real blockers,
5. required smoke tests or manual validation have passed,
6. the final diff contains only in-scope changes.

Once these conditions are met, do not launch another review pass.

If a review agent stalls for more than 10 minutes or makes no meaningful progress:

- stop waiting for it,
- do not retry automatically,
- continue with the completed review evidence,
- retry only if the missing angle is required to determine safety.

If review work exceeds 20 minutes for a small isolated diff:

- stop expanding the analysis,
- consolidate the findings already obtained,
- verify only potential blockers,
- report status and proceed toward closure if no blocker remains.

## 19.5 Validation Frequency

During TDD and implementation:

- run focused tests as often as needed,
- run subsystem tests after the implementation stabilizes,
- run the full project suite once near the end.

If a real blocker is found and fixed, rerun the relevant tests and the full suite as needed.

Do not rerun the full suite after every non-blocking observation or documentation-only change unless there is a specific reason.

## 19.6 Review Tooling

Do not make completion of ordinary tasks depend on external review tooling that is unavailable, stalled, rate-limited, blocked by local policy, or incompatible with the current environment.

If an external reviewer fails for tooling reasons:

1. treat the review as not executed, not as a pass or failure,
2. record the tooling limitation,
3. fall back to one focused local review,
4. do not repeatedly retry the same deterministic tooling failure.

External or second-model review is optional by default and should be reserved for high-risk changes where it materially improves confidence.

Automatic review gates or stop hooks that can create review loops should not be enabled unless explicitly approved.

### 19.6.1 Windows Corporate Environment / Codex

On managed Windows environments where local policy blocks PowerShell or cmd execution from Codex review tooling:

- Do not require `/codex:review` or `/codex:adversarial-review` for task completion.
- Do not repeatedly retry Codex repository-inspection reviews after the same deterministic policy failure.
- Treat a Codex run blocked by local policy as **not executed**, never as a pass or a code failure.
- Prefer the normal focused local review defined above.
- If a second-model review is still useful, provide Codex with the already-generated diff or patch as input instead of requiring Codex to execute Git commands itself.
- Generate that diff with the developer shell that is already allowed in the environment, and exclude secrets, `.env`, `instance/`, database files, credential material, sensitive logs, and unrelated untracked files.
- When feeding a diff to Codex, instruct it to review the supplied patch only and not to inspect the host or execute shell commands.
- Do not weaken corporate execution policies, PowerShell restrictions, endpoint controls, or sandbox rules merely to make review tooling work.
- Do not patch files inside plugin caches as a permanent fix; plugin updates may overwrite them. Prefer supported CLI/configuration changes or wait for an upstream fix.

For Windows corporate environments, the preferred review order is:

1. focused local review in Claude Code,
2. relevant tests,
3. optional second-model review from a supplied diff/patch,
4. no additional review round unless a real blocker is found.

## 19.7 Context Discipline

When a task is complete and committed:

- prefer starting a fresh context before moving to an unrelated task,
- do not carry large completed review transcripts into the next task,
- do not re-investigate decisions already documented in the repository,
- reuse verified conclusions instead of repeating broad discovery work.

The objective is to preserve review quality while preventing disproportionate review time, token consumption, and repeated analysis on small or already-validated changes.

