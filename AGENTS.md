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