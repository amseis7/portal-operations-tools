# CLAUDE.md

This repository is an existing internal operations portal.

Claude Code should work incrementally within the current architecture and preserve existing working behavior unless the task explicitly requires a change.

This file is the Claude Code entrypoint.

Detailed project knowledge is maintained in the shared project documentation rather than duplicated here.

---

## 1. Start Here

Before performing non-trivial work, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
```

`AGENTS.md` contains the global rules for working in this repository.

`docs/PROJECT_MAP.md` identifies the relevant subsystem, source files, dependencies, and available documentation.

Do not begin by reading the entire repository.

---

## 2. Progressive Context Loading

Load context progressively.

Use this order:

```text
CLAUDE.md
    ↓
AGENTS.md
    ↓
docs/PROJECT_MAP.md
    ↓
relevant docs/systems/<subsystem>.md
    ↓
relevant source files
    ↓
additional dependencies only when required
```

Do not automatically load unrelated subsystems.

Example:

For a Vault task, normally begin with:

```text
docs/systems/vault.md
app/vault/
```

Do not automatically inspect:

```text
app/csirt/
app/umbrella/
app/virustotal/
```

unless the task actually crosses those boundaries.

---

## 3. Sources of Project Knowledge

Use the documentation according to its purpose.

### Current implementation

```text
docs/systems/
```

Describes how each subsystem currently works.

Current documented subsystems:

```text
auth
main
csirt
virustotal
umbrella
vault
```

### Repository navigation

```text
docs/PROJECT_MAP.md
```

Use this to determine which files to inspect.

### Known problems and limitations

```text
docs/technical-debt/
```

These documents describe behavior that exists but is known to be problematic.

Do not interpret technical debt as architecture that must be preserved.

### Accepted architectural decisions

```text
docs/decisions/
```

These documents describe deliberate decisions that should normally be respected.

### Proposed or historical work

```text
docs/superpowers/specs/
docs/superpowers/plans/
```

These describe proposed designs or implementation plans.

They do not prove that functionality currently exists.

Always verify current implementation before relying on them.

---

## 4. Source-of-Truth Order

When information conflicts, use this priority:

```text
1. Current application source code
2. Current database models and migrations
3. Automated tests, when available
4. Verified docs/systems documentation
5. docs/generated
6. Accepted architectural decisions
7. Historical specifications and plans
```

Documentation can become stale.

When documentation and current code disagree:

```text
current code = current implementation
```

but report the inconsistency and update documentation when the implementation change makes it stale.

---

## 5. Existing Architecture

This is an existing Flask application organized as a modular monolith.

Current major functional boundaries are:

```text
auth
main
csirt
virustotal
umbrella
vault
```

Do not redesign the application into microservices or replace the framework unless explicitly requested and architecturally justified.

Read:

```text
docs/decisions/ADR-001-flask-modular-monolith.md
```

before proposing major structural changes.

---

## 6. Database Changes

Database persistence uses:

```text
SQLAlchemy
Flask-Migrate
Alembic
```

Schema changes must use the existing migration workflow.

Do not directly edit database files to implement schema changes.

Read:

```text
docs/decisions/ADR-002-database-schema-migrations.md
```

before making database schema changes.

Always consider existing data.

---

## 7. Authorization

Operational tool authorization is based on the existing application model:

```text
User
UserTool
User.has_tool()
proteger_blueprint()
```

Administrator privileges and object-level ownership checks are separate concerns.

Read:

```text
docs/decisions/ADR-003-tool-authorization-model.md
docs/systems/auth.md
```

before redesigning permissions.

Do not create a parallel authorization system without an explicit requirement.

---

## 8. Secrets and Sensitive Data

Persistent secrets must remain encrypted at rest.

Current encryption domains include:

```text
SECRET_KEY_DB
VAULT_KEY
```

Do not assume they are interchangeable.

Read:

```text
docs/decisions/ADR-004-secrets-at-rest.md
```

before changing secret persistence or encryption.

Never expose or include real secrets in:

```text
source code
logs
audit data
documentation
examples
commits
responses
```

Do not inspect real secret values merely to understand application architecture.

---

## 9. Protected Runtime Areas

Do not inspect by default:

```text
.env
instance/
*.db
*.db.old
*.kdbx
*.keyx
certificate/private-key material
runtime credential files
```

Do not use production/runtime data as normal coding context.

Only access sensitive runtime data when the user explicitly requests it and it is necessary for the task.

---

## 10. Generated and Irrelevant Context

Do not use these as normal architecture context:

```text
venv/
__pycache__/
build/
dist/
.git/
.opencode/node_modules/
```

The existing:

```text
.opencode/
```

directory was experimental and is not the canonical source of project instructions.

Do not load generic OpenCode agents from that directory unless explicitly requested.

---

## 11. Existing Work

Before editing files for a non-trivial task, inspect:

```bash
git status --short
```

Assume unrelated uncommitted changes are active work.

Do not discard, overwrite, reset, or revert unrelated work.

Never use destructive Git operations such as:

```bash
git reset --hard
git clean -fd
git checkout -- .
```

unless the user explicitly requests and understands the operation.

---

## 12. Scope Control

Prefer the smallest change that satisfies the request.

Do not automatically:

```text
refactor unrelated code
rename unrelated files
upgrade dependencies
reformat entire modules
fix unrelated technical debt
reorganize directories
replace working architecture
```

If unrelated problems are discovered, report them separately.

---

## 13. Technical Debt

Known technical debt is tracked in:

```text
docs/technical-debt/current.md
```

When a task touches a listed item:

1. identify the relevant debt;
2. determine whether the proposed change preserves, worsens, partially resolves, or resolves it;
3. avoid silently expanding the scope.

Security debt must not be treated as intended architecture.

---

## 14. Validation

Do not claim a change works or is safe without appropriate validation.

Depending on the task, validation may include:

```text
syntax/import checks
automated tests
route behavior
authorization checks
migration review
existing-data compatibility
external API error handling
background processing
audit behavior
UI flow
secret exposure review
```

If automated tests do not exist for the affected behavior, state that explicitly.

---

## 15. Documentation Maintenance

When implementation changes materially alter current behavior, update the appropriate documentation.

Examples:

```text
behavior changed
    → docs/systems/<subsystem>.md

known debt resolved
    → docs/technical-debt/current.md

architectural decision changed
    → docs/decisions/

new subsystem or dependency boundary
    → docs/PROJECT_MAP.md
```

Do not update documentation merely to make it match an incorrect assumption.

---

## 16. Planning Non-Trivial Changes

Before implementing a non-trivial change, determine:

```text
objective
current behavior
affected subsystem
affected files
database impact
authorization/security impact
external API impact
background-processing impact
known technical debt interaction
risks
validation strategy
documentation impact
```

Do not create an unnecessarily large plan for trivial changes.

When project skills are introduced, use the relevant skill instead of duplicating its procedure here.

---

## 17. External Services

The application currently interacts with external systems including:

```text
CSIRT
VirusTotal
Cisco Umbrella
KeePass/filesystem integration
```

External operations must consider:

```text
timeouts
authentication
rate limits or quotas
partial failures
provider errors
retry behavior
external side effects
```

Do not add uncontrolled retry loops.

Do not assume external services are always available.

---

## 18. Background Work

The current application uses multiple existing background mechanisms, including:

```text
APScheduler
in-process threads
```

Do not introduce a new background framework simply for architectural preference.

When modifying background behavior, consider:

```text
process restart
partial completion
duplicate execution
database session handling
external side effects
status persistence
```

Known limitations are documented in:

```text
docs/technical-debt/current.md
```

---

## 19. Shell Environment

Prefer Bash-compatible commands.

Do not assume PowerShell is available.

Commands should normally be suitable for execution from the repository root.

---

## 20. Skill routing

This project uses gstack skills installed under:

```text
~/.claude/skills/gstack/
```

Use gstack for general engineering workflows and project-specific skills for portal-specific procedures.

### General engineering workflows

Prefer existing gstack skills instead of recreating equivalent project skills.

Use:

```text
/investigate
```

for bugs, regressions, unexpected behavior, stack traces, and root-cause analysis.

Use:

```text
/plan-eng-review
```

when a non-trivial implementation plan needs engineering review before coding.

Use:

```text
/autoplan
```

only for large or high-impact changes that justify the full multi-perspective planning pipeline.

Do not use `/autoplan` automatically for small or localized changes.

Use:

```text
/review
```

before landing meaningful code changes or when a diff requires structured review.

Use:

```text
/qa
```

or:

```text
/qa-only
```

when functional verification is required after implementation.

Use:

```text
/careful
```

when destructive operations, migrations, sensitive data, production-like environments, or risky Git operations may be involved.

Use:

```text
/guard
```

when both destructive-command protection and a strict edit-directory boundary are useful.

Use:

```text
/codex
```

when an independent second opinion would materially improve confidence.

Typical uses include:

```text
code review
architecture challenge
security-sensitive changes
migration review
difficult debugging
alternative implementation analysis
```

Codex should normally act as a reviewer or consultant rather than independently modifying the same files concurrently with Claude.

Use:

```text
/context-save
/context-restore
```

for long-running work that must continue across Claude Code sessions.

### Project-specific knowledge

gstack provides general engineering workflows.

It does not replace project-specific context.

Before using a gstack workflow on this repository, still follow:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/
docs/technical-debt/
docs/decisions/
```

Relevant project documentation defines the architectural and security constraints within which the gstack workflow must operate.

### Skill precedence

When both a general gstack skill and a project-specific skill apply:

```text
gstack skill
    = engineering workflow

project skill
    = repository-specific procedure and constraints
```

Use both when they complement each other.

Do not create project-specific skills that merely duplicate existing gstack functionality.

### High-risk changes

For high-risk work involving:

```text
authentication
authorization
Vault secrets
encryption
database migrations
external production mutations
```

consider enabling:

```text
/careful
```

or:

```text
/guard
```

before implementation.

For particularly important changes, consider an independent:

```text
/codex review
```

before accepting the final implementation.

---

## 21. Working Principle

Use evidence over assumptions.

Before changing behavior:

```text
understand
    ↓
locate
    ↓
verify
    ↓
plan
    ↓
change
    ↓
validate
    ↓
update documentation when necessary
```

The goal is not to rewrite a functioning application.

The goal is to improve it safely, incrementally, and with enough context to avoid regressions.