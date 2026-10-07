---
name: portal-docs-and-adr-maintenance
description: >
  Project-specific workflow for maintaining documentation in Portal Operations Tools.
  Use when implementation behavior changes, technical debt is added or resolved,
  project structure changes, architecture decisions are introduced, or system
  documentation needs to be updated. Defines when to modify docs/systems,
  docs/technical-debt, docs/PROJECT_MAP, and docs/decisions without turning
  documentation into a second source of truth.
---

# Portal Docs and ADR Maintenance

## Purpose

Use this skill whenever code changes affect documentation or architectural records.

Examples:

- current subsystem behavior changed;
- new route behavior was introduced;
- authorization behavior changed;
- database behavior changed;
- background execution changed;
- external integration behavior changed;
- technical debt was resolved;
- new technical debt was intentionally accepted;
- module/file ownership changed;
- a new operational tool was added;
- a deliberate architectural decision was made;
- an old document became stale.

This skill defines where information belongs and how to keep documentation useful without duplicating the codebase.

It does not replace:

- `/review`
- `/plan-eng-review`
- `/codex`
- subsystem-specific portal skills

It complements them by maintaining project knowledge.

---

# 1. Documentation Is Not the Primary Source of Runtime Truth

For current implementation behavior, use this priority:

```text
1. current code
2. current database models/migrations
3. automated tests
4. docs/systems/
5. docs/generated/
6. ADRs
7. historical specs/plans
```

Documentation explains the system.

It does not override the current implementation automatically.

If documentation and code disagree:

```text
inspect actual implementation
        ↓
determine intended behavior
        ↓
fix code or documentation according to task scope
```

Do not change working code merely to make it match stale documentation.

---

# 2. Load Documentation Context

Before editing project documentation, inspect:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/technical-debt/current.md
```

Then read only the system or ADR documents relevant to the change.

Examples:

```text
Vault change
→ docs/systems/vault.md

authorization change
→ docs/systems/auth.md
→ ADR-003

database architecture change
→ ADR-002

secret-storage architecture change
→ ADR-004
```

Do not rewrite every document after each feature.

---

# 3. Know the Purpose of Each Documentation Area

Use the documentation hierarchy consistently.

```text
docs/PROJECT_MAP.md
→ where things are and what owns them

docs/systems/
→ how the current implemented system behaves

docs/technical-debt/current.md
→ current known problems or limitations

docs/decisions/
→ deliberate architectural decisions and their rationale

historical specs/plans
→ historical intent and planning context
```

Do not mix these purposes.

---

# 4. `docs/systems/` Describes Current Behavior

A system document should answer questions such as:

```text
What does this subsystem do?
Where is it implemented?
Which routes exist?
Which models does it use?
How does authorization work?
What external services does it call?
What background work exists?
What important workflows exist?
```

It should describe:

```text
current implemented behavior
```

not:

```text
future plans
ideal architecture
known bugs
wishlist items
```

Those belong elsewhere.

---

# 5. Keep System Docs Verifiable

System documentation should refer to real implementation concepts.

Prefer statements such as:

```text
The Vault Blueprint is registered in app/__init__.py.
```

over vague statements such as:

```text
Vault is securely integrated into the application.
```

Documentation should make it easier for another agent/developer to navigate the code.

---

# 6. Avoid Copying Large Amounts of Code Into Docs

Do not duplicate implementation line-for-line.

Prefer:

```text
behavior
flow
ownership
security boundary
important file references
```

instead of copying entire functions.

Large code duplication quickly becomes stale.

Use short snippets only when they clarify a non-obvious contract.

---

# 7. Document Important Files, Not Every File

For each subsystem, list files that materially help understand it.

Examples:

```text
routes.py
models.py
logic.py
sync.py
forms.py
key templates
shared helpers
```

Do not create exhaustive file inventories unless necessary.

`PROJECT_MAP.md` provides broader navigation.

---

# 8. `docs/PROJECT_MAP.md` Is the Navigation Map

Update `PROJECT_MAP.md` when:

```text
new subsystem added
new major module added
important responsibility moved
shared infrastructure changed
new operational tool added
new architectural boundary introduced
```

Do not update it for:

```text
minor route
small form change
one new helper
template text change
small bug fix
```

Keep the map high-level.

---

# 9. Project Map Must Reflect Ownership

For each important area, document:

```text
purpose
main directory/file
important dependencies
shared infrastructure
high-risk relationships
```

Example:

```text
Vault
→ app/vault/
→ encrypted credential storage
→ KeePass synchronization
→ authorization + security-sensitive
```

Do not turn the project map into a complete API reference.

---

# 10. Documentation Status

If the project map tracks documentation status, use consistent states such as:

```text
VERIFIED
PARTIAL
MISSING
STALE
```

Use them deliberately.

Meaning:

```text
VERIFIED
→ inspected against current implementation

PARTIAL
→ useful but incomplete

MISSING
→ document does not exist or lacks meaningful coverage

STALE
→ known to describe outdated behavior
```

Do not mark a document VERIFIED merely because it exists.

---

# 11. Updating Verification Status

Mark a system document VERIFIED only after comparing it with the relevant current code.

If code changes significantly and the document has not been rechecked:

```text
update it
```

or, if intentionally postponed:

```text
mark it PARTIAL/STALE
```

Do not leave a known incorrect document labeled VERIFIED.

---

# 12. `docs/technical-debt/current.md` Describes Current Problems

Technical debt should represent:

```text
known current limitation
known security weakness
known correctness issue
known architectural compromise
known testing gap
known operational risk
```

It should not contain:

```text
already-fixed issues
general ideas
feature requests
random TODOs
historical bugs no longer present
```

---

# 13. Technical Debt Is Not a Backlog Dump

Do not add every possible improvement to technical debt.

A debt item should represent a meaningful existing problem.

Good examples:

```text
background jobs are not durable across process restart
authorization is weaker than intended on specific routes
provider partial-success handling is inaccurate
temporary plaintext secret files can remain after abandonment
```

Poor examples:

```text
could use nicer UI
maybe add Redis someday
rewrite this module later
add more comments
```

---

# 14. New Technical Debt Must Be Intentional

If implementation knowingly ships with a limitation, document:

```text
what the limitation is
why it matters
affected subsystem
risk/severity
possible direction for future resolution
```

Do not use technical debt documentation to excuse a fundamental security or correctness flaw that must be fixed before shipping.

---

# 15. Remove or Update Resolved Debt

When a task resolves an existing debt item:

```text
update docs/technical-debt/current.md
```

Do not leave it listed as unresolved.

Depending on the document structure:

```text
remove item
mark resolved
move to historical record
```

following current project convention.

Do not create a permanent graveyard inside `current.md`.

---

# 16. Partial Resolution

If a change fixes only part of a debt item, update the item accurately.

Example:

```text
Before:
Vault edit/delete missing object authorization.

After:
Vault edit fixed; delete still missing.

Debt:
Vault delete route still lacks required object authorization.
```

Do not mark the entire issue resolved because one path improved.

---

# 17. Severity Should Match Risk

If technical debt uses priority categories such as:

```text
P0
P1
P2
P3
```

use them consistently.

Consider:

```text
security impact
data-loss risk
production impact
likelihood
operational severity
```

Do not inflate every issue to P0.

Do not downgrade serious security issues because they are inconvenient to fix.

---

# 18. ADRs Record Decisions, Not Current Implementation Details

An ADR should answer:

```text
What architectural decision was made?
Why was it made?
What alternatives existed?
What are the tradeoffs?
What consequences follow from it?
```

Examples:

```text
use Flask modular monolith
use SQLAlchemy + Alembic for schema evolution
use UserTool + proteger_blueprint for tool authorization
encrypt persistent secrets at rest
```

Do not create ADRs for normal implementation details.

---

# 19. When to Create a New ADR

Consider a new ADR when the project deliberately decides to adopt or change something such as:

```text
background worker architecture
new authentication model
new authorization model
new persistence technology
new encryption domain
new secrets manager
new deployment architecture
new frontend framework
new cross-module communication model
dropping platform support
new durable queue
```

Do not create an ADR simply because:

```text
a route was added
a model gained a column
a bug was fixed
a provider endpoint changed
a template changed
```

---

# 20. ADRs Must Describe Accepted Decisions

Do not create an ADR for an idea still under exploration unless the project explicitly uses proposed ADR states.

If a decision has not been accepted, keep it in planning/discussion.

An accepted ADR should represent a deliberate direction.

---

# 21. ADRs Are Historical

Once an ADR represents a historical architectural decision, do not silently rewrite its meaning because the architecture later changes.

Instead:

```text
create new ADR
        ↓
mark old ADR superseded if project convention supports it
```

Preserve decision history.

Minor typo/clarity corrections are fine.

Do not rewrite history.

---

# 22. ADR Structure

Follow existing ADR format.

If no stronger convention exists, an ADR should typically include:

```md
# ADR-XXX: Decision Title

## Status

Accepted

## Context

Why the decision is needed.

## Decision

What the project will do.

## Alternatives Considered

Other realistic options.

## Consequences

Positive and negative tradeoffs.

## Implementation Notes

Important constraints where helpful.
```

Do not over-document trivial decisions.

---

# 23. ADR Numbering

Follow existing numbering.

Before creating a new ADR:

```text
inspect docs/decisions/
identify highest existing number
use next sequential number
```

Do not reuse an existing ADR number.

Do not renumber historical ADRs.

---

# 24. ADR Titles

Use decision-oriented titles.

Good:

```text
ADR-005-durable-background-jobs.md
ADR-006-centralized-secrets-management.md
```

Avoid:

```text
ADR-new-stuff.md
ADR-fixes.md
ADR-background.md
```

The filename should make the decision discoverable.

---

# 25. Do Not Create ADRs Retroactively Without Evidence

If architecture already exists but there is no ADR, create one only if documenting that architecture now is useful and its rationale can be established.

Do not invent historical reasoning.

If rationale is unknown, state what is verifiable.

---

# 26. Keep ADRs Focused

One ADR should represent one coherent architectural decision.

Avoid combining:

```text
database
auth
frontend
background jobs
deployment
```

into one giant ADR.

Separate unrelated decisions.

---

# 27. Historical Specs and Plans

Historical design documents may explain why something exists.

They do not override current implementation.

Use them as context only after:

```text
current code
models/migrations
tests
current system docs
```

Do not implement old plans automatically.

---

# 28. Generated Documentation

If `docs/generated/` exists, treat it according to its intended source.

Do not manually maintain generated files when they should be regenerated.

Do not treat generated docs as more authoritative than current source code.

---

# 29. Documentation Should Be Updated After Behavior Is Confirmed

Preferred order:

```text
implement
        ↓
validate
        ↓
update documentation to match verified behavior
```

Do not document intended behavior as if already implemented before confirming it works.

Planning documents are the exception.

---

# 30. Security Documentation

When security behavior changes, document:

```text
authorization boundary
ownership behavior
admin behavior
secret handling
```

but never document:

```text
real secrets
real encryption keys
real credentials
sensitive runtime values
```

Security documentation should help understand controls without exposing protected material.

---

# 31. Do Not Document Secret Values

Never include actual values for:

```text
SECRET_KEY
SECRET_KEY_DB
CREDENTIAL_MANAGER_KEY
VAULT_KEY
VAULT_KDBX_PASSWORD
API keys
client secrets
tokens
private keys
```

Safe:

```text
VAULT_KEY encrypts Vault-specific persisted secret material.
```

Unsafe:

```text
VAULT_KEY=abc...
```

---

# 32. Environment Documentation

When documenting configuration, distinguish:

```text
required
optional
fallback
feature-specific
```

Document variable names and purpose.

Do not copy the user's `.env`.

Do not assume a variable is required unless source confirms it.

---

# 33. Database Documentation

When schema behavior changes, documentation may need to mention:

```text
new model
new important relationship
new ownership behavior
new persisted configuration
```

Do not duplicate the entire schema.

Detailed schema truth remains in:

```text
SQLAlchemy models
Alembic migrations
```

Use `portal-database-change` for actual persistence changes.

---

# 34. Migration History Is Not Documentation to Rewrite

Do not edit old migration files to improve documentation.

Migration files are executable history.

Use comments sparingly where needed.

Architectural explanation belongs in docs/ADRs.

---

# 35. External Integration Documentation

For provider integrations, system docs should explain:

```text
provider
authentication type
major operations
retry/timeout behavior at high level
cache behavior
important failure semantics
background execution
external mutation risk
```

Do not copy full provider API documentation.

Link/mention external contracts only where useful.

---

# 36. Background Job Documentation

If background behavior changes, document relevant semantics such as:

```text
trigger
execution model
persistence
restart limitation
duplicate behavior
job ownership
```

Do not describe in-process threads as durable.

Known limitations belong in technical debt.

---

# 37. New Operational Tool Documentation

Every genuinely new tool should receive:

```text
docs/systems/<tool>.md
```

and an entry in:

```text
docs/PROJECT_MAP.md
```

The system doc should include at least:

```text
purpose
main code locations
authorization
data/persistence
external integrations
background work
important workflows
known limitations where cross-reference is useful
```

Do not copy the new-tool implementation plan verbatim.

---

# 38. Cross-References

Use cross-references to avoid duplication.

Example:

```text
Authorization follows ADR-003.
```

instead of duplicating the complete authorization architecture in every system doc.

Likewise:

```text
Database schema evolution follows ADR-002.
```

Keep subsystem docs focused on subsystem-specific behavior.

---

# 39. Avoid Documentation Drift Through Duplication

If the same architectural rule appears in:

```text
AGENTS.md
CLAUDE.md
PROJECT_MAP
six system docs
four ADRs
```

it becomes difficult to maintain.

Prefer:

```text
one canonical policy
+
short references elsewhere
```

Do not duplicate large policy sections unnecessarily.

---

# 40. AGENTS.md

`AGENTS.md` contains global repository working rules.

Update it only when:

```text
repository-wide working policy changes
source-of-truth priority changes
protected data policy changes
global validation rules change
global architecture constraints change
```

Do not update it for individual features.

---

# 41. CLAUDE.md

`CLAUDE.md` is the Claude Code entry point.

Keep it concise.

It should primarily point Claude toward:

```text
AGENTS.md
PROJECT_MAP
system docs
technical debt
ADRs
skills
gstack routing
```

Do not turn CLAUDE.md into a second copy of the entire project architecture.

---

# 42. Skill Documentation

Project-local skills belong in:

```text
.claude/skills/
```

A skill should encode:

```text
repeatable project-specific workflow
risk rules
context-loading requirements
validation expectations
```

Do not create a skill for every subsystem unless repeated specialized behavior justifies it.

Avoid duplicating gstack functionality.

---

# 43. Skill Changes Should Be Documented Only When Necessary

Adding a project-local skill usually does not require an ADR.

Update CLAUDE.md skill routing if the new skill materially affects how Claude should choose workflows.

Do not clutter PROJECT_MAP with every skill unless it is useful for project navigation.

---

# 44. Documentation Style

Prefer:

```text
clear headings
short paragraphs
concrete file names
explicit behavior
small diagrams where helpful
```

Avoid:

```text
marketing language
vague claims
overly theoretical explanations
unnecessary repetition
```

Documentation should be usable during active engineering work.

---

# 45. Use Exact Names

Use real repository names:

```text
UserTool
proteger_blueprint()
VaultSyncConfig
app/tools_config.py
```

Do not rename concepts in documentation for stylistic consistency if the code uses different terminology.

Documentation should help search the repository.

---

# 46. Distinguish Verified Facts From Inference

When documenting after incomplete investigation, say:

```text
PARTIAL
```

or explicitly state uncertainty.

Do not present inferred behavior as verified implementation.

If behavior is unclear, inspect source before marking documentation current.

---

# 47. Do Not Invent Future Behavior

Avoid statements such as:

```text
The system will automatically recover jobs after restart.
```

unless that behavior actually exists.

Future plans belong in planning documents or technical debt, not current system docs.

---

# 48. Document Error Behavior When Important

For operational workflows, meaningful failure semantics deserve documentation.

Examples:

```text
VirusTotal 404 is treated as not found
Umbrella partial success may occur
Vault sync can fail on invalid KDBX credentials
```

Do not enumerate every possible Python exception.

Focus on behavior important to users/developers.

---

# 49. Document Security Boundaries

For sensitive subsystems, include high-level authorization behavior.

Examples:

```text
tool-level access
object ownership
admin bypass
sharing
```

Do not rely on UI descriptions to communicate security.

---

# 50. Document Cross-Subsystem Side Effects

If one subsystem updates another, document it.

Example:

```text
VirusTotal analysis may propagate metadata to matching CSIRT IoCs.
```

Cross-module behavior is easy to miss during maintenance.

Include it in relevant system docs or project map.

---

# 51. Document Shared Infrastructure

When a subsystem depends on shared infrastructure, mention it.

Examples:

```text
AuditLog
Notification
UserTool
shared IOC models/mixins
extensions
scheduler
```

Do not imply the subsystem owns infrastructure that is actually shared.

---

# 52. Remove Stale References

When files/routes/models are renamed or removed, update documentation references.

Search for:

```text
old filename
old class
old route
old subsystem name
```

in documentation.

Do not leave dead navigation paths.

---

# 53. Avoid Formatting-Only Documentation Churn

Do not rewrap or reformat unrelated documentation during a small change.

Large formatting diffs hide meaningful edits.

Keep documentation changes scoped.

---

# 54. Preserve Historical Context Where Valuable

When changing architecture, do not erase useful historical explanation from ADRs.

For current system docs, however, remove outdated implementation descriptions.

Difference:

```text
ADR
→ historical decision record

system doc
→ current implementation description
```

Use each accordingly.

---

# 55. Documentation and Technical Debt Should Agree

If a system doc describes a known limitation, cross-reference technical debt rather than presenting it as normal intended architecture.

Example:

```text
Current Vault import preview uses temporary persisted state.
See technical debt item ...
```

Do not normalize insecure or incorrect behavior through neutral documentation wording.

---

# 56. Documentation and ADRs Should Agree

If current architecture intentionally differs from an accepted ADR:

```text
determine whether implementation is wrong
```

or:

```text
decision has changed
```

If decision changed:

```text
create superseding ADR
```

Do not silently edit the old ADR to match new implementation.

---

# 57. Documentation Review After Refactoring

After moving files or responsibilities:

```text
search docs for old paths
update PROJECT_MAP
update relevant system doc
check CLAUDE.md references
check skills that mention exact paths
```

Project-local skills can become stale too.

---

# 58. Skills Are Documentation Too

When architecture changes, inspect relevant skill instructions.

Example:

```text
authorization model changes
→ portal-security-change may require update

background architecture changes
→ portal-background-job-change may require update

database bootstrap changes
→ portal-runtime-environment-change may require update
```

Do not let skills enforce outdated architecture.

---

# 59. Search Before Editing Documentation

Before changing a concept, search for existing references.

Examples:

```bash
grep -R "VaultSyncConfig" docs .claude/skills AGENTS.md CLAUDE.md
```

or:

```bash
rg "VaultSyncConfig" docs .claude/skills AGENTS.md CLAUDE.md
```

Use available tools.

Do not update only one document when the same important rule exists elsewhere.

---

# 60. Avoid Blind Global Replacement

Do not run broad replacements across all docs without reviewing context.

The same term may represent:

```text
historical behavior
current behavior
decision rationale
technical debt
```

Each may need different treatment.

---

# 61. Verify Documentation After Editing

Review:

```bash
git diff -- docs AGENTS.md CLAUDE.md .claude/skills
```

where appropriate.

Check:

```text
correct filenames
correct paths
correct subsystem names
no accidental secret values
no unrelated formatting
no contradictory statements
```

---

# 62. Documentation Should Match Validated Behavior

Before marking a doc VERIFIED, confirm relevant code behavior.

For a non-trivial change:

```text
implementation
        ↓
testing
        ↓
documentation
        ↓
final diff review
```

Do not mark documentation verified based only on intended implementation.

---

# 63. Documentation Tests

Documentation usually does not need automated tests.

But validate structural claims manually:

```text
file exists
route exists
model exists
helper exists
skill exists
```

Do not leave references to nonexistent paths.

---

# 64. Links and Paths

Prefer repository-relative paths:

```text
app/vault/routes.py
docs/systems/vault.md
```

Avoid developer-specific absolute paths.

Do not use local machine paths in project docs.

---

# 65. Technical Debt IDs

If the current debt document uses identifiers, preserve them.

Do not renumber existing debt items unnecessarily.

Stable IDs are useful for:

```text
discussion
commits
PRs
future tasks
```

If no ID convention exists, do not invent one casually.

---

# 66. Priority Changes

If a technical debt item's severity changes, explain why.

Example:

```text
P1 → P0
because newly discovered route allows unauthorized secret deletion.
```

Do not change severity based only on subjective cleanup priority.

---

# 67. Resolved Debt Must Be Verified

Do not remove a debt item immediately after writing the fix.

First validate the behavior.

Preferred order:

```text
implement
        ↓
test
        ↓
confirm debt resolved
        ↓
update current.md
```

---

# 68. New Debt Discovered During Work

If unrelated technical debt is discovered:

```text
do not automatically fix it
```

If material enough to track:

```text
add concise debt item
```

only if within documentation scope or explicitly appropriate.

Otherwise report it to the user.

Do not let side findings explode the current task.

---

# 69. ADR Alternatives Must Be Real

When writing an ADR, list meaningful alternatives actually considered.

Avoid fake alternatives added only to fill a template.

Good:

```text
threading.Thread
APScheduler
Celery/RQ durable worker
```

when evaluating background architecture.

Poor:

```text
do nothing
do something else
```

---

# 70. ADR Consequences Must Include Tradeoffs

Do not write only positive consequences.

Document:

```text
benefits
costs
operational burden
migration impact
security implications
complexity
future constraints
```

An ADR is useful because it preserves tradeoffs.

---

# 71. ADR Decision Language

Use clear decision language.

Good:

```text
The application will continue as a Flask modular monolith.
```

Avoid:

```text
We might probably keep using Flask for now.
```

Accepted decisions should be unambiguous.

---

# 72. ADR Scope

An ADR should not prescribe implementation details that may change without affecting architecture.

Example:

```text
Decision:
Use Alembic migrations for schema evolution.

Implementation detail:
exact migration filename
```

Keep the decision durable.

---

# 73. Do Not Create Documentation for Generated Runtime State

Do not document current values of:

```text
database contents
job IDs
tokens
runtime paths specific to one machine
active sessions
current .env secrets
```

Document configuration semantics, not transient state.

---

# 74. Commit Documentation With the Behavior It Describes

When practical, documentation updates should be committed with the code change they describe.

This reduces drift.

Do not create a giant documentation cleanup commit unrelated to active work unless intentionally performing documentation maintenance.

---

# 75. New System Doc Template

When adding a new subsystem document, use a concise structure such as:

```md
# <Subsystem Name>

## Purpose

What the subsystem does.

## Main Components

Important source files and responsibilities.

## Routes / Entry Points

Important routes or triggers.

## Data Model

Important persisted data and relationships.

## Authorization

Tool-level and object-level access rules.

## External Integrations

Providers and important request behavior.

## Background Work

Threads, scheduler, jobs, durability limitations.

## Important Workflows

Key operational flows.

## Security Notes

Secrets, sensitive data, dangerous operations.

## Known Limitations

Cross-reference technical debt where relevant.
```

Adapt it to the subsystem.

Do not include empty sections merely for template compliance.

---

# 76. Existing System Docs Should Preserve Their Style

When editing an existing system doc, follow its current structure unless there is a strong reason to reorganize it.

Do not rewrite the whole document to fit a preferred template during a small update.

Keep diffs readable.

---

# 77. Documentation for APIs

Do not create full public API documentation unless the portal actually exposes a supported API.

For internal provider clients, system docs should describe integration behavior, not every method signature.

Code remains the implementation reference.

---

# 78. Documentation for Forms/Templates

System docs usually do not need to enumerate every field or button.

Document UI details only when they represent important workflow or security behavior.

Example:

```text
Sync settings do not render stored plaintext KDBX password.
```

is important.

Button colors are not.

---

# 79. Documentation for Tests

If meaningful test coverage exists for a subsystem, system docs may briefly mention where.

Do not maintain exhaustive test-case inventories in system docs.

Testing rules belong in:

```text
portal-testing-and-validation
```

and actual tests.

---

# 80. Documentation for Deployment

Deployment/runtime behavior may belong in:

```text
PROJECT_MAP
runtime/setup docs
ADR
```

depending on scope.

Do not mix deployment instructions deeply into unrelated subsystem docs.

Use:

```text
portal-runtime-environment-change
```

when deployment behavior changes.

---

# 81. Required Pre-Documentation Summary

For a non-trivial documentation update, summarize internally:

```md
## Documentation Impact

### Behavior Changed

What verified implementation behavior changed.

### System Docs

Which docs/systems files require updates.

### Project Map

Whether module ownership/navigation changed.

### Technical Debt

Which debt items were added, changed, or resolved.

### ADR

Whether an architectural decision was introduced or superseded.

### Skills

Whether any project skill now contains stale instructions.

### Validation

How the documentation was checked against implementation.
```

Keep this proportional to the change.

---

# 82. Recommended Workflow for Normal Feature Changes

```text
implementation
        ↓
portal-testing-and-validation
        ↓
portal-docs-and-adr-maintenance
        ↓
/review
```

Update only documentation affected by verified behavior.

---

# 83. Recommended Workflow for Technical Debt Fixes

```text
/investigate if needed
        ↓
implement fix
        ↓
validate fix
        ↓
portal-docs-and-adr-maintenance
        ↓
update current.md
        ↓
/review
```

Do not remove debt before confirming the fix.

---

# 84. Recommended Workflow for Architectural Changes

```text
/plan-eng-review
        ↓
evaluate alternatives
        ↓
make explicit decision
        ↓
create/supersede ADR
        ↓
implementation
        ↓
validation
        ↓
update system docs + PROJECT_MAP
        ↓
/review
        ↓
/codex review or challenge when appropriate
```

---

# 85. Recommended Workflow for New Operational Tools

```text
portal-new-operational-tool
        ↓
implementation
        ↓
validation
        ↓
create docs/systems/<tool>.md
        ↓
update docs/PROJECT_MAP.md
        ↓
update technical debt if required
        ↓
ADR only if architecture changed
```

---

# 86. Completion Checklist

Before declaring documentation maintenance complete, verify:

```text
[ ] Current implementation was checked
[ ] Documentation does not override code assumptions
[ ] Relevant system doc matches current behavior
[ ] PROJECT_MAP updated only if structure/ownership changed
[ ] Technical debt reflects current unresolved issues
[ ] Resolved debt was removed/updated only after validation
[ ] Partial debt fixes were represented accurately
[ ] ADR created only for an architectural decision
[ ] Historical ADRs were not rewritten improperly
[ ] ADR numbering is correct
[ ] ADR contains real tradeoffs
[ ] No secret values were added to docs
[ ] No machine-specific absolute paths were added
[ ] Cross-subsystem behavior documented where important
[ ] Known limitations point to technical debt where appropriate
[ ] Relevant project skills were checked for stale rules
[ ] CLAUDE.md was not expanded unnecessarily
[ ] AGENTS.md was changed only for repository-wide policy
[ ] No unrelated documentation was reformatted
[ ] File/path references were verified
[ ] Documentation status is accurate
[ ] Final documentation diff was reviewed
```

---

# 87. Core Rule

Never treat documentation maintenance as:

```text
change code
update random README text
done
```

For this project:

```text
code
→ describes what actually exists

docs/systems
→ explains current behavior

PROJECT_MAP
→ explains where responsibilities live

technical-debt/current.md
→ records current known problems

ADRs
→ explain deliberate architectural decisions

skills
→ encode repeatable project-specific engineering workflows
```

Keep each layer focused on its own purpose and update it only when the verified implementation makes that update necessary.