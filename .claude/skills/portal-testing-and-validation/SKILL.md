---
name: portal-testing-and-validation
description: >
  Project-specific workflow for validating changes in Portal Operations Tools.
  Use after modifying routes, forms, models, permissions, background jobs,
  external integrations, startup/runtime behavior, templates, migrations,
  security-sensitive flows, or new operational tools. Defines the minimum
  validation expected before considering a change complete and complements
  gstack review/QA workflows with repository-specific checks.
---

# Portal Testing and Validation

## Purpose

Use this skill whenever a change must be validated before it is considered complete.

This includes:

- bug fixes;
- new features;
- route changes;
- form changes;
- permission changes;
- database changes;
- migrations;
- Vault changes;
- external API changes;
- background jobs;
- startup/runtime changes;
- new operational tools;
- template changes;
- security-sensitive changes;
- cross-subsystem behavior.

This skill defines the expected validation discipline for Portal Operations Tools.

It does not replace:

- `/review`
- `/qa`
- `/qa-only`
- `/investigate`
- `/codex`
- subsystem-specific portal skills

It complements them with project-specific validation rules.

---

# 1. Load Project Context First

Before validating a change, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
```

Then identify:

```text
affected subsystem
affected routes
affected models
affected templates
affected external services
affected security boundaries
affected runtime behavior
```

Read only the relevant subsystem documentation:

```text
docs/systems/<subsystem>.md
```

If the change touches known technical debt, also read:

```text
docs/technical-debt/current.md
```

---

# 2. Validation Must Match the Change

Do not run the same checklist mechanically for every task.

Choose validation based on what changed.

Examples:

```text
template-only change
→ route render + visual/manual check

authorization change
→ allowed + denied route tests

database migration
→ upgrade + downgrade review + data compatibility

external API change
→ success + timeout + provider error + partial result

background job change
→ success + failure + duplicate/restart behavior

runtime change
→ startup + clean environment + config behavior
```

Validation should be proportional, but never superficial.

---

# 3. Minimum Completion Standard

A change is not complete merely because:

```text
code compiles
page loads once
no exception appeared
```

At minimum, determine:

```text
Does the intended behavior work?

Does the previous behavior still work?

Do denied/error cases behave correctly?

Did the change affect anything outside its intended scope?

Are sensitive boundaries still enforced?

Did the application still start correctly?
```

---

# 4. Validate the Smallest Relevant Surface

Prefer targeted validation over broad unstructured testing.

Start with:

```text
changed function
changed route
changed model
changed template
changed workflow
```

Then expand outward only where the change can realistically propagate.

Example:

```text
Vault authorization helper changed
        ↓
test reveal
test edit
test delete
test shared access
```

Do not run unrelated subsystem tests without reason.

---

# 5. Inspect Git State Before Validation

Before testing, run:

```bash
git status --short
```

Know what is currently modified.

Do not accidentally validate against unrelated uncommitted edits without realizing it.

If multiple unrelated changes exist, identify which files belong to the current task.

---

# 6. Syntax and Import Validation

For Python changes, first ensure the affected files can parse/import.

Useful checks may include:

```bash
python3 -m py_compile path/to/file.py
```

or broader checks where appropriate.

Do not rely only on static syntax checks.

A file can compile and still fail at runtime due to:

```text
missing imports
wrong configuration
bad database assumptions
Flask context
authorization
provider behavior
```

---

# 7. Application Startup Smoke Test

For most non-trivial changes, verify the application still starts.

At minimum:

```text
application imports
create_app() succeeds
extensions initialize
database initialization does not fail
Blueprints register
server starts
```

Do not skip startup validation after touching:

```text
app/__init__.py
config.py
extensions.py
models
migrations
requirements
server.py
run.py
```

---

# 8. Login and Dashboard Smoke Test

For portal-wide or security-sensitive changes, verify:

```text
login page loads
valid login succeeds
dashboard loads
expected tools appear
navigation remains functional
```

Do not assume a subsystem works because the server starts.

---

# 9. Route Validation

For every changed route, verify:

```text
expected HTTP method
expected status
expected redirect
expected template
expected data
expected authorization
expected error behavior
```

Do not validate only by manually clicking the UI.

Consider direct route access.

---

# 10. GET Must Not Accidentally Mutate State

When validating routes, check whether GET requests alter data.

If a GET route:

```text
creates
updates
deletes
marks state
runs external mutation
```

flag it unless that behavior is explicitly intended and justified.

Do not copy existing GET mutation patterns into new code.

---

# 11. POST and CSRF

For state-changing form routes, verify:

```text
valid POST succeeds
invalid CSRF fails
invalid form input fails safely
unauthorized POST fails
duplicate submission behavior is understood
```

Do not disable CSRF simply to make a test pass.

---

# 12. Authorization Testing

Authorization changes require both positive and negative tests.

At minimum consider:

```text
anonymous
authenticated unauthorized user
authorized user
resource owner
shared user
administrator
```

depending on the feature.

Do not test only the admin path.

---

# 13. Direct URL Testing

A hidden button or dashboard card is not sufficient protection.

For protected routes, test direct URL access.

Examples:

```text
unauthorized user manually enters route
user changes object ID
user opens edit URL directly
user opens delete/reveal endpoint directly
```

Verify server-side denial.

---

# 14. Object-Level Authorization

For user-owned resources, test another user's object.

Example:

```text
User A creates object
User B has tool access
User B attempts direct access to User A object
```

Expected behavior must match the authorization model.

Do not infer correctness from list-page filtering.

---

# 15. Security Negative Tests

Security-sensitive changes should include attempts that must fail.

Examples:

```text
reveal secret without permission
edit another user's entry
delete another user's entry
use tool without UserTool permission
submit admin action as normal user
tamper with object ID
submit malformed CSRF
reuse invalid token
```

A security change is incomplete without negative validation.

---

# 16. Secret Exposure Validation

If secrets are involved, verify they do not appear in:

```text
HTML source
logs
audit records
flash messages
URLs
database plaintext
temporary files
exception messages
JavaScript variables
hidden inputs
```

Use synthetic credentials only.

Do not inspect real secrets.

---

# 17. Database Validation

If models or persistence changed, also use:

```text
portal-database-change
```

Validate:

```text
model creation
reads
writes
relationships
constraints
defaults
existing-data compatibility
migration state
```

Do not validate schema changes only through UI behavior.

---

# 18. Migration Validation

For Alembic changes:

```text
inspect generated migration
inspect upgrade()
inspect downgrade()
apply upgrade to disposable DB
verify resulting schema
verify app startup
review downgrade behavior
```

If downgrade is unsafe or lossy, state it clearly.

Do not claim reversibility unless it was actually reviewed.

---

# 19. Fresh Database Validation

If startup or schema initialization changed, test a disposable fresh database.

Verify:

```text
initial schema creation
migration history
bootstrap behavior
application startup
initial admin/setup flow where applicable
```

Do not destroy or replace the user's real runtime database for this test.

---

# 20. Existing Database Validation

Also consider an already-populated database.

Verify:

```text
upgrade succeeds
existing rows remain valid
encrypted data remains readable
relationships remain correct
application starts afterward
```

Fresh-install success alone is insufficient for schema evolution.

---

# 21. Data Integrity Validation

For changes that update persistent data, verify:

```text
no duplicate records
no orphaned relationships
no unexpected nulls
no unintended cascade deletion
no invalid ownership
no lost encrypted content
```

Do not assume database constraints alone guarantee business correctness.

---

# 22. Vault Validation

If the change touches Vault, also use:

```text
portal-vault-change
```

Consider testing:

```text
list
view
create
edit
delete
reveal
shared access
owner access
admin access
group behavior
sync config
import
export
KeePass sync
```

Only test flows affected by the task.

---

# 23. Vault Secret Validation

For Vault changes involving encrypted content:

```text
plaintext not stored in DB
authorized decrypt succeeds
unauthorized access denied
HTML does not expose plaintext unnecessarily
logs do not expose plaintext
audit does not expose plaintext
```

Use synthetic secrets.

---

# 24. KeePass Validation

If sync/import/export changed, use a disposable synthetic KDBX when practical.

Validate relevant cases:

```text
valid password
wrong password
missing file
new entry
existing entry
duplicate/stable UUID
partial failure
sync failure
cleanup
```

Never use the user's real KDBX for automated validation.

---

# 25. External API Validation

If external integrations changed, also use:

```text
portal-external-api-change
```

Validate relevant provider outcomes:

```text
success
timeout
connection failure
401
403
404 when meaningful
429
500
invalid JSON
missing fields
partial success
retry exhaustion
```

Do not test production mutations unless explicitly approved.

---

# 26. Prefer Mocked External Responses

For automated tests, prefer:

```text
mocked HTTP responses
synthetic provider payloads
dry-run
sandbox provider environment
```

Avoid depending on live provider availability.

Tests should remain repeatable.

---

# 27. Validate Retry Behavior

If retries changed, verify:

```text
retryable error retries
non-retryable error does not retry
maximum attempts respected
delay remains bounded
eventual success works
final failure is reported
```

Do not allow tests to sleep for long real delays if mocking time/backoff is practical.

---

# 28. Partial Success Validation

For batch APIs or multi-item operations, test:

```text
all succeed
some succeed
all fail
```

Verify local job/result state accurately reflects provider outcome.

Do not flatten partial success into generic success unless intended.

---

# 29. Background Job Validation

If background execution changed, also use:

```text
portal-background-job-change
```

Validate:

```text
job starts
status changes
worker executes
results persist
failure produces deterministic status
duplicate execution behavior
partial completion
```

Do not validate only the route that launches the thread.

---

# 30. Worker Exception Validation

Force or simulate worker failure.

Verify:

```text
exception is logged safely
job does not remain falsely successful
job does not remain running forever if avoidable
user can understand failure state
```

Do not swallow exceptions.

---

# 31. Restart Behavior

If restart durability matters, validate or explicitly document:

```text
what survives restart
what does not
what stale job state remains
whether retry is safe
whether recovery exists
```

Do not claim durability unless architecture and validation support it.

---

# 32. Duplicate Job Validation

For high-risk background work, test repeated trigger attempts.

Examples:

```text
double click
same request twice
manual + scheduler overlap
retry after partial completion
```

Verify duplicate behavior matches the intended design.

---

# 33. Runtime Environment Validation

If startup/runtime changed, also use:

```text
portal-runtime-environment-change
```

Validate:

```text
environment loading
required configuration
optional configuration
server startup
path portability
dependency imports
certificate detection
database bootstrap
```

---

# 34. Dependency Validation

If `requirements.txt` changes:

```text
verify package is actually required
verify import succeeds
verify clean installation when practical
verify app startup afterward
```

Do not treat local `pip install` as sufficient proof.

---

# 35. Cross-Platform Validation

For path/runtime changes, review compatibility with:

```text
Windows
macOS
Linux
```

Look for:

```text
hardcoded separators
absolute paths
shell-specific commands
case sensitivity
platform-specific APIs
```

Do not claim multi-platform support if only one environment was considered.

---

# 36. Template Validation

For Jinja/template changes, verify:

```text
template renders
variables exist
empty state works
normal state works
permissions hide/show correctly
forms submit correctly
no undefined values
```

Do not validate only with data-rich cases.

Empty datasets often expose template errors.

---

# 37. UI Permission Validation

When UI elements depend on permission:

```text
authorized user sees action
unauthorized user does not
```

but also verify:

```text
backend denies unauthorized direct request
```

UI visibility is not the security boundary.

---

# 38. Form Validation

For changed forms, test:

```text
valid input
missing required input
invalid format
unexpected choice
oversized field
tampered object ID
```

Only test cases relevant to the form.

Do not rely exclusively on client-side constraints.

---

# 39. Empty State

For list/dashboard pages, test no-data behavior.

Verify:

```text
page renders
no index error
helpful empty message where appropriate
no false action availability
```

New installations frequently begin empty.

---

# 40. Large Data Behavior

If the task affects lists, imports, jobs, or provider catalogs, consider whether behavior changes with larger input.

Look for:

```text
unbounded loops
N+1 queries
huge HTML pages
per-row provider calls
excessive commits
memory growth
```

Do not optimize without evidence, but identify obvious scaling regressions.

---

# 41. Error Page Behavior

Expected operational failures should not become generic 500s where better handling exists.

Validate relevant cases such as:

```text
missing record
invalid ID
provider unavailable
configuration missing
validation failure
unauthorized access
```

Return behavior should match current Flask conventions.

---

# 42. Logging Validation

Check logs for:

```text
useful operational context
no secret leakage
no excessive noise
no stack trace for expected user errors unless needed
```

Do not require perfectly silent logs.

Warnings and actionable failures are acceptable.

---

# 43. Audit Validation

If audit behavior changed, verify:

```text
audit record created where expected
actor correct
operation correct
target correct
result correct
no secret content
```

Be aware that audit persistence may depend on surrounding transaction commits.

Do not assume calling an audit helper guarantees a committed record.

---

# 44. Notification Validation

If notifications changed, verify:

```text
correct user/audience
correct content
correct read/unread behavior
no secret content
no duplicate notification where avoidable
```

Be aware of known global read-state limitations.

Do not expand scope unless the task addresses them.

---

# 45. Regression Validation

After validating the changed behavior, test the nearest unchanged behavior that could reasonably regress.

Examples:

```text
changed Vault edit
→ verify Vault view/reveal still work

changed auth helper
→ verify at least two protected tools

changed app factory
→ verify multiple Blueprints

changed shared IoC model
→ verify VT + CSIRT

changed external utility
→ verify every caller
```

Do not run unrelated portal features arbitrarily.

---

# 46. Shared Code Requires Broader Validation

Changes to shared files increase test surface.

Examples:

```text
app/__init__.py
app/extensions.py
app/models.py
app/utils.py
app/tools_config.py
base.html
shared mixins/helpers
```

When these change, identify all known consumers.

Validate representative callers.

---

# 47. Source-of-Truth Validation

When documentation and implementation disagree:

```text
current code
```

is normally authoritative for current behavior.

Do not change working code solely to match stale documentation unless the requested task says the documented behavior is intended.

Instead:

```text
validate code
update documentation if needed
```

---

# 48. Test Data Must Be Synthetic

Do not use real:

```text
passwords
API keys
tokens
personal Vault entries
production IoCs when mutation is possible
KDBX files
private certificates
```

for automated testing.

Use synthetic values.

---

# 49. Do Not Modify Protected Runtime Data for Testing

Avoid destructive tests against:

```text
instance/
real SQLite DB
real KDBX
.env
private key files
production provider state
```

Use disposable copies or test fixtures.

---

# 50. Test Isolation

Tests should avoid depending on execution order.

Where possible:

```text
create own data
clean own data
mock external services
use disposable DB
```

Do not require another test to run first.

---

# 51. Reproducibility

A validation result should be repeatable.

Avoid tests that depend on:

```text
current provider live data
current clock without control
random external state
developer-specific filesystem
manual hidden setup
```

When unavoidable, state the limitation.

---

# 52. Time-Dependent Behavior

For logic involving freshness windows, retries, schedules, or expiry:

```text
control or mock time where practical
test boundary conditions
```

Examples:

```text
just before expiration
exact expiration
just after expiration
```

Do not only test one arbitrary timestamp.

---

# 53. Cache Validation

If cache/reuse logic changes, test:

```text
cache hit
cache miss
stale cache
fresh cache
related-record reuse
provider call avoided when expected
provider call performed when expected
```

This is particularly important for VirusTotal quota-sensitive behavior.

---

# 54. Database Query Count Awareness

If a change moves logic into loops over database rows, inspect whether it introduces obvious N+1 behavior.

Do not optimize every query automatically.

But if a page now performs:

```text
1 query per row
```

where previously it did not, consider it a regression risk.

---

# 55. Browser Manual Validation

Manual browser testing is useful for:

```text
navigation
layout
forms
flash messages
interactive flows
permissions
empty states
```

It is not enough for:

```text
authorization correctness
database integrity
secret storage
retry behavior
migration correctness
```

Combine manual and programmatic validation appropriately.

---

# 56. UI/UX Validation

For significant UI work, verify:

```text
desktop layout
common viewport sizes
form clarity
error feedback
loading state
disabled state
empty state
danger actions
```

If using:

```text
ui-ux-pro-max
```

ensure visual recommendations do not override backend/security rules.

---

# 57. Accessibility Sanity Check

For changed UI, at least consider:

```text
form labels
button semantics
keyboard usability
contrast where obvious
descriptive text
not relying only on color
```

Do not turn every portal change into a full accessibility audit unless requested.

---

# 58. Dangerous Actions

For destructive actions such as:

```text
delete
external mutation
credential reset
bulk update
```

validate:

```text
authorization
clear user intent
CSRF
confirmation where appropriate
server-side enforcement
audit
```

A confirmation modal alone is not sufficient.

---

# 59. Test the Error Path Before Calling It Done

For each non-trivial workflow, ask:

```text
What is the most likely failure?
```

Then validate it.

Examples:

```text
API timeout
invalid credential
DB constraint
missing file
unauthorized user
duplicate job
wrong KDBX password
```

Do not ship a feature whose failure behavior is unknown.

---

# 60. Do Not Hide Failing Tests

If an existing test fails after the change:

```text
determine whether regression
determine whether test is stale
determine whether unrelated pre-existing failure
```

Do not simply delete or skip the test.

If unrelated and pre-existing, report it explicitly.

---

# 61. Missing Test Coverage

If the repository lacks tests for the affected area, say so.

Do not imply:

```text
fully tested
```

when validation was only manual.

State:

```text
what was tested
what was not tested
why
```

---

# 62. Validation Evidence

When reporting completion, summarize concrete validation.

Good:

```text
Validated:
- unauthorized Vault user receives 403 on edit
- owner can edit successfully
- admin can edit successfully
- password remains encrypted in DB
- app starts after migration
```

Avoid vague statements such as:

```text
Everything looks good.
```

---

# 63. Diff Review

Before declaring completion, review:

```bash
git diff
```

and when staged:

```bash
git diff --cached
```

Look for:

```text
unrelated edits
debug prints
temporary code
secret values
generated files
accidental formatting
missing migration
missing docs
```

This is mandatory for non-trivial changes.

---

# 64. Run gstack Review When Appropriate

For non-trivial changes, use:

```text
/review
```

before finalizing.

For broader interactive QA:

```text
/qa
```

or:

```text
/qa-only
```

when appropriate.

Do not duplicate the entire gstack review process manually in this skill.

This skill provides project-specific validation expectations.

---

# 65. Use Codex as Secondary Review When Risk Justifies It

Consider:

```text
/codex review
```

for changes involving:

```text
security
encryption
complex migrations
external production mutations
background durability
major shared architecture
```

Do not require secondary review for every trivial change.

---

# 66. Validation Order

A good default order is:

```text
syntax/import
        ↓
targeted unit/logic validation
        ↓
database/migration validation if applicable
        ↓
route/security validation
        ↓
external/background validation if applicable
        ↓
application smoke test
        ↓
manual UI check if relevant
        ↓
git diff review
        ↓
/review
```

Adapt this to the task.

---

# 67. Stop on Fundamental Failure

If a core validation fails:

```text
migration fails
authorization bypass exists
secret exposed
app no longer starts
external mutation unsafe
data loss occurs
```

do not continue polishing unrelated aspects.

Fix the fundamental issue first.

---

# 68. Do Not Change Requirements to Make Tests Pass

If validation reveals a mismatch between implementation and expected behavior:

```text
understand the cause
```

before changing the expected behavior.

Do not weaken:

```text
authorization
constraints
validation
security checks
```

just to get a green result.

---

# 69. Technical Debt Interaction

If validation exposes unrelated known debt:

```text
report it
```

but do not automatically fix it.

If the current task resolves an existing debt item:

```text
update docs/technical-debt/current.md
```

Do not leave resolved debt documented as unresolved.

---

# 70. Documentation Validation

When behavior changes, verify documentation still matches:

```text
docs/systems/<subsystem>.md
docs/PROJECT_MAP.md
docs/technical-debt/current.md
docs/decisions/
```

Do not update docs based on intended behavior before confirming the implementation actually works that way.

---

# 71. Validation for New Operational Tools

For a newly added tool, also use:

```text
portal-new-operational-tool
```

Minimum validation should include:

```text
Blueprint registered
dashboard card appears for authorized user
hidden for unauthorized user
direct URL denied for unauthorized user
main workflow works
errors handled
tool permission configurable
existing portal still starts
```

---

# 72. Validation for Shared Authorization Changes

If changing:

```text
User.has_tool()
proteger_blueprint()
admin checks
shared permission helpers
```

test more than one subsystem.

Shared security helpers can affect the entire portal.

At minimum validate representative protected tools.

---

# 73. Validation for Shared Models

If changing a shared model/mixin, identify every subsystem that uses it.

Example:

```text
shared IoC metadata
→ VirusTotal + CSIRT
```

Do not validate only the file where the model is declared.

---

# 74. Validation for App Factory Changes

If `app/__init__.py` changes, verify:

```text
all expected Blueprints
extensions
scheduler
authorization protection
error handlers
startup
```

A successful import alone is insufficient.

---

# 75. Validation for Requirements Changes

If dependencies change, verify:

```text
requirements syntax
package installability
import
application startup
```

If version constraints change, test the behavior that motivated the version change.

---

# 76. Validation for Configuration Changes

If `config.py` changes, test:

```text
valid configuration
missing mandatory configuration
missing optional configuration
invalid numeric/boolean configuration
```

Only where relevant.

Do not print secrets while testing.

---

# 77. Validation for Certificate/Server Changes

If server/TLS behavior changes, verify:

```text
certificate present path
certificate missing path
expected protocol
expected port
bind address
startup failure behavior
```

Do not expose private key content.

---

# 78. Validation for Docker Changes

If Docker files change, verify:

```text
build succeeds
runtime command works
dependencies available
ports correct
environment passed safely
persistent data location correct
```

Do not claim Docker compatibility without testing or clearly stating it was not tested.

---

# 79. Validation for PyInstaller Changes

If packaging changes, verify when practical:

```text
build succeeds
templates included
static files included
hidden imports resolved
runtime paths work
startup works
```

If full build is not performed, state that explicitly.

---

# 80. Performance Sanity Check

For changes likely to affect operational performance, inspect:

```text
loop count
query count
provider call count
file IO
large payload handling
```

Do not perform elaborate benchmarking unless needed.

Look for obvious regressions.

---

# 81. Concurrency Sanity Check

For changes involving threads/scheduler/shared files:

```text
consider overlapping execution
shared mutable state
database session safety
file access
duplicate external calls
```

Do not assume only one request or worker exists.

---

# 82. Final Validation Summary

Before declaring a non-trivial task complete, provide a concise summary:

```md
## Validation

### Passed

- ...
- ...
- ...

### Not Tested

- ...
- ...

### Known Limitations

- ...
- ...

### Regression Check

- ...
```

Do not claim unperformed checks.

---

# 83. Completion Checklist

Before declaring a change validated, verify:

```text
[ ] Affected subsystem identified
[ ] Relevant documentation reviewed
[ ] Git state inspected
[ ] Syntax/import checked where applicable
[ ] Application starts
[ ] Changed behavior works
[ ] Error path tested
[ ] Authorization allowed path tested if applicable
[ ] Authorization denied path tested if applicable
[ ] Direct URL considered if applicable
[ ] CSRF behavior checked for mutations
[ ] Secret exposure checked if applicable
[ ] Database integrity checked if applicable
[ ] Migration upgrade reviewed/tested if applicable
[ ] Existing-data compatibility considered if applicable
[ ] External failure behavior tested if applicable
[ ] Retry/partial-success behavior tested if applicable
[ ] Background failure/duplicate behavior tested if applicable
[ ] Runtime/config behavior tested if applicable
[ ] Nearest regression surface checked
[ ] Logs reviewed for unsafe output where relevant
[ ] Audit behavior checked where relevant
[ ] Manual UI check performed where relevant
[ ] No protected runtime data was modified unnecessarily
[ ] git diff reviewed
[ ] Missing coverage explicitly reported
[ ] Documentation updated if behavior changed
[ ] /review used for non-trivial changes when appropriate
```

---

# 84. Core Rule

Never treat validation as:

```text
it runs
there is no error
done
```

For this project, validation means:

```text
intended behavior
+
error behavior
+
authorization
+
data integrity
+
security
+
external failures
+
background behavior
+
runtime startup
+
regression checks
+
diff review
```

A change is complete only when there is concrete evidence that it works and that
the most relevant ways it could fail have been considered.