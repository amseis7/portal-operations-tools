---
name: portal-vault-change
description: >
  Project-specific workflow for modifying the Vault subsystem in Portal Operations Tools.
  Use when changing Vault routes, templates, forms, models, permissions, sharing, groups,
  secret reveal behavior, encrypted fields, KeePass import/export, synchronization,
  VaultSyncConfig, temporary import state, or related audit/security behavior.
  Complements portal-security-change, portal-database-change, and portal-external-api-change
  with Vault-specific constraints and workflows.
---

# Portal Vault Change

## Purpose

Use this skill whenever a task modifies the Vault subsystem.

Examples:

- Vault entry creation;
- Vault entry editing;
- Vault entry deletion;
- secret reveal;
- ownership;
- shared entries;
- groups;
- encrypted fields;
- custom fields;
- KeePass import;
- KeePass export;
- KeePass synchronization;
- Vault sync settings;
- `VaultSyncConfig`;
- Vault templates;
- Vault forms;
- Vault routes;
- Vault auditing;
- Vault authorization fixes;
- Vault data migrations.

Vault is a high-sensitivity subsystem.

Changes must preserve:

```text
authorization
+
ownership
+
encryption
+
secret confidentiality
+
KeePass compatibility
+
database integrity
+
auditability
```

This skill does not replace:

- `portal-security-change`
- `portal-database-change`
- `portal-external-api-change`
- `/investigate`
- `/plan-eng-review`
- `/review`
- `/careful`
- `/codex`

Use them when their concerns also apply.

---

## 1. Load Vault Context First

Before modifying Vault behavior, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/vault.md
docs/decisions/ADR-003-tool-authorization-model.md
docs/decisions/ADR-004-secrets-at-rest.md
docs/technical-debt/current.md
```

If models or persisted configuration will change, also read:

```text
docs/decisions/ADR-002-database-schema-migrations.md
```

Do not begin by editing a route or template in isolation.

First understand the complete Vault flow affected by the task.

---

## 2. Inspect the Actual Vault Implementation

Inspect only the files relevant to the requested change.

Typical Vault files include:

```text
app/vault/__init__.py
app/vault/routes.py
app/vault/forms.py
app/vault/models.py
app/vault/sync.py
app/templates/vault/
```

Also inspect shared infrastructure when needed:

```text
app/__init__.py
app/models.py
app/extensions.py
app/utils.py
app/tools_config.py
```

Do not assume documentation is perfectly current.

Current source code is authoritative.

---

## 3. Vault Is a Security-Sensitive Subsystem

Treat all Vault work as potentially security-sensitive.

Before implementation, identify whether the change touches:

```text
authentication
tool authorization
ownership
shared access
administrator access
secret reveal
encryption
plaintext lifetime
temporary files
KeePass credentials
audit
export
```

If any of these are involved, also apply:

```text
portal-security-change
```

Do not treat Vault changes as ordinary CRUD by default.

---

## 4. Known Vault Technical Debt

Current Vault technical debt must be considered when relevant.

Known areas include:

```text
Blueprint-level Vault authorization may be incomplete
edit authorization may be weaker than intended
delete authorization may be weaker than intended
group management may be broadly available
temporary plaintext import preview data may remain on disk
Vault sync settings may expose decrypted KDBX password in rendered forms
VaultAuditLog may duplicate the global audit architecture
```

These are known problems.

They are not design patterns to copy.

If the requested task touches one of these areas, explicitly state whether the change:

```text
preserves the debt
partially resolves it
fully resolves it
could worsen it
```

Do not silently fix unrelated Vault debt.

---

## 5. Tool-Level Authorization

Vault should participate in the canonical tool authorization model:

```text
UserTool
+
User.has_tool()
+
proteger_blueprint()
```

Before changing Vault access, verify whether the Blueprint is currently protected correctly.

Do not assume:

```text
Vault card hidden
```

means:

```text
Vault routes protected
```

A user may manually enter a route URL.

Backend enforcement is authoritative.

---

## 6. Tool Access Is Not Entry Access

A user having Vault access does not mean they may access every Vault entry.

Vault authorization has at least two layers:

```text
tool access
        +
entry/object access
```

For every route involving a specific Vault entry, determine:

```text
Can the owner perform this action?
Can a shared user perform this action?
Can an administrator perform this action?
Can another Vault user perform this action?
```

Do not infer these answers from template visibility.

---

## 7. Understand `_can_access()`

Before modifying entry access, inspect the current helper responsible for access checks.

If `_can_access()` exists, determine exactly what it means.

It may represent:

```text
view permission
```

rather than:

```text
edit permission
delete permission
```

Do not automatically reuse a read-access helper for destructive actions unless its semantics are correct.

If separate policies are required, prefer clear helpers such as conceptually:

```text
_can_view(...)
_can_edit(...)
_can_delete(...)
```

only if the existing architecture and task justify it.

Do not refactor authorization merely for stylistic reasons.

---

## 8. Define the Vault Authorization Matrix

For any non-trivial permission change, define behavior for:

```text
anonymous user
authenticated user without Vault tool
Vault user who does not own entry
shared-access user
entry owner
administrator
```

and actions such as:

```text
list
view
reveal
create
edit
delete
share
export
manage groups
configure sync
run sync
```

Do not implement authorization from assumptions.

---

## 9. Viewing Is Not Editing

Do not assume that because a user can view a shared Vault entry they should also be able to edit it.

Similarly:

```text
view
reveal
edit
delete
share
```

may require different permissions.

For every affected operation, define the intended rule explicitly.

---

## 10. Deletion Is High Risk

Vault deletion is destructive.

Before modifying delete behavior, verify:

```text
tool authorization
entry authorization
request method
CSRF
audit
related records
group relationships
sync implications
```

Do not implement secret deletion through GET.

Do not rely on a confirmation dialog as authorization.

The server must enforce permission.

---

## 11. Secret Reveal Is High Risk

Revealing a secret is different from viewing Vault metadata.

For reveal behavior, verify:

```text
authentication
Vault tool access
entry-level access
request type
response behavior
browser caching implications
audit
logging
```

Never reveal plaintext through:

```text
query strings
redirect URLs
flash messages
logs
audit details
```

Keep plaintext lifetime minimal.

---

## 12. Persistent Secret Fields Must Remain Encrypted

Sensitive Vault content must remain encrypted at rest.

Examples include:

```text
password
notes
custom secret fields
sync credentials
```

Do not replace encrypted fields with plaintext storage.

Do not create new plaintext shadow columns for convenience.

If a new sensitive field is required, determine:

```text
which encryption mechanism applies
when encryption occurs
when decryption occurs
whether existing helpers can be reused
```

Use:

```text
portal-security-change
```

and:

```text
portal-database-change
```

when adding persistent encrypted data.

---

## 13. Encryption Domain

Vault-specific encrypted content may use:

```text
VAULT_KEY
```

while other application secrets may use another encryption domain such as:

```text
SECRET_KEY_DB
```

Do not assume keys are interchangeable.

Before storing a new secret, inspect the existing encryption helper used by semantically similar Vault fields.

Reuse the established mechanism where appropriate.

---

## 14. Never Log Decrypted Vault Data

Do not log:

```text
password plaintext
notes plaintext
custom field secrets
KeePass password
decrypted sync configuration
imported secret content
```

This applies to:

```text
debug logs
exception logs
audit logs
temporary troubleshooting output
```

Safe metadata may include:

```text
entry ID
entry UUID
operation
user ID
result
error category
```

when appropriate.

---

## 15. Templates Must Not Leak Secrets

Inspect rendered HTML behavior when changing Vault templates.

Avoid placing decrypted values in:

```text
hidden inputs
data-* attributes
JavaScript variables
page source
pre-populated password inputs
HTML comments
```

A field hidden visually is still exposed to the browser.

For edit/configuration forms, prefer:

```text
blank secret field
        ↓
empty submission preserves existing secret
        ↓
new value replaces existing secret
```

when that matches the workflow.

---

## 16. Sync Configuration Passwords

Vault synchronization configuration deserves special care.

A stored KeePass password should not normally be decrypted and rendered back into the settings form.

Preferred semantics:

```text
existing password configured
        ↓
form does not reveal plaintext
        ↓
empty password field means preserve current value
        ↓
new password means replace current value
```

If the task touches this behavior, treat it as:

```text
portal-security-change
```

and update technical debt if resolved.

---

## 17. KeePass Integration

Vault synchronization may interact with a KeePass/KDBX file.

Before modifying synchronization, determine:

```text
where KDBX path comes from
where KDBX password comes from
whether DB config overrides environment config
when file is opened
how entries are matched
how conflicts are handled
what direction synchronization runs
what fields are synchronized
```

Do not infer sync semantics solely from variable names.

Inspect:

```text
app/vault/sync.py
```

and current Vault documentation.

---

## 18. Vault Sync Configuration Precedence

Current synchronization configuration may use:

```text
database configuration
```

with environment variables as fallback.

Relevant environment variables may include:

```text
VAULT_KDBX_PATH
VAULT_KDBX_PASSWORD
```

Before changing precedence, identify existing behavior precisely.

Do not accidentally cause environment configuration to override persisted administrator configuration unless explicitly intended.

---

## 19. KeePass Password Handling

KeePass passwords must not be:

```text
logged
rendered unnecessarily
stored plaintext in DB
committed
written into documentation
```

Plaintext may exist temporarily when opening the KDBX file.

Keep that lifetime narrow.

Avoid passing it through unrelated functions or long-lived state.

---

## 20. KeePass Paths

Treat KDBX file paths carefully.

Do not trust user-controlled paths blindly.

Consider:

```text
absolute vs relative paths
cross-platform behavior
file existence
permissions
path traversal
unexpected file types
```

Do not hardcode Windows-only separators.

The project must remain portable across:

```text
Windows
macOS
Linux
```

Use appropriate path utilities.

---

## 21. Entry UUIDs

If Vault entries use UUIDs for synchronization or stable identification, preserve their semantics.

Before changing UUID behavior, determine:

```text
when UUID is created
whether UUID is unique
whether KeePass uses it for matching
whether imports preserve it
whether exports depend on it
```

Do not regenerate stable identifiers merely because an entry is edited.

Changing identifiers can break synchronization.

---

## 22. Import Workflows

Vault import is high risk because imported content may contain plaintext secrets.

Before modifying import behavior, map the complete flow:

```text
upload
        ↓
parse
        ↓
preview
        ↓
temporary state
        ↓
user confirmation
        ↓
database encryption
        ↓
cleanup
```

Identify exactly where plaintext exists.

Minimize it.

---

## 23. Import Preview Data

Plaintext import preview files are known security debt.

Do not copy that pattern into new workflows.

If the task touches import preview, consider replacing persistent plaintext temporary state with a safer approach such as:

```text
short-lived in-memory state
encrypted temporary data
session-bound protected storage
```

Choose based on actual requirements.

Do not redesign the whole import system unless the task requires it.

---

## 24. Temporary File Cleanup

If temporary Vault files are unavoidable, define cleanup behavior for:

```text
successful import
cancelled import
validation failure
exception
process restart
abandoned preview
```

Do not assume the normal success path is enough.

Security-sensitive temporary files should not remain indefinitely.

---

## 25. Import Validation

Imported entries must be validated before persistence.

Consider:

```text
required fields
duplicate UUID
duplicate semantic entries
invalid types
oversized fields
malformed custom fields
encoding
unsupported values
```

Do not persist imported plaintext before validation unless necessary.

Encrypt sensitive data before durable database storage.

---

## 26. Export Workflows

Before modifying Vault export, define:

```text
who can export
which entries are included
whether shared entries are included
whether plaintext secrets are exported
format
encryption
destination
audit
```

An export may be equivalent to bulk secret disclosure.

Treat it accordingly.

Do not add export functionality as a convenience without explicit authorization design.

---

## 27. Sharing

If Vault entries can be shared, define exactly what sharing means.

Possible semantics include:

```text
view metadata
reveal secret
edit entry
delete entry
reshare
export
```

Do not treat a generic:

```text
shared = True
```

as sufficient policy documentation.

Inspect current implementation and preserve its actual intended behavior unless explicitly changing it.

---

## 28. Groups

Before modifying Vault groups, determine:

```text
who can create groups
who can delete groups
who can add entries
who can remove entries
whether groups are global
whether groups are per-user
whether groups affect authorization
```

Do not infer that groups are merely presentation folders.

If group operations currently have broad authorization and the task touches them, evaluate that known debt explicitly.

---

## 29. Group Deletion

Before deleting a group, inspect relationships.

Determine whether deletion:

```text
deletes entries
unlinks entries
affects shared access
affects KeePass sync
affects UI only
```

Do not add cascade behavior without understanding consequences.

---

## 30. Custom Fields

Custom Vault fields may contain sensitive information.

Treat them as sensitive unless clearly proven otherwise.

Before modifying custom-field persistence or rendering, determine:

```text
which fields are encrypted
how keys/names are stored
how values are encrypted
how they are rendered
how they are synced
how imports/exports handle them
```

Do not assume custom fields are safe metadata.

---

## 31. Forms

Vault forms may contain sensitive values.

Use Flask-WTF and preserve CSRF.

Do not prepopulate secrets unnecessarily.

Server-side validation should cover:

```text
required metadata
length
URLs when applicable
group IDs
shared flags
custom fields
sync configuration
```

Do not trust submitted ownership or user IDs.

Ownership should be determined server-side.

---

## 32. Route Object Lookup

When loading a Vault entry by ID or UUID:

```text
fetch object
        ↓
check existence
        ↓
check authorization
        ↓
perform action
```

Do not perform the action before authorization.

Avoid authorization decisions based solely on values submitted by the client.

---

## 33. Avoid Insecure Direct Object References

Assume users can alter route IDs manually.

For routes such as:

```text
/vault/<id>
/vault/<id>/edit
/vault/<id>/delete
/vault/<id>/reveal
```

verify entry-level authorization every time.

A valid object ID is not proof of permission.

---

## 34. Administrator Access

Use the established administrator model.

Do not create Vault-specific special admin usernames or IDs.

If admins can override ownership, make that behavior explicit and test it.

Administrator bypass must not accidentally grant access to unauthenticated or ordinary users.

---

## 35. Database Changes

Any Vault model or schema modification must also use:

```text
portal-database-change
```

Examples:

```text
new encrypted field
new ownership field
new sync configuration field
new sharing relationship
new group relationship
new index
new constraint
```

Do not modify historical migrations.

Create a new Alembic migration.

---

## 36. Existing Data Compatibility

Vault migrations must consider existing encrypted data.

Ask:

```text
Will existing ciphertext still decrypt?
Does a new required field need backfill?
Will UUIDs remain stable?
Will ownership remain valid?
Will sharing relationships remain intact?
Will sync continue to match entries?
```

A migration that works only on a fresh database is insufficient.

---

## 37. Encryption Migration

Changing Vault encryption is a major security change.

Do not simply change:

```text
VAULT_KEY
```

for existing encrypted records.

If ciphertext must be migrated, define:

```text
old-key access
decrypt
validate
re-encrypt
new-key verification
rollback
failure recovery
```

Use:

```text
/plan-eng-review
portal-security-change
portal-database-change
/codex review
```

for significant encryption migration work.

---

## 38. Audit

Vault actions may require auditing.

Candidate operations include:

```text
create
edit
delete
reveal
share
unshare
group administration
sync configuration change
sync execution
import
export
```

Use the existing global audit architecture when appropriate.

Do not automatically expand or create a Vault-specific audit framework.

---

## 39. VaultAuditLog

If a Vault-specific audit model exists, verify whether it is actually used before building on it.

Do not assume an existing model is canonical merely because it exists.

The global `AuditLog` architecture may already be the intended system.

If the task encounters duplicate audit mechanisms, report the discrepancy.

Do not silently migrate or delete historical audit structures without explicit scope.

---

## 40. Audit Must Not Store Secrets

Vault audit records must never contain:

```text
password plaintext
notes plaintext
KeePass password
custom secret values
encryption keys
full exported secret content
```

Use metadata such as:

```text
entry ID
operation
actor
result
```

where appropriate.

---

## 41. Background Synchronization

If Vault sync runs in a thread or scheduled context, inspect:

```text
startup behavior
database application context
duplicate execution
restart behavior
failure state
credential lifetime
```

Do not assume in-process work is durable.

If reliable recovery after process restart becomes a requirement, stop and run:

```text
/plan-eng-review
```

before changing architecture.

---

## 42. Sync Concurrency

Consider what happens if:

```text
manual sync starts twice
scheduled sync overlaps manual sync
two workers touch the same KDBX file
entry is edited during sync
```

Do not introduce concurrency locks unless needed, but do not ignore possible file corruption or conflicting writes.

If the current architecture cannot safely satisfy a new concurrency requirement, surface that limitation.

---

## 43. Sync Failure

A sync failure must not corrupt local Vault data or the KDBX file.

Distinguish:

```text
file not found
invalid password
invalid KDBX
permission denied
conflict
database failure
unexpected exception
```

Provide sanitized user-facing errors.

Never include the actual KeePass password in the error.

---

## 44. Partial Sync

If synchronization can partially succeed, define how that is represented.

Do not claim:

```text
sync successful
```

when some entries failed.

Where practical, record:

```text
processed
created
updated
skipped
failed
```

without leaking secret content.

---

## 45. Transaction Boundaries

Be careful when database writes and KDBX writes occur together.

They cannot be made fully atomic through a normal SQL transaction.

Consider both failure sequences:

```text
database succeeds
KDBX write fails
```

and:

```text
KDBX write succeeds
database commit fails
```

If the task changes sync persistence, explicitly consider consistency and recovery.

---

## 46. Do Not Over-Refactor Vault

Vault already contains sensitive working behavior.

Do not combine a requested change with:

```text
large route refactor
model renaming
template redesign
encryption rewrite
sync rewrite
group redesign
authorization redesign
```

unless the task requires it.

Prefer the smallest correct change.

---

## 47. UI Changes

Vault UI must not alter security semantics implicitly.

Examples:

```text
adding a share checkbox
adding a reveal button
adding export action
adding editable ownership
```

all have backend security consequences.

Do not implement UI first and assume backend behavior later.

Define server-side semantics before exposing the control.

---

## 48. Reveal UI

A reveal button should not cause the server to embed all plaintext secrets in the initial page.

Prefer on-demand authorized reveal behavior.

Do not hide already-rendered plaintext with CSS and call that secure.

If plaintext is present in DOM, assume the browser/user can access it.

---

## 49. Copy-to-Clipboard

If implementing copy-to-clipboard functionality:

```text
authorize reveal first
return only the required secret
avoid unnecessary persistence
avoid logging
```

Do not preload every credential in JavaScript.

Clipboard behavior is a convenience layer, not an authorization boundary.

---

## 50. Browser Caching

For routes directly returning sensitive plaintext, consider whether response caching should be limited.

Do not rely solely on this as protection, but avoid encouraging browsers/proxies to retain secret responses unnecessarily.

Follow existing project/web conventions and change headers only when justified.

---

## 51. Search

If adding Vault search, determine whether searching requires decrypting secret content.

Prefer searching non-sensitive metadata where practical.

Do not decrypt every password merely to implement broad free-text search unless explicitly required and reviewed.

Consider:

```text
performance
plaintext exposure
memory lifetime
authorization
```

---

## 52. Sorting and Filtering

Filtering by:

```text
group
owner
shared status
title
username
URL
```

may be safer than filtering on encrypted secret content.

Preserve authorization when filtering.

A filter must never expose entries the user could not otherwise access.

---

## 53. Import/Export Test Data

Never use real Vault credentials for development or automated tests.

Use synthetic values such as:

```text
example-user
example-password
example.local
```

Do not commit real KDBX files.

Do not commit key files containing real secret material.

---

## 54. Protected Files

Do not read, modify, expose, or commit sensitive runtime artifacts unless explicitly necessary.

Examples:

```text
.env
instance/
*.db
*.kdbx
*.keyx
private keys
runtime secret exports
temporary Vault plaintext files
```

Use structure/code inspection instead of opening real secret data.

---

## 55. Git Safety

Before modifying Vault files:

```bash
git status --short
```

Vault may contain existing uncommitted work.

Do not:

```text
reset
restore
checkout over
clean
discard
```

existing changes without explicit approval.

For high-risk work consider:

```text
/careful
```

or:

```text
/guard
```

---

## 56. Tests

Vault changes should include targeted tests where practical.

Depending on the task, cover:

```text
tool authorization
entry authorization
owner access
shared access
administrator access
unauthorized direct URL
create
edit
delete
reveal
encryption
sync configuration
KeePass sync
import
group behavior
```

Test denied paths as well as successful paths.

---

## 57. Security Tests

For sensitive changes, explicitly verify:

```text
user without Vault permission denied
Vault user cannot access unauthorized entry
shared-user permissions match intended policy
secret not exposed in initial HTML
secret not written to log
secret not written to audit
CSRF blocks invalid mutation
direct object ID manipulation denied
```

Do not only test the owner/admin happy path.

---

## 58. Encryption Tests

Use synthetic secrets.

Verify:

```text
database does not contain plaintext
decrypt returns original synthetic value
invalid ciphertext fails safely
wrong key fails safely
new fields follow same encryption policy
```

Do not inspect production/runtime secrets.

---

## 59. Sync Tests

Where practical, test Vault sync using a disposable synthetic KeePass database.

Do not point automated tests at the user's real KDBX file.

Test relevant cases such as:

```text
valid file
wrong password
missing file
new entry
existing entry update
duplicate UUID
sync conflict
partial failure
```

Only test scenarios affected by the task.

---

## 60. Import Tests

For import changes, test:

```text
valid import
malformed import
duplicate data
cancelled preview
cleanup
exception cleanup
encrypted persistence
unauthorized import
```

If plaintext temporary state exists, verify cleanup behavior explicitly.

---

## 61. Documentation Updates

After changing Vault behavior, update:

```text
docs/systems/vault.md
```

when actual behavior changes.

Update:

```text
docs/technical-debt/current.md
```

when known Vault debt is:

```text
added
partially resolved
fully resolved
```

Update:

```text
docs/PROJECT_MAP.md
```

only if Vault structure or important file ownership changes.

Create an ADR only for a real architectural decision.

---

## 62. Recommended Workflow for Vault Bugs

For a Vault bug:

```text
/investigate
        ↓
identify root cause
        ↓
portal-vault-change
        ↓
portal-security-change if relevant
        ↓
implementation
        ↓
/review
```

Do not fix symptoms without understanding the authorization/data path.

---

## 63. Recommended Workflow for Vault Database Changes

For schema or persistence changes:

```text
portal-vault-change
        +
portal-database-change
        +
portal-security-change when secret/authorization related
        ↓
implementation
        ↓
/review
```

For high-risk encrypted migrations:

```text
/plan-eng-review
        ↓
/careful
        ↓
portal-vault-change
        ↓
portal-database-change
        ↓
portal-security-change
        ↓
implementation
        ↓
/review
        ↓
/codex review
```

---

## 64. Recommended Workflow for KeePass Changes

For synchronization/import/export changes:

```text
portal-vault-change
        ↓
portal-security-change
        ↓
portal-external-api-change only when external/network behavior is actually involved
        ↓
implementation
        ↓
/review
```

KeePass filesystem interaction alone does not automatically require the external API skill.

Use skills based on actual concerns.

---

## 65. Required Pre-Implementation Summary

Before implementing a non-trivial Vault change, summarize:

```md
## Vault Change

### Objective

What Vault behavior needs to change.

### Current Flow

Which routes, forms, models, templates, and sync/import components currently implement it.

### Authorization

Who can currently perform the action and who should be able to perform it after the change.

### Secret Handling

Which sensitive values are involved and where plaintext may exist.

### Persistence

Models, encrypted fields, relationships, or migrations affected.

### KeePass Impact

Whether import, export, UUID matching, or synchronization behavior changes.

### Technical Debt Interaction

Relevant known Vault debt and whether this change affects it.

### Proposed Change

The smallest implementation that satisfies the requirement.

### Risks

Authorization bypass, secret exposure, data loss, sync corruption, migration failure, or regression risks.

### Validation

Allowed/denied cases, encryption checks, sync/import tests, and manual flows required.
```

Keep the summary proportional to the task.

---

## 66. Completion Checklist

Before declaring a Vault change complete, verify:

```text
[ ] docs/systems/vault.md was reviewed
[ ] Relevant ADRs were reviewed
[ ] Vault technical debt was checked
[ ] Actual Vault implementation was inspected
[ ] Tool authorization remains correct
[ ] Entry/object authorization remains correct
[ ] Owner/shared/admin behavior is defined
[ ] Direct object URL access was considered
[ ] State-changing routes use appropriate methods
[ ] CSRF remains enabled
[ ] Secrets remain encrypted at rest
[ ] Plaintext lifetime is minimized
[ ] Secrets are not unnecessarily rendered into HTML
[ ] Secrets are not logged
[ ] Secrets are not written to audit
[ ] KeePass password is not exposed unnecessarily
[ ] Import temporary data behavior was considered
[ ] Temporary sensitive files are cleaned up if applicable
[ ] UUID stability was considered
[ ] KeePass compatibility was considered
[ ] Database migration exists if schema changed
[ ] Existing encrypted data remains compatible
[ ] Allowed authorization paths were tested
[ ] Denied authorization paths were tested
[ ] Encryption behavior was tested if applicable
[ ] Sync/import behavior was tested if applicable
[ ] Documentation was updated
[ ] Relevant technical debt was updated if resolved
[ ] Final diff was reviewed
```

---

## 67. Core Rule

Never treat a Vault change as merely:

```text
CRUD
+
template
+
database
```

For this project, Vault work means:

```text
tool authorization
+
entry authorization
+
ownership
+
sharing
+
secret encryption
+
minimal plaintext exposure
+
KeePass compatibility
+
safe import/export
+
sync consistency
+
audit
+
negative security testing
```

Preserve confidentiality and authorization before convenience.