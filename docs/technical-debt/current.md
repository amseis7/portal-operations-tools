# Current Technical Debt

## Purpose

This document tracks known technical debt, security concerns, architectural limitations, and implementation inconsistencies.

These items describe **known weaknesses or limitations in the current system**.

They must NOT be interpreted as invariants that agents should preserve.

Agents should:

1. preserve current behavior during unrelated work;
2. avoid silently refactoring these items;
3. flag them when a requested change touches the affected area;
4. prefer explicit, scoped remediation tasks;
5. update this document when a listed item is resolved.

---

# Priority Levels

## P0 — Critical

Immediate security or data-loss risk.

Should be addressed as soon as practical.

## P1 — High

Meaningful security, authorization, reliability, or operational risk.

Should be prioritized before major feature expansion.

## P2 — Medium

Maintainability, consistency, scalability, or operational limitations.

Should be addressed deliberately but do not normally block unrelated work.

## P3 — Low

Quality-of-life, cleanup, or architectural improvement.

Useful but not urgent.

---

# 1. Vault Edit Authorization

Status:

```text
RESOLVED
```

Priority:

```text
P0
```

Area:

```text
Vault
Authorization
```

Historical behavior (resolved — kept for context):

```text
/vault/<entry_id>/edit
```

requires authentication but does not currently enforce:

```python
_can_access(entry)
```

or an equivalent ownership/admin authorization check.

Risk:

An authenticated user who can reach or guess an entry ID may potentially access the edit flow for an entry they do not own.

Resolution:

```text
Added a dedicated _can_edit(entry) helper in app/vault/routes.py,
deliberately separate from _can_access(entry):

    def _can_edit(entry):
        return current_user.is_admin or entry.owner_id == current_user.id

Final criterion (explicit product decision, not inferred from code):
    owner can edit
    admin can edit
    entry.shared == True does NOT grant edit permission

_can_access(entry) (view/reveal permission, which does include
entry.shared) was left untouched. edit() now calls _can_edit(entry) and
aborts with 403 when it returns False, before any form processing.
```

Files changed:

```text
app/vault/routes.py
app/templates/vault/detail.html (Editar button hidden for non-owner/non-admin)
tests/vault/test_edit_authorization.py
```

Evidence:

```text
tests/vault/test_edit_authorization.py covers:
    owner can GET/POST edit
    admin can GET/POST edit
    non-owner, shared=False -> 403 on GET and POST
    non-owner, shared=True  -> 403 on GET and POST (the key regression:
        shared visibility does not imply edit permission)
    authorized POST persists changes
    unauthorized POST does not modify the entry
```

Not changed by this resolution (explicitly out of scope, tracked separately):

```text
Vault Delete Authorization (debt item #2)
proteger_blueprint() for the vault blueprint (debt item #3)
detail()/reveal() authorization (_can_access(), unchanged)
```

---

# 2. Vault Delete Authorization

Status:

```text
RESOLVED
```

Priority:

```text
P0
```

Area:

```text
Vault
Authorization
```

Historical behavior (resolved — kept for context):

```text
POST /vault/<entry_id>/delete
```

required authentication but did not enforce:

```python
_can_access(entry)
```

or equivalent ownership/admin authorization. Any authenticated user with a
valid entry ID could delete any Vault entry.

Resolution:

```text
Added a dedicated _can_delete(entry) helper in app/vault/routes.py,
kept separate from both _can_access(entry) and _can_edit(entry):

    def _can_delete(entry):
        return current_user.is_admin or entry.owner_id == current_user.id

Final criterion (explicit product decision, consistent with the edit
policy already resolved in debt item #1):
    owner can delete
    admin can delete
    entry.shared == True does NOT grant delete permission

delete() now calls _can_delete(entry) immediately after
_get_entry_or_404(), before log_audit(), db.session.delete(),
db.session.commit(), and vault_sync.trigger_async() — so an unauthorized
attempt produces no side effect at all (no audit record, no deletion, no
KeePass resync trigger).

The "Eliminar" button/action was hidden for non-owner/non-admin users in
both app/templates/vault/detail.html and app/templates/vault/index.html.
In detail.html this required hiding the entire confirmation modal (not
just the trigger button), since the modal's <form action="..."> baked
the real delete URL into the page unconditionally — hiding only the
trigger button left that URL present in the page source.
```

Files changed:

```text
app/vault/routes.py
app/templates/vault/detail.html
app/templates/vault/index.html
tests/vault/test_delete_authorization.py
```

Evidence:

```text
tests/vault/test_delete_authorization.py covers:
    owner can delete own entry
    admin can delete any entry
    non-owner, shared=False -> 403, entry remains
    non-owner, shared=True  -> 403, entry remains (the key regression:
        shared visibility does not imply delete permission)
    authorized delete cascades to VaultEntryField (custom fields)
    unauthorized attempt creates no AuditLog(action="delete") for that entry
    "Eliminar" visibility correct in detail.html and index.html
```

Not changed by this resolution (explicitly out of scope, tracked separately):

```text
_can_access() and _can_edit() (unchanged)
edit() (unchanged)
proteger_blueprint() for the vault blueprint (debt item #3)
import/export and sync internals (only verified, not modified)
```

---

# 3. Vault Blueprint Missing Tool-Level Protection

Priority:

```text
P1
```

Area:

```text
Vault
Authorization
```

Current behavior:

CSIRT, VirusTotal, and Umbrella use blueprint-level protection through:

```python
proteger_blueprint(...)
```

Vault currently relies on route-level:

```python
@login_required
```

and does not use the same:

```text
UserTool("vault")
```

server-side protection model.

Risk:

A user who should not have the Vault tool may potentially access Vault routes directly even if the dashboard hides the tool.

Expected remediation:

```text
Apply consistent server-side tool authorization to Vault.
```

Requires careful review of:

```text
shared entries
admin routes
existing users
tool permissions
```

---

# 4. Plaintext Vault Import Preview Files

Status:

```text
RESOLVED
```

Priority:

```text
P0
```

Area:

```text
Vault
Secrets
Filesystem
```

Historical behavior (resolved — kept for context):

KeePass import preview used to write temporary files:

```text
instance/vault_import_<token>.json
```

containing decrypted:

```text
passwords
notes
custom fields
```

Risk (historical):

Plaintext credentials were temporarily persisted on disk, exposed to
filesystem access, backups, endpoint security tools, crash recovery,
manual file inspection, and stale files.

Resolution:

```text
Replaced the on-disk JSON file with app/vault/import_staging.py — an
in-process, in-memory dict keyed by the same import token, protected by
a threading.Lock, with a 30-minute TTL purged lazily on store()/
retrieve() (no background thread, no APScheduler, no new infra).

instance/vault_import_<token>.json is no longer written at any point in
the import flow. Only the token itself is kept in the Flask session
(unchanged). The upload-time .kdbx/.keyx temp-file save-then-delete in
the existing `finally` block was left untouched, as required — that
part was already correct.

This was chosen over an encrypted-file or DB-staging alternative because
it is the option ADR-004 already points to ("prefer... non-persistent
temporary state"), requires no migration, and the app runs as a single
multi-threaded process (Cheroot), so process memory is a valid shared
store for this use case. Trade-off: an in-progress import is lost on
process restart (the admin re-uploads the .kdbx) — acceptable for an
admin-only, infrequent, non-critical-path workflow.
```

Files changed:

```text
app/vault/import_staging.py (new)
app/vault/routes.py (import_kdbx/import_preview/import_confirm)
tests/vault/test_import_staging.py
tests/vault/test_import_flow.py
```

Evidence:

```text
tests/vault/test_import_staging.py covers: store/retrieve/discard,
TTL expiry, lazy purge of other expired tokens on both store() and
retrieve(), isolation between concurrent tokens.

tests/vault/test_import_flow.py covers: full upload -> preview -> confirm
flow against a synthetic .kdbx, preview/confirm with a missing or
nonexistent token, and an explicit assertion that
instance/vault_import_*.json is never created at any point in the flow
(including on an abandoned import).
```

This resolution also resolves debt item #5 ("Abandoned Vault Import
Files") as a direct consequence — see that item.

---

# 5. Abandoned Vault Import Files

Status:

```text
RESOLVED
```

Priority:

```text
P1
```

Area:

```text
Vault
Secrets
Cleanup
```

Historical behavior (resolved — kept for context):

Temporary import JSON files were deleted during confirmed import, but no
cleanup mechanism existed for abandoned preview workflows — plaintext
temporary import files could remain under `instance/` indefinitely.

Resolution:

```text
Resolved as a direct side effect of debt item #4: the on-disk
instance/vault_import_<token>.json file this item was about no longer
exists at all. There is nothing left to abandon on disk.

The in-memory staging in app/vault/import_staging.py does still hold an
abandoned import's data until its 30-minute TTL lazily purges it (on the
next store() or retrieve() call anywhere in the process) — but that is
process memory, not a file, and was never the subject of this debt item.
```

Evidence:

```text
tests/vault/test_import_flow.py::test_abandoned_import_leaves_no_files_on_disk
uploads a .kdbx, never confirms, and asserts no vault_import_*.json or
leftover import_*.kdbx/.keyx files exist afterward.
```

---

# 6. Vault Sync Password Rendered Back to UI

Priority:

```text
P1
```

Area:

```text
Vault
Secrets
UI
```

Current behavior:

The Vault sync configuration route decrypts the stored KeePass password and provides it to the rendered settings page.

Risk:

Existing secret is unnecessarily exposed in plaintext to:

```text
browser DOM
screen capture
browser extensions
developer tools
client-side code
```

Expected remediation:

```text
Do not return the existing password to the UI.
```

Use behavior such as:

```text
blank password field = preserve existing secret
new value = replace stored secret
```

---

# 7. Duplicate / Unused VaultAuditLog Model

Priority:

```text
P2
```

Area:

```text
Vault
Audit
Architecture
```

Current behavior:

Model:

```text
VaultAuditLog
```

exists, while current Vault routes primarily use global:

```text
AuditLog
```

through:

```python
log_audit()
```

Risk:

Conflicting audit concepts increase confusion for maintainers and agents.

Expected remediation:

Decide explicitly whether:

```text
global AuditLog
```

is the canonical audit mechanism.

If so:

```text
migrate/remove unused VaultAuditLog safely
```

Otherwise define clear responsibilities for both.

Do not delete historical tables/models without migration review.

---

# 8. Vault Group Administration Is Broad

Priority:

```text
P1
```

Area:

```text
Vault
Authorization
```

Current behavior:

Authenticated users can create and delete Vault groups.

Groups currently have no ownership model.

Risk:

One user may change shared Vault organization for other users.

Expected remediation requires a product decision:

```text
admin-only groups
shared group management
per-user groups
group-level ownership/permissions
```

Do not choose a model implicitly.

---

# 9. Global Notifications Share Read State

Priority:

```text
P2
```

Area:

```text
Main
Notifications
Data model
```

Current behavior:

Global notifications use:

```text
user_id = NULL
```

with one shared:

```text
is_read
```

field.

When one user marks the global notification as read, the row becomes read for everyone.

Risk:

Users may miss global notifications because another user acknowledged them.

Expected remediation:

Use per-user notification acknowledgment if individual read state is required.

Possible model:

```text
Notification
+
NotificationRead
```

Do not redesign unless product requirements require individual read tracking.

---

# 10. Audit Interface Has No Pagination

Priority:

```text
P2
```

Area:

```text
Main
Audit
Performance
```

Current behavior:

Audit route loads at most:

```text
500
```

records.

Risk:

```text
older records inaccessible from UI
growing query cost
limited investigation usability
```

Expected remediation:

```text
server-side pagination
filters
date ranges
possibly indexed search
```

---

# 11. CSIRT Mass Update Uses GET for State Mutation

Priority:

```text
P1
```

Area:

```text
CSIRT
HTTP semantics
Security
```

Current behavior:

```text
GET /csirt/admin/stream_actualizacion
```

performs persistence-oriented work.

Risk:

GET requests are expected to be safe/idempotent by browsers, proxies, crawlers, and tooling.

Potential issues:

```text
accidental execution
prefetch
replay
CSRF semantics
unexpected proxy behavior
```

Expected remediation:

Move state-changing initiation to:

```text
POST
```

while preserving streaming/progress behavior.

---

# 12. CSIRT Alert External Identity Not DB-Enforced

Priority:

```text
P2
```

Area:

```text
CSIRT
Database integrity
```

Current behavior:

Code treats:

```text
Alerta.nombre_alerta
```

as effectively unique.

Duplicate prevention is application-level.

Database schema does not currently enforce a unique constraint.

Risk:

Concurrent or alternative insert paths may create duplicate alerts.

Expected remediation:

Before adding a unique constraint:

```text
check existing duplicates
confirm upstream identity semantics
create migration
```

---

# 13. CSIRT Live Discovery Uses Incremental Commits

Priority:

```text
P2
```

Area:

```text
CSIRT
Transactions
Reliability
```

Current behavior:

Live discovery may commit alert records individually and IoCs separately.

Risk:

Partial persistence after failures.

Example:

```text
alert created
IoC retrieval fails
```

leaving an incomplete alert requiring later repair.

Current recovery logic partially accounts for this.

Expected remediation:

Only consider transaction redesign with explicit workflow analysis.

Atomic processing may not always be desirable because external requests can fail independently.

---

# 14. CSIRT Historical Import Invalid-Date Fallback

Priority:

```text
P2
```

Area:

```text
CSIRT
Data quality
```

Current behavior:

Invalid historical dates fall back to:

```python
datetime.now()
```

Risk:

Historical records may silently receive incorrect dates.

Expected remediation options:

```text
reject row
flag row
leave null if schema allows
require explicit correction
```

Avoid silently changing import semantics without user-facing feedback.

---

# 15. VirusTotal Background Jobs Are Not Durable

Priority:

```text
P1
```

Area:

```text
VirusTotal
Background processing
Reliability
```

Current behavior:

Analysis uses:

```python
threading.Thread
```

inside the application process.

Risk:

Jobs may be interrupted by:

```text
application restart
process crash
deployment
worker recycle
```

No persistent job queue exists.

Expected remediation if reliability requirements increase:

```text
persisted job model
worker queue
restart recovery
```

Possible technologies should be evaluated only when actual requirements justify additional infrastructure.

---

# 16. VirusTotal Job State Is Inferred

Priority:

```text
P2
```

Area:

```text
VirusTotal
Background processing
Observability
```

Current behavior:

Case progress is inferred from `VtIoc` fields.

There is no dedicated job object representing:

```text
queued
running
failed
completed
cancelled
```

Risk:

Difficult to distinguish:

```text
worker terminated
provider quota stopped batch
completed with partial failures
actively processing
```

Expected remediation:

Consider explicit job state if operational visibility becomes important.

---

# 17. VirusTotal CSIRT Case Link Uses Name Equality

Priority:

```text
P2
```

Area:

```text
VirusTotal
CSIRT
Data relationships
```

Current behavior:

CSIRT-derived cases are found through case name:

```text
CSIRT: <ticket>
```

Risk:

Case name acts as implicit relationship key.

Renaming or duplicate names may break association.

Expected remediation:

Consider explicit source metadata such as:

```text
source_type
source_id
```

or a direct relation if requirements justify it.

---

# 18. VirusTotal Simple IP Validation

Priority:

```text
P3
```

Area:

```text
VirusTotal
Validation
```

Current behavior:

IPv4 validation checks textual structure but not octet range.

Example potentially accepted:

```text
999.999.999.999
```

Expected remediation:

Use a standard IP parser such as Python's:

```python
ipaddress
```

when validation consistency is intentionally addressed.

---

# 19. VirusTotal Error Data Stored in IoC Metadata

Priority:

```text
P2
```

Area:

```text
VirusTotal
Error handling
Data exposure
```

Current behavior:

Some background exceptions are written into:

```text
vt_motores_json
```

Risk:

Internal exception messages may become visible in UI/export or persist longer than intended.

Expected remediation:

Store:

```text
safe user-facing error category
```

separately from:

```text
internal diagnostic logging
```

---

# 20. VirusTotal Audit Coverage Is Inconsistent

Priority:

```text
P2
```

Area:

```text
VirusTotal
Audit
```

Current behavior:

Core actions are audited.

Export-template administration does not appear to have equivalent audit coverage in all paths.

Risk:

Administrative configuration changes may lack traceability.

Expected remediation:

Define an explicit audit policy for:

```text
template create
template edit
template delete
```

---

# 21. Umbrella Background Jobs Are Not Durable

Priority:

```text
P1
```

Area:

```text
Umbrella
Background processing
Reliability
```

Current behavior:

Jobs run using daemon:

```python
threading.Thread
```

Risk:

Application restart or process failure can interrupt external mutation jobs.

Persisted job may remain:

```text
running
```

indefinitely.

This is particularly important because Umbrella performs external write operations.

Expected remediation:

Before introducing a queue, define:

```text
job idempotency
external mutation retry rules
recovery semantics
stale-job handling
```

---

# 22. Umbrella HTTP 207 Handling

Priority:

```text
P1
```

Area:

```text
Umbrella
External API
Correctness
```

Current behavior:

HTTP:

```text
207
```

is treated as:

```text
labeled
```

for the full PATCH chunk.

Risk:

Partial external success may be recorded as complete success for all applications.

Expected remediation:

Parse provider response and persist individual application outcome if the Cisco API provides sufficient detail.

Before changing, verify actual API response semantics.

---

# 23. Umbrella Plaintext Credentials Passed to Worker Thread

Priority:

```text
P2
```

Area:

```text
Umbrella
Credentials
Background processing
```

Current behavior:

Encrypted credentials are decrypted in the request and passed as plaintext function arguments to the background thread.

They are not persisted.

Risk is limited primarily to process memory, debugging, exception handling, and accidental logging.

Expected remediation:

Potentially resolve credentials inside the worker using client ID/reference rather than passing plaintext.

Do not increase credential persistence to solve this issue.

---

# 24. Umbrella Provider Error Text Persistence

Priority:

```text
P2
```

Area:

```text
Umbrella
Error handling
Data exposure
```

Current implementation may persist provider/internal text into:

```text
UmbrellaJob.error_message
UmbrellaAppResultado.error_message
```

Risk:

Provider responses may expose internal details to users or remain persisted.

Expected remediation:

Separate:

```text
safe operational message
internal diagnostic detail
```

---

# 25. Umbrella Catalog Reloaded Per Job

Priority:

```text
P3
```

Area:

```text
Umbrella
Performance
External API
```

Current behavior:

Each job constructs a new client and loads the full App Discovery catalog.

Risk:

```text
additional API calls
longer startup for each job
higher provider load
```

Expected remediation only if performance/API consumption becomes material.

Any cache would need:

```text
expiration
process-safety
catalog freshness
invalidations
```

---

# 26. Umbrella Tool Architecture Has Only One Real Type

Priority:

```text
P3
```

Area:

```text
Umbrella
Architecture
```

Current design supports multiple:

```text
TIPOS_HERRAMIENTA
```

but only:

```text
app_discovery
```

currently exists.

Risk:

Premature generalization if future development builds abstractions for hypothetical tools.

Guidance:

```text
Do not expand tool-framework complexity until a second concrete use case exists.
```

---

# 27. Password Policy Inconsistency in Admin User Edit

Priority:

```text
P1
```

Area:

```text
Auth
Password policy
```

Current behavior:

Normal password workflows call:

```python
validar_complejidad_password()
```

but administrator user editing can set a replacement password using:

```python
set_password()
```

without equivalent complexity validation.

Risk:

Administrators can assign passwords that violate normal application password policy.

Expected remediation:

Apply consistent password policy to all password-setting paths.

---

# 28. Profile Transaction Is Split

Priority:

```text
P2
```

Area:

```text
Auth
Transactions
```

Current behavior:

Profile basic fields may be committed before optional password validation completes.

Risk:

User may receive a password-change error while other submitted profile fields were already persisted.

Expected remediation:

Review whether profile update should be atomic.

---

# 29. Shared Utility Coupling

Priority:

```text
P3
```

Area:

```text
Architecture
Maintainability
```

File:

```text
app/utils.py
```

contains functionality used by multiple subsystems, including:

```text
authorization
report generation
```

Risk:

Unrelated functionality may gradually accumulate in a general utility module.

Guidance:

Do not refactor merely for aesthetics.

If the file materially grows or causes cross-system coupling, split by clear responsibilities.

---

# 30. Documentation Drift

Priority:

```text
P1
```

Area:

```text
AI context
Documentation
```

Current known example:

Historical:

```text
CLAUDE.md
```

did not reflect all currently registered blueprints.

Risk:

Agents may make decisions using stale documentation.

Current mitigation:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/*
documentation status table
```

Expected ongoing rule:

Any material implementation change must update relevant subsystem documentation.

---

# 31. Test Coverage

Priority:

```text
P1
```

Area:

```text
Project-wide
Quality
Regression safety
```

Current project documentation indicates the application does not yet have a comprehensive automated regression suite.

Risk is especially high around:

```text
authentication
authorization
Vault
migrations
CSIRT parsing
VirusTotal caching
Umbrella external mutation
```

Before allowing agents to make increasingly autonomous changes, establish tests for critical invariants.

Recommended first coverage:

```text
auth permissions
Vault authorization
tool authorization
CSIRT simulation/no-write behavior
VirusTotal cache behavior
Umbrella dry-run behavior
```

---

# 32. In-Process Background Work Is Repeated Across Modules

Priority:

```text
P2
```

Area:

```text
Architecture
Background processing
```

Current modules using process-local threads include:

```text
VirusTotal
Umbrella
Vault sync
```

Risk:

Each subsystem independently inherits limitations around:

```text
restart survival
visibility
recovery
worker concurrency
```

Guidance:

Do not introduce a global worker system solely for architectural purity.

If reliability requirements justify it, evaluate background processing as a cross-project architectural decision rather than replacing one module at a time.

---

# 33. Technical Debt Handling Rule for Agents

When an agent encounters an item listed in this document:

### If unrelated to the requested task

Do not modify it.

Report only if materially relevant.

### If directly touched by the task

Explicitly mention the debt and assess whether the requested change would:

```text
preserve it
worsen it
partially resolve it
fully resolve it
```

### If remediation is required

Prefer:

```text
small
testable
isolated
reviewable
```

changes.

Avoid combining several unrelated debt items into one refactor.

---

# 34. Resolution Procedure

When a debt item is fixed:

1. Add or update automated tests.
2. Update affected subsystem documentation.
3. Update architectural decisions if applicable.
4. Remove or mark the debt item as resolved.
5. Include migration/operational instructions when required.

Do not silently delete debt records without evidence that the issue is resolved.

---

# 35. Current Remediation Priority

Recommended broad priority based on current known risk:

```text
FIRST

P0 Vault authorization
P0 Vault plaintext temporary credentials

THEN

P1 Vault tool authorization
P1 Vault sync password exposure
P1 password-policy inconsistency
P1 durable/recoverable external mutation concerns
P1 Umbrella HTTP 207 correctness
P1 critical automated tests

THEN

P2 transactional consistency
P2 job observability
P2 notification model
P2 audit consistency
P2 provider error handling

LAST

P3 architectural cleanup
P3 validation refinements
P3 performance optimizations
```

Priorities should be revisited when production requirements, deployment architecture, or threat model change.

---

# 36. Knowledge Base Has No Full-Text Search

Priority:

```text
P3
```

Area:

```text
Knowledge Base
Search
```

Current behavior:

Search uses an escaped `LIKE` match over title/problem/solution. No SQLite
FTS5 or external search index exists.

Risk:

Relevance degrades as the number of articles grows; no ranking, only
substring matching.

Expected remediation only if volume/usability actually requires it — this
was deliberately deferred in the MVP, not an oversight.

---

# 37. Knowledge Base Client/Platform Are Free Text

Priority:

```text
P3
```

Area:

```text
Knowledge Base
Data quality
```

Current behavior:

`client` and `platform` are plain strings with UI autocomplete from
existing distinct values, not managed master tables. Inconsistent casing or
near-duplicate values (e.g. "Acme" vs "ACME Corp") are possible and will
fragment filter results.

Expected remediation only if fragmentation becomes a real problem in
practice — deliberately deferred, per the confirmed MVP scope.

---

# 38. Vault Custom Field Protection Loses Secrets on Key Rename or Duplicate Keys

Status:

```text
RESOLVED
```

Priority:

```text
P0
```

Area:

```text
Vault
Custom fields
Secrets
```

File:

```text
app/vault/routes.py (_diff_custom_fields, _apply_custom_fields)
```

Historical behavior (resolved — kept for context):

`_save_custom_fields` preserved a protected custom field's existing
ciphertext when the submitted value was blank by matching the submitted
`field_key` against the prior protected fields **by string equality**,
not by any stable per-field identity (no field id round-tripped through
the form). The prior protected rows for the entry were bulk-deleted
first, then re-matched against incoming form rows by key.

Risk (historical):

Possible **silent loss or swap of a secret**, with no error shown to the
user and no way to recover the original ciphertext after the delete
already ran:

```text
- Renaming a protected field's key while leaving its value blank: the
  renamed key has no match among the (already-deleted) prior protected
  rows, so the "blank = keep unchanged" path does not fire; the field is
  instead (re)created from an empty submitted value, permanently
  replacing the real secret with an encrypted empty string.

- Multiple protected fields sharing the same key (explicitly supported
  by the model and by tests/vault/test_custom_field_protection.py's
  duplicate-key coverage): deleting or reordering one of several
  same-keyed protected rows while leaving another blank can hand the
  surviving field the wrong (now-deleted) ciphertext, losing its own
  real secret and silently receiving an unrelated one instead.
```

Resolution:

```text
Replaced _save_custom_fields' delete-all/recreate + field_key string
matching with two pure functions:

    _diff_custom_fields(entry, cf_json_str)
    _apply_custom_fields(entry, updates, new_items, delete_ids)

The edit page now round-trips each VaultEntryField.id through a hidden
custom_fields_json payload. Submitted items are classified strictly by
id, never by field_key equality: update (id matches a current row of
THIS entry), new (no id, non-blank key), or delete (id present on the
entry but not mentioned, or mentioned with a blanked-out key). Any
structurally invalid payload, duplicate id in one payload, or id that
does not belong to the entry being edited raises CustomFieldConflict,
which the route turns into a 409 with no partial persistence — renaming
or reordering fields can no longer silently lose or swap a sibling's
ciphertext.

A second /review pass after this fix found two further gaps in the new
validation itself, confirmed by direct code inspection and fixed in the
same follow-up, before this item was marked resolved:

  1. An explicit JSON null for key or value was stringified to the
     literal "None" instead of being treated as blank (raw_key/raw_value
     are now mapped to "" when None, matching the existing "never
     coerce" strictness already applied to id).

  2. A whitespace-only submitted value (e.g. a stray space typed into
     the masked protected-field input, invisible to the user) was not
     stripped before the blank-vs-replace decision in
     _apply_custom_fields, so it bypassed the ciphertext-preserve branch
     and silently replaced the real secret with encrypt(" ") — the same
     class of silent secret loss this debt item exists to eliminate,
     reintroduced via an edge case the initial id-based fix missed. The
     preserve-vs-replace check now uses value.strip() for that decision
     only; the stored value itself is never stripped, so a deliberate
     non-blank replacement still keeps any real leading/trailing
     whitespace.
```

Relationship to prior work:

```text
This is the same code path exercised by
tests/vault/test_custom_field_protection.py (built earlier this session
to protect blank-submitted custom fields from being overwritten). That
earlier work covered the same-key/no-rename/no-deletion path correctly;
it did not cover key rename or duplicate-key deletion/reorder, which is
exactly where this item's original gap was found (by /review, during
unrelated Knowledge Base attachments work).
```

Files changed:

```text
app/vault/routes.py
app/templates/vault/edit.html
tests/vault/test_custom_field_identity.py
tests/vault/test_custom_field_protection.py
docs/superpowers/plans/2026-10-09-vault-custom-field-identity-fix.md
docs/systems/vault.md
```

Evidence:

```text
tests/vault/test_custom_field_identity.py and
tests/vault/test_custom_field_protection.py cover: rename with blank
value preserves id and ciphertext; duplicate-key deletion/reorder
preserves the correct survivor's own secret (both directions); foreign/
unknown/duplicate/non-int id fails closed with 409 and persists nothing,
including entry-attribute changes in the same request; empty submission
deletes all fields; null key is treated as blank (deletes or is inert,
never becomes a field literally named "None"); null value is treated as
blank (preserves ciphertext on a protected field); whitespace-only value
preserves a protected field's ciphertext (at both the pure-function and
full HTTP-request level) while still wiping an unprotected field as
before; and an end-to-end combined rename+duplicate+delete+add scenario
in one submission. Manual smoke test confirmed: renaming a protected
field in the real edit UI with a blank value keeps the same field id,
the same ciphertext, and the Edit form continues to render value="" with
the "Dejar vacío para no cambiar" placeholder for protected fields — no
plaintext secret is introduced into the DOM at any point. Full Vault
suite: 78/78 passing. Full project suite: 187/187 passing.
```

Not changed by this resolution (explicitly out of scope, tracked
separately):

```text
On-demand reveal of a protected custom field's value in the detail view
does not exist (there is no route, no JS, and no reveal control for
custom fields — the shield-lock badge next to a protected field in
detail.html is a static label, unrelated to the entry-level password
reveal button). This was never part of what this debt item covered and
is not a regression caused by this fix — investigated and confirmed
separately, not implemented here.

detail() unconditionally decrypting every protected custom field's
ciphertext server-side even though the template never renders the
plaintext — tracked separately as debt item #46 (RESOLVED).
```

---

# 39. Knowledge Base Attachment Delete Can Silently Orphan a File on Windows

Priority:

```text
P2
```

Area:

```text
Knowledge Base
Attachments
Filesystem
```

File:

```text
app/knowledge_base/attachment_storage.py (safe_unlink)
```

Current behavior:

`safe_unlink` catches `FileNotFoundError` (expected — the file is already
gone) but also catches any other `OSError` as a mere `logger.warning`,
swallowing it. Every caller (`attachment_delete`, `eliminar()`,
`purge_expired_drafts`) proceeds to delete the DB row regardless of
whether the physical unlink actually succeeded.

Risk:

On Windows, a file can be transiently locked (open for a concurrent
`send_file` stream, antivirus scan, search indexing) when a delete runs.
`os.remove()` then raises `PermissionError`, which is logged but not
surfaced; the caller deletes the DB row anyway. The physical file is
permanently orphaned on disk with no DB row left to ever reconcile it
against — no code path scans disk for files without a corresponding row.

Found by: `/review` during Checkpoint C of the Knowledge Base attachments
work (substituting for an unavailable `/codex review`), out of scope for
that checkpoint — not fixed there.

Expected remediation:

```text
Not decided yet. Options to evaluate:
  - have safe_unlink return success/failure and let callers decide
    whether to still delete the DB row on failure (but leaving the row
    in place means a "clean" row whose file is temporarily locked is
    also temporarily unservable until retried — needs a retry/requeue
    story, not just a boolean);
  - a periodic disk-vs-DB reconciliation job (new infrastructure, likely
    overkill for a narrow Windows-locking edge case);
  - accept the current behavior and document the operational risk.
```

---

# 40. Knowledge Base Attachment Upload Can Orphan a File If the DB Commit Fails

Priority:

```text
P3
```

Area:

```text
Knowledge Base
Attachments
Filesystem
```

File:

```text
app/knowledge_base/attachment_routes.py (_handle_attachment_upload)
```

Current behavior:

The uploaded file is written to disk and scanned before
`db.session.commit()` persists the `KnowledgeAttachment` row.

Risk:

If that commit fails (DB lock/timeout), the row is never persisted, but
the file already written under its UUID name on disk has no DB row
referencing it. `purge_expired_drafts` can never find it, since it only
ever queries existing rows — the orphan is permanent.

Found by: `/review` during Checkpoint C (substitute for `/codex review`),
out of scope for that checkpoint.

Expected remediation:

```text
Low severity — an orphaned file with no DB row is not servable and not
a security concern, only wasted disk space, in the same category as the
already-documented "no global disk-usage cap" limitation (plan Risks
section). Revisit only if disk usage actually becomes a problem; a full
fix would need write-ahead/two-phase handling (e.g. commit the row
first in a "pending" state, write the file after, instead of the
current order) which is a larger change than this narrow risk justifies
today.
```

---

# 41. Knowledge Base Attachment Quota Check Has a TOCTOU Race Under Concurrent Uploads

Priority:

```text
P2
```

Area:

```text
Knowledge Base
Attachments
Concurrency
```

File:

```text
app/knowledge_base/attachment_routes.py (_handle_attachment_upload)
```

Current behavior:

The total-size quota check reads the current sum of `size_bytes` via a
separate `SELECT` before the new row is inserted, with no locking between
the read and the eventual insert.

Risk:

Two near-simultaneous uploads to the same `article_id`/`draft_token`
(e.g. a multi-file picker) can each read the sum before the other's row
is committed, both pass the `total + len(data) > KB_ATTACHMENT_MAX_TOTAL_BYTES`
check, and both commit — the total can exceed the configured limit by up
to one extra file's size.

Found by: `/review` during Checkpoint C (substitute for `/codex review`),
out of scope for that checkpoint.

Expected remediation:

```text
This is a soft resource limit, not a security boundary, and the
overage is bounded (at most one extra file, i.e. at most
KB_ATTACHMENT_MAX_SIZE_BYTES over the configured total). A full fix
would need an application-level lock or a DB-level serializable
check-and-insert per article_id/draft_token scope. Revisit only if the
bounded overage is actually a problem in practice — not building
locking infrastructure for a narrow race on a soft limit today.
```

---

# 42. Knowledge Base New-Tag Creation Has a Race on Concurrent First Use

Priority:

```text
P3
```

Area:

```text
Knowledge Base
Database integrity
Concurrency
```

File:

```text
app/knowledge_base/logic.py (sync_tags)
```

Current behavior:

`sync_tags()`'s get-or-create for a tag name queries for an existing
`KnowledgeTag` by name and, if not found, adds a new one — with no
locking between the check and the insert. `KnowledgeTag.name` is unique.

Risk:

Two requests (`crear()`/`editar()`) submitted near-simultaneously with
the same brand-new tag name can both see no existing row, both
add+flush a new `KnowledgeTag`, and the second commit raises an
unhandled `IntegrityError` on the unique constraint — a 500 for that
request. Pre-existing code from the original Knowledge Base feature, not
touched by the attachments work.

Found by: `/review` during Checkpoint D of the Knowledge Base attachments
work, out of scope for that plan — not fixed there.

Expected remediation:

```text
Catch IntegrityError around the insert and retry the lookup (the losing
request re-queries and finds the row the winner just committed), or use
an upsert-style INSERT ... ON CONFLICT if the project's SQLite/SQLAlchemy
version supports it cleanly. Low priority: tag creation is infrequent
and the failure window is narrow (same never-before-used tag name,
within the same request-processing instant).
```

---

# 43. Vault Edit/Delete Authorization Duplicated Across Templates With No Single Source of Truth

Priority:

```text
P2
```

Area:

```text
Vault
Authorization
Templates
Maintainability
```

Files:

```text
app/templates/vault/detail.html
app/templates/vault/index.html
```

Current behavior:

`_can_edit()`/`_can_delete()` in `app/vault/routes.py` both compute
`current_user.is_admin or entry.owner_id == current_user.id`. Neither
`detail()` nor `index()` passes a computed `can_edit`/`can_delete` value
to the template (unlike Knowledge Base's `detalle()`, which does); the
templates instead re-hardcode that exact same expression inline, 5
separate times across the two files.

Risk:

The authorization rule now has 7 independent copies (2 Python helpers +
5 template copies) with no single source of truth. A future policy
change (e.g. adding a shared-editor tier) could update the two Python
helpers while missing one of the 5 template copies, silently re-exposing
the Editar/Eliminar button to an unauthorized user — the same class of
bug that debt items #1 and #2 (Vault Edit/Delete Authorization) in this
document already had to fix once.

Found by: `/review` during Checkpoint D of the Knowledge Base attachments
work, out of scope for that plan — not fixed there. Pre-existing from
this session's earlier Vault Edit/Delete Authorization hardening tasks
(debt items #1/#2), not introduced by the attachments work.

Expected remediation:

```text
Have detail()/index() compute can_edit/can_delete server-side (mirroring
Knowledge Base's detalle()) and pass them to the templates, replacing
all 5 inline hardcoded expressions with the passed-in values. A
same-session, low-risk refactor once picked up — but do not bundle it
into unrelated work; template visibility is UX only, the actual
authorization enforcement in the routes themselves is unaffected either
way (per portal-security-change: server-side checks are authoritative,
template hiding is not a security control).
```

---

# 44. Knowledge Base Attachments Have No Real Malware Scanner Wired Up

Priority:

```text
P2
```

Area:

```text
Knowledge Base
Attachments
Malware scanning
```

File:

```text
app/knowledge_base/scanning.py
```

Current behavior:

In any environment that has not explicitly opted in to the local-dev
escape hatch below, `get_scanner()` only ever returns `NullScanner`,
which never returns `clean` — every uploaded attachment permanently
stays `not_scanned`. Since `scan_status == "clean"` is the only state
`/view`/`/download` (and inline Markdown rendering) will ever serve,
**every attachment uploaded in this version is permanently unservable**
in that default/production configuration: visible in the attachment
list with a "Sin scanner" badge, but never viewable or downloadable.

This is the **confirmed, deliberate MVP policy** (explicit product
decision during this feature's design) for production, not an oversight
or a bug — documented here per the plan's own Task 13 instruction to
record it as a known limitation.

**Local-development-only escape hatch** (added during a later session,
not a resolution of this item): `app/knowledge_base/scanning.py` now
also registers `DevAllowScanner`, which marks every file `clean`
*without actually scanning it*. It is never the default and cannot be
reached accidentally — `get_scanner()` only returns it when **both**
`KB_SCANNER=dev_allow` and `KB_ALLOW_INSECURE_DEV_SCANNER=true` are
explicitly set (checked by `is True`, not plain truthiness), re-checked
on every call (not just at startup), and `validate_scanner_config()`
raises `RuntimeError` at `create_app()` time for any `KB_SCANNER` value
it does not recognize — no silent fallback to `NullScanner` for a typo
or an unimplemented engine name. Every `dev_allow` upload's audit entry
records `detail="dev-allow: file was NOT malware-scanned"`, so a
rubber-stamped upload remains distinguishable from a real scan in the
audit trail. See `docs/systems/knowledge_base.md` §8.3 for the full
mechanism. This does **not** reduce production risk at all — it exists
solely so a developer without a local AV engine can see attachments
render/download while working on unrelated Knowledge Base UI, and it
requires deliberate, explicit configuration to activate anywhere.

Risk:

In production (or any environment that has not explicitly opted into
`dev_allow`), the feature remains end-to-end untestable-by-a-human
beyond upload/validation without a real scanner integrated — no
attachment can actually be retrieved by any user until this item is
resolved with a real engine. The risk this item tracks is unchanged by
the dev-only escape hatch above.

Expected remediation:

```text
Integrate a real Scanner implementation (ClamAV via a clamd socket
client, Windows Defender, Trellix, etc.) behind the existing Scanner
ABC / get_scanner() factory — app/knowledge_base/scanning.py's interface
was deliberately designed so this plugs in without touching any caller
(attachment_routes.py only ever calls get_scanner().scan_file(path)).
Each real engine would likely need its own narrow dependency, evaluated
on its own merits when picked up — not decided here.

When a real engine is integrated, attachments already stuck at
`not_scanned` (from before the engine existed) are not automatically
rescanned — `scan_status` is only ever written once, at upload time.
Rescanning existing rows needs its own explicit remediation task
(investigated but deliberately not implemented alongside `dev_allow`):
a one-off, admin-triggered pass over `not_scanned`/`scan_error` rows,
not a new recurring APScheduler job.
```

---

# 45. Knowledge Base Attachment Scanning Is Synchronous Only

Priority:

```text
P3
```

Area:

```text
Knowledge Base
Attachments
Malware scanning
Background processing
```

File:

```text
app/knowledge_base/attachment_routes.py (_handle_attachment_upload)
```

Current behavior:

`get_scanner().scan_file(path)` is called synchronously, inline, during
the upload request itself — there is no async/out-of-band scanning path,
no job queue, no "pending → scan later → flip status" background
mechanism.

Risk:

A real scanner that takes meaningfully longer than an HTTP request
should (e.g. a full AV engine scan of a large file) would block the
upload response for that entire duration. Not a problem for the current
`NullScanner` (instant), but would become one the moment debt item #44
is resolved with a slow real engine.

Expected remediation:

```text
Deliberately out of scope for this version — explicitly deferred,
not an oversight. If a future real scanner integration proves too slow
for a synchronous request/response cycle, revisit: leave new rows
scan_status="pending", scan out-of-band (a background thread/job, same
instance-level constraints as the rest of this project's background
work — see debt item #32), and flip scan_status (running the same
immediate-unlink-on-infected step) from whatever mechanism calls
scan_file(). The Scanner interface (app/knowledge_base/scanning.py)
does not need to change either way — only who calls scan_file() and
when.
```

---

# 46. Vault Detail View Decrypts Every Protected Custom Field Unconditionally

Status:

```text
RESOLVED
```

Priority:

```text
P2
```

Area:

```text
Vault
Custom fields
Secrets
```

File:

```text
app/vault/routes.py (detail())
```

Historical behavior (resolved — kept for context):

```python
custom_fields = [
    {"key": f.field_key, "value": decrypt(f.field_value_enc), "protected": f.is_protected}
    for f in entry.custom_fields
]
return render_template("vault/detail.html", entry=entry, notes=notes, custom_fields=custom_fields, now=now)
```

`detail()` called `decrypt()` on every `VaultEntryField` belonging to the
entry, including protected ones, on every single page view — regardless
of whether the viewer ever asked to see a protected value.
`detail.html` (section 15's custom-fields table) only ever renders
`••••••••` for a row where `field.protected` is true; it never outputs
`field.value` in that branch. So:

```text
- there was NO DOM leak: Jinja only emits what the template references,
  and the template never referenced the decrypted value for a protected
  row;
- but the plaintext existed unnecessarily in server-side memory/request
  context (the `custom_fields` list and the `field.value` Jinja
  variable) for every protected field on every view of the entry,
  whether or not anyone asked for it.
```

Risk (historical):

Low (no leak path existed), but the decrypted plaintext's lifetime and
surface area (process memory, any future template change, any future
logging/exception handler that captures local variables or the render
context) was wider than it needed to be for data nobody requested.

Found by: self-review during the investigation and resolution of debt
item #38 (Vault custom-field stable-id fix) — unrelated to that fix's
actual change, not introduced by it, and explicitly out of scope for it.

Resolution:

```text
detail() no longer decrypts a custom field when is_protected is True —
it substitutes an empty string for `value` instead, mirroring the
pattern _build_existing_cf() (used by edit.html) already established:

    "value": "" if f.is_protected else decrypt(f.field_value_enc),

No template change was needed: detail.html already ignored `field.value`
whenever `field.protected` is true, so eliminating the decrypt call
changes nothing observable for either protected or unprotected fields.
Unprotected fields are decrypted and rendered exactly as before.

Verified with tests/vault/test_detail_protected_fields.py: decrypt() is
not called at all for an entry with only a protected field; it is called
exactly once, with only the unprotected field's ciphertext, for a mixed
protected/unprotected entry; plaintext never appears in the detail
response body; duplicate field_key entries (one protected, one not)
render correctly without identity confusion; and detail()'s existing
authorization behavior (_can_access()) is unchanged for both the
non-owner/non-shared 403 case and the shared-entry 200 case.

Vault suite: 88/88 passing. Full project suite: 228/228 passing.
```

Not part of this resolution (tracked separately, not a pending part of
this item):

```text
On-demand reveal of a protected custom field's value in the detail view
still does not exist (no route, no JS, no reveal control — the
shield-lock badge next to a protected field in detail.html remains a
static label). This was investigated as part of this task and
deliberately deferred: it is a separate feature with its own
authorization/CSRF/IDOR surface, not a requirement for closing the
unnecessary-decrypt exposure this item tracked. A design sketch for a
future POST /vault/<entry_id>/field/<field_id>/reveal endpoint
(entry_id+field_id scoped, _can_access()-gated, CSRF-protected, no
logging of the plaintext) exists in the investigation record for
whoever picks that up; it is not scheduled.
```

---

# 47. Knowledge Base Inline Attachment Orphaning Has No Cleanup

Priority:

```text
P3
```

Area:

```text
Knowledge Base
Attachments
Storage
```

File:

```text
app/knowledge_base/attachment_routes.py
app/models/knowledge.py (KnowledgeAttachment.kind, visible_attachments())
```

Current behavior:

```text
A KnowledgeAttachment with kind="inline" (pasted into problem_md/
solution_md via the Markdown editor) is deliberately excluded from the
"Adjuntos" UI (KnowledgeArticle.visible_attachments only returns
kind="attachment" rows) — this is the confirmed, intentional design,
not a bug.

Consequence: if the user removes the ![captura](...) reference from the
Markdown text (editing the textarea directly, not via any delete
action), the underlying row and its physical file remain fully attached
to the article. The row:
    - is not deleted;
    - does not reappear in "Adjuntos" (kind is unchanged);
    - still counts toward KB_ATTACHMENT_MAX_TOTAL_BYTES for that
      article (the quota query sums all kinds, not just "attachment");
    - has no delete button anywhere in the UI, since attachment_delete()
      is only ever wired to the "Adjuntos" list, which never renders an
      inline row.
```

Risk:

```text
Not a security issue — bounded by the existing per-article quota, same
category as other already-accepted storage-accumulation limitations in
this document (e.g. #39-#41). The only consequence is wasted quota/disk
for images a user pasted and later un-referenced from the text, with no
way to reclaim that space short of deleting the entire article.
```

Expected remediation:

```text
Not decided — do not implement speculatively. Options to evaluate when
this is actually picked up:
    - on-save reconciliation: when an article is saved, re-scan its
      problem_md/solution_md for /kb/attachments/<id>/view references
      and flag/delete any kind="inline" row for this article no longer
      referenced. Must run only at save time, never on every read/view
      (re-parsing Markdown on every page load was already rejected as a
      design for the kind feature itself);
    - an explicit "remove inline image" UI affordance, independent of
      the Adjuntos list;
    - accept and document as a permanent limitation.

Security must not be traded for automatic cleanup — in particular, do
not reintroduce runtime inference of "is this attachment inline" from
Markdown content as a replacement for the persisted `kind` column; that
was evaluated and explicitly rejected (docs/systems/knowledge_base.md
§8.1's "Attachment kind" subsection) when `kind` was designed.
```