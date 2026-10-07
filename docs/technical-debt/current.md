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

Priority:

```text
P0
```

Area:

```text
Vault
Authorization
```

Current behavior:

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

Expected remediation:

```text
Apply the same explicit access model used by Vault detail/reveal routes.
```

Likely files:

```text
app/vault/routes.py
tests/vault/
```

Do not silently fix during unrelated tasks.

---

# 2. Vault Delete Authorization

Priority:

```text
P0
```

Area:

```text
Vault
Authorization
```

Current behavior:

```text
POST /vault/<entry_id>/delete
```

requires authentication but does not currently enforce:

```python
_can_access(entry)
```

or equivalent ownership/admin authorization.

Risk:

Unauthorized deletion of Vault entries.

Expected remediation:

```text
Add explicit entry-level authorization before deletion.
```

Additional review should determine whether:

```text
owner
admin
shared user
```

should each have deletion rights.

Do not infer that shared visibility implies delete permission.

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

Current behavior:

KeePass import preview writes temporary files:

```text
instance/vault_import_<token>.json
```

containing decrypted:

```text
passwords
notes
custom fields
```

Risk:

Plaintext credentials are temporarily persisted on disk.

Exposure may occur through:

```text
filesystem access
backups
endpoint security tools
crash recovery
manual file inspection
stale files
```

Expected remediation options should be evaluated explicitly.

Possible approaches include:

```text
encrypted temporary storage
server-side session-backed state
short-lived database staging with encryption
in-memory workflow when feasible
```

Do not redesign without first considering import size and multi-request workflow requirements.

---

# 5. Abandoned Vault Import Files

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

Current behavior:

Temporary import JSON files are deleted during confirmed import.

No cleanup mechanism is currently documented for abandoned preview workflows.

Risk:

Plaintext temporary import files may remain under:

```text
instance/
```

indefinitely.

Expected remediation:

```text
Add expiration / cleanup behavior for abandoned import state.
```

Could include:

```text
timestamp-based cleanup
startup cleanup
scheduled cleanup
explicit cancel action
```

Any cleanup logic must avoid deleting active imports.

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