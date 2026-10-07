# Vault System

## Purpose

This document describes the current implementation of the Vault subsystem.

It covers:

- credential storage
- encryption/decryption
- entry ownership and sharing
- groups
- custom fields
- password reveal
- KeePass import
- KeePass export/synchronization
- sync configuration
- auditing
- current authorization behavior
- sensitive temporary data

It describes the **current implementation**, not a future security design.

Vault is a high-risk subsystem because it handles credentials and decrypted secret material.

Primary files:

```text
app/vault/__init__.py
app/vault/routes.py
app/vault/models.py
app/vault/forms.py
app/vault/crypto.py
app/vault/sync.py
app/models/audit.py
app/__init__.py
```

Primary templates:

```text
app/templates/vault/index.html
app/templates/vault/detail.html
app/templates/vault/new.html
app/templates/vault/edit.html
app/templates/vault/import.html
app/templates/vault/import_preview.html
app/templates/vault/sync_settings.html
```

Relevant migrations:

```text
migrations/versions/df3aeaa9dd65_add_vault_tables.py
migrations/versions/7c7c366d70ca_vault_audit_nullable_entry_id_add_entry_.py
migrations/versions/c2c533f5e0cb_vault_keepass_schema.py
migrations/versions/1b639e84d474_add_vault_sync_config_table.py
```

---

# 1. Blueprint

The Vault blueprint is:

```text
vault
```

and is registered in:

```text
app/__init__.py
```

under:

```text
/vault
```

Important current behavior:

Unlike some other operational modules, the current application factory does **not** call:

```python
proteger_blueprint(vault_bp, "vault")
```

for Vault.

Instead, Vault routes individually use:

```python
@login_required
```

and some administrative routes additionally use:

```python
@admin_required
```

Therefore the current Vault access model is not identical to CSIRT, VirusTotal, or Umbrella.

Do not assume dashboard tool authorization alone protects Vault routes.

---

# 2. Core Models

Current Vault models:

```text
VaultGroup
VaultEntry
VaultEntryField
VaultSyncConfig
VaultAuditLog
```

defined in:

```text
app/vault/models.py
```

Conceptually:

```text
VaultGroup
   │
   ├── child VaultGroup[]
   │
   └── VaultEntry[]
             │
             ├── VaultEntryField[]
             └── owner → User

VaultSyncConfig
    → KeePass synchronization configuration
```

---

# 3. VaultEntry

Database table:

```text
vault_entry
```

Fields:

```text
id
uuid
title
category
username
password_enc
url
notes_enc
shared
owner_id
group_id
expires_at
icon_id
created_at
updated_at
```

Sensitive fields:

```text
password_enc
notes_enc
```

These contain encrypted values.

---

# 4. Entry UUID

Each entry has:

```text
uuid
```

with:

```text
unique=True
nullable=False
```

Default generation:

```python
str(uuid4())
```

The UUID is particularly important for KeePass synchronization/import.

It should not be treated as interchangeable with the internal SQLAlchemy:

```text
id
```

---

# 5. Entry Categories

Current categories defined by the form:

```text
server
platform
api
other
```

Display labels:

```text
Servidor
Plataforma
API / Token
Otro
```

Imported KeePass entries are currently assigned:

```text
category = other
```

regardless of their original KeePass grouping.

---

# 6. Entry Ownership

Each entry contains:

```text
owner_id → user.id
```

Relationship:

```python
owner
```

User back reference:

```text
vault_entries
```

with:

```text
lazy = dynamic
```

Ownership is used by some Vault authorization checks.

---

# 7. Shared Entries

Field:

```text
shared
```

controls whether non-owner users may see/access an entry under the current access helper.

Current helper:

```python
_can_access(entry)
```

returns `True` when:

```text
current user is administrator
OR
current user owns the entry
OR
entry.shared is True
```

This helper is used by some routes but **not all entry-mutating routes**.

See the authorization section below.

---

# 8. Encryption

Primary file:

```text
app/vault/crypto.py
```

Encryption library:

```text
cryptography.fernet.Fernet
```

Vault-specific encryption key source:

```text
VAULT_KEY
```

read directly from:

```python
os.environ
```

This differs from some other encrypted application data that uses:

```text
SECRET_KEY_DB
```

Agents must not assume Vault and other credential systems share encryption keys.

---

# 9. Encryption Flow

Function:

```python
encrypt(plaintext)
```

Behavior:

```text
empty value
    → ""

non-empty value
    → Fernet(VAULT_KEY)
    → encrypt
    → encoded ciphertext string
```

---

# 10. Decryption Flow

Function:

```python
decrypt(ciphertext)
```

Behavior:

```text
empty value
    → ""

valid ciphertext
    → plaintext

InvalidToken
    → ValueError
```

Error message:

```text
Error al descifrar: clave inválida o dato corrupto
```

Agents must not silently replace or regenerate `VAULT_KEY`.

Changing the Vault encryption key without migration/re-encryption would make existing encrypted data unreadable.

---

# 11. Password Storage

Passwords are stored in:

```text
VaultEntry.password_enc
```

using:

```python
encrypt()
```

Plaintext is only produced when:

```text
creating/updating
revealing
rendering authorized detail/edit content
exporting to KeePass
importing from KeePass
```

No plaintext password column exists in the Vault models.

---

# 12. Notes Encryption

Entry notes are stored in:

```text
notes_enc
```

using the same Vault Fernet mechanism.

Notes are decrypted for:

```text
detail view
edit form
KeePass synchronization
```

---

# 13. Custom Fields

Model:

```text
VaultEntryField
```

Database table:

```text
vault_entry_field
```

Fields:

```text
id
entry_id
field_key
field_value_enc
is_protected
```

Custom values are encrypted using:

```python
encrypt()
```

---

# 14. Custom Field Replacement

Helper:

```python
_save_custom_fields()
```

currently performs:

```text
delete all current fields for entry
        ↓
parse submitted JSON
        ↓
recreate fields
```

This is replace-all behavior.

It does not calculate field-level differences.

---

# 15. Protected Custom Fields

Each field has:

```text
is_protected
```

This flag is preserved during KeePass export through:

```python
e.set_custom_property(..., protect=field.is_protected)
```

It controls KeePass field protection semantics.

It does not replace Vault encryption.

All custom field values are encrypted in the application database regardless of this flag.

---

# 16. Vault Groups

Model:

```text
VaultGroup
```

Database table:

```text
vault_group
```

Fields:

```text
id
uuid
name
parent_id
icon_id
created_at
```

Groups support a self-referencing hierarchy:

```text
parent
children
```

---

# 17. Group Tree

Helper:

```python
_build_group_tree()
```

constructs:

```text
(group, depth)
```

pairs recursively.

Groups are sorted alphabetically at each level.

This structure is used for:

```text
index navigation
entry group selector
```

---

# 18. Vault Index

Route:

```text
GET /vault/
```

Protection:

```python
@login_required
```

For administrators:

```text
all VaultEntry rows
```

are available.

For normal users:

```text
entries owned by current user
OR
shared entries
```

are returned.

Optional filter:

```text
?group=<id>
```

limits results by:

```text
VaultEntry.group_id
```

---

# 19. Sync Status on Index

The Vault index also exposes KeePass synchronization state:

```text
sync_configured
sync_last_at
sync_last_ok
sync_last_entries
```

Runtime sync state comes from the process-local:

```python
vault_sync
```

service object.

This status is not persisted in the database.

Application restart therefore resets runtime sync status.

---

# 20. Entry Creation

Route:

```text
GET/POST /vault/new
```

Protection:

```python
@login_required
```

Creation requires a password.

Although the form defines password as optional, the route explicitly rejects an empty password.

New entries include:

```text
owner_id = current_user.id
```

and submitted:

```text
shared
group
expiration date
custom fields
```

---

# 21. Default Sharing

Form definition:

```python
shared = BooleanField(..., default=True)
```

Therefore newly-created credentials default to:

```text
shared = True
```

unless changed by the submitted form.

This is current behavior and should not be silently altered during unrelated work.

---

# 22. Entry Creation Flow

Current flow:

```text
form validation
    ↓
require password
    ↓
encrypt password
    ↓
encrypt notes
    ↓
create VaultEntry
    ↓
flush
    ↓
encrypt/create custom fields
    ↓
global audit entry
    ↓
commit
    ↓
trigger asynchronous KeePass sync
```

---

# 23. Entry Detail

Route:

```text
GET /vault/<entry_id>
```

Protection:

```python
@login_required
```

Authorization:

```python
_can_access(entry)
```

Unauthorized users receive:

```text
HTTP 403
```

The route decrypts:

```text
notes
custom field values
```

before rendering the template.

Password itself is not returned by the detail GET route.

---

# 24. Entry View Audit

Opening an authorized entry detail creates a global audit event:

```text
module = vault
action = view
object_type = entry
```

The database session is committed before rendering.

---

# 25. Password Reveal

Route:

```text
POST /vault/<entry_id>/reveal
```

Protection:

```python
@login_required
```

Authorization:

```python
_can_access(entry)
```

The route decrypts:

```text
password_enc
```

and returns:

```json
{"password": "<plaintext>"}
```

The reveal is audited:

```text
action = reveal
```

before the plaintext response is returned.

---

# 26. Reveal Security Boundary

The reveal route is one of the most security-sensitive endpoints in the project.

Preserve:

```text
POST-only behavior
authentication
access check
audit
CSRF protection
```

Do not convert reveal into a GET endpoint.

Do not place plaintext passwords in URLs, logs, audit details, templates, or database fields.

---

# 27. Entry Editing

Route:

```text
GET/POST /vault/<entry_id>/edit
```

Protection:

```python
@login_required
```

Important current behavior:

The route currently loads the requested entry but does **not** call:

```python
_can_access(entry)
```

and does not explicitly check ownership or administrator status.

Therefore current edit authorization does not match detail/reveal authorization.

This is a verified implementation characteristic and a security concern.

Do not interpret it as the intended permission model.

Do not silently change it during unrelated work; treat it as explicit technical/security debt.

---

# 28. Edit Decryption

On GET, the edit route decrypts:

```text
notes
custom fields
```

Password field is intentionally cleared:

```text
form.password.data = ""
```

The existing password is therefore not preloaded into the form.

---

# 29. Password Update Behavior

During edit:

```text
password submitted
    → encrypt and replace password_enc

password left empty
    → preserve existing password_enc
```

---

# 30. Entry Deletion

Route:

```text
POST /vault/<entry_id>/delete
```

Protection:

```python
@login_required
```

Important current behavior:

Like edit, the route currently does **not** call:

```python
_can_access(entry)
```

before deletion.

Therefore any authenticated user capable of reaching the route and knowing an entry ID is not explicitly restricted by owner/shared/admin logic in this handler.

This is current implementation behavior and should be treated as a high-priority security issue, not as an intended invariant.

Deletion is audited and followed by KeePass synchronization.

---

# 31. Group Creation

Route:

```text
POST /vault/grupos/nuevo
```

Protection:

```python
@login_required
```

Current implementation does not require administrator privileges.

Any authenticated user can create Vault groups under the current route protection.

No dedicated Vault ownership exists for groups.

---

# 32. Group Deletion

Route:

```text
POST /vault/grupos/<group_id>/eliminar
```

Protection:

```python
@login_required
```

Current implementation does not require administrator privileges.

Before deletion:

```text
entries in group
    → group_id = NULL

direct child groups
    → parent_id = NULL
```

Then the group itself is deleted.

Entries and subgroups are not cascade-deleted.

---

# 33. Group Deletion Behavior

Deleting a group intentionally produces:

```text
ungrouped entries
ungrouped direct child groups
```

rather than deleting their content.

After commit, KeePass synchronization is triggered.

---

# 34. Expiration Dates

Vault entries support:

```text
expires_at
```

The web form supplies:

```text
YYYY-MM-DD
```

Parsing helper:

```python
_parse_expires_at()
```

returns:

```text
datetime
or
None
```

Invalid values currently become:

```text
None
```

rather than producing an explicit validation error.

---

# 35. KeePass Import

Import route:

```text
GET/POST /vault/import
```

Protection:

```python
@login_required
@admin_required
```

Only administrators may perform KeePass imports.

Supported database type:

```text
.kdbx
```

Authentication may use:

```text
password
keyfile upload
or both
```

---

# 36. Temporary KeePass Files

Uploaded KeePass database is temporarily written under:

```text
current_app.instance_path
```

with a random filename:

```text
import_<uuid>.kdbx
```

Uploaded keyfiles are similarly stored as:

```text
import_<uuid>.keyx
```

The route removes these temporary files in a:

```python
finally
```

block after attempting to open the database.

---

# 37. KeePass Parsing

Library:

```text
pykeepass
```

Class:

```python
PyKeePass
```

The application reads entries after successfully opening the temporary KeePass file.

For each KeePass entry it extracts:

```text
uuid
title
username
password
url
notes
expiration
custom fields
group path
```

---

# 38. Import Identity

Entry matching between Vault and KeePass uses:

```text
UUID
```

Current Vault entries are indexed in memory by:

```text
entry.uuid
```

Imported KeePass UUIDs are compared against those values.

UUID therefore acts as synchronization/import identity.

---

# 39. Import Classification

Entries are divided into:

```text
new
conflicts
```

A conflict means:

```text
same UUID exists in Vault
```

It does not mean title or username similarity.

---

# 40. Import Preview Temporary JSON

After reading KeePass, the import route creates:

```text
vault_import_<token>.json
```

under:

```text
instance/
```

The JSON contains import preview data including:

```text
password
notes
custom fields
```

in plaintext.

This is a critical current security characteristic.

The JSON file is temporary but contains decrypted secret material on disk.

Agents must never treat files under `instance/` as normal project context.

---

# 41. Import Token

A random token is stored in Flask session:

```python
session["vault_import_token"]
```

The token maps the current import session to:

```text
vault_import_<token>.json
```

The filename itself is not supplied by the browser.

---

# 42. Import Preview

Route:

```text
GET /vault/import/preview
```

Protection:

```python
@login_required
@admin_required
```

The route reloads the temporary JSON file and presents:

```text
new entries
conflicts
group paths
```

for human selection.

---

# 43. Import Confirmation

Route:

```text
POST /vault/import/confirm
```

Protection:

```python
@login_required
@admin_required
```

The session token is removed using:

```python
session.pop()
```

The temporary JSON is read and then deleted using:

```python
os.remove()
```

before processing selected entries.

---

# 44. Abandoned Import Sessions

The shown implementation deletes the JSON during successful confirmation.

However, if a user abandons the workflow after preview, no cleanup scheduler or expiry mechanism is shown for:

```text
vault_import_*.json
```

Therefore plaintext temporary import files may remain under:

```text
instance/
```

after abandoned flows.

This is a security/technical-debt item.

---

# 45. Import New Entries

New imported entries are created with:

```text
UUID from KeePass
category = other
shared = True
owner_id = current_user.id
```

Sensitive values are re-encrypted into the application database using:

```text
VAULT_KEY
```

---

# 46. Conflict Resolution

For existing UUID conflicts, the preview allows choosing whether to preserve Vault or replace data from KeePass.

Current default:

```text
vault
```

If choice:

```text
kdbx
```

the existing Vault entry is updated.

---

# 47. Imported Custom Fields

Imported KeePass custom fields are stored as:

```text
VaultEntryField
```

with:

```text
is_protected = False
```

Current import logic does not preserve KeePass custom-field protection status.

This is current behavior.

---

# 48. Imported Group Hierarchy

Helper:

```python
_get_or_create_group_chain()
```

reconstructs KeePass group hierarchy by:

```text
name + parent_id
```

Existing matching groups are reused.

Missing groups are created.

Group UUID from KeePass is not used for this hierarchy reconstruction.

---

# 49. Import Transaction Behavior

Import confirmation stages selected:

```text
new entries
conflict updates
groups
custom fields
```

and then calls:

```python
db.session.commit()
```

Once.

After that commit, a global audit record is created:

```text
action = import
```

Important current behavior:

The audit entry is added **after** the database commit, and there is no second commit shown immediately after `log_audit()` in this route.

Therefore the import audit persistence behavior depends on later session activity.

Do not assume the import audit is atomically committed with the imported data.

---

# 50. KeePass Synchronization

Primary service:

```python
VaultSyncService
```

defined in:

```text
app/vault/sync.py
```

Singleton:

```python
vault_sync
```

Synchronization exports the application Vault into a `.kdbx` database.

---

# 51. Sync Direction

Current automatic synchronization is:

```text
Vault database
    ↓
KeePass .kdbx
```

It is an export/rebuild process.

KeePass → Vault synchronization is performed separately through the explicit admin import workflow.

Do not assume bidirectional automatic synchronization exists.

---

# 52. Sync Trigger

Automatic synchronization is triggered after operations including:

```text
entry creation
entry editing
entry deletion
group creation
group deletion
KeePass import
```

Administrator can also trigger manually through:

```text
POST /vault/sync-ahora
```

---

# 53. Manual Sync Route

Route:

```text
POST /vault/sync-ahora
```

Protection:

```python
@login_required
@admin_required
```

It calls:

```python
vault_sync.trigger_async()
```

and immediately returns.

---

# 54. Background Sync

Synchronization runs through:

```python
threading.Thread
```

with:

```text
daemon=True
```

It is an in-process, non-durable background operation.

Application restart or process termination may interrupt synchronization.

---

# 55. Synchronization Lock

The service contains:

```python
self._lock = threading.Lock()
```

Actual export runs inside:

```python
with self._lock
```

This prevents concurrent sync operations inside the same Python process.

It does not coordinate multiple independent application processes or hosts.

---

# 56. Sync Configuration

Model:

```text
VaultSyncConfig
```

Database table:

```text
vault_sync_config
```

Fields:

```text
id
kdbx_path
kdbx_password_enc
kdbx_keyfile_path
updated_at
```

The model is described as:

```text
single-row table
```

but the database does not enforce a single-row constraint.

Current routes simply use:

```python
VaultSyncConfig.query.first()
```

---

# 57. Sync Configuration Sources

KeePass sync configuration can come from:

```text
VaultSyncConfig database record
```

and/or application configuration:

```text
VAULT_KDBX_PATH
VAULT_KDBX_PASSWORD
```

Database configuration is preferred when present.

---

# 58. KeePass Password Storage

Database-configured KeePass password is stored as:

```text
kdbx_password_enc
```

encrypted using the Vault:

```text
VAULT_KEY
```

It is not stored as plaintext in the database.

---

# 59. KeePass Keyfile

Current sync configuration stores:

```text
kdbx_keyfile_path
```

as a filesystem path.

The keyfile contents themselves are not stored in the database.

The security of that keyfile therefore depends on filesystem access controls.

---

# 60. Sync Settings Route

Route:

```text
GET/POST /vault/configuracion
```

Protection:

```python
@login_required
@admin_required
```

POST requires:

```text
kdbx path
+
password and/or keyfile path
```

---

# 61. Sync Settings Password Exposure

On GET, if a database sync password exists, the current route:

```python
decrypt(cfg.kdbx_password_enc)
```

and passes it into:

```text
sync_settings.html
```

as:

```text
current_password
```

Therefore the existing KeePass synchronization password is decrypted and exposed to the server-rendered administrative page.

This is current implementation behavior and a high-risk security characteristic.

Do not interpret it as required behavior.

---

# 62. Export Database Creation

The sync service uses:

```python
pykeepass.create_database()
```

for the configured target path.

Before writing, if the file exists:

```python
os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
```

is used to make it writable.

---

# 63. Export Group Hierarchy

All Vault groups are read ordered by:

```text
VaultGroup.id
```

and recreated inside KeePass.

Mapping:

```text
Vault group id
→ KeePass group object
```

Ungrouped entries are placed under a synthetic KeePass group:

```text
Sin Grupo
```

---

# 64. Export Entry Content

Each Vault entry exports:

```text
title
username
decrypted password
URL
decrypted notes
UUID
expiration
custom fields
```

Plaintext secret material necessarily exists in process memory during export.

It must never be logged.

---

# 65. UUID Preservation

After creating a KeePass entry, the service attempts:

```python
e.uuid = UUID(entry.uuid)
```

Malformed UUIDs are logged as warnings and export continues.

---

# 66. Entry-Level Sync Failure

Each Vault entry is wrapped in an individual exception handler.

If one entry fails:

```text
warning is logged
entry is skipped
remaining entries continue
```

Synchronization can therefore succeed partially.

---

# 67. Custom Field Sync Failure

Each custom field is also individually protected with exception handling.

A failed custom field:

```text
is skipped
```

while the rest of the entry continues.

---

# 68. KeePass Save

After constructing the database:

```python
kp.save()
```

is called.

On success:

```text
last_sync_ok = True
last_sync_entries = number exported
```

On failure:

```text
last_sync_ok = False
```

---

# 69. Read-Only Target

After every sync attempt, if the target exists, the service sets:

```text
read-only filesystem permissions
```

using:

```python
os.chmod()
```

Current mode:

```text
owner/group/others read
```

with no write bit.

The intent is for KeePass consumers to open the synchronized database as read-only.

---

# 70. Sync Runtime Status

The service tracks:

```text
last_sync_at
last_sync_ok
last_sync_entries
```

only in process memory.

These values are not persisted.

Restarting the application resets them.

---

# 71. Audit Systems

The project currently contains two Vault-related audit concepts.

### Global application audit

Used by current Vault routes:

```python
log_audit()
```

from:

```text
app/models/audit.py
```

### VaultAuditLog

Model:

```text
VaultAuditLog
```

table:

```text
vault_audit_log
```

defined in:

```text
app/vault/models.py
```

---

# 72. VaultAuditLog Current Usage

The current Vault routes do **not** write to:

```text
VaultAuditLog
```

They use the global:

```text
AuditLog
```

through:

```python
log_audit()
```

Therefore `VaultAuditLog` currently appears to be unused application infrastructure.

Do not assume its presence means Vault actions are stored there.

---

# 73. Current Global Audit Actions

Vault currently generates global audit actions including:

```text
create
view
reveal
edit
delete
import
```

and sync configuration uses:

```text
edit
```

with object type:

```text
sync_config
```

Group creation/deletion and manual synchronization do not appear to generate dedicated audit records in the shown implementation.

---

# 74. Audit and Secrets

Audit entries should contain metadata only.

Never add:

```text
passwords
notes
custom field secret values
KeePass master passwords
keyfile contents
VAULT_KEY
```

to audit details.

---

# 75. Current Authorization Model

The current Vault security model is not uniform.

### Index

Normal users see:

```text
owned entries
+
shared entries
```

### Detail

Uses:

```python
_can_access()
```

### Reveal

Uses:

```python
_can_access()
```

### Edit

Currently does not call `_can_access()`.

### Delete

Currently does not call `_can_access()`.

### Create

Any authenticated user.

### Groups

Any authenticated user.

### KeePass import

Admin only.

### Sync now

Admin only.

### Sync settings

Admin only.

This inconsistency must be understood before making access-control changes.

---

# 76. Blueprint-Level Tool Authorization

Current application registration does not show:

```python
proteger_blueprint(vault_bp, "vault")
```

Therefore a user's `UserTool("vault")` assignment is not currently the same kind of server-side blueprint guard used by:

```text
CSIRT
VirusTotal
Umbrella
```

Dashboard visibility and direct URL access are separate concerns.

This should be treated as explicit authorization debt.

---

# 77. High-Priority Security Characteristics

The following current behaviors deserve explicit review in a future security task:

```text
Vault edit lacks entry access check.

Vault delete lacks entry access check.

Vault blueprint lacks global tool permission protection.

Group creation/deletion is available to any authenticated user.

Import preview stores plaintext secrets in temporary JSON.

Abandoned import JSON files have no shown cleanup mechanism.

Sync settings decrypt existing KeePass password into rendered page.

VaultAuditLog exists but current Vault actions use global AuditLog.
```

These are not reasons to modify the application during unrelated feature work.

They should be addressed through deliberate security changes with tests.

---

# 78. Sensitive Files and Agent Context

Agents must not inspect:

```text
instance/
*.kdbx
*.keyx
temporary vault_import_*.json
.env
```

during normal Vault development.

Architecture and behavior can be understood from:

```text
models
routes
forms
crypto
sync
migrations
```

without accessing real credential data.

---

# 79. Forms

Primary form:

```python
VaultEntryForm
```

Fields:

```text
title
category
group_id
username
password
url
expires_at
notes
shared
submit
```

Validation includes:

```text
title required
category required
length constraints
URL validation
```

Expiration parsing is handled separately in the route rather than by a WTForms date validator.

---

# 80. URL Validation

Vault URLs use WTForms:

```python
URL()
```

validator.

URL is optional.

Do not bypass server-side validation when modifying the frontend.

---

# 81. Transaction Characteristics

Vault uses several transaction patterns.

### Entry create/edit/delete

```text
change
audit
commit
sync
```

### Group create/delete

```text
change
commit
sync
```

### Import

```text
apply imported data
commit
log audit afterward
sync
```

### Sync settings

```text
config change
commit
log audit afterward
```

Therefore not every audit event is necessarily committed in the same transaction as the corresponding change.

Agents should not assume uniform transactional auditing.

---

# 82. Synchronization Consistency

Automatic KeePass sync is triggered only after database commit.

This means:

```text
application database
```

is the primary committed state.

KeePass export happens afterward.

If synchronization fails:

```text
database changes remain committed
```

The `.kdbx` output may therefore temporarily diverge from the application database.

---

# 83. Source of Truth

For current runtime state:

```text
Vault application database
```

is the primary source.

The synchronized `.kdbx` is an exported representation.

A manually imported `.kdbx` can update Vault only through the explicit import workflow.

Do not assume two-way automatic conflict resolution exists.

---

# 84. External/Filesystem Dependencies

Vault depends on:

```text
cryptography
pykeepass
filesystem access
configured KDBX path
optional KeePass keyfile
```

Potential failure modes include:

```text
missing VAULT_KEY
invalid VAULT_KEY
corrupted ciphertext
missing KDBX path
invalid KDBX password
missing keyfile
filesystem permissions
network share unavailable
malformed UUID
individual field export failure
```

---

# 85. High-Risk Changes

Additional review is mandatory for changes involving:

```text
VAULT_KEY
encryption/decryption
password reveal
entry authorization
shared-entry semantics
ownership
KeePass import
temporary import files
sync credentials
sync target path
keyfiles
custom field encryption
UUID identity
entry deletion
group deletion
audit behavior
```

---

# 86. Current Characteristics Requiring Caution

These observations describe the current implementation.

They are not instructions to preserve insecure behavior indefinitely.

## Edit authorization differs from detail/reveal

No `_can_access()` call is present.

## Delete authorization differs from detail/reveal

No `_can_access()` call is present.

## Vault lacks the common tool-blueprint guard

Current registration does not call `proteger_blueprint()` for Vault.

## Import preview writes plaintext secret data to disk

Temporary JSON contains credentials.

## Abandoned import files may remain

No cleanup mechanism is shown.

## Sync password is decrypted into the configuration page

This increases plaintext exposure.

## VaultAuditLog is currently unused

Actual actions are written to global AuditLog.

## Background sync is process-local

Jobs are not durable.

## Sync status is process-local

Status disappears on restart.

---

# 87. Context Loading Guide

For normal Vault entry UI work, load:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/vault.md
app/vault/routes.py
app/vault/models.py
app/vault/forms.py
```

For encryption work, additionally load:

```text
app/vault/crypto.py
```

Do not load `.env` or encrypted runtime data.

For KeePass import work, additionally load:

```text
app/vault/routes.py
app/vault/sync.py
```

and relevant migration history.

For KeePass sync work, additionally load:

```text
app/vault/sync.py
app/vault/models.py
config.py
```

without inspecting real sync credentials.

For authorization changes, additionally load:

```text
docs/systems/auth.md
app/utils.py
app/__init__.py
```

For audit changes, additionally load:

```text
app/models/audit.py
app/vault/models.py
```

because both global and Vault-specific audit models currently exist.

---

# 88. Invariants for Agents

Unless an explicit security/design task says otherwise, preserve these safe invariants:

```text
Vault secrets remain encrypted at rest.

VAULT_KEY is never exposed, logged, documented, or committed.

Changing VAULT_KEY requires an explicit migration/re-encryption strategy.

Password reveal remains authenticated, POST-only, CSRF-protected, and audited.

Plaintext passwords are never stored in normal database columns.

Notes and custom field values remain encrypted.

KeePass master passwords remain encrypted at rest when stored in VaultSyncConfig.

KeePass OAuth-style/token concepts must not be invented; current auth is password/keyfile based.

UUID remains the identity used for KeePass import conflict matching.

KDBX synchronization happens after application database commits.

Synchronization failures do not roll back already-committed Vault database changes.

Normal development does not inspect instance/, KDBX files, keyfiles, or real credentials.

Security weaknesses discovered in the current implementation are reported explicitly rather than silently preserved as architectural requirements.
```

---

# 89. Security Debt That Must Not Become an Invariant

The following current behaviors are **not** safe invariants:

```text
edit without _can_access()
delete without _can_access()
absence of proteger_blueprint(vault_bp, "vault")
plaintext import-preview JSON
rendering decrypted sync password
unused duplicate VaultAuditLog
```

Agents must not cite this documentation as justification to preserve those behaviors.

If a task touches one of these areas, the agent should explicitly flag the security implication and propose the smallest safe correction.