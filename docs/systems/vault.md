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

# 14. Custom Field Diff (id-based, not replace-all)

Helpers in `app/vault/routes.py`:

```python
_diff_custom_fields(entry, cf_json_str)
_apply_custom_fields(entry, updates, new_items, delete_ids)
```

replaced the earlier delete-all/recreate `_save_custom_fields()`. The edit
page now round-trips each existing `VaultEntryField.id` through a hidden
JSON payload (`custom_fields_json`), and the submitted payload is matched
against the entry's *current* rows **by `id`, never by `field_key` string
equality**:

```text
parse submitted JSON
        ↓
validate every item carrying a non-null id (must be an int, not bool/float/
str; must belong to THIS entry; no duplicate ids in one payload) —
fails closed with 409 and persists nothing on any violation
        ↓
classify: update (id matched) / new (no id, non-blank key) /
delete (id present in entry but not mentioned, or mentioned with a
blanked-out key)
        ↓
apply — rename, protect/unprotect, and replace/preserve ciphertext
per field, by row identity
```

This makes renaming a key, or deleting one of several fields that share
the same `field_key` (duplicate keys are legal — no `UNIQUE(entry_id,
field_key)` constraint exists), safe: the correct row's ciphertext is never
lost or swapped with a sibling's. See `docs/technical-debt/current.md`
item #38 (resolved) for the vulnerability this replaced.

A submitted `id` of JSON `null` and a submitted `key`/`value` of JSON
`null` are both treated as blank, not coerced to the string `"None"`.

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

## Blank-value preserve semantics

When editing an existing protected field, submitting a **blank value**
preserves the stored ciphertext unchanged (the field is only renamed/
re-flagged). A **whitespace-only** value (e.g. a stray space typed into
the masked input) is also treated as blank for this decision — only the
stored value itself is never stripped, so a deliberate non-blank
replacement value keeps any real leading/trailing whitespace. This
distinction exists because the masked `type="password"` input makes a
lone space visually indistinguishable from empty.

This preserve behavior applies only to fields matched by `id` in the
submitted payload (`updates`, see section 14). It does not apply to
newly added fields (`new_items`), which have no prior ciphertext to
preserve, and it does not apply to unprotected fields, which have no
preserve semantics at all.

## Detail view currently decrypts protected fields unconditionally

`detail()` in `app/vault/routes.py` builds the `custom_fields` list by
calling `decrypt()` on every `VaultEntryField`, including protected ones,
even though `detail.html` only ever renders `••••••••` for protected
rows and never outputs the decrypted value into the template. There is
no current DOM leak, but see `docs/technical-debt/current.md` item #46
for the unnecessary-decrypt concern this creates. Protected custom
fields have no on-demand reveal mechanism in the UI today — the
`bi-shield-lock` badge next to a protected field is a static label, not
a control; it is unrelated to the entry-level password reveal button
(`btnReveal` / `POST /vault/<id>/reveal`), which only ever reveals
`entry.password_enc`.

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

ADR-005 (Fase 4): the index no longer builds one flat tree from every
`VaultGroup` row. `_shared_group_tree()` builds the "Compartidas" tree from
`scope="shared"` groups only; `_personal_group_trees(user)` builds
"Personales" — for a normal user, exactly their own tree; for admin, one
independently-built tree per owner, each labeled with that user's safe
human identifier (never a raw id), never merged into one ambiguous tree.
`_group_new_parent_choices(user)` builds the group-creation form's parent
options the same way, scoped to what `user` could actually create under.
The `VaultEntryForm.group_id` dropdown is filtered by
`_populate_group_choices(form, owner_id, shared)` using the same
`(owner_id, shared)` pair `_validate_group_assignment()` checks — owner_id
is the entry's real owner (`entry.owner_id` in `edit()`, never
`current_user.id`), so admin editing another user's entry sees that
user's personal groups, not admin's own. None of this filtering is a
security boundary — `_validate_group_assignment()` / `_validate_group_
parent()` / `group_new()` / `group_delete()` remain authoritative
regardless of what is rendered. `VaultEntryForm.group_id` uses
`validate_choice=False` precisely so WTForms' own choice-membership check
never becomes an accidental second gate ahead of that authority.

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

Authorization:

```python
_can_edit(entry)
```

called immediately after loading the entry, before any form processing.
Unauthorized users receive:

```text
HTTP 403
```

`_can_edit()` is deliberately separate from `_can_access()` (view/reveal):

```text
owner can edit
admin can edit
entry.shared == True does NOT grant edit permission
```

Shared visibility (`_can_access()`) intentionally does not imply edit
permission — this was resolved as technical-debt item #1 (RESOLVED); see
`docs/technical-debt/current.md` and `tests/vault/test_edit_authorization.py`.

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

Authorization:

```python
_can_delete(entry)
```

called immediately after `_get_entry_or_404()`, before `log_audit()`,
`db.session.delete()`, `db.session.commit()`, and
`vault_sync.trigger_async()` — an unauthorized attempt produces no side
effect at all (no audit record, no deletion, no KeePass resync trigger).
Unauthorized users receive:

```text
HTTP 403
```

`_can_delete()` uses the same criterion as `_can_edit()` (kept as its own
helper, not a shared call) — `entry.shared == True` does NOT grant delete
permission, only owner or admin. Resolved as technical-debt item #2
(RESOLVED); see `docs/technical-debt/current.md` and
`tests/vault/test_delete_authorization.py`.

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

plus ADR-005 scope/ownership rules enforced inline in the route:

```text
scope == "shared"   => current_user.is_admin required; owner_id = NULL
scope == "personal" => any vault-tool user; owner_id = current_user.id,
                        always server-computed, never from form input
                        (including for admin — no "create on behalf of
                        another user")
```

Parent/scope coherence (`parent_id` must point to a group of a compatible
scope/owner) is validated by `_validate_group_parent()`, independent of the
authorization check above.

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

plus ADR-005 authorization enforced inline in the route:

```text
group.scope == "shared"   => current_user.is_admin required
group.scope == "personal" => current_user.is_admin or
                              group.owner_id == current_user.id
```

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

ADR-005 (Fase 5): the lookup/creation is scoped to shared groups only —
`scope == "shared"` is part of the match criteria, and a newly created
group is explicitly `scope="shared", owner_id=None`. A personal group
with a matching name/parent is never reused, even if one exists; if both
a shared and a personal group share the name, the shared one is reused.

Existing matching shared groups are reused.

Missing groups are created as shared groups.

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

ADR-005 (Fase 5): KeePass operates only on shared data. Only groups with:

```text
VaultGroup.scope == "shared"
```

are read (ordered by `VaultGroup.id`) and recreated inside KeePass.
`scope == "personal"` groups are never read by export, regardless of
owner, name, or parent_id — a personal group is never a node in the
service's internal group map.

Mapping:

```text
Vault group id
→ KeePass group object
```

(shared groups only — a personal group's id never appears in this map).

Ungrouped entries are placed under a synthetic KeePass group:

```text
Sin Grupo
```

A shared entry whose `group_id` points at a personal group — historical
or otherwise inconsistent data; this should not happen through the
validated `new()`/`edit()` routes, but export does not assume it can't —
also lands under `Sin Grupo`, as a direct consequence of the personal
group never being in the group map. Export never mutates the database to
"fix" this; it only reads.

---

# 63a. Export Entry Selection

Only entries with:

```text
VaultEntry.shared == True
```

are exported. A personal entry (`shared == False`) is never written to
the shared `.kdbx` file, regardless of its `owner_id` or `group_id`.

---

# 64. Export Entry Content

Each exported Vault entry exports:

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

# 71. Audit System

Vault uses the single, global application audit mechanism — the same
one CSIRT, VirusTotal, Umbrella, Auth, and Knowledge Base use:

```python
log_audit()
```

from:

```text
app/models/audit.py
```

writing to the global `AuditLog` table (`audit_log`), with
`module="vault"`. The global `/audit` route (`app/main/routes.py`)
reads it with `?module=vault` filtering; `'vault'` is registered in that
route's `AUDIT_MODULES`.

A Vault-specific `VaultAuditLog` model/table (`vault_audit_log`) existed
historically (technical-debt item #7, RESOLVED) but is no longer part of
the codebase — removed once investigation confirmed it had no active
writer or reader and `AuditLog` already covered its fields as a strict
superset. Do not reintroduce a parallel Vault-specific audit model.

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

Three distinct object-level helpers exist by deliberate design, not by
accident — `_can_access()`, `_can_edit()`, and `_can_delete()` return the
same boolean type but encode different policies, and view/reveal must not
be conflated with edit/delete (technical-debt items #1 and #2, RESOLVED).

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

Uses `_can_edit()` — **not** `_can_access()`, deliberately:
`entry.shared == True` grants view/reveal but must not grant edit. Owner
or admin only.

### Delete

Uses `_can_delete()` — same owner-or-admin criterion as `_can_edit()`,
kept as its own helper rather than a shared call. `entry.shared == True`
does not grant delete permission.

### Create

Any authenticated user.

### Groups

ADR-005: shared groups admin-only; personal groups any vault-tool user for
their own `owner_id` only (see sections 31-32).

### KeePass import

Admin only.

### Sync now

Admin only.

### Sync settings

Admin only.

---

# 76. Blueprint-Level Tool Authorization

```python
proteger_blueprint(bp, 'vault')
```

is called at module load in `app/vault/routes.py`, immediately after the
imports, the same pattern used by:

```text
CSIRT
VirusTotal
Umbrella
```

A user without `UserTool("vault")` is redirected before any route body
(including ownership/share logic) ever runs — dashboard visibility is not
the security boundary; this blueprint-level guard is. Resolved as
technical-debt item #3 (RESOLVED); see `docs/technical-debt/current.md`
and `tests/vault/test_vault_authorization.py`.

---

# 77. High-Priority Security Characteristics

The following current behaviors deserve explicit review in a future security task:

```text
Vault edit lacks entry access check.

Vault delete lacks entry access check.

Vault blueprint lacks global tool permission protection.

Group creation/deletion is available to any authenticated user. (RESOLVED
by ADR-005 — see technical-debt item #8 and sections 31-32.)

Import preview stores plaintext secrets in temporary JSON.

Abandoned import JSON files have no shown cleanup mechanism.

Sync settings decrypt existing KeePass password into rendered page.
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
```

Agents must not cite this documentation as justification to preserve those behaviors.

If a task touches one of these areas, the agent should explicitly flag the security implication and propose the smallest safe correction.