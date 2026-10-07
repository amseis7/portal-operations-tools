# Cisco Umbrella System

## Purpose

This document describes the current implementation of the Cisco Umbrella subsystem.

It covers:

- Umbrella client configuration
- encrypted API credentials
- configurable Umbrella tools
- Excel input processing
- App Discovery catalog lookup
- label assignment
- dry-run execution
- background jobs
- progress/status polling
- persisted execution results
- CSV export
- audit behavior

It describes the **current implementation**, not a future design.

Primary files:

```text
app/umbrella/__init__.py
app/umbrella/routes.py
app/umbrella/client.py
app/umbrella/reader.py
app/umbrella/logic.py
app/umbrella/background.py
app/models/umbrella.py
app/models/audit.py
app/utils.py
```

Primary templates:

```text
app/templates/umbrella/index.html
app/templates/umbrella/editar_cliente.html
app/templates/umbrella/herramienta_app_discovery.html
app/templates/umbrella/resultado.html
```

---

# 1. Blueprint and Authorization

The Umbrella blueprint is protected globally through:

```python
proteger_blueprint(bp, 'umbrella')
```

defined in:

```text
app/utils.py
```

Access therefore requires:

```text
authenticated user
+
current_user.has_tool("umbrella")
```

Administrators automatically pass the tool permission check.

Administrative operations add:

```python
@admin_required
```

Do not introduce a separate Umbrella-specific authorization system unless explicitly required.

---

# 2. Current Functional Architecture

The subsystem is intentionally split by responsibility:

```text
routes.py
    HTTP flow and permissions

reader.py
    Excel reading and normalization

client.py
    Cisco Umbrella API client

logic.py
    business processing

background.py
    asynchronous in-process execution

models/umbrella.py
    persistence and encrypted credentials
```

Agents should preserve this separation.

Do not move API calls into route handlers or Excel parsing into persistence models without a strong reason.

---

# 3. Current Tool Types

Tool-type metadata is defined in:

```text
app/models/umbrella.py
```

through:

```python
TIPOS_HERRAMIENTA
```

Currently implemented tool type:

```text
app_discovery
```

Metadata includes:

```text
label
icon
color
descripcion
```

Current description:

```text
Asignación de etiquetas a aplicaciones descubiertas en Cisco Umbrella
```

---

# 4. Tool Template Mapping

HTTP rendering maps tool types to templates through:

```python
_TEMPLATE_MAP
```

Current mapping:

```text
app_discovery
    → umbrella/herramienta_app_discovery.html
```

Unknown types fall back to:

```text
umbrella/herramienta_desconocida.html
```

Adding a new Umbrella tool type may therefore require changes in:

```text
TIPOS_HERRAMIENTA
_TEMPLATE_MAP
templates
routes/business logic
possibly models
```

---

# 5. Main Data Model

Current models:

```text
UmbrellaCliente
UmbrellaHerramienta
UmbrellaJob
UmbrellaAppResultado
```

Conceptually:

```text
UmbrellaCliente
      │
      └── UmbrellaHerramienta[]
                │
                └── UmbrellaJob[]
                           │
                           └── UmbrellaAppResultado[]
```

Cascade rules mean deleting parent objects can remove dependent objects.

---

# 6. UmbrellaCliente

Database table:

```text
umbrella_cliente
```

Important fields:

```text
id
nombre
descripcion
created_at
created_by
client_id_enc
client_secret_enc
```

Credentials are not stored in plaintext.

Internal encrypted fields:

```text
_client_id_enc
_client_secret_enc
```

---

# 7. Umbrella Credential Encryption

Encryption uses:

```python
cryptography.fernet.Fernet
```

with key source:

```python
current_app.config["SECRET_KEY_DB"]
```

Methods:

```text
set_credentials()
get_client_id()
get_client_secret()
has_credentials()
```

Saving:

```text
plaintext Client ID / Client Secret
        ↓
Fernet encryption
        ↓
encoded encrypted strings
        ↓
database
```

Reading:

```text
encrypted database values
        ↓
Fernet decryption
        ↓
plaintext only in application memory
```

If decryption fails:

```text
None
```

is returned.

Agents must never log, document, or expose decrypted credentials.

---

# 8. Client Ownership Metadata

`UmbrellaCliente.created_by` references:

```text
user.id
```

Relationship:

```python
creador
```

User back reference:

```text
umbrella_clientes
```

This records who created the client configuration.

It is not currently used as the authorization boundary for client management.

Administrative decorators enforce those operations.

---

# 9. Client Creation

Route:

```text
POST /umbrella/cliente/crear
```

Protection:

```python
@admin_required
```

Required inputs:

```text
nombre
client_id
client_secret
```

Optional:

```text
descripcion
```

Flow:

```text
validate required values
        ↓
create UmbrellaCliente
        ↓
set_credentials()
        ↓
flush
        ↓
audit
        ↓
commit
```

Audit action:

```text
module = umbrella
action = create
object_type = cliente
```

---

# 10. Client Editing

Route:

```text
GET/POST /umbrella/cliente/<cliente_id>/editar
```

Protection:

```python
@admin_required
```

Editable fields:

```text
nombre
descripcion
credentials
```

Credential update behavior:

```text
both client_id and client_secret provided
    → replace both encrypted values

only one provided
    → do not update credentials
    → show warning
```

Existing credentials remain unchanged unless both new values are submitted.

---

# 11. Client Deletion

Route:

```text
POST /umbrella/cliente/<cliente_id>/eliminar
```

Protection:

```python
@admin_required
```

Deleting a client cascades to:

```text
UmbrellaHerramienta
```

and through those relationships may also remove:

```text
UmbrellaJob
UmbrellaAppResultado
```

This is a destructive operation with broad persistence impact.

The operation is audited.

---

# 12. UmbrellaHerramienta

Database table:

```text
umbrella_herramienta
```

Fields:

```text
id
cliente_id
tipo
nombre
slug
descripcion
created_at
```

Foreign key:

```text
cliente_id → umbrella_cliente.id
```

Relationship:

```text
UmbrellaCliente.herramientas
```

---

# 13. Tool Slug

Each Umbrella tool has a unique:

```text
slug
```

Slug generation is implemented by:

```python
generate_slug()
```

using helper:

```python
_make_slug()
```

Normalization includes:

```text
lowercase
trim
remove unsupported punctuation
spaces/underscores → hyphens
collapse duplicate hyphens
maximum 100 base characters
```

If the slug already exists:

```text
-1
-2
...
```

is appended until uniqueness is achieved.

The database column itself is also:

```text
unique=True
```

---

# 14. Tool Creation

Route:

```text
POST /umbrella/herramienta/crear
```

Protection:

```python
@admin_required
```

Inputs:

```text
cliente_id
tipo
nombre
descripcion
```

`tipo` must exist in:

```python
TIPOS_HERRAMIENTA
```

If name is omitted, the system generates:

```text
<tool label> — <client name>
```

Creation temporarily uses:

```text
slug = "__tmp__"
```

then flushes the row and calls:

```python
generate_slug()
```

before commit.

---

# 15. Tool View

Route:

```text
GET /umbrella/herramienta/<herramienta_slug>/
```

The route loads:

```text
UmbrellaHerramienta
```

and up to:

```text
50
```

most recent jobs.

Jobs are ordered by:

```text
created_at descending
```

and eagerly load:

```text
ejecutor
```

The template is selected based on the tool type.

---

# 16. Tool Deletion

Route:

```text
POST /umbrella/herramienta/<herramienta_slug>/eliminar
```

Protection:

```python
@admin_required
```

Deleting a tool cascades to:

```text
UmbrellaJob
```

and their result rows.

The operation is audited.

---

# 17. UmbrellaJob

Database table:

```text
umbrella_job
```

Fields:

```text
id
herramienta_id
usuario_id
created_at
input_filename
column_name
label_name
dry_run
status
error_message
total
labeled
skipped
failed
```

Relationships:

```text
herramienta_id → umbrella_herramienta.id
usuario_id → user.id
```

User relation:

```python
ejecutor
```

---

# 18. Job Status

Default:

```text
pending
```

Current route flow creates jobs directly as:

```text
running
```

Background execution later changes status to:

```text
completed
```

or:

```text
failed
```

There is no separate persisted queue state beyond these fields.

---

# 19. Job Counters

Current counters:

```text
total
labeled
skipped
failed
```

Dry-run results are not represented by their own persisted summary counter.

They exist at individual result-row level through:

```text
status = dry_run
```

This is current behavior.

---

# 20. UmbrellaAppResultado

Database table:

```text
umbrella_app_resultado
```

Fields:

```text
id
job_id
app_name
category
status
label
http_code
error_message
```

Foreign key:

```text
job_id → umbrella_job.id
```

Each result stores the outcome for one input application.

---

# 21. Result Status Values

Current business logic may produce:

```text
labeled
skipped
failed
dry_run
```

Meaning:

```text
labeled
    API assignment attempted successfully

skipped
    application already had requested label

failed
    application resolution or labeling failed

dry_run
    application resolved but no API mutation was made
```

---

# 22. Excel Preview

Route:

```text
POST /umbrella/herramienta/<herramienta_slug>/preview
```

This is an AJAX endpoint.

Inputs:

```text
excel_file
column_name
```

Default column:

```text
App
```

The route first reads available Excel columns using:

```python
get_excel_columns()
```

then resets the stream:

```python
archivo.stream.seek(0)
```

and reads application names with:

```python
read_apps()
```

---

# 23. Preview Response

Successful response:

```text
apps
total
columns
```

Missing file:

```text
HTTP 400
```

Parsing/validation failure:

```text
HTTP 422
```

with error text returned in JSON.

No Umbrella API call is made during preview.

---

# 24. Excel Reader

Primary file:

```text
app/umbrella/reader.py
```

Excel support uses:

```text
pandas
openpyxl
```

Main function:

```python
read_apps(file_source, column)
```

supports:

```text
filesystem path
Path
file-like object
```

---

# 25. Excel Validation

The reader verifies:

```text
file can be parsed
requested column exists
column contains non-empty values
```

Errors are raised as:

```python
ValueError
```

or dependency problems as:

```python
RuntimeError
```

---

# 26. App Name Deduplication

Input values are:

```text
drop null
convert to string
trim
remove empty values
```

Then duplicates are removed case-insensitively.

The first original representation is preserved.

Example conceptually:

```text
Teams
teams
TEAMS
```

becomes one logical input entry.

---

# 27. Mojibake Correction

Helper:

```python
_fix_mojibake()
```

attempts to repair some strings incorrectly decoded between:

```text
cp1252
and
UTF-8
```

The correction is conservative.

If conversion fails or does not appear preferable, the original string is retained.

Do not replace this with blanket re-encoding without testing Spanish and accented application names.

---

# 28. Column Discovery

Function:

```python
get_excel_columns()
```

loads:

```text
nrows=0
```

so it retrieves only column headers rather than the full Excel dataset.

This is used by the preview UI.

---

# 29. Execution Route

Route:

```text
POST /umbrella/herramienta/<herramienta_slug>/ejecutar
```

Inputs:

```text
excel_file
label_name
column_name
dry_run
```

Default column:

```text
App
```

Dry-run flag:

```text
dry_run == "1"
```

---

# 30. Label Validation

Valid Cisco Umbrella labels are defined in:

```text
app/umbrella/client.py
```

Set:

```python
VALID_LABELS
```

Current values:

```text
unreviewed
approved
notApproved
underAudit
```

The UI options intentionally exclude:

```text
unreviewed
```

through:

```python
_LABEL_OPTIONS = sorted(VALID_LABELS - {'unreviewed'})
```

However, route validation still accepts any value in `VALID_LABELS`.

---

# 31. Credential Decryption Before Background Execution

The execution route retrieves:

```python
herramienta.cliente.get_client_id()
herramienta.cliente.get_client_secret()
```

inside the HTTP request context.

This happens **before launching the background thread**.

If either credential is unavailable:

```text
job is not started
```

and the user receives an error.

---

# 32. Important Credential Boundary

The current background launcher receives decrypted:

```text
client_id
client_secret
```

as in-memory function arguments.

They are **not stored on `UmbrellaJob`**.

This preserves encrypted-at-rest behavior but means plaintext credentials temporarily exist in process memory and thread arguments.

Agents must not persist these values in:

```text
database
logs
audit details
job result rows
documentation
```

---

# 33. Synchronous Excel Parsing

Excel parsing happens before the background job starts.

Current flow:

```text
HTTP request
   ↓
decrypt client credentials
   ↓
read Excel
   ↓
deduplicate application names
   ↓
create UmbrellaJob
   ↓
commit
   ↓
launch background thread
   ↓
redirect
```

The route assumes Excel parsing is fast enough to remain synchronous.

Do not move network API processing back into the HTTP request.

---

# 34. Job Creation

A job is created with:

```text
herramienta_id
usuario_id
input_filename
label_name
column_name
dry_run
status = running
total = number of apps
```

The job is committed before background execution begins.

Audit action:

```text
module = umbrella
action = execute
object_type = herramienta
```

Audit details include:

```text
label
app count
dry_run
job_id
```

Credentials are not included.

---

# 35. Background Execution

Primary file:

```text
app/umbrella/background.py
```

Launcher:

```python
lanzar_job_background()
```

Current implementation uses:

```python
threading.Thread
```

with:

```text
daemon=True
```

This is an in-process, non-durable background mechanism.

It is not:

```text
Celery
RQ
persistent task queue
external worker
```

---

# 36. Background Worker

Worker:

```python
_worker()
```

enters:

```python
app.app_context()
```

then reloads the:

```text
UmbrellaJob
```

using:

```python
db.session.get()
```

If the job no longer exists, the worker returns.

---

# 37. Umbrella Client Initialization

The worker creates:

```python
UmbrellaClient(client_id, client_secret)
```

Client initialization immediately authenticates against Umbrella and obtains an OAuth access token.

The client then loads the App Discovery catalog before processing input applications.

---

# 38. Cisco Umbrella API Base

Primary API base:

```text
https://api.umbrella.com
```

Authentication endpoint:

```text
/auth/v2/token
```

Current OAuth grant:

```text
client_credentials
```

Requested scopes:

```text
reports.appDiscovery:read
reports.appDiscovery:write
```

---

# 39. Authentication Request

Token retrieval uses:

```python
HTTPBasicAuth(client_id, client_secret)
```

with body:

```text
grant_type = client_credentials
scope = reports.appDiscovery:read reports.appDiscovery:write
```

Timeout:

```text
30 seconds
```

If authentication fails, the client raises:

```python
RuntimeError
```

including HTTP status and response text.

This propagates to the background worker and can become the job error message.

Treat provider response bodies as potentially sensitive.

---

# 40. Session Authentication

After token retrieval, the requests session is updated with:

```text
Authorization: Bearer <token>
Content-Type: application/json
```

Tokens are held only in process memory.

---

# 41. Automatic Token Refresh

For API requests returning:

```text
401
403
```

the client:

```text
refreshes token
retries request once through normal retry logic
```

Agents should preserve this behavior when modifying API transport.

---

# 42. Retry Strategy

Helper:

```python
_request_with_retry()
```

handles retryable conditions.

Default maximum retries:

```text
3
```

Configurable through environment:

```text
UMBRELLA_RETRY_MAX
UMBRELLA_RETRY_INITIAL_DELAY
UMBRELLA_RETRY_MAX_DELAY
```

Defaults:

```text
initial delay = 2 seconds
max delay = 8 seconds
```

Backoff:

```text
exponential
```

---

# 43. Retryable Network Errors

Current retryable exceptions:

```text
ConnectionError
Timeout
SSLError
```

HTTP statuses retried:

```text
429
500
502
503
504
```

Other HTTP responses are returned immediately.

Do not remove bounded retry behavior.

---

# 44. Request Timeout

Default Umbrella API timeout:

```text
30 seconds
```

set through:

```python
_DEFAULT_TIMEOUT
```

Do not introduce requests without a timeout.

---

# 45. App Discovery Catalog

Catalog endpoint:

```text
/reports/v2/appDiscovery/applications
```

Catalog pagination:

```text
limit = 100
offset = 0, 100, 200...
```

The client continues until a page returns fewer than:

```text
100
```

items.

Between full pages it sleeps:

```text
0.5 seconds
```

---

# 46. Catalog Structure

Each valid catalog entry stores internally:

```text
id
label
category
```

Primary index key:

```text
application name lowercased
```

A secondary index removes spaces from names to detect possible near matches.

The full catalog is held in memory for the lifetime of the `UmbrellaClient`.

---

# 47. Exact App Resolution

Function:

```python
search_app(app_name)
```

first attempts exact case-insensitive name lookup.

If exactly one match exists:

```text
return application metadata
```

If multiple exact catalog entries share the name:

```python
AmbiguousAppError
```

is raised.

---

# 48. Near-Match Behavior

If no exact name exists, the client compares names after removing spaces.

If no possible match exists:

```python
AppNotFoundError
```

is raised.

If possible no-space matches exist, the client does **not** automatically choose one.

Instead it raises:

```python
AmbiguousAppError
```

and asks for exact catalog-name verification.

This conservative behavior is important.

Do not introduce fuzzy automatic matching without explicit review because it could label the wrong Umbrella application.

---

# 49. Business Processing

Primary function:

```python
run_batch()
```

defined in:

```text
app/umbrella/logic.py
```

Processing has two phases:

```text
Phase 1
Resolve each app against catalog

Phase 2
Bulk PATCH applications requiring label changes
```

---

# 50. Phase 1: Resolution

For each application:

```text
search catalog
        ↓
not found / ambiguous
        → failed

exact match
        ↓
already has target label
        → skipped

dry_run enabled
        → dry_run

otherwise
        → queue for PATCH
```

No mutation occurs during resolution.

---

# 51. Existing Label Behavior

If the catalog application's current label equals the requested label case-insensitively:

```text
status = skipped
```

with message:

```text
Ya tenía la etiqueta asignada
```

No PATCH is sent.

---

# 52. Dry Run

When:

```text
dry_run = True
```

resolvable applications receive:

```text
status = dry_run
```

and are not added to the mutation queue.

Dry run therefore still performs:

```text
authentication
catalog loading
application resolution
```

but skips label mutation.

---

# 53. Bulk PATCH

Applications requiring changes are processed in chunks.

Chunk size:

```text
50
```

constant:

```python
PATCH_CHUNK_SIZE
```

Endpoint:

```text
/reports/v2/appDiscovery/applications
```

Method:

```text
PATCH
```

Payload:

```text
label
applicationsList
```

---

# 54. PATCH Response Handling

For:

```text
HTTP 200–299
```

the chunk is considered:

```text
labeled
```

Special case:

```text
HTTP 207
```

is still marked:

```text
labeled
```

but includes warning:

```text
Éxito parcial (HTTP 207) — verifique apps individuales
```

This means HTTP 207 does not currently produce per-application verification.

Agents must not assume all entries in a 207 response were individually successful.

---

# 55. PATCH Failure

Non-2xx response:

```text
status = failed
```

with:

```text
Fallo en asignación masiva (HTTP <code>)
```

If an exception occurs:

```text
http_code = None
status = failed
error_message = Error de asignación: ...
```

All applications in that chunk receive the same result status.

---

# 56. Batch Summary

Function:

```python
summarize()
```

counts:

```text
total
labeled
skipped
failed
dry_run
```

Current persisted `UmbrellaJob` summary stores:

```text
labeled
skipped
failed
```

but not a separate dry-run count.

---

# 57. Background Persistence

After batch completion:

```text
job.labeled
job.skipped
job.failed
job.status = completed
```

Each `AppResult` is persisted as:

```text
UmbrellaAppResultado
```

with:

```text
app_name
category
status
label
http_code
error_message
```

Then:

```python
db.session.commit()
```

is performed.

---

# 58. Background Failure

If an unhandled exception escapes batch processing:

```text
job.status = failed
job.error_message = str(exc)
```

and the exception is logged with traceback.

The job is then committed.

This means provider/internal exception text may be persisted in:

```text
UmbrellaJob.error_message
```

Current behavior should be reviewed before exposing error messages directly to users.

---

# 59. Job Status Polling

Route:

```text
GET /umbrella/herramienta/<herramienta_slug>/estado
```

Returns JSON for the latest:

```text
50 jobs
```

Fields:

```text
id
status
total
labeled
skipped
failed
error_message
```

The UI uses polling to update execution state.

There is no separate real-time transport such as WebSocket or SSE for this flow.

---

# 60. Job Detail Authorization

Route:

```text
GET /umbrella/herramienta/<herramienta_slug>/job/<job_id>
```

The route verifies:

```text
job belongs to requested herramienta
```

Then applies ownership rules:

```text
administrator
    → can view

normal user
    → only if job.usuario_id == current_user.id
```

This is an important security boundary.

---

# 61. Result Download Authorization

Route:

```text
GET /umbrella/herramienta/<herramienta_slug>/job/<job_id>/descargar
```

uses the same ownership rule:

```text
admin
or
job owner
```

Do not weaken this check when modifying result handling.

---

# 62. CSV Export

Downloaded output is generated from persisted:

```text
UmbrellaAppResultado
```

Columns:

```text
#
Aplicacion
Categoria
Estado
Etiqueta
HTTP
Mensaje
```

Encoding:

```text
UTF-8 with BOM
```

through:

```text
utf-8-sig
```

for Excel compatibility.

---

# 63. CSV Filename

Current pattern:

```text
umbrella_app_discovery_<job_id>_<YYYYMMDD_HHMMSS>.csv
```

Timestamp comes from:

```text
job.created_at
```

---

# 64. Download Audit

Result download records:

```text
module = umbrella
action = download
object_type = job
```

with tool slug in audit details.

The audit entry is committed before CSV generation.

---

# 65. Job Deletion

Route:

```text
POST /umbrella/job/<job_id>/eliminar
```

Protection:

```python
@admin_required
```

Deleting a job cascades to:

```text
UmbrellaAppResultado
```

The deletion is audited.

---

# 66. Audit Actions

Current Umbrella audit actions include:

```text
create
edit
delete
execute
download
```

Objects include:

```text
cliente
herramienta
job
```

Agents adding sensitive operations should consider whether an audit event is required.

---

# 67. Credential and Job Separation

A key current invariant is:

```text
UmbrellaCliente
    stores encrypted credentials

UmbrellaJob
    stores execution metadata only
```

Jobs do not persist:

```text
Client ID
Client Secret
OAuth token
```

Do not change this separation casually.

---

# 68. External State Mutation

Unlike VirusTotal analysis, Umbrella App Discovery can mutate an external production system.

The key mutation is:

```text
PATCH label assignment
```

Therefore a mistake in:

```text
application resolution
label selection
batch construction
```

can have direct external impact.

This subsystem should be treated as higher-risk than read-only enrichment APIs.

---

# 69. Dry Run as Safety Mechanism

Dry run provides a partial safety layer.

It verifies:

```text
credentials
catalog access
input parsing
exact app resolution
current category
current label
```

without performing:

```text
PATCH label assignment
```

Agents modifying App Discovery should preserve dry-run behavior.

---

# 70. External Identity Matching

Umbrella application matching is based primarily on:

```text
exact application name
case-insensitive
```

The system deliberately avoids automatic fuzzy assignment.

This is a critical safety characteristic.

A request to improve matching should be treated as a potentially high-risk behavioral change.

---

# 71. Current Retry Safety

Retry logic can repeat:

```text
GET
PATCH
```

requests under specific transient conditions.

Retries are bounded.

However, PATCH retry semantics depend on Cisco Umbrella's behavior.

Agents changing retry conditions should consider:

```text
idempotency
partial provider success
HTTP 207
duplicate mutation risk
```

---

# 72. Current Transaction Characteristics

The HTTP route commits:

```text
UmbrellaJob
+
execution audit
```

before launching the thread.

The background worker later commits:

```text
job summary
+
all result rows
```

This creates separate transaction boundaries.

Consequences:

```text
job may remain "running" if process dies before worker completion
job persists even if background thread never starts successfully
```

This is current architecture.

Do not assume job lifecycle is durable.

---

# 73. Background Durability Limitation

Because execution uses daemon threads:

```text
application restart
process crash
worker recycle
```

can interrupt jobs.

There is currently no recovery queue.

Persisted status may remain:

```text
running
```

indefinitely after abnormal process termination.

Record possible redesign under:

```text
docs/technical-debt/
```

rather than adding a queue framework during unrelated work.

---

# 74. Input File Persistence

The uploaded Excel file is parsed from the request stream.

The original file is not persisted by the shown implementation.

Only this metadata is stored:

```text
input_filename
column_name
```

The background worker receives:

```text
parsed list of app names
```

rather than the original Excel file.

This reduces retained sensitive file data.

---

# 75. External API Failure Modes

Current code handles:

```text
authentication failure
network connection errors
timeouts
SSL errors
HTTP 429
HTTP 5xx
401/403 token refresh
catalog failure
app not found
ambiguous app
PATCH failure
partial HTTP 207 response
```

Do not assume every failure is equivalent.

---

# 76. Error Message Exposure

Current implementation may persist or display provider/internal error text in:

```text
UmbrellaJob.error_message
UmbrellaAppResultado.error_message
```

Some exceptions can include:

```text
HTTP response bodies
application names
provider details
```

Before broadening error visibility, review whether messages may contain sensitive information.

---

# 77. Environment Configuration

Retry settings are read directly from environment variables:

```text
UMBRELLA_RETRY_MAX
UMBRELLA_RETRY_INITIAL_DELAY
UMBRELLA_RETRY_MAX_DELAY
```

Do not inspect `.env` by default.

Agents can reason about expected environment keys from source code without reading secret values.

---

# 78. Dependencies

The subsystem depends on:

```text
Flask
Flask-Login
SQLAlchemy
cryptography
requests
pandas
openpyxl
Cisco Umbrella API
```

Shared application dependencies include:

```text
auth
audit
SECRET_KEY_DB
```

---

# 79. Umbrella and Auth Boundary

Authorization depends on:

```text
proteger_blueprint(bp, "umbrella")
```

Administrative configuration routes additionally depend on:

```text
@admin_required
```

Execution ownership is tracked through:

```text
UmbrellaJob.usuario_id
```

and enforced when viewing/downloading job results.

---

# 80. Umbrella and Audit Boundary

Umbrella uses shared:

```python
log_audit()
```

for configuration changes, executions, downloads, and deletions.

The helper does not commit automatically.

Routes commit audit entries together with their corresponding database change in most current flows.

---

# 81. Umbrella and Database Boundary

Persistence stores:

```text
clients
encrypted credentials
tool configuration
job metadata
per-app results
```

External Umbrella catalog data is not persisted as a standalone catalog table.

The catalog exists only in memory during a client instance.

---

# 82. Catalog Lifetime

Each background worker creates a new:

```python
UmbrellaClient
```

and loads the full application catalog.

The catalog is cached only within that client object.

It is not shared across jobs or processes.

This means multiple jobs can independently reload the catalog.

---

# 83. High-Risk Changes

Additional review is required when changing:

```text
credential encryption
SECRET_KEY_DB usage
OAuth authentication
App Discovery catalog matching
fuzzy/name matching behavior
label validation
PATCH construction
retry behavior
HTTP 207 handling
dry-run semantics
job ownership checks
background execution
job status lifecycle
provider error exposure
client/tool deletion cascades
```

---

# 84. Current Characteristics Requiring Caution

These are current implementation observations, not automatic refactoring instructions.

## In-process daemon threads

Jobs are not durable.

## Running jobs may become stale

There is no crash-recovery mechanism.

## Catalog is loaded for every worker

There is no shared persistent cache.

## Dry-run count is not stored separately on UmbrellaJob

Individual result rows preserve `dry_run` state.

## HTTP 207 is treated as labeled

Individual partial-success verification is not performed.

## Credential plaintext exists temporarily in thread arguments

Credentials remain encrypted at rest but are passed in process memory.

## Provider error text can reach persisted job/result error fields

Review before exposing these fields more broadly.

## Tool types are currently extensible but only App Discovery exists

Do not over-generalize architecture without an actual second use case.

---

# 85. Context Loading Guide

For normal Umbrella UI work, load:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/umbrella.md
app/umbrella/routes.py
app/models/umbrella.py
```

For Excel/input work, additionally load:

```text
app/umbrella/reader.py
```

For Cisco Umbrella API behavior, additionally load:

```text
app/umbrella/client.py
```

For label-processing/business logic, additionally load:

```text
app/umbrella/logic.py
```

For background/job execution, additionally load:

```text
app/umbrella/background.py
app/models/umbrella.py
```

For authorization changes, additionally load:

```text
docs/systems/auth.md
app/utils.py
```

For credential/security changes, inspect:

```text
config.py
app/models/umbrella.py
```

without reading `.env` secret values.

Do not load CSIRT, VirusTotal, or Vault for normal Umbrella work.

---

# 86. Invariants for Agents

Unless explicitly required otherwise, preserve these invariants:

```text
Umbrella access remains authenticated and tool-authorized.

Client/tool administration remains admin-only.

Client ID and Client Secret remain encrypted at rest.

Plaintext Umbrella credentials are never stored in UmbrellaJob or result rows.

OAuth tokens are never persisted.

API requests retain finite timeouts.

Retry behavior remains bounded.

App matching remains conservative and does not auto-select ambiguous candidates.

Dry-run remains non-mutating with respect to Umbrella labels.

Already-labeled applications remain skipped.

External mutations continue to use validated labels.

Bulk PATCH remains bounded in chunk size.

Job results remain associated with their originating tool and user.

Normal users cannot inspect or download another user's job results.

Deleting a client/tool/job continues to respect existing cascades.

Uploaded Excel contents are not persisted unnecessarily.

Execution remains auditable.

Secrets are never written to logs, audit details, documentation, or exported CSVs.
```

If a requested change conflicts with one of these invariants, the agent must identify the conflict before implementation.