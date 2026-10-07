# VirusTotal System

## Purpose

This document describes the current implementation of the VirusTotal investigation subsystem.

It covers:

- VirusTotal investigation cases
- manual IoC entry
- IoC validation
- VirusTotal API analysis
- database-backed result reuse
- cross-hash reuse
- background processing
- CSIRT integration
- export templates
- multiformat ZIP generation
- case progress reporting
- per-user VirusTotal API credentials

It describes the **current implementation**, not a future design.

Primary files:

```text
app/virustotal/__init__.py
app/virustotal/routes.py
app/virustotal/logic.py
app/virustotal/background.py
app/models/virustotal.py
app/models/mixins.py
app/models/csirt.py
app/models/user.py
app/models/audit.py
app/utils.py
```

Primary templates:

```text
app/templates/virustotal/index.html
app/templates/virustotal/detalle_caso.html
app/templates/virustotal/admin_templates.html
```

---

# 1. Blueprint

The VirusTotal blueprint is registered as:

```text
virustotal
```

and exposed under the VirusTotal URL prefix configured by the application factory.

The entire blueprint is protected through:

```python
proteger_blueprint(bp, 'virustotal')
```

defined in:

```text
app/utils.py
```

Access therefore requires:

```text
authenticated user
+
current_user.has_tool("virustotal")
```

Administrators automatically satisfy tool authorization.

---

# 2. Main Data Model

Primary models:

```text
VtTicket
VtIoc
ExportTemplate
```

defined in:

```text
app/models/virustotal.py
```

Conceptually:

```text
VtTicket
   │
   └── VtIoc[]
```

Export templates are independent configuration records used during output generation.

---

# 3. VtTicket

Database table:

```text
vt_ticket
```

Fields:

```text
id
nombre
descripcion
fecha_creacion
usuario_id
```

Relationship:

```text
usuario_id → user.id
```

User relation:

```python
creador
```

with user back reference:

```text
vt_tickets
```

IoC relationship:

```python
iocs
```

using:

```text
cascade = all, delete-orphan
```

Therefore deleting a VirusTotal case also removes its related `VtIoc` records.

---

# 4. VtIoc

Database table:

```text
vt_ioc
```

Fields directly defined by the model:

```text
id
ticket_id
tipo
valor
```

Relationship:

```text
ticket_id → vt_ticket.id
```

`VtIoc` also inherits VirusTotal metadata from:

```python
VtInfoMixin
```

defined in:

```text
app/models/mixins.py
```

---

# 5. Shared VirusTotal Metadata

`VtInfoMixin` defines:

```text
vt_last_check
vt_reputation
vt_positives
vt_total
vt_permalink
vt_md5
vt_sha1
vt_sha256
vt_motores_json
```

The mixin is shared between:

```text
VtIoc
and
CSIRT Ioc
```

This is an important cross-system dependency.

Changes to `VtInfoMixin` may affect both:

```text
VirusTotal investigation data
CSIRT IoC data
```

---

# 6. Engine Results Storage

Engine-level VirusTotal information is stored in:

```text
vt_motores_json
```

Serialization helper:

```python
set_motores(data)
```

uses:

```python
json.dumps()
```

Retrieval helper:

```python
get_motores()
```

uses:

```python
json.loads()
```

If no engine data exists:

```text
{}
```

is returned.

Agents should not introduce another engine-result serialization mechanism without explicit reason.

---

# 7. Investigation Case Index

Route:

```text
GET /virustotal/
```

Handler:

```python
index()
```

The route retrieves:

```text
all VtTicket records
```

ordered by:

```text
fecha_creacion descending
```

and eagerly loads:

```text
VtTicket.creador
```

using:

```python
joinedload()
```

Rendered template:

```text
virustotal/index.html
```

---

# 8. Case Creation

Route:

```text
POST /virustotal/crear_caso
```

Handler:

```python
crear_caso()
```

Inputs:

```text
nombre
descripcion
```

New cases are associated with:

```python
current_user.id
```

through:

```text
usuario_id
```

Flow:

```text
create VtTicket
→ add
→ flush
→ audit
→ commit
→ redirect to case
```

Audit action:

```text
module = virustotal
action = create
object_type = caso
```

---

# 9. Case Detail

Route:

```text
GET/POST /virustotal/caso/<caso_id>
```

Handler:

```python
ver_caso()
```

GET behavior:

```text
load VtTicket
load ExportTemplate records
render case detail
```

POST behavior allows manual IoC insertion.

---

# 10. Manual IoC Entry

Inputs:

```text
hashes_input
tipo_ioc
```

The entered text is split by lines.

Empty lines are ignored.

Each remaining value is individually validated.

Supported current manual types include behavior for:

```text
ip
hash
dominio
```

Other selected types may pass without the specialized validation rules shown for those categories.

---

# 11. Manual IP Validation

IPv4 validation currently uses:

```text
^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$
```

Important:

This checks the textual IPv4 shape but does not validate each octet is in the range:

```text
0–255
```

This is current behavior.

Do not silently replace it as part of unrelated work.

---

# 12. Manual Hash Validation

Hash validation accepts hexadecimal strings of:

```text
32 characters
40 characters
64 characters
```

representing:

```text
MD5
SHA1
SHA256
```

Current regex:

```text
^[a-fA-F0-9]{32}$
|
^[a-fA-F0-9]{40}$
|
^[a-fA-F0-9]{64}$
```

---

# 13. Manual Domain Normalization

For:

```text
tipo_ioc = dominio
```

the current logic removes:

```text
https://
http://
```

and keeps only the host portion before:

```text
/
```

A domain is considered structurally valid when the normalized value contains:

```text
.
```

This is simple validation, not full DNS validation.

---

# 14. Duplicate Prevention Inside a Case

Before adding a new IoC, the case checks:

```python
VtIoc.query.filter_by(
    ticket_id=caso.id,
    valor=valor_limpio
)
```

For hash-like types, additional cross-hash duplicate checking is performed against:

```text
vt_md5
vt_sha1
vt_sha256
```

inside the same case.

This allows a previously analyzed file to prevent duplicate addition when a different hash representation of the same file is later entered.

---

# 15. Manual IoC Persistence

Valid, non-duplicate IoCs are added as:

```python
VtIoc(
    ticket_id=caso.id,
    tipo=tipo_seleccionado,
    valor=valor_limpio
)
```

The operation records:

```text
number added
number ignored
```

through audit action:

```text
add_iocs
```

and commits the changes.

---

# 16. VirusTotal API Key Requirement

Analysis requires a per-user VirusTotal API key.

Retrieval:

```python
current_user.get_vt_key()
```

If no key exists, analysis routes redirect the user toward:

```text
auth.perfil
```

API key storage and encryption are documented in:

```text
docs/systems/auth.md
```

The VirusTotal subsystem must never store a plaintext copy of the key in its own models.

---

# 17. Analyze Existing Case

Route:

```text
POST /virustotal/analizar_caso/<caso_id>
```

Handler:

```python
analizar_caso()
```

Optional query parameters:

```text
tipo
source
origin_id
force
```

The route selects IoCs from the case.

Optional filtering supports:

```text
hash
    → hash, md5, sha1, sha256

other values
    → exact VtIoc.tipo match
```

---

# 18. Force Analysis

Query parameter:

```text
force=true
```

sets:

```python
force = True
```

and is passed to the background worker.

When force is disabled, existing analyzed IoCs may be skipped or reused from cache.

When force is enabled, the analysis logic bypasses normal freshness shortcuts.

---

# 19. Background Launch

Case analysis does not run synchronously in the HTTP request.

Instead:

```python
lanzar_analisis_background(
    caso.id,
    current_user.id,
    force
)
```

is called.

The route then records an audit event and redirects immediately.

This keeps VirusTotal network processing outside the request lifecycle.

---

# 20. Background Implementation

Primary file:

```text
app/virustotal/background.py
```

Background execution currently uses:

```python
threading.Thread
```

This is an in-process thread.

It is not:

```text
Celery
RQ
external worker
persistent queue
```

Agents must not assume jobs survive process restarts.

---

# 21. Background Worker

Worker:

```python
_worker_analisis(app, caso_id, user_id, force)
```

receives:

```text
Flask application object
case ID
user ID
force flag
```

It enters:

```python
app.app_context()
```

and resets the SQLAlchemy scoped session using:

```python
db.session.remove()
```

before and after processing.

---

# 22. Background User Resolution

The worker reloads the user:

```python
User.query.get(user_id)
```

and obtains the VirusTotal API key from that user.

If:

```text
user does not exist
```

or:

```text
API key is missing
```

the worker exits.

The API key is therefore resolved inside the background thread rather than passed as plaintext from the request.

---

# 23. Background IoC Selection

The worker loads:

```text
VtIoc records belonging to the case
```

If:

```text
force = False
```

the initial query additionally filters:

```text
vt_last_check IS NULL
```

This means already checked IoCs are normally not included in the worker query.

Further caching decisions may still happen inside the analysis function.

---

# 24. Background Processing Loop

Each IoC is sent to:

```python
consultar_virustotal_ioc(
    ioc,
    forzar=force,
    api_key=api_key
)
```

Counters track:

```text
processed successfully
failed
```

Current loop includes:

```python
time.sleep(0.5)
```

between requests.

This acts as a basic pacing mechanism.

It is not a full rate-limit scheduler.

---

# 25. Quota Abort Behavior

If processing raises an exception containing:

```text
VT_QUOTA_EXCEEDED
```

the background worker:

```text
marks current IoC with quota error
commits
sets stop_process
breaks remaining analysis
```

The rest of the case is therefore not analyzed during that run.

Current error marker:

```text
Cuota Diaria Excedida - Análisis Abortado
```

stored in engine-result JSON.

---

# 26. Generic Background Failure

If analysis returns:

```text
False
```

the worker stores:

```text
ERROR = Fallo consulta (Posible Cuota Excedida)
```

and commits the IoC.

For unexpected exceptions, it stores:

```text
ERROR = Excepción interna: ...
```

Current implementation therefore writes some internal exception text into:

```text
vt_motores_json
```

This is current behavior.

Do not expand exposure of internal exception data without review.

---

# 27. Analysis Orchestrator

Primary function:

```python
consultar_virustotal_ioc()
```

defined in:

```text
app/virustotal/logic.py
```

It accepts either:

```text
VtIoc
or
CSIRT Ioc
```

because both use:

```text
VtInfoMixin
```

---

# 28. Local Freshness Shortcut

If:

```text
forzar = False
```

and the current IoC already has:

```text
vt_last_check
```

less than:

```text
7 days
```

old, the function returns:

```text
True
```

without calling VirusTotal.

This is the first cache layer.

---

# 29. Database Result Reuse

Function:

```python
buscar_resultado_freco_en_db()
```

searches for the same:

```text
valor
```

in:

```text
VtIoc
then
CSIRT Ioc
```

with:

```text
vt_last_check >= now - 14 days
```

Default validity window:

```text
14 days
```

If found, the complete stored VirusTotal metadata is copied into the target object.

This includes:

```text
vt_last_check
vt_reputation
vt_positives
vt_total
vt_permalink
vt_md5
vt_sha1
vt_sha256
vt_motores_json
```

and the target is committed.

No VirusTotal request is made.

---

# 30. Cross-Hash Database Reuse

Function:

```python
buscar_hash_existente_cross_format()
```

first identifies whether the requested value looks like:

```text
MD5
SHA1
SHA256
```

Then it searches:

```text
VtIoc
and
CSIRT Ioc
```

for a record where any of:

```text
vt_md5
vt_sha1
vt_sha256
```

matches the requested hash.

Freshness window:

```text
14 days
```

This allows:

```text
SHA256 result
```

to satisfy a later request for:

```text
MD5
```

of the same file, if VirusTotal metadata already contains both hashes.

---

# 31. Hash Type Detection

Helper:

```python
detectar_tipo_hash()
```

recognizes:

```text
32 hex → md5
40 hex → sha1
64 hex → sha256
```

If cross-hash reuse succeeds, the IoC's stored type may be refined to the detected hash type.

---

# 32. VirusTotal API Base

Current API base:

```text
https://www.virustotal.com/api/v3
```

Authentication header:

```text
x-apikey
```

The API key may come from:

```text
explicit api_key parameter
```

or, when available in request context:

```python
current_user.get_vt_key()
```

Background execution explicitly passes the API key.

---

# 33. Endpoint Mapping

Current IoC type mapping:

```text
hash / md5 / sha1 / sha256
    → /files/<value>

ip / smtp
    → /ip_addresses/<value>

dominio
    → /domains/<normalized-domain>

url
    → /urls/<base64-url-id>
```

Email is intentionally not queried against VirusTotal.

---

# 34. URL Identifier

URL IoCs are encoded using:

```python
base64.urlsafe_b64encode()
```

and trailing:

```text
=
```

characters are removed.

The resulting value is used as the VirusTotal URL identifier.

---

# 35. Email Behavior

For:

```text
tipo = email
```

the system intentionally skips external VirusTotal analysis.

It sets:

```text
vt_last_check = now
vt_positives = 0
vt_total = 0
vt_reputation = 0
```

and engine information:

```text
INFO = Email ignorado (No analizable en VT)
```

The function returns:

```text
True
```

so the processing pipeline considers the IoC completed.

---

# 36. Unsupported Types

Unknown IoC types are also marked as completed.

The system sets:

```text
vt_last_check = now
```

and engine data:

```text
ERROR = Tipo '<tipo>' no soportado por VT
```

Then returns:

```text
True
```

This prevents unsupported items from permanently blocking progress reporting.

---

# 37. Successful VirusTotal Response

For successful API responses, the analysis logic reads VirusTotal attributes and stores metadata including:

```text
last analysis statistics
reputation
hashes
permalink
individual engine categories
meaningful filename/title
```

Engine categories are stored by engine name.

The synthetic key:

```text
filename
```

is also stored in engine JSON.

---

# 38. Positive Detection Count

Current analysis derives detection information from VirusTotal's:

```text
last_analysis_stats
```

and related attributes.

Stored summary fields:

```text
vt_positives
vt_total
vt_reputation
```

These fields are used later by UI and export behavior.

---

# 39. File Hash Metadata

For file results, VirusTotal response metadata can populate:

```text
vt_md5
vt_sha1
vt_sha256
```

This information enables:

```text
cross-format duplicate detection
cross-format caching
intelligent export hash selection
```

These fields therefore have behavioral importance beyond display.

---

# 40. VirusTotal Permalink

The system builds a VirusTotal GUI link based on IoC type.

Examples include:

```text
file
domain
ip-address
smtp
```

For not-found results, the permalink falls back to a VirusTotal search URL.

---

# 41. 404 Behavior

If VirusTotal returns:

```text
404
```

the IoC is still marked as processed.

Current metadata includes:

```text
vt_last_check = now
vt_reputation = 0
vt_positives = 0
ERROR = Not Found in VirusTotal
```

and a VirusTotal search permalink.

The function returns:

```text
True
```

---

# 42. Non-404 API Failure

For other non-success responses, the logic logs:

```text
status code
response text
```

and returns:

```text
False
```

This allows the background worker to mark the IoC as failed.

Agents modifying error handling should consider whether response bodies could contain sensitive provider information.

---

# 43. VirusTotal → CSIRT Result Propagation

When the analyzed object is a:

```text
VtIoc
```

the logic also searches CSIRT:

```python
Ioc.query.filter_by(valor=valor_original).all()
```

For every matching CSIRT IoC, it copies the fresh VirusTotal result:

```text
vt_last_check
vt_positives
vt_total
vt_reputation
vt_permalink
engine results
```

This means analysis of a VirusTotal case may update historical CSIRT IoC rows.

This is a major cross-system side effect.

Agents must not treat VirusTotal case analysis as isolated persistence.

---

# 44. CSIRT Import

Route:

```text
POST /virustotal/analizar_ticket_csirt/<ticket_id>
```

allows a CSIRT ticket to generate or extend a VirusTotal case.

The route:

```text
validates API key
queries CSIRT IoCs
applies optional type filter
calls procesar_importacion_csirt()
launches background analysis
audits
redirects to VirusTotal case
```

---

# 45. CSIRT Ticket Filters

Supported query filter behavior:

```text
hash
    → hash, md5, sha1, sha256

url
    → url, dominio

other
    → exact type
```

This allows selective transfer from CSIRT into VirusTotal investigation.

---

# 46. CSIRT Alert Import

Route:

```text
POST /virustotal/analizar_alerta/<alerta_id>
```

loads one:

```text
Alerta
```

and its associated CSIRT IoCs.

The parent ticket ID is used as the target case grouping key.

Thus analyzing multiple alerts from the same CSIRT ticket normally contributes to the same VirusTotal case.

---

# 47. CSIRT-Generated Case Naming

Function:

```python
procesar_importacion_csirt()
```

uses:

```text
CSIRT: <ticket>
```

as the VirusTotal case name.

It first searches:

```python
VtTicket.query.filter_by(nombre=nombre_caso).first()
```

If no case exists, it creates one.

Therefore CSIRT-linked case reuse currently depends on:

```text
case-name equality
```

rather than a dedicated foreign key to a CSIRT ticket.

---

# 48. CSIRT Import Ownership

When a new CSIRT-derived case is created:

```text
usuario_id = current_user.id
```

The user initiating the import becomes the case creator.

The case is committed immediately after creation.

---

# 49. CSIRT IoC Append

For each imported CSIRT IoC:

```text
check exact value in target case
```

then, for hash-like types:

```text
check vt_md5 / vt_sha1 / vt_sha256
```

to prevent cross-format duplication.

New IoCs are appended rather than replacing existing case contents.

---

# 50. CSIRT Import Transaction Characteristics

`procesar_importacion_csirt()` currently:

```text
may commit new case creation
then
adds IoCs
then
commits imported IoCs
```

This is not one atomic transaction.

Partial persistence may therefore occur.

Do not assume CSIRT import is transactional as a single unit.

---

# 51. Case Deletion

Route:

```text
POST /virustotal/eliminar_caso/<caso_id>
```

Protection:

```python
@admin_required
```

The route also contains an ownership/admin check.

Because the route is already admin-only, the owner branch is effectively redundant under current behavior.

This is a current implementation characteristic.

Do not remove it as part of unrelated work.

Deletion:

```text
audits
deletes case
cascades related VtIoc records
commits
```

On failure:

```text
rollback
log internal error
show generic user error
```

---

# 52. Export Templates

Model:

```text
ExportTemplate
```

Database table:

```text
export_template
```

Fields:

```text
id
nombre_plataforma
vt_engine_name
supported_hashes
file_extension
header_content
row_template
footer_content
```

Templates define output format for downstream blocking/import systems.

---

# 53. Template Administration

Admin route:

```text
GET/POST /virustotal/admin/templates
```

Protection:

```python
@admin_required
```

Administrators can:

```text
list
create
edit
delete
```

export templates.

---

# 54. Template Validation

Function:

```python
validar_plantilla()
```

validates:

```text
platform name
VirusTotal engine name
file extension
row template
supported hashes
template variables
```

Allowed extensions:

```text
csv
txt
xml
json
```

---

# 55. Allowed Template Variables

Current allowed placeholders:

```text
valor
tipo
tipo_real
ticket
filename
md5
sha1
sha256
positives
total
estado_motor
```

Template row placeholders outside this set are rejected.

Agents extending export functionality must update validation if new variables are introduced.

---

# 56. Supported Hash Configuration

Template field:

```text
supported_hashes
```

accepts comma-separated values from:

```text
md5
sha1
sha256
```

Other values are rejected.

Default model value:

```text
md5,sha1,sha256
```

---

# 57. Multiformat Export

Function:

```python
generar_exportacion_multiformato()
```

creates an in-memory ZIP.

Primary export route:

```text
POST /virustotal/exportar_zip/<caso_id>/<caso_nombre>
```

The user selects one or more export templates.

If none are selected, export is skipped.

---

# 58. Export Data Source

For:

```text
origen = caso
```

the exporter loads:

```text
VtTicket
VtIoc records
```

For alternative origin mode, it can load:

```text
CSIRT IoCs
```

through:

```text
Alerta.ticket
```

This means export logic can operate on both VirusTotal cases and CSIRT ticket data.

---

# 59. Export Engine Filtering

For each IoC, the exporter reads engine results:

```python
ioc.get_motores()
```

and obtains the state for:

```text
template.vt_engine_name
```

If the engine state is:

```text
malicious
or
suspicious
```

the IoC is excluded from the export.

The export therefore appears oriented toward producing blocking/allow-list-style files only for entries not detected by the configured engine.

Agents must verify business semantics before changing this filter.

---

# 60. Intelligent Hash Selection

For hash IoCs, the exporter avoids duplicate representation of the same file.

Deduplication key preference:

```text
vt_sha256
then
vt_sha1
then
vt_md5
then
original value
```

Template-supported hash priority:

```text
sha256
then
sha1
then
md5
```

when available.

If analyzed hash metadata is absent, the original value length is used to infer:

```text
md5
sha1
sha256
```

---

# 61. Export File Deduplication

During each template export, already-exported files are tracked in:

```text
hashes_archivo_ya_exportados
```

This prevents the same underlying file from appearing multiple times through different hash representations.

---

# 62. Export Filename Metadata

The exporter retrieves:

```text
filename
```

from engine JSON.

Fallback:

```text
Desconocido
```

is used when missing.

The exporter also normalizes empty or `-` filenames to that fallback.

---

# 63. Template Rendering

Each row uses:

```python
template.row_template.format(**variables)
```

with validated variables.

Errors during rendering are logged and that row is skipped.

The exporter continues processing other IoCs/templates.

---

# 64. XML Cleanup

After template rendering, current logic removes some empty XML structures using regular expressions.

Examples include:

```text
empty hexadecimal tags
self-closing empty elements
empty open/close element pairs
```

This cleanup is part of current export behavior.

Do not assume the exporter is a generic XML serializer.

---

# 65. ZIP File Naming

Generated output files use a pattern similar to:

```text
Bloqueo_<reference>_<platform>.<extension>
```

The final ZIP response uses:

```text
Pack_<case-name>_<YYYYMMDD>.zip
```

---

# 66. Export Audit

Export route records:

```text
module = virustotal
action = export_zip
```

including selected template IDs in audit details.

---

# 67. Case Progress API

Route:

```text
GET /virustotal/api/estado_caso/<caso_id>
```

returns JSON progress information.

Fields:

```text
total
procesados
porcentaje
estado
```

---

# 68. Processed IoC Definition

Progress counts an IoC as processed when either:

```text
vt_last_check IS NOT NULL
```

or engine JSON contains:

```text
"ERROR"
```

This allows failed or intentionally unsupported IoCs to still advance the progress indicator.

---

# 69. Progress State

Current state calculation:

```text
porcentaje >= 100
    → completado

otherwise
    → procesando
```

There is no persisted job object representing:

```text
queued
running
failed
completed
```

The state is inferred from IoC records.

---

# 70. Progress API Error

If progress calculation fails:

```text
HTTP 500
```

is returned with:

```json
{
  "error": "Error interno",
  "porcentaje": 0,
  "estado": "error"
}
```

Internal exception details are logged rather than returned.

---

# 71. VirusTotal Quota Lookup

Function:

```python
obtener_uso_api(api_key)
```

is used by the user profile system.

Endpoint:

```text
https://www.virustotal.com/api/v3/users/<api_key>
```

Header:

```text
x-apikey
```

Timeout:

```text
10 seconds
```

Returned summary includes:

```text
daily used / allowed
hourly used / allowed
monthly used / allowed
```

On provider or connection failure:

```text
None
```

is returned.

---

# 72. Auth Dependency

VirusTotal depends on authentication for:

```text
current_user
per-user API key
case ownership
tool authorization
```

Auth also depends back on VirusTotal logic for:

```text
quota display in profile
```

This creates a small bidirectional dependency.

Agents should avoid increasing this coupling unnecessarily.

---

# 73. CSIRT Dependency

VirusTotal directly uses:

```text
Alerta
Ioc
```

from CSIRT for:

```text
ticket import
alert import
historical result propagation
```

CSIRT also queries VirusTotal models for cross-system IoC search.

This is an intentional current integration boundary.

---

# 74. Shared Cache Across Subsystems

VirusTotal analysis cache is effectively shared across:

```text
VtIoc
and
CSIRT Ioc
```

because lookup functions search both tables.

This can reduce API calls but means:

```text
changing cache rules affects both systems
```

Cache changes require cross-system review.

---

# 75. Cache Windows

Current freshness behavior is not represented by one single value.

There are two important windows:

```text
current IoC already checked:
7 days

reuse from other DB records:
14 days
```

Agents must preserve this distinction unless deliberately redesigning caching policy.

---

# 76. External Dependency

Primary external service:

```text
VirusTotal API v3
```

Current implementation must handle:

```text
provider failures
quota exhaustion
not-found objects
unsupported IoC types
network errors
rate constraints
partial batch completion
```

Do not assume provider availability.

---

# 77. Background Execution Limitation

Current analysis jobs are in-process threads.

Consequences include:

```text
job state is not persisted
process restart can terminate analysis
multiple application processes may behave independently
no durable queue exists
```

These are current architectural characteristics.

Record potential redesign under:

```text
docs/technical-debt/
```

rather than introducing a queue framework during unrelated changes.

---

# 78. Logging

The VirusTotal subsystem uses Python logging.

Current logs include:

```text
provider failures
cache reuse
unsupported types
template errors
background failures
quota errors
```

Background worker also uses direct:

```python
print()
```

statements for operational progress.

This mixture is current behavior.

Do not expose:

```text
API keys
credentials
sensitive production data
```

in either mechanism.

---

# 79. Audit Logging

Current VirusTotal audit actions include:

```text
create
add_iocs
analyze
analyze_from_csirt
analyze_from_alert
delete
export_zip
```

Template administration currently performs database changes but does not consistently create corresponding audit events in the shown implementation.

Do not silently change audit policy as part of unrelated work.

---

# 80. Current Transaction Characteristics

The subsystem uses several transaction boundaries.

Examples:

### Case creation

```text
flush
audit
commit
```

### Manual IoC entry

```text
add multiple IoCs
audit
commit
```

### Background analysis

```text
individual IoC processing may commit repeatedly
```

### CSIRT import

```text
case may commit
then IoCs commit
```

### Export

```text
audit commit
then ZIP generation
```

Therefore VirusTotal processing is not globally atomic.

---

# 81. High-Risk Changes

Additional review is required for changes involving:

```text
API key handling
VirusTotal request logic
cache freshness
cross-hash matching
CSIRT result propagation
background processing
quota handling
VtInfoMixin
hash metadata
export filtering
template rendering
case deletion
CSIRT case reuse
```

---

# 82. Current Characteristics Requiring Caution

These observations are not automatic refactoring instructions.

## In-process background threads

Jobs are not durable.

## Case progress is inferred

There is no dedicated job-state table.

## CSIRT case identity uses case name

There is no explicit CSIRT-ticket foreign key.

## VirusTotal analysis updates CSIRT records

This side effect can surprise agents assuming module isolation.

## Different cache windows exist

7-day local freshness and 14-day database reuse are intentional current behaviors.

## Some validation is intentionally simple

IP/domain validation is not comprehensive.

## Admin-only case deletion includes an additional ownership check

The inner ownership test is redundant under current route protection.

## API quota behavior aborts remaining batch

Partial analysis is expected.

---

# 83. Context Loading Guide

For normal VirusTotal case UI work, load:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/virustotal.md
app/virustotal/routes.py
app/models/virustotal.py
```

For API analysis behavior, additionally load:

```text
app/virustotal/logic.py
app/models/mixins.py
```

For background processing changes, additionally load:

```text
app/virustotal/background.py
app/extensions.py
```

For CSIRT integration changes, additionally load:

```text
docs/systems/csirt.md
app/models/csirt.py
app/csirt/routes.py
```

only when route semantics require them.

For API-key/profile changes, additionally load:

```text
docs/systems/auth.md
app/models/user.py
app/auth/routes.py
```

For export behavior, load:

```text
app/virustotal/logic.py
app/models/virustotal.py
app/templates/virustotal/admin_templates.html
```

Do not load Umbrella or Vault code for normal VirusTotal work.

---

# 84. Invariants for Agents

Unless explicitly required otherwise, preserve these invariants:

```text
VirusTotal access remains authenticated and tool-authorized.

API keys remain per-user and encrypted at rest.

API keys are not persisted in VirusTotal models.

Long-running VirusTotal analysis remains outside the HTTP request path.

Existing fresh results are reused unless analysis is explicitly forced.

Cross-hash result reuse remains functional.

VirusTotal metadata remains compatible with both VtIoc and CSIRT Ioc.

CSIRT imports append rather than erase existing case IoCs.

Duplicate hash representations of the same file remain minimized.

Quota exhaustion stops the remaining background batch.

Unsupported IoC types do not permanently block progress.

Case deletion continues to cascade related VtIoc records.

Export templates remain administrator-managed.

Template variables remain validated before persistence.

Export engine filtering remains unchanged unless explicitly requested.

VirusTotal analysis may propagate fresh results back into matching CSIRT IoCs.

Provider failures must not expose API keys or sensitive internal data to users.
```

If a requested change conflicts with one of these invariants, identify the conflict before implementation.