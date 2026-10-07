# CSIRT System

## Purpose

This document describes the current implementation of the CSIRT subsystem.

It covers:

- CSIRT alert discovery
- ticket-based grouping
- IoC extraction
- historical import/export
- IoC search
- reporting
- background monitoring
- notifications
- interaction with VirusTotal data

It describes the **current implementation**, not a future design.

Primary files:

```text
app/csirt/__init__.py
app/csirt/routes.py
app/csirt/logic.py
app/models/csirt.py
app/models/virustotal.py
app/models/notification.py
app/models/audit.py
app/__init__.py
app/utils.py
```

Primary templates:

```text
app/templates/csirt/index.html
app/templates/csirt/detalle_gestion.html
app/templates/csirt/detalle_iocs.html
app/templates/csirt/importar.html
app/templates/csirt/resultados_busqueda.html
```

---

# 1. Blueprint

The CSIRT blueprint is defined in:

```text
app/csirt/__init__.py
```

Blueprint name:

```text
csirt
```

Registered in:

```text
app/__init__.py
```

with URL prefix:

```text
/csirt
```

---

# 2. Authorization

The complete CSIRT blueprint is protected using:

```python
proteger_blueprint(bp, 'csirt')
```

defined in:

```text
app/utils.py
```

This means access requires:

```text
authenticated user
+
current_user.has_tool("csirt")
```

Administrators automatically pass tool authorization.

The CSIRT dashboard visibility is also driven by the same tool identifier:

```text
csirt
```

defined in:

```text
app/tools_config.py
```

The dashboard is not the security boundary.

Blueprint protection must remain active.

---

# 3. Core Data Model

Primary models:

```text
Alerta
Ioc
```

defined in:

```text
app/models/csirt.py
```

Relationship:

```text
Alerta
   │
   └── Ioc[]
```

Each alert belongs to a logical CSIRT ticket.

A ticket itself is not represented by a dedicated table.

Instead, multiple:

```text
Alerta.ticket
```

values are grouped to represent one operational ticket.

This distinction is important.

Agents must not assume a `Ticket` CSIRT model exists.

---

# 4. Alerta Model

Database table:

```text
alerta
```

Fields:

```text
id
ticket
responsable
fecha_realizacion
nombre_alerta
tipo_alerta
user_id
```

Indexes include:

```text
ticket
responsable
fecha_realizacion
nombre_alerta
tipo_alerta
```

Composite index:

```text
(ticket, tipo_alerta)
```

User relation:

```text
user_id → user.id
```

Relationship:

```python
creator
```

with user back reference:

```text
created_alerts
```

---

# 5. IoC Model

Database table:

```text
ioc
```

Fields:

```text
id
tipo
valor
alerta_id
```

Foreign key:

```text
alerta_id → alerta.id
```

Relationship:

```text
Alerta.iocs
```

uses:

```text
cascade = all, delete-orphan
```

Therefore deleting an `Alerta` also removes its related IoCs.

---

# 6. VirusTotal Metadata on CSIRT IoCs

`Ioc` inherits from:

```python
VtInfoMixin
```

This means CSIRT IoCs can contain VirusTotal-related metadata defined by the shared mixin.

Agents changing VirusTotal metadata structures must inspect:

```text
app/models/mixins.py
```

because the change may affect both:

```text
CSIRT Ioc
and
VirusTotal VtIoc
```

---

# 7. Ticket Listing

Route:

```text
GET /csirt/
```

Handler:

```python
index()
```

The ticket list is generated dynamically from `Alerta`.

Grouping:

```text
ticket
responsable
```

Aggregated values:

```text
maximum fecha_realizacion
count of Alerta rows
```

Ordering:

```text
most recent alert first
```

The result therefore represents:

```text
logical tickets derived from alert records
```

rather than rows from a dedicated ticket table.

---

# 8. Ticket Management View

Route:

```text
GET /csirt/gestion/<ticket_id>
```

Handler:

```python
ver_gestion()
```

It loads alerts for the ticket where:

```text
Alerta.ticket == ticket_id
```

and excludes:

```text
tipo_alerta == AVC
```

Results are ordered by:

```text
fecha_realizacion descending
```

Rendered template:

```text
csirt/detalle_gestion.html
```

---

# 9. Ticket IoC View

Route:

```text
GET /csirt/iocs/<ticket_id>
```

Handler:

```python
ver_iocs()
```

The query joins:

```text
Ioc
→ Alerta
```

and filters by:

```text
Alerta.ticket
```

Optional query parameter:

```text
tipo
```

supports visual filtering.

Special grouped filters:

```text
hash
    → hash, md5, sha1, sha256

url
    → url, dominio
```

Other values are matched directly against:

```text
Ioc.tipo
```

---

# 10. IoC Recurrence

IoC views calculate how many times the same IoC value appears across the CSIRT database.

Helper:

```python
obtener_mapa_recurrencia()
```

defined in:

```text
app/csirt/logic.py
```

The result maps:

```text
IoC value
→ occurrence count
```

using grouped database queries.

This is used to show recurrence across historical alerts.

---

# 11. Alert-Specific IoC View

Route:

```text
GET /csirt/iocs_alerta/<alerta_id>
```

Handler:

```python
ver_iocs_alerta()
```

Unlike the ticket IoC view, this route only loads IoCs associated with one specific:

```text
Alerta.id
```

It supports the same visual IoC type filtering.

It also calculates recurrence using:

```python
obtener_mapa_recurrencia(iocs)
```

---

# 12. Manual CSIRT Processing

Route:

```text
POST /csirt/procesar
```

Handler:

```python
procesar()
```

Inputs:

```text
ticket
modo_prueba
```

Ticket validation currently requires:

```text
RF-<digits>
```

Regex:

```text
^RF-\d+$
```

Example:

```text
RF-123456
```

---

# 13. Responsible User

When manually processing a ticket, responsible identity is determined from:

```python
current_user.nombre_completo
```

falling back to:

```python
current_user.username
```

The current user ID is also passed into the processing flow.

This allows persisted alerts to retain the creator relation.

---

# 14. Simulation Mode

The manual processing route supports:

```text
modo_prueba
```

When enabled:

```text
simulacion = True
```

The system performs discovery and parsing logic but should avoid persisting newly detected alerts and IoCs.

Simulation results are shown to the user.

Agents modifying this flow must preserve the distinction between:

```text
analysis
and
persistence
```

Simulation must not accidentally write operational data.

---

# 15. Master Processing Function

Primary orchestration function:

```python
ejecutar_proceso_csirt()
```

defined in:

```text
app/csirt/logic.py
```

High-level flow:

```text
ticket
  ↓
escanear_y_guardar_alertas()
  ↓
new alerts
  ↓
descargar_iocs_para_alerta()
  ↓
persist IoCs
  ↓
return summary
```

---

# 16. Alert Discovery Sources

Alert discovery currently uses two external sources from:

```text
https://www.csirt.gob.cl
```

Primary sources:

```text
RSS
HTML pages
```

The system intentionally combines both.

---

# 17. RSS Source

Function:

```python
obtener_alertas_desde_rss()
```

Endpoint:

```text
https://www.csirt.gob.cl/rss/alertas
```

Default maximum:

```text
10 items
```

The RSS parser extracts:

```text
id
tipo
fecha
titulo
url_suffix
```

HTTP timeout:

```text
15 seconds
```

If the request or XML parsing fails:

```text
None
```

is returned.

---

# 18. HTML Source

Function:

```python
escanear_y_guardar_alertas_desde_html()
```

Base URL:

```text
https://www.csirt.gob.cl/alertas/
```

Default operational scan:

```text
10 pages
```

The implementation identifies alert links by URL:

```text
/alertas/...
```

rather than depending heavily on page heading selectors.

HTTP timeout:

```text
10 seconds
```

Errors on individual pages are logged and scanning continues.

---

# 19. Source Merge

Function:

```python
escanear_y_guardar_alertas()
```

retrieves from both:

```text
HTML
+
RSS
```

and merges records by alert ID.

Current merge order:

```text
HTML records
then RSS records
```

with deduplication through a `vistos` set.

The comments describe RSS as preferred for some metadata, but agents should verify the actual merge behavior before changing precedence.

Do not assume comments always perfectly match implementation.

---

# 20. Alert Type Detection

Alert type is derived from the alert identifier using a regex.

Conceptually:

```text
alert ID
→ extract 3-character type
```

Examples of types used by current logic include:

```text
AIA
ACF
AVC
AIC
```

The exact external naming convention belongs to the upstream CSIRT source.

Do not hardcode additional type assumptions without validating current upstream data.

---

# 21. Blocked Alert Types

Current logic skips:

```text
AVC
AIC
```

during IoC-oriented processing.

The code comments describe these as alert categories without blockable IoCs for this workflow.

These types are excluded from:

```text
new IoC download
missing-IoC recovery
background monitoring notifications
```

Do not change this rule as part of unrelated work.

---

# 22. Duplicate Alert Detection

Before saving a discovered alert, the system checks:

```python
Alerta.query.filter_by(nombre_alerta=alerta['id']).first()
```

Existing alert IDs are skipped.

Therefore:

```text
nombre_alerta
```

acts operationally as a de facto unique alert identifier.

However, there is no model-level unique constraint shown for this field.

Agents must distinguish:

```text
application-level uniqueness assumption
```

from:

```text
database-enforced uniqueness
```

---

# 23. Latest Alert Reference

Helper:

```python
obtener_ultimos_ids_db()
```

groups alerts by:

```text
tipo_alerta
```

and returns the maximum:

```text
nombre_alerta
```

for each type.

The returned structure is:

```text
tipo_alerta
→ latest known alert identifier
```

This is used by:

```text
alert scanning
background monitoring
```

---

# 24. Alert Persistence

New `Alerta` records are created with:

```text
nombre_alerta
ticket
tipo_alerta
responsable
fecha_realizacion
user_id
```

In non-simulation mode, the current implementation commits each newly created alert during scanning.

This means alert discovery is not one large atomic transaction.

Agents changing transaction boundaries must account for partial persistence.

---

# 25. IoC Extraction from Alert Pages

Function:

```python
descargar_iocs_para_alerta()
```

builds the external URL from:

```text
https://www.csirt.gob.cl
+
url_suffix
```

It requests the page and finds the first HTML:

```text
<table>
```

Rows are then processed into:

```text
type
value
description
```

---

# 26. Cloudflare Email Decoding

External alert tables may contain Cloudflare-protected email addresses.

Helper:

```python
decrypt_cfemail()
```

decodes the `data-cfemail` representation.

Failure returns:

```text
empty string
```

rather than propagating an exception.

---

# 27. IoC Type Normalization

External IoC types are normalized before persistence.

Current mappings include:

```text
IPv4 / IP
    → ip

IPv4 with SMTP description
    → smtp

URL
    → url

Email
    → email

SHA / MD5
    → hash

Dominio
    → dominio
```

Unrecognized types become:

```text
otro
```

and are skipped.

Email rows identified as subject-related are also skipped.

---

# 28. IoC Persistence

Each extracted IoC is stored as:

```python
Ioc(
    tipo=...,
    valor=...,
    alerta=alerta_obj
)
```

In non-simulation mode:

```text
IoCs are added
then committed after processing the alert table
```

Current logic does not enforce a database uniqueness constraint on:

```text
tipo + valor + alerta_id
```

Agents must not assume duplicate prevention exists at model level.

---

# 29. AIA Special Behavior

During master processing:

```text
AIA
```

alerts receive special handling.

If an AIA alert returns:

```text
0 IoCs
```

in non-simulation mode, the alert is deleted again.

This behavior is part of current workflow and should not be removed accidentally.

---

# 30. Missing IoC Recovery

Route:

```text
POST /csirt/actualizar_iocs/<ticket_id>
```

uses:

```python
actualizar_iocs_faltantes()
```

The function searches alerts for the ticket that:

```text
are not AVC/AIC
and
currently contain no IoCs
```

It reconstructs alert URLs using:

```text
/alertas/<nombre_alerta.lower()>
```

and reuses:

```python
descargar_iocs_para_alerta()
```

---

# 31. Massive IoC Recovery

Generator:

```python
generador_actualizacion_masiva()
```

searches globally for alert records that:

```text
are not AVC/AIC
and
have zero IoCs
```

It yields textual progress messages during processing.

This supports streaming status to the administrator.

---

# 32. Massive Update Stream

Route:

```text
GET /csirt/admin/stream_actualizacion
```

Handler:

```python
stream_actualizacion()
```

Protection:

```python
@admin_required
```

Response:

```text
text/plain
```

using:

```python
stream_with_context()
```

and:

```python
generador_actualizacion_masiva()
```

This route performs state-changing work over a GET request in the current implementation.

That is a current characteristic, not a recommendation.

Do not silently redesign it as part of unrelated work.

---

# 33. Historical CSV Export

Route:

```text
GET /csirt/admin/exportar_todo_csv
```

Current authorization is performed manually with:

```python
current_user.is_admin
```

rather than using:

```python
@admin_required
```

It exports all `Alerta` records.

CSV delimiter:

```text
;
```

Columns:

```text
Nombre Alerta
Tipo
Ticket
Responsable
Fecha
```

Date format:

```text
dd-mm-YYYY
```

The operation is audited.

---

# 34. Historical CSV Import

Route:

```text
GET/POST /csirt/importar_historico
```

Protection:

```python
@admin_required
```

Expected file:

```text
.csv
```

Maximum size:

```text
5 MB
```

Supported decoding:

```text
UTF-8
fallback Latin-1
```

Expected separator:

```text
;
```

---

# 35. Historical Import Columns

The importer expects columns equivalent to:

```text
Nombre Alerta
Tipo
Ticket
Responsable
Fecha
```

Column names are stripped of surrounding whitespace.

Rows without:

```text
Nombre Alerta
```

are skipped.

Existing alert names are skipped using:

```python
Alerta.query.filter_by(nombre_alerta=nombre_alerta).first()
```

---

# 36. Historical Date Parsing

Historical CSV import attempts:

```text
dd-mm-YYYY
```

and:

```text
dd/mm/YYYY
```

If parsing fails:

```text
datetime.now()
```

is used.

Agents modifying historical import should understand that invalid dates currently fall back rather than causing the row to fail.

---

# 37. Historical Import Transaction

Imported alerts are added to the SQLAlchemy session.

Audit event:

```text
import_csv
```

is generated.

Then the session is committed.

On exception:

```python
db.session.rollback()
```

is executed.

This import therefore behaves more transactionally than the live alert discovery flow.

---

# 38. Ticket IoC CSV Export

Route:

```text
GET /csirt/descargar_csv/<ticket_id>
```

Loads all IoCs associated with alerts belonging to the ticket.

CSV delimiter:

```text
;
```

Columns:

```text
Tipo
Valor
Alerta Origen
Ticket
```

If no IoCs exist, the user is redirected with a warning.

The export is audited.

---

# 39. Ticket Deletion

Route:

```text
POST /csirt/eliminar_ticket/<ticket_id>
```

Protection:

```python
@admin_required
```

All alerts associated with the ticket are loaded and deleted.

Because:

```text
Alerta.iocs
```

uses delete-orphan cascade, associated IoCs are also deleted.

The operation is audited.

On exception:

```text
db.session.rollback()
```

is performed.

---

# 40. Reporting

Route:

```text
POST /csirt/generar_reporte
```

Inputs:

```text
fecha_inicio
fecha_fin
```

Expected format:

```text
YYYY-MM-DD
```

The end date is converted to an inclusive end-of-day timestamp.

Alerts are filtered by:

```text
fecha_realizacion
```

and ordered ascending.

---

# 41. Excel Report Generation

Report generation delegates to:

```python
generar_reporte_excel()
```

defined in:

```text
app/utils.py
```

The result is returned as:

```text
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
```

Report generation is audited using:

```text
export_report
```

Changes to report formatting may therefore require reading:

```text
app/utils.py
```

rather than only the CSIRT module.

---

# 42. IoC Search

Route:

```text
GET /csirt/buscar
```

Handler:

```python
buscar_ioc()
```

Input:

```text
q
```

The search is intentionally cross-system.

It searches:

```text
CSIRT IoCs
+
VirusTotal case IoCs
```

---

# 43. CSIRT Search Query

CSIRT search joins:

```text
Ioc
→ Alerta
```

and searches:

```text
Ioc.valor
```

Results are ordered by:

```text
Alerta.fecha_realizacion descending
```

The alert relation is loaded using:

```python
contains_eager()
```

---

# 44. VirusTotal Search Query

The same CSIRT search route also queries:

```text
VtIoc
→ VtTicket
→ creator
```

Results are ordered by:

```text
VtTicket.fecha_creacion descending
```

This means the CSIRT subsystem has a direct read dependency on VirusTotal persistence.

Agents working on CSIRT search must load:

```text
app/models/virustotal.py
```

and possibly VirusTotal behavior if semantics change.

---

# 45. Search Audit

Every search is audited with:

```text
module = csirt
action = search
object_type = ioc
```

Details include counts found in:

```text
CSIRT
VirusTotal
```

---

# 46. Background Alert Monitor

Function:

```python
vigilar_nuevas_alertas(app)
```

runs inside:

```python
app.app_context()
```

It is scheduled from:

```text
app/__init__.py
```

using:

```text
APScheduler
```

---

# 47. Scheduler Configuration

Current job:

```text
id = vigilante_csirt
```

Trigger:

```text
interval
```

Frequency:

```text
60 minutes
```

The application factory starts the scheduler and registers this job.

Agents modifying:

```text
vigilar_nuevas_alertas()
```

must inspect:

```text
app/__init__.py
```

as well.

---

# 48. Monitoring Source Strategy

The background monitor first uses:

```python
obtener_alertas_desde_rss(max_items=5)
```

If RSS fails and returns:

```text
None
```

it falls back to:

```python
escanear_y_guardar_alertas_desde_html(max_paginas=1)
```

This differs from the manual processing flow, which combines sources more broadly.

Do not assume manual scanning and monitoring use identical discovery strategies.

---

# 49. Monitoring Logic

The monitor retrieves:

```text
latest known alert ID per alert type
```

then compares newly fetched alerts against those values.

It skips:

```text
AVC
AIC
```

and avoids repeated processing of the same type during a monitoring round.

It does not automatically persist newly discovered alerts into the CSIRT workflow.

Instead, its purpose is currently:

```text
detect availability
→ create notification
```

---

# 50. CSIRT Notifications

When new alerts are detected, the monitor creates:

```python
Notification(
    message=...,
    category="csirt",
    link="/csirt"
)
```

No `user_id` is provided.

Therefore these are:

```text
global notifications
```

under the current notification model.

See:

```text
docs/systems/main.md
```

for the implications of global notification read state.

---

# 51. Notification Deduplication

Before creating a new alert notification, the monitor checks for an existing unread notification with the exact same:

```text
message
```

If one exists:

```text
no duplicate is created
```

Deduplication is therefore based on:

```text
message equality
+
is_read=False
```

not on a dedicated event identifier.

---

# 52. External Dependency

The CSIRT subsystem depends directly on:

```text
https://www.csirt.gob.cl
```

External operations include:

```text
RSS retrieval
HTML alert listing retrieval
individual alert-page retrieval
```

Network behavior must account for:

```text
timeouts
site structure changes
RSS failures
HTML parsing changes
partial external outages
```

Agents must not assume the upstream site is stable.

---

# 53. Current External Request Timeouts

Current request timeouts include:

```text
RSS:
15 seconds

HTML listing:
10 seconds

Individual alert page:
10 seconds
```

Do not remove timeouts.

---

# 54. Logging

The subsystem uses Python:

```python
logging
```

with:

```python
logger = logging.getLogger(__name__)
```

Current logging includes:

```text
RSS errors
HTML fallback errors
new alert detection
simulation output
IoC download errors
background-monitor status
mass-update failures
```

Do not log:

```text
credentials
secrets
sensitive unrelated data
```

---

# 55. Audit Logging

CSIRT routes currently generate audit records for operations including:

```text
scrape
update_iocs
export_csv
import_csv
delete
export_report
search
```

Audit helper:

```python
log_audit()
```

does not commit automatically.

Routes generally commit after creating the audit record.

Agents adding sensitive CSIRT operations should determine whether a new audit event is required.

---

# 56. CSIRT and VirusTotal Boundary

The strongest current CSIRT → VirusTotal dependency is:

```text
IoC historical search
```

CSIRT directly queries:

```text
VtTicket
VtIoc
```

This allows users to see whether a searched IoC appears in:

```text
historical CSIRT alerts
or
VirusTotal investigation cases
```

Do not create additional coupling between the modules unless needed.

---

# 57. CSIRT and Main Boundary

CSIRT interacts with Main through:

```text
Notification
```

The background monitor creates global notifications consumed by the shared navigation interface.

If changing notification semantics, read:

```text
docs/systems/main.md
app/models/notification.py
app/templates/base.html
```

---

# 58. CSIRT and Auth Boundary

Access depends on:

```text
proteger_blueprint(bp, "csirt")
```

and administrative operations additionally use:

```text
@admin_required
```

Do not implement a parallel CSIRT-specific user permission system.

---

# 59. CSIRT and Shared Utilities

CSIRT uses:

```python
generar_reporte_excel()
```

from:

```text
app/utils.py
```

Shared authorization helpers are also imported from the same module.

Changes to `app/utils.py` may affect other subsystems.

Avoid changing shared utilities for a CSIRT-only requirement unless necessary.

---

# 60. Current Transaction Characteristics

The CSIRT subsystem does not use one consistent transaction strategy.

Examples:

### Live discovery

New alerts may be committed individually during scanning.

### IoC extraction

IoCs for an alert are committed after processing its table.

### Historical import

Rows are staged and committed as one operation.

### Ticket deletion

Deletion and audit logging are committed together.

Therefore agents must not assume CSIRT operations are globally atomic.

Transaction refactoring requires an explicit task and regression review.

---

# 61. Current Data Identity Assumptions

Current code relies operationally on:

```text
Alerta.nombre_alerta
```

as an external alert identity.

Current ticket identity relies on:

```text
Alerta.ticket
```

shared across multiple rows.

Current IoC identity does not appear to have an enforced unique key.

These are implementation assumptions, not necessarily database constraints.

---

# 62. High-Risk Changes

Additional review is required when changing:

```text
external scraping
RSS parsing
HTML parsing
alert ID parsing
IoC normalization
ticket deletion
historical imports
background monitoring
scheduler configuration
CSIRT ↔ VirusTotal search
database relationships
simulation behavior
notification creation
```

---

# 63. Current Characteristics Requiring Caution

These observations describe current behavior.

They are not automatic refactoring instructions.

## GET performs state-changing work

```text
/admin/stream_actualizacion
```

starts persistence-oriented recovery through a GET request.

## External uniqueness is application-enforced

`nombre_alerta` is checked before insert but is not shown as uniquely constrained at database level.

## Live scanning commits incrementally

Partial persistence can occur if later alert processing fails.

## Invalid imported dates fallback to current time

Historical import does not reject such rows.

## Global notification state is shared

CSIRT background notifications use global notifications.

## CSIRT search directly knows VirusTotal models

This creates intentional current coupling.

Record possible redesigns separately under:

```text
docs/technical-debt/
```

rather than silently changing them.

---

# 64. Context Loading Guide

For a normal CSIRT UI or ticket-management task, load:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/csirt.md
app/csirt/routes.py
app/models/csirt.py
```

For alert discovery or scraping, additionally load:

```text
app/csirt/logic.py
```

For scheduler or monitoring changes, additionally load:

```text
app/__init__.py
app/models/notification.py
docs/systems/main.md
```

For CSIRT search changes, additionally load:

```text
app/models/virustotal.py
```

and VirusTotal documentation when available.

For authorization changes, additionally load:

```text
docs/systems/auth.md
app/utils.py
```

For report generation changes, additionally load:

```text
app/utils.py
```

Do not load Vault or Umbrella code for normal CSIRT changes.

---

# 65. Invariants for Agents

Unless an explicit requirement says otherwise, preserve these invariants:

```text
CSIRT access remains authenticated and tool-authorized.

Ticket IDs submitted manually remain validated.

Simulation mode must not persist live operational data.

AVC and AIC remain excluded from IoC-oriented workflows.

Existing alerts are not intentionally duplicated.

IoCs remain related to Alerta records.

Deleting alerts continues to clean dependent IoCs.

External requests retain timeouts.

Scraping failures do not expose internal exception details to users.

Historical import remains administrator-only.

Ticket deletion remains administrator-only.

CSIRT operations remain auditable.

Background monitoring continues to run independently of manual processing.

CSIRT search continues to distinguish CSIRT history from VirusTotal investigation history.

Secrets and unrelated production data are never included in logs or documentation.
```

If a requested change conflicts with these invariants, the agent must identify the conflict before implementation.