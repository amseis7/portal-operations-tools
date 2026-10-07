# PROJECT_MAP.md

## Purpose

This file is the navigation map for AI agents and developers working in this repository.

Use it to identify the minimum relevant context required for a task.

Do not read the entire repository by default.

Workflow:

1. Read `AGENTS.md`.
2. Identify the subsystem involved.
3. Use this map to locate the relevant files.
4. Read the subsystem documentation under `docs/systems/` when available.
5. Inspect related source files.
6. Expand context only when necessary.

## Documentation Status

This section tracks the current documentation coverage for each subsystem.

Status meanings:

- `VERIFIED` — documentation has been reviewed against the current implementation.
- `PARTIAL` — documentation exists but has not been fully validated against current code.
- `MISSING` — subsystem documentation has not yet been created.
- `STALE` — documentation exists but is known to be outdated.

| Subsystem | Documentation | Status |
|---|---|---|
| Authentication / Users | `docs/systems/auth.md` | VERIFIED |
| Main / Dashboard | `docs/systems/main.md` | VERIFIED |
| CSIRT | `docs/systems/csirt.md` | VERIFIED |
| VirusTotal | `docs/systems/virustotal.md` | VERIFIED |
| Umbrella | `docs/systems/umbrella.md` | VERIFIED |
| Vault | `docs/systems/vault.md` | VERIFIED |

Agents must use this status when deciding how much they can rely on documentation.

If a subsystem is marked:

### VERIFIED

Use the subsystem documentation as the primary navigation aid, but verify implementation details in source code when making changes.

### PARTIAL

Use the documentation only as supporting context.

Inspect the relevant implementation before relying on undocumented behavior.

### MISSING

Do not infer behavior from the absence of documentation.

Use `PROJECT_MAP.md` to identify the relevant source files and reconstruct the current behavior from code.

### STALE

Treat the document as historical context only.

Current source code takes priority.

---

## Documentation Maintenance Rule

When implementation changes materially alter documented behavior, update the corresponding file in:

```text
docs/systems/
```

as part of the same change.

A subsystem may only be marked `VERIFIED` after its documentation has been compared against the current source implementation.

Do not mark documentation as verified merely because the file exists.

---

# 1. Application Entry Points

## Flask Application Factory

Primary file:

```text
app/__init__.py
```

Responsibilities:

- Flask application creation
- Extension initialization
- Security headers
- Scheduler initialization
- Blueprint registration
- Tool injection into templates
- Initial admin setup check

Registered blueprints:

```text
auth
main
csirt
virustotal
umbrella
vault
```

When changing:

- application initialization
- blueprint registration
- scheduler startup
- Flask extensions
- global request behavior
- security headers

Read:

```text
app/__init__.py
app/extensions.py
config.py
```

---

# 2. Shared Infrastructure

## Extensions

Primary file:

```text
app/extensions.py
```

Contains shared Flask extensions used across the application.

Changes here may affect multiple subsystems.

Inspect this file when modifying:

- SQLAlchemy
- Flask-Login
- CSRF
- Flask-Migrate
- rate limiting
- globally shared extensions

---

## Global Configuration

Primary file:

```text
config.py
```

Use when working with:

- Flask configuration
- database URI
- application secrets configuration
- API-related configuration
- environment-specific behavior

Never inspect `.env` unless explicitly required.

---

## Shared Utilities

Primary file:

```text
app/utils.py
```

Used by several modules.

Before adding a new shared helper:

1. Check this file.
2. Check whether equivalent logic already exists locally.
3. Avoid creating duplicate utilities.

Changes here potentially affect:

```text
auth
main
csirt
virustotal
umbrella
vault
```

---

# 3. Tool Registry

Primary file:

```text
app/tools_config.py
```

Currently registered operational tools:

```text
csirt
virustotal
umbrella
vault
```

This registry controls tool metadata presented to the application interface.

Read this file when:

- adding a new operational tool
- changing tool names or descriptions
- changing navigation endpoints
- modifying tool visibility metadata

A new major tool may also require:

```text
new blueprint
permissions
templates
models
migration
documentation
```

---

# 4. Authentication and User Administration

Subsystem:

```text
AUTH
```

Primary source:

```text
app/auth/__init__.py
app/auth/routes.py
app/models/user.py
```

Templates:

```text
app/templates/auth/login.html
app/templates/auth/setup.html
app/templates/auth/perfil.html
app/templates/auth/cambiar_inicial.html
app/templates/auth/admin_usuarios.html
```

Related shared components:

```text
app/extensions.py
app/utils.py
app/models/audit.py
```

Responsibilities include:

- initial administrator setup
- login/logout
- password validation
- initial password change
- user profile
- user administration
- user creation
- user editing
- user deletion
- tool authorization

Important route areas:

```text
/auth/setup
/auth/login
/auth/logout
/auth/perfil
/auth/admin/usuarios
```

Potential cross-system impact:

```text
all protected tools
tool permissions
audit logging
VirusTotal-related user behavior
```

Before changing authentication or authorization, also inspect:

```text
app/models/user.py
app/utils.py
app/models/audit.py
```

Do not create a parallel authorization mechanism without explicit approval.

---

# 5. Main / Dashboard

Subsystem:

```text
MAIN
```

Primary source:

```text
app/main/__init__.py
app/main/routes.py
```

Templates:

```text
app/templates/main/dashboard.html
app/templates/main/audit.html
app/templates/base.html
```

Related models:

```text
app/models/notification.py
app/models/audit.py
app/models/user.py
```

Responsibilities:

- main dashboard
- global tool navigation
- notifications
- audit interface

Important routes:

```text
/
/dashboard
/audit
/notificacion/leida/<id>
/notificaciones/limpiar
```

Read this subsystem when changing:

- dashboard behavior
- global navigation
- notifications
- audit display

---

# 6. CSIRT

Subsystem:

```text
CSIRT
```

Primary source:

```text
app/csirt/__init__.py
app/csirt/routes.py
app/csirt/logic.py
```

Models:

```text
app/models/csirt.py
```

Related models:

```text
app/models/virustotal.py
app/models/audit.py
```

Templates:

```text
app/templates/csirt/index.html
app/templates/csirt/detalle_gestion.html
app/templates/csirt/detalle_iocs.html
app/templates/csirt/importar.html
app/templates/csirt/resultados_busqueda.html
```

Responsibilities include:

- CSIRT ticket processing
- alert handling
- IoC extraction
- IoC historical import
- IoC search
- CSV export
- report generation
- alert monitoring

Important routes include:

```text
/csirt/
/csirt/gestion/<ticket_id>
/csirt/iocs/<ticket_id>
/csirt/procesar
/csirt/actualizar_iocs/<ticket_id>
/csirt/importar_historico
/csirt/buscar
/csirt/generar_reporte
```

Background behavior:

The application scheduler invokes:

```text
vigilar_nuevas_alertas
```

from:

```text
app/csirt/logic.py
```

The scheduler is configured in:

```text
app/__init__.py
```

Therefore, changes to CSIRT alert monitoring may require reading both files.

Cross-system dependencies:

```text
VirusTotal
Audit
Notifications
Scheduler
Database
```

When changing IoC structures or ticket relationships, inspect:

```text
app/models/csirt.py
app/models/virustotal.py
migrations/
```

---

# 7. VirusTotal / IoC Analysis

Subsystem:

```text
VIRUSTOTAL
```

Primary source:

```text
app/virustotal/__init__.py
app/virustotal/routes.py
app/virustotal/logic.py
app/virustotal/background.py
```

Models:

```text
app/models/virustotal.py
```

Related models:

```text
app/models/csirt.py
app/models/audit.py
```

Templates:

```text
app/templates/virustotal/index.html
app/templates/virustotal/detalle_caso.html
app/templates/virustotal/admin_templates.html
```

Responsibilities include:

- IoC analysis
- case creation
- VirusTotal processing
- analysis of CSIRT tickets
- analysis of CSIRT alerts
- case status
- result export
- export templates
- background processing

Important routes:

```text
/virustotal/
/virustotal/crear_caso
/virustotal/caso/<id>
/virustotal/analizar_caso/<id>
/virustotal/analizar_ticket_csirt/<ticket_id>
/virustotal/analizar_alerta/<id>
/virustotal/exportar_zip/<id>/<nombre>
/virustotal/api/estado_caso/<id>
```

Cross-system dependencies:

```text
CSIRT
User permissions
Audit
Background jobs
External VirusTotal API
Database
```

Before modifying VirusTotal processing, inspect:

```text
app/virustotal/logic.py
app/virustotal/background.py
app/models/virustotal.py
```

If modifying integration with CSIRT, also inspect:

```text
app/models/csirt.py
app/csirt/routes.py
```

---

# 8. Cisco Umbrella

Subsystem:

```text
UMBRELLA
```

Primary source:

```text
app/umbrella/__init__.py
app/umbrella/routes.py
app/umbrella/logic.py
app/umbrella/client.py
app/umbrella/reader.py
app/umbrella/background.py
```

Models:

```text
app/models/umbrella.py
```

Related:

```text
app/models/audit.py
```

Templates:

```text
app/templates/umbrella/index.html
app/templates/umbrella/editar_cliente.html
app/templates/umbrella/herramienta_app_discovery.html
app/templates/umbrella/resultado.html
```

Responsibilities include:

- Umbrella client management
- configurable Umbrella tools
- Excel input processing
- data preview
- Umbrella API execution
- background jobs
- result storage
- result download

Important routes include:

```text
/umbrella/
/umbrella/cliente/crear
/umbrella/cliente/<id>/editar
/umbrella/herramienta/crear
/umbrella/herramienta/<slug>/
/umbrella/herramienta/<slug>/preview
/umbrella/herramienta/<slug>/ejecutar
/umbrella/herramienta/<slug>/estado
```

File roles:

```text
routes.py
    HTTP endpoints and request flow

client.py
    Cisco Umbrella API interaction

reader.py
    input / Excel parsing

logic.py
    application/domain logic

background.py
    background processing

models/umbrella.py
    persistence
```

Cross-system dependencies:

```text
Audit
Authentication/permissions
External Cisco Umbrella API
Background processing
Database
```

If modifying API behavior, read:

```text
client.py
logic.py
background.py
```

If modifying Excel processing, read:

```text
reader.py
routes.py
logic.py
```

---

# 9. Vault / Credential Management

Subsystem:

```text
VAULT
```

Primary source:

```text
app/vault/__init__.py
app/vault/routes.py
app/vault/forms.py
app/vault/models.py
app/vault/crypto.py
app/vault/sync.py
```

Templates:

```text
app/templates/vault/index.html
app/templates/vault/detail.html
app/templates/vault/new.html
app/templates/vault/edit.html
app/templates/vault/import.html
app/templates/vault/import_preview.html
app/templates/vault/sync_settings.html
```

Responsibilities include:

- credential entry management
- encrypted password storage
- groups
- custom fields
- credential reveal
- KeePass import
- import preview
- import synchronization
- Vault sync configuration
- access control
- Vault-related auditing

File roles:

```text
routes.py
    HTTP flows and access validation

forms.py
    form definitions and validation

models.py
    Vault-specific database models

crypto.py
    encryption/decryption

sync.py
    KeePass synchronization
```

Security sensitivity:

```text
HIGH
```

Changes to this subsystem must consider:

- encryption
- authorization
- plaintext exposure
- temporary import files
- audit logging
- KeePass compatibility
- database migrations
- secret handling

Never use files under:

```text
instance/
```

as normal development context.

Current relevant migrations include:

```text
migrations/versions/df3aeaa9dd65_add_vault_tables.py
migrations/versions/c2c533f5e0cb_vault_keepass_schema.py
migrations/versions/7c7c366d70ca_vault_audit_nullable_entry_id_add_entry_.py
migrations/versions/1b639e84d474_add_vault_sync_config_table.py
```

Historical design context exists in:

```text
SPECKIT_vault_csirt.md
docs/superpowers/
```

Treat those documents as historical/design context, not automatically as current implementation.

---

# 10. Database Models

Global model package:

```text
app/models/
```

Current shared models:

```text
app/models/user.py
app/models/csirt.py
app/models/virustotal.py
app/models/umbrella.py
app/models/notification.py
app/models/audit.py
app/models/mixins.py
```

Vault uses its own model module:

```text
app/vault/models.py
```

Model exports are also present in:

```text
app/models/__init__.py
```

Before changing a model:

1. identify dependent routes and logic;
2. inspect current migrations;
3. determine whether existing data must remain compatible;
4. create a new migration rather than editing historical migrations.

---

# 11. Migrations

Migration root:

```text
migrations/
```

Configuration:

```text
migrations/env.py
migrations/alembic.ini
migrations/script.py.mako
```

Migration history:

```text
migrations/versions/
```

Use when changing:

- tables
- columns
- indexes
- relationships
- constraints
- persisted configuration

Do not infer the current schema only from migrations.

Use:

```text
current SQLAlchemy models
+
migration history
```

to understand database state.

Never inspect production database content merely to infer architecture.

---

# 12. Audit Logging

Primary model / logic:

```text
app/models/audit.py
```

Used by several subsystems.

Audit-related UI:

```text
app/main/routes.py
app/templates/main/audit.html
```

Subsystems currently interacting with audit logic include:

```text
auth
main
csirt
virustotal
umbrella
vault
```

Before introducing a sensitive action, verify whether it should produce an audit record.

---

# 13. Notifications

Primary model:

```text
app/models/notification.py
```

Main notification flows:

```text
app/main/routes.py
```

Templates may consume notification context globally through:

```text
app/templates/base.html
```

---

# 14. Background Processing

Background execution currently exists in multiple areas.

## Application Scheduler

Configured in:

```text
app/__init__.py
```

Currently schedules CSIRT monitoring.

## VirusTotal

```text
app/virustotal/background.py
```

## Umbrella

```text
app/umbrella/background.py
```

When changing background work, determine which mechanism is currently used before adding another execution model.

Avoid creating new background frameworks unless necessary.

---

# 15. Templates and UI

Global template:

```text
app/templates/base.html
```

Subsystem templates:

```text
app/templates/auth/
app/templates/main/
app/templates/csirt/
app/templates/virustotal/
app/templates/umbrella/
app/templates/vault/
```

When making UI changes:

1. identify whether behavior belongs in the shared base template;
2. avoid affecting unrelated subsystems;
3. inspect corresponding route/form logic;
4. preserve server-side validation.

Frontend validation must not replace backend validation.

---

# 16. Deployment and Runtime

Potential application entry points:

```text
run.py
server.py
```

Deployment-related files:

```text
Dockerfile
docker-compose.yml
Portal-Operations-Tools.spec
```

Legacy deployment/build information may exist under:

```text
legacy/
```

Do not modify runtime or deployment configuration as part of unrelated application work.

When changing deployment behavior, inspect:

```text
run.py
server.py
Dockerfile
docker-compose.yml
config.py
```

and the application factory.

---

# 17. Legacy Code

Directory:

```text
legacy/
```

Treat legacy code as historical reference only unless explicitly required.

Do not reintroduce legacy behavior into the current application without verification.

Do not use legacy files as the primary source of truth.

---

# 18. Documentation Areas

## Current subsystem behavior

```text
docs/systems/
```

## Architectural decisions

```text
docs/decisions/
```

## Automatically generated technical information

```text
docs/generated/
```

## Known limitations and technical debt

```text
docs/technical-debt/
```

## Superpowers specifications

```text
docs/superpowers/specs/
```

These describe proposed or designed behavior.

## Superpowers implementation plans

```text
docs/superpowers/plans/
```

These describe planned implementation steps.

A plan or specification is not proof that functionality exists.

Always verify current code.

---

# 19. Historical Project Documents

Existing project-level documents include:

```text
CLAUDE.md
AUDITORIA_TECNICA.md
SPECKIT_vault_csirt.md
```

These may contain useful historical context.

However, they may be outdated.

Use them as secondary references.

Do not treat them as higher priority than current source code.

---

# 20. Context Loading Guide

Use the following minimum context by task.

## Authentication / users

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/auth.md
app/auth/
app/models/user.py
app/utils.py
```

Expand to audit or tool configuration only if needed.

---

## CSIRT

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/csirt.md
app/csirt/
app/models/csirt.py
```

Add VirusTotal files only when the task crosses into IoC analysis.

---

## VirusTotal

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/virustotal.md
app/virustotal/
app/models/virustotal.py
```

Add CSIRT files only when handling CSIRT-originated cases or alerts.

---

## Umbrella

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/umbrella.md
app/umbrella/
app/models/umbrella.py
```

---

## Vault

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/vault.md
app/vault/
```

Add Vault-related migrations when changing persistence.

Never automatically inspect Vault runtime data.

---

## Database change

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
relevant model
relevant subsystem
migrations/versions/
```

Do not load unrelated models unless relationships require it.

---

## Global application change

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
app/__init__.py
app/extensions.py
config.py
```

Expand only to affected subsystems.

---

## Deployment change

Read:

```text
AGENTS.md
docs/PROJECT_MAP.md
run.py
server.py
Dockerfile
docker-compose.yml
config.py
```

---

# 21. High-Risk Areas

Treat changes in these areas with additional review:

```text
Vault encryption
Vault credential reveal
KeePass synchronization
Authentication
Authorization
Database migrations
External API credentials
CSIRT / IoC processing
Background jobs
Audit logging
```

Changes affecting these systems should include explicit validation and security review.

---

# 22. Current System Boundaries

The application is currently structured as a Flask monolith with functional modules implemented primarily through blueprints.

Current major functional boundaries:

```text
AUTH
MAIN
CSIRT
VIRUSTOTAL
UMBRELLA
VAULT
```

Do not split these into separate services or introduce microservices merely for architectural preference.

Any major architectural change requires explicit justification and approval.