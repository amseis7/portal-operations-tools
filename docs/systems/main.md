# Main / Dashboard System

## Purpose

This document describes the current implementation of the main dashboard, global audit interface, and notification handling.

It describes the **current code**, not future behavior.

Primary files:

```text
app/main/__init__.py
app/main/routes.py
app/templates/main/dashboard.html
app/templates/main/audit.html
app/templates/base.html
app/models/notification.py
app/models/audit.py
app/tools_config.py
app/__init__.py
app/utils.py
```

---

# 1. Main Blueprint

The main blueprint is defined in:

```text
app/main/__init__.py
```

Blueprint name:

```text
main
```

It is registered without a URL prefix.

Therefore its routes are available directly from the application root.

---

# 2. Dashboard

Primary routes:

```text
/
/dashboard
```

Handler:

```python
dashboard()
```

Protection:

```python
@login_required
```

The dashboard retrieves the authenticated user's first name from:

```python
current_user.nombre_completo
```

using:

```python
current_user.nombre_completo.split()[0]
```

and passes it to:

```text
app/templates/main/dashboard.html
```

as:

```text
nombre
```

---

# 3. Tool Navigation

The dashboard does not hardcode the operational tools.

Available tools are defined in:

```text
app/tools_config.py
```

through:

```python
TOOLS
```

The application factory imports `TOOLS` and exposes it globally to templates through:

```python
@app.context_processor
def inject_tools():
    return dict(lista_herramientas=TOOLS)
```

Therefore templates can access:

```text
lista_herramientas
```

without each route passing it explicitly.

Current registered tools are:

```text
csirt
virustotal
umbrella
vault
```

---

# 4. Dashboard Tool Visibility

The dashboard iterates through:

```text
lista_herramientas
```

and renders a tool only when:

```python
current_user.has_tool(key)
```

returns `True`.

Authorization is therefore connected to:

```text
User.has_tool()
UserTool
```

documented in:

```text
docs/systems/auth.md
```

Administrators automatically pass this check.

Normal users require explicit tool authorization.

The dashboard is therefore only a **presentation layer for permissions**.

It is not the security boundary.

Each protected module must continue enforcing access independently.

Do not rely only on hiding dashboard cards to restrict access.

---

# 5. Dashboard Tool Metadata

Each tool entry currently contains:

```text
titulo
descripcion
icono
endpoint
color
```

Example conceptual structure:

```python
TOOLS = {
    "tool_name": {
        "titulo": "...",
        "descripcion": "...",
        "icono": "...",
        "endpoint": "...",
        "color": "..."
    }
}
```

Changing a tool identifier may affect:

```text
navigation
authorization
UserTool records
blueprint protection
existing users
```

Display metadata can normally be changed without changing authorization identifiers.

---

# 6. Administrator Dashboard Entry

Administrators receive an additional dashboard card:

```text
Administrar Usuarios
```

This is not part of:

```text
TOOLS
```

It is rendered directly when:

```python
current_user.is_admin
```

is true.

The card points to:

```text
auth.admin_usuarios
```

User administration remains protected server-side by the authentication subsystem.

---

# 7. Notifications

Notification persistence is defined in:

```text
app/models/notification.py
```

Model:

```text
Notification
```

Database table:

```text
notification
```

Fields:

```text
id
timestamp
message
category
is_read
link
user_id
```

A notification may either:

```text
belong to a specific user
```

or:

```text
be global
```

A global notification is represented by:

```text
user_id = NULL
```

---

# 8. Notification Relationship

`Notification.user_id` references:

```text
user.id
```

through:

```text
ForeignKey("user.id")
```

Relationship:

```python
user = db.relationship("User", backref="notifications")
```

Therefore a user can access related notification records through the generated back reference.

---

# 9. Notification Index

The notification table defines:

```text
ix_notification_read
```

covering:

```text
is_read
timestamp
```

The timestamp field is also independently indexed.

This supports notification retrieval ordered by recent unread state.

---

# 10. Global Notification Injection

The main blueprint registers:

```python
@bp.app_context_processor
```

function:

```python
inject_notifications()
```

For authenticated users it retrieves unread notifications where:

```text
Notification.user_id == current_user.id
```

or:

```text
Notification.user_id IS NULL
```

Results are ordered by:

```text
timestamp descending
```

The context processor exposes:

```text
mis_notificaciones
cantidad_notif
```

to templates.

For unauthenticated users it returns:

```text
mis_notificaciones = []
cantidad_notif = 0
```

---

# 11. Notification UI

Notification data is consumed globally by:

```text
app/templates/base.html
```

The navigation area displays:

```text
notification bell
unread count
notification dropdown
```

The unread badge is shown only when:

```text
cantidad_notif > 0
```

Each notification can include:

```text
message
category
link
```

The notification link is rendered directly from:

```python
notif.link
```

or falls back to:

```text
#
```

Agents modifying notification links should consider whether values can originate from untrusted sources.

---

# 12. Notification Categories

The UI uses:

```text
Notification.category
```

to determine visual representation.

At minimum, current notification usage includes security-related categories such as:

```text
csirt
```

Other categories may exist depending on producers.

Do not infer all valid notification categories solely from the base template.

Inspect notification creation sites when changing category behavior.

---

# 13. Mark Single Notification as Read

Route:

```text
POST /notificacion/leida/<notif_id>
```

Handler:

```python
marcar_leida()
```

Protection:

```python
@login_required
```

The requested notification is loaded through:

```python
Notification.query.get_or_404(notif_id)
```

Authorization rule:

If:

```text
notification belongs to a specific user
```

and that user is not the authenticated user, access is denied.

Global notifications:

```text
user_id = NULL
```

may be marked as read by any authenticated user under the current implementation.

After authorization:

```text
notif.is_read = True
db.session.commit()
```

The user is redirected to:

```text
request.referrer
```

or:

```text
main.dashboard
```

if no referrer exists.

---

# 14. Important Global Notification Behavior

Because global notifications are represented by a single database row:

```text
user_id = NULL
```

and `is_read` belongs to that same row, marking a global notification as read changes:

```text
is_read = True
```

on the global record itself.

This means the current model does **not** store per-user read state for global notifications.

Agents must not assume global notifications have individual read tracking.

Changing this behavior would require a deliberate data-model redesign.

---

# 15. Mark All Notifications as Read

Route:

```text
POST /notificaciones/limpiar
```

Handler:

```python
marcar_todas_leidas()
```

Protection:

```python
@login_required
```

The query selects unread notifications where:

```text
Notification.user_id == current_user.id
```

or:

```text
Notification.user_id IS NULL
```

and performs a bulk update:

```python
{"is_read": True}
```

followed by:

```python
db.session.commit()
```

The user is redirected to:

```text
request.referrer
```

or the dashboard.

The same global-notification behavior described above applies here.

---

# 16. CSRF on Notification Actions

Notification state-changing routes use:

```text
POST
```

The base template submits the "mark all as read" action through a hidden form containing:

```text
csrf_token
```

The application has global CSRF protection enabled.

Do not convert these actions to GET for convenience.

---

# 17. Global Audit Interface

Route:

```text
GET /audit
```

Handler:

```python
audit()
```

Protection:

```python
@login_required
@admin_required
```

Only administrators should access the global audit interface.

The route reads an optional query parameter:

```text
module
```

Example:

```text
/audit?module=csirt
```

---

# 18. Audit Query

The default audit query is:

```python
AuditLog.query.order_by(AuditLog.timestamp.desc())
```

If a module filter is supplied:

```python
query.filter(AuditLog.module == module_filter)
```

The interface loads at most:

```text
500 records
```

using:

```python
limit(500)
```

There is currently no pagination.

Agents should not assume all audit records are displayed.

---

# 19. Audit Model

Audit persistence is defined in:

```text
app/models/audit.py
```

Model:

```text
AuditLog
```

Database table:

```text
audit_log
```

Fields:

```text
id
module
action
object_type
object_id
object_name
user_id
timestamp
ip_address
details
```

The `module` and `timestamp` fields are indexed.

---

# 20. Audit User Relationship

`AuditLog.user_id` references:

```text
user.id
```

The relationship creates the user back reference:

```text
module_audit_logs
```

with:

```text
lazy = dynamic
```

Audit entries may exist without an authenticated user.

In that case:

```text
user_id = NULL
```

and the audit UI displays:

```text
<sistema>
```

---

# 21. Audit Logging Helper

Shared helper:

```python
log_audit()
```

defined in:

```text
app/models/audit.py
```

It creates and stages an `AuditLog` object in the current SQLAlchemy session.

Important behavior:

```text
log_audit() does not commit.
```

The caller is responsible for:

```python
db.session.commit()
```

Do not assume calling `log_audit()` immediately persists the event.

---

# 22. Audit IP Detection

The audit helper first checks:

```text
X-Forwarded-For
```

and falls back to:

```text
request.remote_addr
```

If multiple values exist in `X-Forwarded-For`, only the first address is stored.

Reverse-proxy configuration therefore affects the trust assumptions behind audit IP addresses.

---

# 23. Audit Modules

The audit interface currently exposes explicit filters for:

```text
csirt
virustotal
umbrella
vault
auth
```

The template also supports displaying unknown modules through a generic badge.

Therefore:

```text
audit.module
```

is not technically constrained to those five values.

Agents adding a new audit-producing subsystem should consider:

```text
whether the audit UI needs an explicit filter/button
whether the module label needs a dedicated visual style
```

---

# 24. Audit Actions

The UI recognizes several actions for visual styling, including:

```text
create
delete
analyze
analyze_from_csirt
analyze_from_alert
scrape
execute
export_csv
export_report
export_zip
download
import_csv
edit
update_iocs
add_iocs
reveal
view
search
login
login_failed
logout
change_password
edit_profile
setup
```

Unknown actions are still displayed through a generic fallback.

This list is presentation logic, not a strict application-level enum.

Do not treat it as a canonical list of all valid audit actions.

---

# 25. Main System Dependencies

The main subsystem depends directly on:

```text
Flask-Login
Notification
AuditLog
User authorization
TOOLS registry
base.html
```

Conceptually:

```text
AUTH
  │
  ├── current_user
  ├── admin_required
  └── has_tool()
        │
        ▼
      MAIN
        │
        ├── Dashboard
        ├── Notifications
        └── Audit UI
                │
                ▼
           Other modules
```

Main therefore acts mainly as a global UI and aggregation layer.

---

# 26. Cross-System Impact

Changes to:

```text
app/tools_config.py
```

may affect:

```text
dashboard
user permissions
navigation
tool authorization
```

Changes to:

```text
Notification
```

may affect any subsystem that generates notifications.

Changes to:

```text
AuditLog
```

may affect every subsystem producing audit events.

Changes to:

```text
base.html
```

may affect the entire application.

These files should be treated as shared infrastructure.

---

# 27. Current Security Boundaries

The dashboard itself requires:

```python
@login_required
```

The audit page requires:

```python
@login_required
@admin_required
```

Notification mutation routes require:

```python
@login_required
```

Individual operational modules enforce their own authorization independently.

The dashboard must never be treated as the only authorization mechanism.

---

# 28. Current Characteristics

Verified behavior:

### Dashboard visibility is permission-aware

Cards are shown using:

```python
current_user.has_tool(key)
```

### Tool definitions are centralized

Operational dashboard cards come from:

```text
app/tools_config.py
```

### Notifications are available globally to templates

Through:

```python
@bp.app_context_processor
```

### Notifications may be user-specific or global

Global notifications use:

```text
user_id = NULL
```

### Global notification read state is shared

Current schema does not maintain per-user read state for global notifications.

### Audit is admin-only

The `/audit` route uses:

```python
@admin_required
```

### Audit display is bounded

Only the latest:

```text
500
```

matching records are loaded.

### Audit persistence is caller-controlled

`log_audit()` stages records but does not commit.

---

# 29. Areas Requiring Caution but Not Automatic Refactoring

These are current implementation observations, not instructions to change them automatically.

## Global notifications

The current global notification model uses one shared `is_read` value.

If per-user acknowledgment is required in the future, a different persistence model would be necessary.

## Audit pagination

The audit interface currently loads a maximum of 500 rows without pagination.

## Dashboard user name

The dashboard assumes:

```python
current_user.nombre_completo.split()[0]
```

can safely obtain a first name.

Changes to optional profile fields should account for this assumption.

## Notification referrer redirects

Notification actions redirect to:

```python
request.referrer
```

when present.

Do not change redirect/security behavior as part of unrelated work.

---

# 30. Adding a New Operational Tool

When adding a new tool, Main-related work usually includes:

```text
1. Add metadata to app/tools_config.py
2. Ensure endpoint exists
3. Ensure blueprint is registered
4. Configure authorization
5. Verify dashboard visibility
6. Update project documentation
```

If the tool produces audit events:

```text
consider adding an audit filter/style
```

If the tool produces notifications:

```text
verify notification category/rendering behavior
```

---

# 31. Context Loading for Main Tasks

For dashboard work, load:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/main.md
app/main/routes.py
app/templates/main/dashboard.html
app/tools_config.py
```

For notification work, additionally load:

```text
app/models/notification.py
app/templates/base.html
```

and the module that creates the notification.

For audit work, additionally load:

```text
app/models/audit.py
app/templates/main/audit.html
app/utils.py
```

For global template/navigation changes, inspect:

```text
app/templates/base.html
app/__init__.py
```

Do not load all operational modules unless the change genuinely crosses subsystem boundaries.

---

# 32. Invariants for Agents

Unless explicitly required otherwise, preserve these behaviors:

```text
Dashboard requires authentication.

Dashboard cards respect current tool permissions.

Operational modules enforce authorization independently.

Tool metadata remains centralized in app/tools_config.py.

Audit remains administrator-only.

Notification-changing operations remain POST requests.

CSRF protection remains active.

User-specific notifications cannot be modified by other users.

Audit records remain available for system/non-user events.

log_audit() remains caller-committed unless deliberately redesigned.

Shared files are not refactored as part of unrelated feature work.
```

If a requested change conflicts with these invariants, identify the conflict before implementation.