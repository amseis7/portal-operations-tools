# Authentication and Authorization System

## Purpose

This document describes the current authentication, user-management, authorization, password, profile, and tool-access implementation.

It describes the **current code**, not a future design.

Primary files:

```text
app/auth/__init__.py
app/auth/routes.py
app/models/user.py
app/utils.py
app/models/audit.py
app/extensions.py
app/tools_config.py
app/__init__.py
```

Primary templates:

```text
app/templates/auth/login.html
app/templates/auth/setup.html
app/templates/auth/cambiar_inicial.html
app/templates/auth/perfil.html
app/templates/auth/admin_usuarios.html
```

---

# 1. Authentication Technology

Authentication uses:

```text
Flask-Login
Werkzeug password hashing
SQLAlchemy
Flask-Limiter
Flask-WTF CSRF
```

The shared LoginManager is defined in:

```text
app/extensions.py
```

and initialized in:

```text
app/__init__.py
```

Configuration includes:

```python
login_manager.login_view = 'auth.login'
login_manager.login_message = "Por favor inicia sesión para acceder."
login_manager.login_message_category = "warning"
```

Unauthenticated users requesting protected routes are therefore redirected to:

```text
/auth/login
```

---

# 2. Authentication Blueprint

The authentication blueprint is created in:

```text
app/auth/__init__.py
```

Blueprint name:

```text
auth
```

Registered by the application factory with:

```text
/auth
```

as URL prefix.

Therefore authentication routes are exposed under:

```text
/auth/...
```

---

# 3. User Model

Primary model:

```text
app/models/user.py
```

Model:

```text
User
```

Database table:

```text
user
```

Important fields:

```text
id
username
password_hash
is_admin
must_change_password
nombre_completo
email
virustotal_api_key
```

Important constraints:

```text
username
    unique
    indexed
    required

password_hash
    required

email
    indexed
```

The stored VirusTotal field is internally exposed as:

```python
_virustotal_api_key
```

while the database column is:

```text
virustotal_api_key
```

---

# 4. Password Storage

Passwords are not stored directly.

The `User` model uses Werkzeug:

```python
generate_password_hash()
check_password_hash()
```

Methods:

```python
User.set_password(password)
User.check_password(password)
```

Agents must not introduce alternative password storage mechanisms without explicit approval.

Never persist plaintext passwords.

---

# 5. Password Complexity

Password validation is implemented in:

```text
app/auth/routes.py
```

Function:

```python
validar_complejidad_password()
```

Current requirements:

```text
minimum 8 characters
at least one number
at least one uppercase letter
at least one special character
```

The accepted special-character expression currently checks:

```text
!@#$%^&*(),.?":{}|<>
```

This validator is currently used during:

```text
initial administrator setup
initial mandatory password change
user creation
profile password change
```

Any new password-changing workflow should reuse the existing validation mechanism unless the password policy itself is intentionally being changed.

---

# 6. Initial Application Setup

Route:

```text
GET/POST /auth/setup
```

Function:

```python
setup()
```

Rate limit:

```text
3 requests per minute
```

The application also checks globally whether an administrator exists.

This occurs in:

```text
app/__init__.py
```

through:

```python
check_setup_needed()
```

If no administrator exists, requests are redirected to:

```text
/auth/setup
```

except for:

```text
static resources
auth.setup
```

---

# 7. First Administrator Creation

The setup process checks:

```python
User.query.filter_by(is_admin=True).first()
```

If an administrator already exists, setup redirects to login.

The initial administrator receives:

```text
is_admin = True
must_change_password = False
```

After creation, the setup process imports:

```python
TOOLS
```

from:

```text
app/tools_config.py
```

and creates a `UserTool` row for every registered tool.

Current registered tools are:

```text
csirt
virustotal
umbrella
vault
```

Therefore the initial administrator currently receives explicit tool rows for every tool.

However, administrator authorization does **not depend on those rows** because `User.has_tool()` automatically returns `True` for administrators.

An audit entry is generated for initial setup.

---

# 8. Login

Route:

```text
GET/POST /auth/login
```

Function:

```python
login()
```

Rate limit:

```text
5 requests per minute
```

Login flow:

```text
username + password
        ↓
find User by username
        ↓
check_password()
        ↓
login_user()
        ↓
audit login
        ↓
redirect
```

If credentials are invalid:

```text
login_failed audit event
flash error
redirect back to login
```

Successful logins generate:

```text
module: auth
action: login
object_type: usuario
```

Failed logins generate:

```text
module: auth
action: login_failed
object_type: usuario
```

---

# 9. Login Redirect Safety

The login route supports a `next` parameter.

Before redirecting to it, the code parses the URL with:

```python
urlparse()
```

and rejects values that:

```text
contain a network location
or
do not start with /
```

Invalid targets fall back to:

```text
main.dashboard
```

Agents modifying authentication redirects must preserve protection against external redirect targets.

---

# 10. Logout

Route:

```text
POST /auth/logout
```

Protection:

```text
@login_required
```

Logout is intentionally POST-only.

Current flow:

```text
audit logout
commit audit
logout_user()
redirect to login
```

Do not casually convert logout to GET because this changes CSRF and session behavior.

---

# 11. Mandatory Initial Password Change

User field:

```text
must_change_password
```

Default:

```text
True
```

A global authentication blueprint hook is implemented with:

```python
@bp.before_app_request
```

Function:

```python
check_password_change_needed()
```

If an authenticated user has:

```text
must_change_password = True
```

the user is redirected to:

```text
/auth/cambiar_password_inicial
```

Allowed endpoints while this flag is active are:

```text
auth.cambiar_password_inicial
auth.logout
static
```

This prevents users from accessing the application before replacing their initial password.

---

# 12. Initial Password Change

Route:

```text
GET/POST /auth/cambiar_password_inicial
```

Protection:

```text
@login_required
```

Workflow:

```text
new password
confirm password
        ↓
compare values
        ↓
validate complexity
        ↓
set_password()
        ↓
must_change_password = False
        ↓
audit
        ↓
commit
```

Successful completion redirects to:

```text
main.dashboard
```

Any change to user provisioning must account for this workflow.

---

# 13. Tool Authorization Model

Tool authorization uses:

```text
User
+
UserTool
```

Model:

```text
UserTool
```

Database table:

```text
user_tool
```

Composite primary key:

```text
user_id
tool_name
```

Relationship from `User`:

```python
authorized_tools
```

with:

```text
lazy = dynamic
cascade = all, delete-orphan
```

---

# 14. Tool Permission Check

Primary authorization method:

```python
User.has_tool(tool_name)
```

Current behavior:

```text
if user.is_admin:
    return True

otherwise:
    look for matching UserTool row
```

This means:

> Administrator access is implicit and overrides explicit `UserTool` assignments.

An administrator does not require a `UserTool` row to access a tool.

This behavior must be preserved unless authorization policy is intentionally redesigned.

---

# 15. Blueprint-Level Protection

Helper:

```python
proteger_blueprint(bp, nombre_permiso)
```

Defined in:

```text
app/utils.py
```

It registers:

```python
@bp.before_request
@login_required
```

and then checks:

```python
current_user.has_tool(nombre_permiso)
```

If access is denied:

```text
flash warning
redirect to main.dashboard
```

This is the existing mechanism for protecting complete operational modules.

Before implementing a new per-tool authorization mechanism, inspect whether `proteger_blueprint()` already satisfies the requirement.

---

# 16. Administrator Authorization

Decorator:

```python
admin_required
```

Defined in:

```text
app/utils.py
```

Current behavior:

```text
if current_user.is_admin is False
    flash "Acceso denegado."
    redirect to main.dashboard
```

Administrative routes generally combine:

```python
@login_required
@admin_required
```

This is currently used for user administration.

---

# 17. User Administration

Main administrative route:

```text
GET /auth/admin/usuarios
```

Protection:

```text
@login_required
@admin_required
```

The page loads:

```text
all User records
all UserTool records
```

and creates a mapping of tools assigned to each user.

---

# 18. User Creation

Route:

```text
POST /auth/admin/usuarios/crear
```

Protection:

```text
@login_required
@admin_required
```

Inputs include:

```text
username
password
nombre_completo
email
is_admin
tools[]
```

Checks currently include:

```text
email format
duplicate username
password complexity
```

After user creation:

```text
User is inserted
session is flushed to obtain user ID
UserTool rows are created
audit entry is added
transaction is committed
```

Default `must_change_password` behavior comes from the model:

```text
True
```

Therefore newly created users are expected to change their initial password on first authenticated use.

---

# 19. User Editing

Route:

```text
POST /auth/admin/usuarios/editar/<user_id>
```

Protection:

```text
@login_required
@admin_required
```

Current editable data:

```text
username
nombre_completo
email
administrator flag
tool permissions
optional password
```

Tool assignments are currently replaced by:

```text
delete all current UserTool rows
create rows from submitted tools[]
```

If a password is supplied, it is passed through:

```python
set_password()
```

The route records an audit entry describing:

```text
administrator state
assigned tools
whether password was changed
```

Important current behavior:

The edit route does not currently call the shared password-complexity validator before setting an optional administrator-supplied replacement password.

This is current implementation behavior and should not be silently changed as part of unrelated work.

If password-policy consistency is being addressed intentionally, this route should be included in the review.

---

# 20. User Deletion

Route:

```text
POST /auth/admin/usuarios/eliminar/<user_id>
```

Protection:

```text
@login_required
@admin_required
```

The route prevents an administrator from deleting their own currently authenticated account.

Current check:

```python
if user.id == current_user.id
```

Deletion generates an audit event before transaction completion.

Related `UserTool` rows are removed through the relationship cascade.

---

# 21. User Profile

Route:

```text
GET/POST /auth/perfil
```

Protection:

```text
@login_required
```

The profile currently supports:

```text
nombre_completo
email
VirusTotal API key
optional password change
VirusTotal quota lookup
```

---

# 22. Profile Update Transaction Behavior

Profile POST processing currently occurs in two logical blocks.

## Block 1

Always updates basic profile information:

```text
nombre_completo
email
optional VirusTotal API key
```

and immediately commits those changes.

## Block 2

Optionally processes a password change.

The password block checks:

```text
current password
new password confirmation
password complexity
```

and uses a second commit if the password is changed.

Important consequence:

> Basic profile changes may already be committed even if the later optional password-change portion fails validation.

Agents must understand this behavior before changing profile transaction semantics.

---

# 23. Email Validation

Email validation is implemented in:

```text
app/auth/routes.py
```

Function:

```python
validar_email()
```

Current behavior:

```text
empty email is accepted
non-empty email must match EMAIL_REGEX
```

The regex currently validates a conventional email structure.

It is used by:

```text
profile editing
user creation
```

Do not introduce a second email validator without a clear reason.

---

# 24. VirusTotal API Key Storage

The `User` model contains encrypted per-user VirusTotal credentials.

Methods:

```python
set_vt_key()
get_vt_key()
```

Encryption library:

```text
cryptography.fernet.Fernet
```

Encryption key source:

```python
current_app.config["SECRET_KEY_DB"]
```

Database field:

```text
virustotal_api_key
```

Plaintext API keys must never be logged or placed in documentation.

---

# 25. VirusTotal Key Encryption Flow

Saving:

```text
plaintext key
    ↓
Fernet(SECRET_KEY_DB)
    ↓
encrypt
    ↓
decode to string
    ↓
database
```

Reading:

```text
encrypted database value
    ↓
Fernet(SECRET_KEY_DB)
    ↓
decrypt
    ↓
plaintext in memory
```

If decryption fails:

```python
get_vt_key()
```

returns:

```text
None
```

rather than propagating the exception.

This failure behavior may affect code that interprets missing keys.

---

# 26. VirusTotal Profile Integration

The authentication profile directly imports:

```python
obtener_uso_api
```

from:

```text
app/virustotal/logic.py
```

When the profile is loaded with:

```text
?ver_cuota=1
```

and the user has a VirusTotal API key, the application requests quota information.

Therefore:

```text
AUTH
```

currently has a direct dependency on:

```text
VIRUSTOTAL
```

for this feature.

Agents should not assume authentication is fully isolated from VirusTotal.

---

# 27. Audit Logging

Authentication uses:

```python
log_audit()
```

from:

```text
app/models/audit.py
```

Authentication-related audit actions currently include:

```text
setup
login
login_failed
logout
change_password
edit_profile
create
edit
delete
```

Audit entries can store:

```text
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

The caller is responsible for committing the database session.

`log_audit()` only stages the audit entry.

---

# 28. Audit User Attribution

`log_audit()` uses:

```python
current_user.id
```

when a user is authenticated.

Otherwise:

```text
user_id = None
```

This allows events such as failed unauthenticated login attempts to still be recorded.

---

# 29. Audit IP Handling

The audit helper retrieves IP information from:

```text
X-Forwarded-For
```

falling back to:

```text
request.remote_addr
```

If `X-Forwarded-For` contains multiple addresses, only the first entry is retained.

Changes to reverse-proxy handling may affect the trust assumptions behind this behavior.

---

# 30. CSRF Protection

Global CSRF protection is initialized through:

```text
Flask-WTF CSRFProtect
```

in:

```text
app/__init__.py
```

Authentication POST routes therefore operate under the application's global CSRF configuration unless explicitly exempted elsewhere.

Do not disable CSRF to simplify automated changes or form handling.

---

# 31. Rate Limiting

The application initializes:

```text
Flask-Limiter
```

with:

```python
get_remote_address
```

as the key function.

Current explicit authentication limits include:

```text
/auth/setup
    3 per minute

/auth/login
    5 per minute
```

There are no default global limiter rules configured in `app/extensions.py`.

Do not assume all authentication endpoints are rate-limited.

---

# 32. Security Headers

Although not part of the auth blueprint itself, global response headers are applied by:

```text
app/__init__.py
```

Current headers include:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Authentication-related changes should not remove or bypass these headers.

---

# 33. Current Authorization Layers

The current access model can be summarized as:

```text
Unauthenticated user
        │
        ▼
Flask-Login
        │
        ▼
Authenticated user
        │
        ├── admin route
        │       ↓
        │   admin_required
        │
        └── operational tool
                ↓
          proteger_blueprint()
                ↓
          current_user.has_tool()
                │
        ┌───────┴─────────┐
        ▼                 ▼
     admin             normal user
        │                 │
      allow          UserTool lookup
```

---

# 34. Tool Registry Relationship

Available application tools are defined centrally in:

```text
app/tools_config.py
```

Current keys:

```text
csirt
virustotal
umbrella
vault
```

These names are also used as permission identifiers in:

```text
UserTool.tool_name
```

Therefore changing a tool key can impact:

```text
navigation
user permissions
existing UserTool records
blueprint protection
administrator UI
```

Tool identifiers should be treated as persistent authorization identifiers, not merely display names.

---

# 35. Adding a New Protected Tool

When adding a new operational tool, authentication-related work may include:

```text
1. add tool to app/tools_config.py
2. create/register blueprint
3. protect blueprint with proteger_blueprint()
4. expose tool in user administration
5. determine existing-user authorization behavior
6. update documentation
7. consider migration/data implications
```

Do not assume adding a `TOOLS` entry automatically grants normal users access.

Administrators receive access automatically through:

```python
User.has_tool()
```

Normal users require a matching `UserTool` assignment.

---

# 36. High-Risk Changes

Changes in the following areas require additional review:

```text
password hashing
password policy
login flow
mandatory password change
administrator privileges
UserTool permissions
proteger_blueprint()
admin_required
SECRET_KEY_DB
VirusTotal API-key encryption
CSRF
login rate limiting
redirect validation
user deletion
audit logging
```

These changes may affect the entire application.

---

# 37. Known Current Characteristics

The following are verified characteristics of the current implementation.

### Administrators bypass tool assignments

```python
User.has_tool()
```

returns `True` immediately for administrators.

### Normal users use explicit tool assignments

Permissions are stored in:

```text
user_tool
```

### Newly created users normally require an initial password change

Because:

```text
must_change_password
```

defaults to:

```text
True
```

### Initial administrator does not require initial password change

Setup explicitly creates the administrator with:

```text
must_change_password = False
```

### Authentication is not completely isolated

The profile route directly calls VirusTotal logic for quota information.

### Authentication actions are audited

Both successful and failed login activity is recorded.

### Logout is POST-only

This behavior should be preserved unless deliberately redesigned.

---

# 38. Areas Requiring Caution but Not Automatic Refactoring

The following observations describe current implementation details.

They are not instructions to change them automatically.

## Administrator-edited passwords

The administrator user-edit route currently uses:

```python
set_password()
```

for a supplied replacement password but does not invoke:

```python
validar_complejidad_password()
```

## Profile transactions

Profile basic information is committed before optional password processing.

## Authorization helpers

`admin_required` assumes it is used with authentication protection.

Current routes combine it with:

```python
@login_required
```

Do not use these observations as justification for unrelated refactoring.

Record proposed improvements in:

```text
docs/technical-debt/
```

or address them through an explicit task.

---

# 39. Context Loading for Auth Tasks

For most authentication work, load:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/systems/auth.md
app/auth/routes.py
app/models/user.py
app/utils.py
```

Add:

```text
app/models/audit.py
```

when changing auditing.

Add:

```text
app/extensions.py
app/__init__.py
```

when changing Flask-Login, CSRF, limiter configuration, global request hooks, or application initialization.

Add:

```text
app/tools_config.py
```

when changing tool permissions.

Add:

```text
app/virustotal/logic.py
```

only when changing VirusTotal profile/quota functionality.

Do not load unrelated operational modules by default.

---

# 40. Invariants for Agents

Unless an explicit requirement says otherwise, preserve these invariants:

```text
Passwords remain hashed.

VirusTotal API keys remain encrypted at rest.

Normal tool access remains authenticated.

Tool access continues to use UserTool / has_tool.

Administrators retain global tool access.

Administrative user management remains admin-only.

Initial-password enforcement remains functional.

Login redirect validation remains protected against external targets.

CSRF protection remains enabled.

Authentication events remain auditable.

Secrets are never logged or documented.
```

If a requested change conflicts with one of these invariants, the agent must identify the conflict before implementing the change.