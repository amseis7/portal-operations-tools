---
name: portal-runtime-environment-change
description: >
  Project-specific workflow for changes involving application startup, runtime
  configuration, dependencies, environment variables, Flask initialization,
  database bootstrap, development/production servers, certificates, paths,
  packaging, Docker, or cross-platform execution in Portal Operations Tools.
  Use when modifying run.py, server.py, config.py, requirements.txt, Docker files,
  PyInstaller configuration, environment-dependent behavior, startup migrations,
  or deployment/runtime compatibility.
---

# Portal Runtime and Environment Change

## Purpose

Use this skill whenever a change affects how Portal Operations Tools:

- starts;
- loads configuration;
- resolves environment variables;
- initializes extensions;
- prepares the database;
- selects its HTTP server;
- handles certificates;
- resolves filesystem paths;
- installs dependencies;
- runs across Windows, macOS, or Linux;
- builds with PyInstaller;
- runs through Docker;
- behaves differently between development and production.

Typical files include:

```text
run.py
server.py
config.py
requirements.txt
Dockerfile
docker-compose.yml
Portal-Operations-Tools.spec
app/__init__.py
app/extensions.py
```

This skill does not replace:

- `portal-database-change`
- `portal-security-change`
- `/investigate`
- `/plan-eng-review`
- `/review`
- `/careful`
- `/codex`

Use those when their concerns also apply.

---

# 1. Load Project Context First

Before changing runtime or environment behavior, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/technical-debt/current.md
```

Then inspect only the runtime files relevant to the task.

Typical files:

```text
config.py
run.py
server.py
app/__init__.py
app/extensions.py
requirements.txt
```

If deployment or packaging is involved, also inspect:

```text
Dockerfile
docker-compose.yml
Portal-Operations-Tools.spec
```

Do not load every subsystem unless the startup change affects it directly.

---

# 2. Establish the Actual Startup Paths

Before modifying startup behavior, identify every supported entry point.

Current repository may include:

```text
run.py
server.py
Docker
PyInstaller executable
Flask CLI
```

Determine which are actually used.

Do not assume:

```text
run.py
```

and:

```text
server.py
```

behave identically.

Trace each relevant startup path separately.

---

# 3. Map Startup Order

For the affected entry point, establish the actual order.

Typical concerns:

```text
load .env
        ↓
import configuration
        ↓
create Flask application
        ↓
initialize extensions
        ↓
initialize/migrate database
        ↓
register Blueprints
        ↓
configure scheduler/background work
        ↓
start HTTP server
```

Import order matters.

Do not move imports casually when configuration is evaluated at import time.

---

# 4. Environment Must Be Loaded Before Dependent Imports

If application configuration requires environment variables during module import,
the environment must be available first.

Avoid:

```python
from app import create_app
from dotenv import load_dotenv

load_dotenv()
```

when importing `app` causes `config.py` to evaluate required variables.

Prefer conceptually:

```python
from dotenv import load_dotenv

load_dotenv()

from app import create_app
```

when that matches the application architecture.

Do not rely on accidental shell environment state.

---

# 5. `.env` Is Local Runtime Configuration

The `.env` file is sensitive runtime configuration.

Never:

```text
commit .env
print its complete contents
include real values in documentation
copy real secrets into examples
```

Variable names may be inspected or documented when necessary.

Values remain protected.

Before Git operations involving configuration, verify `.env` remains ignored.

---

# 6. Known Environment Variables

Current project configuration may include variables such as:

```text
SECRET_KEY
SECRET_KEY_DB
CREDENTIAL_MANAGER_KEY
VAULT_KEY
VAULT_KDBX_PATH
VAULT_KDBX_PASSWORD
UMBRELLA_RETRY_INITIAL_DELAY
UMBRELLA_RETRY_MAX
UMBRELLA_RETRY_MAX_DELAY
```

Do not assume all variables are mandatory.

Inspect `config.py` and the owning subsystem to determine:

```text
required globally
optional globally
required only for a feature
fallback configuration
default value
```

Do not make optional subsystem configuration globally fatal without a reason.

---

# 7. Global Required Variables

A variable should fail application startup only if the application cannot safely function without it.

Examples may include core application or encryption keys.

Before adding:

```python
raise RuntimeError(...)
```

during configuration import, ask:

```text
Does every portal deployment require this?

Does every subsystem require it?

Could the portal start safely with that feature disabled?

Would failure later at feature use be more appropriate?
```

Use fail-fast behavior for genuine global invariants.

Do not use it mechanically.

---

# 8. Secret Configuration

If configuration contains:

```text
encryption keys
API credentials
passwords
client secrets
```

also apply:

```text
portal-security-change
```

Do not log secrets during startup diagnostics.

Safe:

```text
Vault encryption key configured
```

Unsafe:

```text
VAULT_KEY=<actual key>
```

---

# 9. Do Not Invent Secret Defaults

Never provide insecure fallback values such as:

```python
SECRET_KEY = os.getenv("SECRET_KEY", "secret")
```

for production-sensitive secrets.

A development-only fallback must be deliberate, scoped, and safe.

Security-critical secrets should not silently become predictable.

---

# 10. Configuration Source Precedence

When a setting can come from multiple sources, define precedence explicitly.

Possible sources:

```text
environment
database configuration
application defaults
command-line options
runtime-generated values
```

Example:

```text
database setting
        ↓
environment fallback
```

may be intentional for a subsystem.

Do not reverse precedence accidentally.

---

# 11. Avoid Configuration Duplication

Do not read the same environment variable independently throughout unrelated modules when centralized configuration already exists.

Prefer existing project configuration patterns.

Avoid:

```python
os.getenv(...)
```

scattered across routes and business logic when `current_app.config` or existing configuration objects are the established mechanism.

Do not refactor existing configuration globally unless required.

---

# 12. Cross-Platform Paths

The portal may run on:

```text
Windows
macOS
Linux
```

Avoid platform-specific path literals.

Bad:

```python
"certificado\\cert.pem"
```

Better:

```python
os.path.join("certificado", "cert.pem")
```

or:

```python
Path("certificado") / "cert.pem"
```

following existing project conventions.

Do not assume `/` or `\` semantics manually.

---

# 13. Resolve Paths Relative to the Application

Do not assume the current shell working directory is always the repository root.

When a runtime file must locate project resources, determine whether it should be resolved relative to:

```text
project base directory
instance directory
configured absolute path
current working directory
```

Prefer stable paths derived from the application location when appropriate.

Example conceptually:

```python
BASE_DIR = Path(__file__).resolve().parent
```

Do not introduce absolute paths tied to one developer machine.

---

# 14. Never Hardcode User-Specific Paths

Do not commit paths such as:

```text
/Users/alexis/...
C:\Users\Alexis\...
/home/specific-user/...
```

Runtime configuration must remain portable.

User-specific paths belong in local configuration when genuinely necessary.

---

# 15. Certificates

If the HTTP server supports TLS certificates, determine:

```text
certificate path
private-key path
whether TLS is optional
fallback behavior
permissions
packaging behavior
```

Do not log or expose private-key content.

Do not commit private keys.

A certificate path being present in source does not mean the certificate/key files themselves belong in Git.

---

# 16. Certificate Fallback Behavior

If startup supports behavior such as:

```text
certificate exists
→ HTTPS

certificate missing
→ HTTP
```

preserve or intentionally change that contract.

Do not silently change ports or protocols.

Document operational consequences when changing:

```text
8080
8443
HTTP
HTTPS
```

or their actual configured equivalents.

---

# 17. Development Server vs Production Server

Distinguish:

```text
Flask development server
```

from production-serving options such as:

```text
Cheroot
Waitress
```

Do not use Flask debug server as evidence that production startup works.

Likewise, do not modify production startup merely to solve a development-only issue unless appropriate.

---

# 18. Debug Mode

Debug mode may:

```text
reload processes
execute startup code multiple times
restart background threads
register schedulers repeatedly
expose debugging information
```

Do not enable debug mode in production runtime paths.

Be especially careful when startup performs:

```text
database migration
scheduler registration
thread startup
external calls
```

---

# 19. Flask Application Factory

The application uses an application factory.

Preserve this architecture.

Do not create a second global Flask application instance as a shortcut.

Shared initialization belongs in the established factory or extensions architecture when appropriate.

Read:

```text
app/__init__.py
app/extensions.py
```

before modifying initialization.

---

# 20. Import-Time Side Effects

Minimize new import-time side effects.

Avoid triggering during import:

```text
network requests
database mutations
file creation
background threads
scheduler execution
provider authentication
```

unless existing architecture explicitly requires it.

Imports should primarily define objects and configuration.

Runtime actions should occur intentionally.

---

# 21. Extension Initialization

When modifying Flask extensions, preserve the established pattern.

Examples may include:

```text
SQLAlchemy
Flask-Migrate
Flask-Login
CSRF
APScheduler
rate limiting
```

Do not instantiate duplicate extension objects inside individual modules.

Prefer:

```text
extension = Extension()
```

then:

```text
extension.init_app(app)
```

when that is the current architecture.

---

# 22. Blueprint Registration

Runtime refactors must not accidentally omit or register Blueprints twice.

When changing application initialization, verify current functional modules such as:

```text
auth
main
csirt
virustotal
umbrella
vault
```

remain registered correctly.

Do not use stale documentation as the complete Blueprint list.

Inspect source.

---

# 23. Tool Authorization Registration

If application initialization is responsible for protecting Blueprints, do not accidentally bypass:

```text
proteger_blueprint()
```

when refactoring registration.

Startup refactors can create security regressions even without touching route code.

If authorization registration changes, also use:

```text
portal-security-change
```

---

# 24. Database Startup Behavior

Database initialization is especially sensitive.

Current startup paths may not behave identically.

One path may use behavior conceptually like:

```text
fresh DB
→ migrations
```

while another may use:

```text
fresh DB
→ db.create_all()
→ alembic stamp
```

Do not normalize these flows casually.

First inspect actual implementation.

---

# 25. Database Bootstrap Must Be Deliberate

For database initialization, distinguish:

```text
fresh database creation
existing database upgrade
legacy database without alembic_version
normal startup
```

Each may require different handling.

Do not assume an empty database simply because development uses one.

---

# 26. Alembic Is the Schema History

The accepted persistence architecture uses:

```text
SQLAlchemy
+
Alembic / Flask-Migrate
```

Do not introduce a startup strategy that bypasses migration history for normal schema evolution.

If changing bootstrap behavior, also use:

```text
portal-database-change
```

---

# 27. `db.create_all()` Is Not Migration Management

`db.create_all()` can create tables represented by current models.

It does not reproduce historical migrations or data transformations.

Do not treat:

```python
db.create_all()
```

as equivalent to:

```text
flask db upgrade
```

If bootstrap currently uses both strategies in different entry points, treat that discrepancy carefully.

---

# 28. Alembic `stamp`

`stamp()` changes migration version metadata without applying migration operations.

Do not use it casually.

Before stamping, establish why the physical schema can safely be considered equivalent to that revision.

Incorrect stamping can create:

```text
schema/version mismatch
future migration failures
missing columns
missing data transformations
```

---

# 29. Legacy Database Detection

If startup attempts to recognize old databases without Alembic metadata, preserve compatibility unless deliberately changing it.

Inspect:

```text
table detection
alembic_version detection
stamp behavior
upgrade behavior
```

Do not remove legacy handling merely because a new local database does not need it.

---

# 30. Startup Migrations

Automatically running migrations during application startup has operational tradeoffs.

Before modifying this behavior, consider:

```text
multiple app processes
concurrent startup
migration failure
long-running migration
rollback
permissions
production deployment
```

Do not introduce automatic migration behavior into another startup path without explicit review.

---

# 31. Multiple Processes

If multiple application processes can start simultaneously, database initialization and migration logic may run concurrently.

Be careful with:

```text
db.create_all()
upgrade()
stamp()
scheduler registration
one-time initialization
```

Do not assume a single process unless deployment guarantees it.

---

# 32. Dependencies

When code imports a third-party module, ensure the runtime dependency is declared.

For Python packages, inspect:

```text
requirements.txt
```

Examples of previously relevant packages include:

```text
Flask-WTF
Flask-Migrate
cheroot
```

Do not rely solely on packages installed manually in a developer virtual environment.

A clean install must reproduce the environment.

---

# 33. Requirements Are the Reproducible Contract

If:

```bash
pip install some-package
```

is required to make committed source run, evaluate whether:

```text
some-package
```

belongs in:

```text
requirements.txt
```

Do not leave essential dependencies as undocumented local state.

---

# 34. Do Not Dump Entire Local Environment Into Requirements

Avoid solving missing dependencies with:

```bash
pip freeze > requirements.txt
```

unless the project intentionally maintains a fully pinned freeze.

That can add unrelated packages from the developer machine.

Prefer explicit dependency maintenance consistent with the existing file.

---

# 35. Dependency Versions

Before changing version constraints, determine whether the task actually requires it.

Do not upgrade:

```text
Flask
SQLAlchemy
Alembic
WTForms
requests
```

merely because a newer version exists.

Dependency upgrades can introduce broad regressions.

Keep environment fixes scoped.

---

# 36. New Dependencies

Before adding a dependency:

```text
check whether project already has equivalent functionality
check standard library
check maintenance status
check platform compatibility
check package size/complexity
```

Avoid dependencies for trivial functionality.

---

# 37. Clean Environment Validation

For dependency changes, validate conceptually or actually against a clean environment when practical.

Typical flow:

```bash
python3 -m venv <temporary-env>
source <temporary-env>/bin/activate
pip install -r requirements.txt
```

Then perform a smoke test.

Do not destroy the user's working environment merely to test this.

Use disposable environments.

---

# 38. Virtual Environments

Local virtual environments are runtime artifacts.

Do not commit:

```text
venv/
.venv/
```

unless the project has an unusual explicit policy.

Dependencies belong in reproducible configuration, not committed environment directories.

---

# 39. Python Version Compatibility

When changing runtime code or dependencies, determine supported Python versions from existing project evidence.

Do not introduce syntax or package versions incompatible with the deployed runtime without deliberate decision.

Avoid assuming the Mac developer version is the deployment version.

---

# 40. macOS Compatibility

When validating on macOS, pay attention to:

```text
filesystem paths
case sensitivity differences
certificate locations
shell commands
native package dependencies
PyInstaller behavior
```

Do not solve a Mac-specific problem by breaking Windows or Linux.

---

# 41. Windows Compatibility

Avoid introducing shell/runtime assumptions such as:

```text
bash-only startup command
Unix-only path
chmod requirement
POSIX signal handling
```

into core application behavior unless the project intentionally drops Windows support.

Developer helper scripts may be platform-specific when clearly scoped.

---

# 42. Linux Compatibility

Production-like Linux behavior may differ in:

```text
file permissions
case-sensitive filesystem
service user
network binding
certificate permissions
system timezone
```

Keep runtime code portable unless deployment is explicitly platform-specific.

---

# 43. Shell Commands in Documentation

When adding setup instructions, provide commands appropriate for the relevant environment.

For this repository, do not assume PowerShell is always available.

Prefer portable or Bash/zsh instructions when working on macOS/Linux.

If Windows requires different commands, label them clearly.

---

# 44. Server Binding

Changing:

```text
127.0.0.1
0.0.0.0
```

has operational and security implications.

Do not change bind address casually.

`0.0.0.0` makes the service reachable through available network interfaces, subject to firewall/network controls.

If changing binding behavior, explain why.

---

# 45. Ports

Port changes can affect:

```text
bookmarks
reverse proxies
firewalls
Docker mappings
documentation
TLS expectations
```

Do not change ports as incidental cleanup.

Search relevant deployment files before changing them.

---

# 46. Docker

If modifying Docker behavior, inspect:

```text
Dockerfile
docker-compose.yml
.dockerignore
```

Determine:

```text
build context
Python installation
dependency installation
environment injection
volume mounts
ports
database persistence
runtime command
```

Do not assume Docker follows the same startup path as local execution.

---

# 47. Docker Secrets

Do not bake secrets into Docker images.

Avoid:

```dockerfile
ENV SECRET_KEY=actual-secret
```

or copying local `.env` into the image.

Runtime secrets should be supplied through appropriate environment/configuration mechanisms.

---

# 48. Docker Database State

When changing Docker startup, determine where SQLite data resides.

Be careful with:

```text
container ephemeral filesystem
bind mounts
named volumes
instance/
```

Do not accidentally move persistent database storage into an ephemeral layer.

---

# 49. `.dockerignore`

Ensure build context excludes unnecessary or sensitive runtime artifacts where appropriate.

Potentially sensitive/generated content includes:

```text
.env
instance/
venv/
.git/
build/
dist/
__pycache__/
```

Follow current repository policy.

Do not expose secrets to Docker build context unnecessarily.

---

# 50. PyInstaller

If modifying packaging behavior, inspect:

```text
Portal-Operations-Tools.spec
```

and current runtime resource resolution.

PyInstaller may change:

```text
module discovery
filesystem paths
templates/static location
certificate paths
environment behavior
working directory
```

Do not assume normal source-tree paths work identically in a bundled executable.

---

# 51. Bundled Resource Paths

When code needs files in both normal Python and PyInstaller builds, follow the existing packaging convention.

Do not introduce a second resource-resolution helper unnecessarily.

Test:

```text
source execution
bundled execution
```

when affected.

---

# 52. Generated Build Artifacts

Do not edit or commit generated directories as source changes unless explicitly required.

Typical generated content:

```text
build/
dist/
__pycache__/
```

Change the source or packaging specification that produces them instead.

---

# 53. Startup Logging

Startup logs should help diagnose configuration without exposing secrets.

Useful:

```text
application started
server type
port
database migration status
optional feature configured/not configured
certificate present/missing
```

Unsafe:

```text
secret keys
passwords
tokens
full environment dump
database sensitive contents
```

---

# 54. Failures Should Be Actionable

When startup cannot continue, provide a clear error indicating:

```text
what configuration category is missing
which dependency is unavailable
which file is missing
which migration failed
```

Do not expose secret values.

Good:

```text
CREDENTIAL_MANAGER_KEY is required
```

Bad:

```text
Expected secret abc123 but received ...
```

---

# 55. Optional Feature Failure

If only one optional subsystem is misconfigured, evaluate whether the entire application should fail.

Possible behavior:

```text
portal starts
feature reports configuration missing
```

may be preferable to:

```text
entire portal refuses to start
```

but only when safe.

Do not weaken mandatory security initialization.

---

# 56. Import Errors

When a runtime import fails:

```text
ModuleNotFoundError
```

first determine whether the package is:

```text
missing from requirements
optional
incorrectly imported
platform-specific
```

Do not simply install the module and move on.

Reproducibility requires identifying why the dependency was absent.

---

# 57. Configuration Validation

For numeric settings such as retry values, validate:

```text
type
range
default
```

Do not let invalid environment strings fail later in unrelated runtime code.

Example concerns:

```text
negative retry count
zero/negative delay
invalid port
non-integer value
```

Follow current configuration conventions.

---

# 58. Boolean Configuration

Environment variables are strings.

Do not use naïve behavior such as:

```python
bool(os.getenv("FEATURE_ENABLED"))
```

because:

```text
"false"
```

is truthy in Python.

Use an explicit parser if boolean environment settings are introduced.

Do not create a new helper if an existing one already exists.

---

# 59. Configuration Documentation

If adding a required or important environment variable, document:

```text
name
purpose
required/optional
safe example format
default behavior
```

Do not document real secrets.

If there is an existing environment example file, update it only if repository policy permits and it contains placeholders only.

---

# 60. `.env.example`

If the repository uses an example environment file, it may contain:

```text
VARIABLE_NAME=
```

or synthetic placeholders.

Never copy actual `.env` values into it.

If no such file exists, do not create one automatically unless useful for the task.

---

# 61. Runtime Files and Git

Before making environment changes, inspect:

```bash
git status --short
```

Do not accidentally stage:

```text
.env
instance/app.db
*.db
*.kdbx
*.keyx
private keys
venv/
build/
dist/
```

Runtime artifacts are not source code.

---

# 62. Private Certificates and Keys

Distinguish between:

```text
public certificate
```

and:

```text
private key
```

A private key should not be committed.

If the repository already tracks one, do not expose its contents.

Report the security concern separately.

Do not automatically delete tracked files without explicit approval.

---

# 63. Clean Git Changes

Environment fixes often generate unrelated artifacts.

Before committing, review:

```bash
git status --short
git diff
```

Separate:

```text
source/configuration changes
```

from:

```text
runtime/generated files
```

Do not use:

```bash
git add .
```

blindly when environment work may have created sensitive files.

---

# 64. Startup Changes Can Affect Security

Changes to startup can indirectly affect:

```text
CSRF
login manager
Blueprint protection
encryption initialization
rate limiting
scheduler
database access
```

If changing initialization order, verify security extensions still initialize correctly.

Use:

```text
portal-security-change
```

when a security boundary is affected.

---

# 65. Startup Changes Can Affect Background Jobs

Changes to application creation may alter:

```text
scheduler registration
thread startup
duplicate jobs
debug reload behavior
```

If background work changes, also use:

```text
portal-background-job-change
```

Do not treat scheduler regressions as unrelated to startup changes.

---

# 66. Startup Changes Can Affect Database State

If modifying:

```text
upgrade()
stamp()
db.create_all()
migration detection
database creation
```

also use:

```text
portal-database-change
```

Database bootstrap is part of schema-management architecture.

---

# 67. Avoid Broad Startup Refactors

Do not turn a small environment fix into a redesign of:

```text
configuration classes
application factory
server architecture
database bootstrap
deployment
```

unless necessary.

Prefer:

```text
smallest portable fix
+
validation
```

Startup code is high leverage and can break the whole application.

---

# 68. Runtime Consistency

Where reasonable, startup entry points should produce equivalent application behavior.

If:

```text
run.py
```

and:

```text
server.py
```

differ intentionally, document why.

If they differ accidentally, treat that as technical debt or an explicit cleanup task.

Do not silently normalize them during unrelated work.

---

# 69. Current Bootstrap Divergence

If one startup path initializes a fresh database through migrations while another uses:

```text
db.create_all()
+
stamp()
```

treat that divergence as significant.

Before resolving it, determine:

```text
historical reason
fresh-install expectations
existing deployment compatibility
migration history
packaged executable behavior
Docker behavior
```

Do not choose one simply because it appears cleaner.

---

# 70. Rate Limiter Runtime Configuration

If the application uses in-memory rate-limit storage, understand that it may be suitable for development but not ideal for multi-process/production durability.

Do not change the rate-limiter backend during unrelated runtime work.

If production hardening requires a persistent/shared backend, treat it as a separate infrastructure decision.

---

# 71. Warnings

Distinguish:

```text
fatal errors
```

from:

```text
development/runtime warnings
```

Do not redesign architecture merely to silence a harmless warning.

However, record operationally meaningful warnings as technical debt when appropriate.

---

# 72. Smoke Test After Runtime Changes

At minimum validate:

```text
application imports
application starts
login page loads
login works
dashboard loads
database initializes/upgrades correctly
major Blueprints remain reachable
server binds to expected host/port
```

Do not declare runtime changes complete because Python syntax passes.

---

# 73. Fresh Database Test

If startup/database initialization changes, validate against a disposable fresh database.

Verify:

```text
database is created successfully
migrations/version metadata are correct
admin/bootstrap flow works as expected
application starts again afterward
```

Do not use the user's real runtime database for destructive tests.

---

# 74. Existing Database Test

Also consider an existing migrated database.

Verify:

```text
startup does not recreate tables
upgrade path remains valid
existing data is preserved
Alembic version is correct
```

Fresh-install success alone is insufficient.

---

# 75. Missing Configuration Test

When changing configuration behavior, test expected missing-variable cases.

Examples:

```text
mandatory secret missing
optional provider config missing
certificate missing
optional KDBX path missing
```

Verify failure or fallback matches intended semantics.

---

# 76. Dependency Test

If `requirements.txt` changes, verify imports for affected packages.

Useful checks may include:

```bash
python3 -c "import flask_wtf"
python3 -c "import flask_migrate"
python3 -c "import cheroot"
```

depending on the actual change.

Do not add generic import tests for unrelated dependencies.

---

# 77. Cross-Platform Review

For runtime/path changes, inspect the diff specifically for:

```text
hardcoded separators
absolute user paths
shell-specific commands
platform-only APIs
case-sensitive path assumptions
```

Do not claim cross-platform compatibility without checking these areas.

---

# 78. Docker Validation

If Docker files changed, verify at least:

```text
image builds
dependencies install
startup command is valid
port mapping is correct
environment is supplied safely
persistent data location is preserved
```

Do not require Docker validation for runtime changes unrelated to Docker.

---

# 79. PyInstaller Validation

If the `.spec` or bundled runtime changed, verify build behavior when practical.

At minimum inspect:

```text
hidden imports
data files
template/static inclusion
runtime paths
startup command
```

Do not claim packaged compatibility without either testing or explicitly stating it was not tested.

---

# 80. Tests Must Reflect the Change

Use the smallest meaningful validation set.

Examples:

### Dependency-only change

```text
clean install
import
application startup
```

### Path portability change

```text
path resolution
application startup
certificate detection
```

### Database bootstrap change

```text
fresh DB
existing DB
migration state
startup
```

### Server change

```text
bind
HTTP/HTTPS selection
request smoke test
shutdown behavior
```

Do not run unrelated exhaustive tests automatically if targeted validation is sufficient.

---

# 81. Documentation

After runtime/environment changes, determine whether to update:

```text
docs/PROJECT_MAP.md
docs/technical-debt/current.md
docs/systems/
docs/decisions/
README/setup documentation if present
```

Examples:

```text
startup path changed
→ update PROJECT_MAP or setup docs

bootstrap divergence resolved
→ update technical debt

new runtime architecture
→ ADR

new required environment variable
→ setup/config documentation
```

Do not create an ADR for a simple missing dependency fix.

---

# 82. Architectural Runtime Decisions

Consider an ADR only for significant decisions such as:

```text
canonical production server
canonical database bootstrap model
new deployment architecture
dropping platform support
new secrets source
centralized configuration architecture
new container-only deployment strategy
```

Routine portability fixes do not need ADRs.

---

# 83. Recommended Workflow for Startup Bugs

For an application startup failure:

```text
/investigate
        ↓
identify actual failure stage
        ↓
portal-runtime-environment-change
        ↓
implement smallest fix
        ↓
startup smoke test
        ↓
/review
```

Do not install random packages until the root cause is known.

---

# 84. Recommended Workflow for Dependency Problems

For a missing Python package:

```text
/investigate
        ↓
confirm import requirement
        ↓
check requirements.txt
        ↓
portal-runtime-environment-change
        ↓
install locally if needed
        ↓
update dependency declaration
        ↓
clean-install validation
        ↓
/review
```

Local installation alone is not the complete fix.

---

# 85. Recommended Workflow for Database Bootstrap Changes

```text
/plan-eng-review if non-trivial
        ↓
portal-runtime-environment-change
        +
portal-database-change
        ↓
fresh DB validation
        ↓
existing DB validation
        ↓
/review
        ↓
/codex review if high-risk
```

---

# 86. Recommended Workflow for Security-Sensitive Configuration

```text
portal-runtime-environment-change
        +
portal-security-change
        ↓
implementation
        ↓
secret-exposure review
        ↓
startup validation
        ↓
/review
```

---

# 87. Required Pre-Implementation Summary

Before implementing a non-trivial runtime/environment change, summarize:

```md
## Runtime / Environment Change

### Objective

What startup, configuration, dependency, deployment, or portability behavior needs to change.

### Affected Entry Points

Which of run.py, server.py, Docker, PyInstaller, Flask CLI, or other paths are affected.

### Current Behavior

How the application currently initializes in those paths.

### Configuration

Environment variables, defaults, secrets, and source precedence involved.

### Dependencies

Any package installation or requirements changes required.

### Database Bootstrap

Whether fresh/existing database initialization or Alembic behavior is affected.

### Server Behavior

Development/production server, host, port, HTTP/HTTPS, and certificate implications.

### Cross-Platform Impact

Windows, macOS, and Linux considerations.

### Proposed Change

The smallest implementation that satisfies the requirement.

### Risks

Startup failure, missing dependency, migration mismatch, secret exposure,
platform regression, duplicate initialization, or deployment regression risks.

### Validation

Startup, fresh DB, existing DB, dependency, path, and deployment checks required.
```

Keep the summary proportional to the task.

---

# 88. Completion Checklist

Before declaring a runtime/environment change complete, verify:

```text
[ ] Relevant startup entry points were identified
[ ] Import/configuration order was checked
[ ] Environment variables load before dependent imports where required
[ ] No secret values were exposed
[ ] `.env` remains untracked
[ ] Required vs optional configuration was defined correctly
[ ] Paths are portable
[ ] No developer-specific absolute paths were introduced
[ ] Certificates/private keys remain protected
[ ] Production and development server behavior was distinguished
[ ] Application factory architecture was preserved
[ ] Extensions initialize correctly
[ ] Blueprints remain registered
[ ] Tool authorization registration remains intact
[ ] Database bootstrap behavior was reviewed if affected
[ ] Alembic history remains valid
[ ] `db.create_all()` was not treated as migration history
[ ] Dependencies are declared reproducibly
[ ] No unrelated local packages were dumped into requirements
[ ] Python/platform compatibility was considered
[ ] Background scheduler/thread initialization was checked if affected
[ ] Application starts successfully
[ ] Login/dashboard smoke test succeeds
[ ] Fresh database behavior was tested if affected
[ ] Existing database behavior was tested if affected
[ ] Missing configuration behavior was tested if affected
[ ] Docker behavior was validated if changed
[ ] PyInstaller behavior was validated or explicitly reported untested if changed
[ ] Generated/runtime files were not accidentally staged
[ ] Documentation was updated if needed
[ ] Relevant technical debt was updated if resolved
[ ] Final diff was reviewed
```

---

# 89. Core Rule

Never treat a runtime problem as merely:

```text
install package
change path
start server
done
```

For this project, runtime behavior means:

```text
configuration order
+
secrets
+
dependencies
+
application factory
+
extension initialization
+
database bootstrap
+
server behavior
+
filesystem portability
+
packaging
+
deployment
+
cross-platform compatibility
+
reproducibility
```

A fix is complete only when another clean environment can reproduce the intended
application behavior without depending on undocumented local state.