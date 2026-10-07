---
name: portal-new-operational-tool
description: >
  Project-specific workflow for adding a new operational tool or functional module
  to Portal Operations Tools. Use when creating a new Flask Blueprint, registering
  a new tool in the portal, adding dashboard access, permissions, routes, templates,
  models, migrations, audit behavior, background work, external integrations, or
  subsystem documentation. Ensures new tools fit the existing modular monolith and
  authorization architecture without introducing unnecessary frameworks.
---

# Portal New Operational Tool

## Purpose

Use this skill when adding a genuinely new operational capability to Portal Operations Tools.

Examples:

- a new portal module;
- a new Flask Blueprint;
- a new operational card in the dashboard;
- a new tool with `UserTool` permissions;
- a new set of routes/templates;
- a new external integration exposed as a portal tool;
- a new subsystem with its own models;
- a new operational workflow that does not belong inside an existing subsystem.

This skill exists to ensure that new tools integrate cleanly with the existing application instead of creating a second architecture.

It does not replace:

- `/plan-eng-review`
- `/review`
- `/investigate`
- `/careful`
- `/codex`
- `portal-database-change`
- `portal-security-change`
- `portal-external-api-change`

Use those when their concerns also apply.

---

## 1. First Question: Is This Really a New Tool?

Before creating a new subsystem, determine whether the requested behavior actually belongs inside an existing one.

Current major functional domains include:

```text
auth
main
csirt
virustotal
umbrella
vault
```

Ask:

```text
Does an existing subsystem already own this behavior?

Is this merely a new feature inside an existing tool?

Does this require separate tool-level permissions?

Does it represent a distinct operational workflow?

Would users reasonably expect it as a separate dashboard tool?
```

Do not create a new Blueprint merely because it makes the code look organized.

Prefer:

```text
existing subsystem
    +
new feature
```

when ownership is clear.

Create a new operational tool only when the functional boundary is real.

---

## 2. Load Project Context First

Before designing a new tool, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/decisions/ADR-001-flask-modular-monolith.md
docs/decisions/ADR-003-tool-authorization-model.md
```

If persistence is required, also read:

```text
docs/decisions/ADR-002-database-schema-migrations.md
```

If secrets are required, also read:

```text
docs/decisions/ADR-004-secrets-at-rest.md
```

Inspect:

```text
app/__init__.py
app/tools_config.py
app/extensions.py
```

and one or two existing tools that most closely resemble the requested feature.

Do not read every subsystem by default.

---

## 3. Check Technical Debt

Review relevant entries in:

```text
docs/technical-debt/current.md
```

A new tool must not copy known bad patterns simply because they already exist.

Examples:

```text
missing Blueprint-level authorization
plaintext temporary credentials
non-durable jobs
inconsistent audit commit behavior
GET routes that mutate state
```

Existing technical debt is not a template for new functionality.

---

## 4. Preserve the Modular Monolith

The accepted architecture is:

```text
one Flask application
        ↓
functional Blueprints/modules
        ↓
shared infrastructure
```

Do not introduce:

```text
microservices
separate backend servers
separate authentication systems
independent databases
internal HTTP APIs between local modules
new frameworks
```

unless a concrete requirement justifies them.

A new tool should normally fit inside:

```text
app/<tool_name>/
```

and run inside the existing Flask application.

---

## 5. Choose a Stable Tool Identifier

Every operational tool needs a stable internal identifier.

Example format:

```text
threat_hunting
asset_inventory
certificate_checker
```

Prefer:

```text
lowercase
snake_case or the existing project convention
stable semantic identifier
```

Avoid identifiers based on:

```text
display labels
temporary product names
version numbers
UI wording
```

Tool identifiers may become persistent authorization identifiers.

Changing them later may affect `UserTool` records.

Treat them as part of the application's persistent contract.

---

## 6. Separate Identifier From Display Name

The internal identifier and user-facing name serve different purposes.

Example:

```text
identifier:
certificate_checker

display name:
Certificate Checker
```

Do not use presentation text as the database authorization key if the current tool registry separates these concepts.

UI labels may change.

Authorization identifiers should remain stable.

---

## 7. Inspect Existing Tool Registry

Before registering a new tool, inspect:

```text
app/tools_config.py
```

Determine the current structure used for tool metadata.

Typical information may include:

```text
identifier
display name
description
icon
URL/route
category
availability
```

Follow the existing structure.

Do not introduce a second tool registry.

---

## 8. Authorization Is Mandatory

New operational tools must integrate with the canonical authorization model:

```text
UserTool
+
User.has_tool()
+
proteger_blueprint()
```

Read:

```text
docs/decisions/ADR-003-tool-authorization-model.md
docs/systems/auth.md
```

before implementing access control.

Do not rely only on dashboard visibility.

A user manually entering the route URL must still be protected.

---

## 9. Blueprint Protection

A normal operational Blueprint should use the existing protection mechanism.

Conceptually:

```python
proteger_blueprint(bp, "<tool_identifier>")
```

Verify the actual helper signature before implementation.

Do not duplicate tool checks manually across every route if the existing Blueprint-level protection is appropriate.

Route-specific authorization may still be required for:

```text
administrator-only operations
ownership
shared resources
sensitive actions
```

Tool access and object access are separate.

---

## 10. Administrator Behavior

Administrators currently receive tool access through the established authorization model.

Do not add special conditions such as:

```python
if current_user.username == "admin":
```

or:

```python
if current_user.id == 1:
```

Use the existing administrator mechanisms.

---

## 11. Blueprint Structure

Follow existing subsystem organization where appropriate.

A new tool might begin with:

```text
app/
└── <tool_name>/
    ├── __init__.py
    ├── routes.py
    ├── forms.py
    ├── logic.py
    ├── models.py
    └── ...
```

Not every module is required.

Do not create empty files merely to imitate a template.

Use only the layers needed by the feature.

Examples:

```text
simple tool
→ routes.py + templates

complex business logic
→ routes.py + logic.py

persistent tool
→ routes.py + models.py + migration

external integration
→ routes.py + client.py/logic.py
```

Prefer existing project conventions over theoretical architecture.

---

## 12. Blueprint Registration

A new Blueprint must be registered in the application factory.

Inspect:

```text
app/__init__.py
```

before changing it.

Follow the same registration pattern as current tools.

Do not introduce module auto-discovery or dynamic Blueprint registration unless explicitly required.

Explicit registration is easier to understand and safer for this project.

---

## 13. URL Prefix

Choose a clear and stable URL prefix.

Example:

```text
/certificate-checker
```

or the current project naming convention.

Avoid:

```text
generic /tool
temporary /new
version-specific paths
```

Check for route collisions before registration.

Do not change existing URL structures while adding the new tool unless required.

---

## 14. Dashboard Integration

If the tool should appear on the portal dashboard, integrate it through the existing tool registry and dashboard logic.

Do not hardcode an independent card if the current dashboard already renders tools from:

```text
TOOLS
```

The dashboard should respect:

```text
current_user.has_tool(...)
```

or the existing equivalent.

Remember:

```text
dashboard hiding
≠
authorization
```

Backend protection is still mandatory.

---

## 15. UserTool Integration

Determine how users receive permission to the new tool.

Inspect existing:

```text
UserTool
admin user-management routes
initial admin setup
new-user creation behavior
```

The new identifier may need to be included in:

```text
tool selection UI
initial UserTool creation
admin permission editing
existing helper logic
```

Do not create permission rows independently of the established workflow unless necessary.

---

## 16. Existing Users

When adding a new tool to an existing deployment, decide what happens to existing users.

Possible policies:

```text
no normal user gets access automatically
all users get access
only admins get implicit access
specific migration/backfill grants access
```

Do not assume the desired behavior.

The existing authorization architecture already grants administrators global tool access.

For normal users, access changes may require an explicit decision.

---

## 17. Database Requirements

If the new tool needs persistence, use:

```text
portal-database-change
```

The new subsystem may require:

```text
models
foreign keys
indexes
constraints
Alembic migration
```

Do not use:

```text
db.create_all()
```

as the implementation mechanism for schema evolution.

Follow:

```text
SQLAlchemy
+
Alembic migration
```

---

## 18. Model Ownership

Place tool-specific models in the existing model organization appropriate for the project.

Before creating:

```text
app/<tool>/models.py
```

inspect how current subsystems structure their models.

Do not duplicate a shared model merely to keep the subsystem isolated.

Likewise, do not move an existing shared model into the new subsystem without a reason.

---

## 19. Shared Models

Before adding a model, search for equivalent existing concepts.

Examples:

```text
users
audit logs
notifications
IoC metadata
job/status concepts
tool permissions
```

Reuse existing shared models where their semantics genuinely match.

Do not create:

```text
NewToolUser
NewToolAuditLog
NewToolNotification
```

when the application's shared infrastructure already satisfies the requirement.

---

## 20. Forms and Validation

For server-rendered forms, follow the existing Flask-WTF/WTForms conventions.

Use:

```text
server-side validation
CSRF protection
existing form patterns
```

Do not rely only on browser validation.

Validate:

```text
required values
length
format
allowed choices
relationships
authorization-sensitive identifiers
```

Do not trust submitted object IDs without checking authorization.

---

## 21. CSRF

State-changing form actions must preserve CSRF protection.

Do not disable global CSRF to simplify implementation.

Use POST for mutations where appropriate.

Avoid creating new GET routes that mutate state.

---

## 22. Templates

Use the existing Jinja/Bootstrap design system and layout.

Inspect:

```text
app/templates/base.html
```

and one comparable subsystem template.

Prefer existing:

```text
layout
navigation
cards
forms
tables
alerts
buttons
spacing
```

over introducing another frontend framework.

Do not add React/Vue/etc. for one tool unless explicitly required.

---

## 23. UI/UX Work

When significant interface design is required, use:

```text
ui-ux-pro-max
```

but keep it within project constraints.

UI improvements must not silently change:

```text
authorization
backend behavior
database semantics
operational workflow
```

Visual redesign and functional redesign are different scopes.

---

## 24. Shared Base Template

Changes to:

```text
app/templates/base.html
```

affect the entire portal.

Avoid changing it solely to satisfy one new tool unless the change is genuinely global.

Prefer subsystem-local templates and styles when possible.

Shared-template changes require broader regression review.

---

## 25. Static Assets

Reuse existing static organization.

Do not introduce large frontend build pipelines merely for a new operational module.

If new JavaScript or CSS is required:

```text
keep it scoped
follow existing conventions
avoid global side effects
```

Do not duplicate libraries already loaded globally.

---

## 26. External Integrations

If the tool communicates with an external provider, use:

```text
portal-external-api-change
```

Design must explicitly cover:

```text
authentication
timeouts
bounded retries
rate limits
provider errors
partial success
external side effects
```

Do not create an external client that assumes every request succeeds.

---

## 27. Secrets

If the tool stores:

```text
API keys
passwords
client secrets
tokens
sensitive configuration
```

also use:

```text
portal-security-change
```

and read:

```text
docs/decisions/ADR-004-secrets-at-rest.md
```

Persistent secrets must be encrypted.

Do not invent another encryption key or cryptography implementation unless there is a concrete need.

Reuse the appropriate existing encryption domain when semantics match.

If neither existing domain is appropriate, treat that as an architectural/security decision rather than choosing arbitrarily.

---

## 28. Configuration

Use the existing configuration architecture.

Before adding an environment variable, inspect:

```text
config.py
```

Ask:

```text
Is configuration actually environment-specific?
Is it sensitive?
Should it be persisted in DB instead?
Does an existing configuration mechanism already exist?
```

Do not put every new setting in `.env`.

Do not hardcode production-specific configuration.

---

## 29. Required Environment Variables

Avoid making a new environment variable globally mandatory unless the entire portal truly cannot run without it.

A subsystem-specific credential should generally not prevent unrelated modules from starting if the subsystem is not configured, unless security or architecture explicitly requires it.

Prefer clear feature/configuration errors inside the relevant subsystem.

Do not casually add:

```python
if not NEW_TOOL_SECRET:
    raise RuntimeError(...)
```

at global config import time.

Consider the operational impact first.

---

## 30. Background Work

If the new tool performs long-running operations, first inspect existing background patterns:

```text
APScheduler
threading.Thread
```

Do not automatically introduce:

```text
Celery
RQ
Redis queue
new service
```

for a simple task.

However, do not force existing in-process threads onto a requirement that genuinely needs durability.

Ask:

```text
Can work be lost on restart?
Must it resume?
Can it run twice?
Does status need persistence?
Does it mutate an external system?
```

If durability is required, run:

```text
/plan-eng-review
```

before selecting architecture.

---

## 31. Jobs

If the new tool needs jobs, inspect the Umbrella/VT patterns for comparison but do not copy them blindly.

Define:

```text
job owner
status
started time
completed time
progress
result
error state
partial completion
restart behavior
```

Avoid job abstractions when the operation completes reliably inside a normal request.

---

## 32. Audit Logging

Determine which actions should be auditable.

Common candidates:

```text
tool configuration
admin changes
creates
deletes
exports
sensitive reads
external mutations
permission changes
```

Use the existing global audit mechanism where appropriate.

Do not create a subsystem-specific audit table without a concrete requirement.

Never place secrets in audit details.

---

## 33. Notifications

If users need portal notifications, inspect the existing `Notification` infrastructure.

Reuse it if its semantics fit.

Do not create a second notification framework.

Be aware of current known limitations around global notification read state.

Do not copy known flawed behavior into new designs unnecessarily.

---

## 34. Ownership

If the new tool stores user-owned objects, explicitly define:

```text
who owns each object
who can view it
who can edit it
who can delete it
whether it can be shared
what admins can do
```

Do not add `owner_id` without defining authorization semantics.

Use:

```text
portal-security-change
```

for non-trivial ownership rules.

---

## 35. Admin-Only Configuration

Provider credentials and global operational configuration will often be administrator-only.

Use existing admin authorization.

Do not rely solely on:

```text
admin-only UI button
```

Protect the backend route.

---

## 36. Data Import

If the tool imports files, explicitly consider:

```text
allowed format
maximum size
encoding
schema validation
invalid rows
duplicate handling
temporary storage
transaction behavior
security
```

Do not trust filenames or extensions alone.

Do not store sensitive imported content in plaintext temporary files without a reviewed reason.

---

## 37. Data Export

For exports, determine:

```text
who can export
what data is included
whether secrets are included
file format
encoding
large-data behavior
audit requirements
```

Do not accidentally include fields merely because they exist on the model.

Sensitive exports require explicit authorization.

---

## 38. Delete Behavior

Define deletion semantics explicitly.

Ask:

```text
hard delete?
soft delete?
cascade?
retain audit?
retain job history?
external provider cleanup?
```

Do not apply cascade deletion without reviewing related records.

Do not perform external delete operations merely because the local object is deleted unless required.

---

## 39. Error Handling

New tools should fail consistently with the existing portal.

Handle expected failures such as:

```text
validation errors
missing objects
unauthorized access
external API failure
database errors
invalid uploads
configuration missing
```

Do not expose raw stack traces to users.

Provide actionable but sanitized messages.

---

## 40. Logging

Log enough for operations and troubleshooting.

Useful:

```text
tool
operation
safe object ID
status
error category
provider status
```

Never log:

```text
passwords
API keys
tokens
client secrets
Vault content
Authorization headers
```

Follow existing logging conventions.

---

## 41. Dependencies

Before adding a package:

```text
inspect requirements.txt
check standard library
check already-installed packages
justify new dependency
```

Do not introduce large frameworks for narrow requirements.

If a new dependency is necessary, update:

```text
requirements.txt
```

and validate a clean installation.

---

## 42. Cross-Platform Behavior

The portal may run on:

```text
Windows
macOS
Linux
```

Avoid platform-specific path syntax.

Prefer:

```python
os.path.join(...)
```

or the project's existing cross-platform conventions.

Do not introduce Windows-only paths such as:

```text
folder\file
```

or macOS-only assumptions unless the feature is explicitly platform-specific.

---

## 43. New Installation Behavior

A new tool must work on a clean installation.

Consider:

```text
empty database
migration state
missing optional provider configuration
missing optional files
new administrator setup
UserTool availability
```

Do not require historical runtime data to start.

---

## 44. Existing Installation Behavior

A new tool must also be safe when deployed over an existing database.

If persistence changes:

```text
migration
existing users
UserTool rows
existing data
configuration defaults
```

must be considered.

Do not design exclusively against a fresh local environment.

---

## 45. Tool Permission Backfill

When registering a new tool, existing users may not have corresponding `UserTool` rows.

Define expected behavior explicitly.

Possible approach:

```text
administrators
→ access automatically

existing normal users
→ no access until assigned
```

This aligns with the current authorization model unless the product requirement says otherwise.

Do not automatically grant access to all existing users without a deliberate decision.

---

## 46. Tests

A new operational tool should have targeted automated tests where practical.

At minimum consider:

```text
route access
tool permission denied
tool permission allowed
admin behavior
form validation
primary business logic
database writes
external failures
ownership if relevant
```

For external integrations use mocks/synthetic responses.

For sensitive features test denied paths as well as allowed paths.

---

## 47. Smoke Test

Before considering the tool integrated, manually verify:

```text
portal starts
login works
dashboard loads
tool appears for authorized user
tool is hidden for unauthorized user
direct URL is denied for unauthorized user
primary route loads
primary action works
existing portal tools still load
```

Do not limit validation to the new tool's happy path.

---

## 48. Navigation

Integrate navigation through existing patterns.

Avoid creating inconsistent independent navigation systems.

If the tool is represented by a dashboard card, ensure:

```text
label
description
icon
URL
permission identifier
```

match the tool registry.

---

## 49. Naming Consistency

Choose one stable name across:

```text
Blueprint variable
package directory
tool ID
route prefix
documentation
migration references
```

Display text may differ.

Avoid multiple near-equivalent identifiers such as:

```text
cert_checker
certificate_check
certificate_checker
certificates
```

unless they represent genuinely different concepts.

---

## 50. Avoid Premature Shared Abstractions

A new tool is not evidence that a generalized framework is required.

Do not immediately create:

```text
BaseTool
GenericJobManager
UniversalProvider
ToolFramework
PluginSystem
```

because two modules share a few lines.

Wait until repeated, stable patterns justify abstraction.

Prefer readable duplication over incorrect abstraction.

---

## 51. Shared Infrastructure Changes

If the new tool requires modifying:

```text
app/__init__.py
app/extensions.py
app/utils.py
app/tools_config.py
app/templates/base.html
shared models
```

keep those changes minimal.

Shared changes increase regression surface.

Document which existing subsystems may be affected.

---

## 52. Avoid Unrelated Cleanup

Do not combine a new tool with:

```text
renaming existing modules
reformatting unrelated files
dependency upgrades
framework changes
old debt cleanup
template redesign of other modules
database normalization elsewhere
```

unless required for the feature.

Report unrelated issues separately.

---

## 53. Documentation Is Required

Every genuinely new operational subsystem must receive:

```text
docs/systems/<tool>.md
```

Document actual implemented behavior.

Also update:

```text
docs/PROJECT_MAP.md
```

to include:

```text
subsystem purpose
important source files
models
external dependencies
security boundary
background behavior if applicable
```

Mark documentation status appropriately.

---

## 54. Technical Debt Documentation

If the initial implementation intentionally ships with a known limitation, document it in:

```text
docs/technical-debt/current.md
```

Examples:

```text
non-durable background work
temporary provider limitation
missing pagination
known performance constraint
```

Do not hide known limitations inside comments.

Do not label unfinished fundamental correctness/security issues as harmless debt merely to ship faster.

---

## 55. ADR Decision

A new tool does not automatically require a new ADR.

Create an ADR only if the tool introduces a deliberate architectural decision such as:

```text
new persistence strategy
new background architecture
new authorization model
new encryption domain
major external integration architecture
departure from modular monolith
```

Ordinary implementation belongs in:

```text
docs/systems/
```

not:

```text
docs/decisions/
```

---

## 56. Recommended Development Flow

For a small new tool:

```text
project context
        ↓
portal-new-operational-tool
        ↓
implementation
        ↓
/review
        ↓
QA
```

For a complex tool:

```text
/plan-eng-review
        ↓
portal-new-operational-tool
        ↓
supporting project skills
        ↓
implementation
        ↓
/review
        ↓
/qa
```

For a tool with database changes:

```text
portal-new-operational-tool
        +
portal-database-change
```

For a tool with sensitive permissions/secrets:

```text
portal-new-operational-tool
        +
portal-security-change
```

For a provider-backed tool:

```text
portal-new-operational-tool
        +
portal-external-api-change
```

Use skills as complementary concerns.

Do not run every skill automatically.

---

## 57. High-Risk Tool Flow

If the new tool includes:

```text
external production mutation
secrets
authorization
database migration
background processing
```

consider:

```text
/plan-eng-review
        ↓
/careful
        ↓
portal-new-operational-tool
        ↓
relevant portal-specific skills
        ↓
implementation
        ↓
/review
        ↓
/codex review
        ↓
/qa
```

Use this only when risk justifies the additional review.

---

## 58. Required Pre-Implementation Summary

Before implementing a non-trivial new operational tool, summarize:

```md
## New Operational Tool

### Objective

What operational problem the tool solves.

### Functional Boundary

Why this belongs in a new subsystem instead of an existing one.

### Tool Identifier

Stable internal authorization identifier.

### Blueprint / Routes

Proposed module and URL structure.

### Authorization

Who receives tool access and what object/admin permissions exist.

### Persistence

Models, migrations, or configuration required.

### External Integrations

Providers, authentication, side effects, retries, and timeouts.

### Background Work

Whether jobs/threads/scheduler behavior is required.

### Sensitive Data

Credentials, secrets, encrypted fields, uploads, or exports involved.

### UI

Dashboard, navigation, forms, tables, templates, and main workflows.

### Shared Infrastructure Impact

Any changes to app factory, extensions, tool registry, base templates, or shared models.

### Risks

Concrete regression, security, persistence, and operational risks.

### Validation

Tests and manual flows required before completion.

### Documentation

System docs, project map, debt, or ADR changes required.
```

Keep this proportional to the feature.

---

## 59. Completion Checklist

Before declaring a new operational tool complete, verify:

```text
[ ] Confirmed this genuinely needs a new subsystem
[ ] Stable tool identifier chosen
[ ] Relevant project context reviewed
[ ] Blueprint follows existing architecture
[ ] Blueprint registered correctly
[ ] URL prefix is stable and non-conflicting
[ ] Tool registered in existing tool registry
[ ] Dashboard integration works
[ ] UserTool authorization works
[ ] Direct URL is protected
[ ] Administrator behavior is correct
[ ] Ownership rules defined if applicable
[ ] CSRF remains enabled for state changes
[ ] Server-side validation exists
[ ] Database migration exists if required
[ ] Existing-data behavior was considered
[ ] Secrets are encrypted if applicable
[ ] No credentials are exposed in logs/UI/audit
[ ] External calls have timeouts if applicable
[ ] Retry behavior is bounded if applicable
[ ] Partial provider failures handled if applicable
[ ] Background restart/duplicate behavior considered if applicable
[ ] Audit behavior considered
[ ] Notifications reuse existing infrastructure where appropriate
[ ] Dependencies updated if required
[ ] Cross-platform paths verified
[ ] Authorized user can access tool
[ ] Unauthorized user cannot access direct route
[ ] Existing tools still work
[ ] docs/systems/<tool>.md created
[ ] docs/PROJECT_MAP.md updated
[ ] Relevant technical debt documented
[ ] ADR created only if an actual architectural decision was introduced
[ ] Final diff reviewed
```

---

## 60. Core Rule

Never treat adding a new portal tool as merely:

```text
create route
create template
add dashboard card
done
```

For this project, a new operational tool means:

```text
functional boundary
+
Blueprint
+
tool registry
+
authorization
+
UI
+
validation
+
persistence when needed
+
external integration when needed
+
security
+
audit
+
testing
+
documentation
```

The new tool must feel like part of the existing portal, not a separate application embedded inside it.