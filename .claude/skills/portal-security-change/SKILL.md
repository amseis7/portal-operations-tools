---
name: portal-security-change
description: >
  Project-specific workflow for security-sensitive changes in Portal Operations Tools.
  Use when modifying authentication, authorization, UserTool permissions, ownership
  checks, administrator-only actions, CSRF behavior, secrets, encryption, credential
  handling, Vault access, audit logging, sensitive UI exposure, or other security
  boundaries. Complements gstack security/review workflows with repository-specific rules.
---

# Portal Security Change

## Purpose

Use this skill whenever a change affects a security boundary in Portal Operations Tools.

Examples:

- login behavior;
- password handling;
- administrator permissions;
- `UserTool`;
- `User.has_tool()`;
- `proteger_blueprint()`;
- object ownership;
- shared-resource permissions;
- Vault access;
- reveal-secret behavior;
- API credentials;
- encryption;
- CSRF protection;
- audit logging;
- sensitive fields in forms;
- sensitive values rendered in templates;
- credential storage;
- import/export of secrets;
- authorization bugs.

This skill provides project-specific security rules.

It does not replace:

- `/investigate`
- `/review`
- `/careful`
- `/guard`
- `/codex`

Those provide general engineering and safety workflows.

---

## 1. Load Project Context First

Before changing security-sensitive behavior, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/decisions/ADR-003-tool-authorization-model.md
docs/decisions/ADR-004-secrets-at-rest.md
docs/systems/auth.md
```

Then identify the affected subsystem.

Read only the relevant current-system documentation:

```text
docs/systems/<subsystem>.md
```

Examples:

```text
Vault authorization
→ docs/systems/vault.md

Umbrella job ownership
→ docs/systems/umbrella.md

VirusTotal API key handling
→ docs/systems/virustotal.md
```

Do not scan every subsystem automatically.

---

## 2. Check Known Security Debt

Inspect:

```text
docs/technical-debt/current.md
```

for security-related items relevant to the task.

Current known examples include areas such as:

```text
Vault edit authorization
Vault delete authorization
Vault tool-level authorization
plaintext Vault import preview files
Vault sync password exposure
broad Vault group administration
Auth password-policy inconsistency
```

Do not treat existing insecure behavior as intentional architecture.

If the requested task directly touches known security debt, state whether it:

```text
preserves it
worsens it
partially resolves it
fully resolves it
```

Do not silently fix unrelated debt.

---

## 3. Security Source of Truth

For security behavior, use this order:

```text
1. Current route/decorator implementation
2. Current authorization helpers
3. Current models
4. Automated tests
5. docs/systems/
6. accepted ADRs
7. historical specs/plans
```

Do not infer security from:

```text
dashboard visibility
template conditions
button visibility
route names
comments
historical documentation
```

Security must be enforced server-side.

---

## 4. Authentication vs Authorization

Always distinguish:

```text
Authentication
= Who is the user?

Authorization
= What is the user allowed to do?
```

A route protected only by:

```python
@login_required
```

is not necessarily authorized.

Always determine whether the action additionally requires:

```text
tool permission
administrator permission
object ownership
shared-resource permission
specific action permission
```

---

## 5. Canonical Tool Authorization Model

Operational tool access uses:

```text
UserTool
+
User.has_tool()
+
proteger_blueprint()
```

Administrators currently receive global tool access through `User.has_tool()`.

Do not invent a parallel permission system unless explicitly required.

Do not create:

```text
new ACL tables
new role frameworks
subsystem-specific auth decorators
duplicate permission stores
```

without a concrete requirement.

---

## 6. Tool Access Is Not Object Access

Tool-level authorization and object-level authorization are separate.

Example:

```text
User has access to Vault
```

does not mean:

```text
User may read/edit/delete every VaultEntry
```

Likewise:

```text
User has access to Umbrella
```

does not automatically mean:

```text
User may read another user's job results
```

For every sensitive object operation, determine:

```text
who owns it?
is it shared?
is admin override allowed?
is read different from edit?
is delete more restrictive?
```

---

## 7. Define the Authorization Matrix

For any non-trivial authorization change, explicitly define:

```text
anonymous
authenticated normal user
resource owner
shared-access user
administrator
```

and actions such as:

```text
view
create
edit
delete
reveal
export
configure
administer
```

Example:

```text
Action: Edit Vault entry

Anonymous
→ denied

Authenticated user without Vault tool
→ denied

Vault user, not owner
→ denied unless explicit sharing grants edit

Owner
→ allowed

Administrator
→ allowed
```

Do not implement authorization without first understanding the intended matrix.

---

## 8. Authorization Must Be Server-Side

Never rely on template/UI hiding as a security control.

This is insufficient:

```jinja2
{% if current_user.is_admin %}
    <button>Delete</button>
{% endif %}
```

if the corresponding route does not enforce the same permission.

For every protected action verify:

```text
UI visibility
+
server-side enforcement
```

The server-side check is authoritative.

---

## 9. Protect Direct URLs

Assume users can manually navigate to any route.

A hidden dashboard card does not protect:

```text
/direct/url
```

Tool permissions must be enforced in backend routes or Blueprint-level guards.

This is particularly important for:

```text
Vault
admin routes
exports
configuration routes
secret reveal endpoints
```

---

## 10. Administrator Privileges

Use the existing administrator authorization pattern.

Do not replace it with:

```text
username checks
hardcoded user IDs
special email addresses
magic route conditions
```

Administrator-only actions should use the current admin mechanism.

Verify existing helper behavior before modifying it.

---

## 11. Password Handling

Passwords must never be:

```text
logged
written to audit detail
returned in errors
stored plaintext
committed
included in documentation
```

Password changes should preserve the application's password-policy rules.

If modifying password handling, inspect:

```text
docs/systems/auth.md
```

and the actual password-validation/set-password implementation.

Do not duplicate password-validation logic in multiple routes.

Known password-policy inconsistencies should be treated as technical debt, not as new intended behavior.

---

## 12. Session and Login Behavior

Changes to login/session handling must consider:

```text
Flask-Login
login_required
safe redirects
must_change_password
administrator setup
session state
logout behavior
```

Do not weaken safe redirect validation.

Do not bypass mandatory password-change behavior accidentally.

---

## 13. CSRF Protection

The project uses global CSRF protection.

State-changing browser actions should normally use:

```text
POST
PUT/PATCH when appropriate
DELETE when appropriate
```

with valid CSRF protection.

Avoid GET routes that mutate state.

If an existing GET route performs mutations, treat that as debt and do not use it as precedent.

Do not disable CSRF globally to make a form or route easier to implement.

If an API-style endpoint legitimately needs different handling, scope the exception narrowly and document why.

---

## 14. Secrets at Rest

Persistent secret material must remain encrypted.

Relevant examples include:

```text
VirusTotal API keys
Umbrella client secrets
Vault passwords
Vault notes
Vault custom fields
KeePass sync passwords
```

Current encryption domains include:

```text
SECRET_KEY_DB
VAULT_KEY
```

Do not assume they are interchangeable.

Do not replace encrypted columns with plaintext storage.

---

## 15. Plaintext Lifetime

Plaintext secrets may exist temporarily in memory when required for legitimate operations.

Examples:

```text
calling an external API
revealing an authorized Vault password
KeePass import/export
credential replacement
```

Plaintext lifetime should be minimized.

Do not unnecessarily persist plaintext to:

```text
database
filesystem
temporary JSON
session storage
logs
audit
HTML
URLs
```

---

## 16. Sensitive Browser Exposure

A value being encrypted in the database does not make it safe to expose to the browser.

Do not decrypt a stored secret merely to prepopulate a form.

Preferred update behavior:

```text
empty field
→ preserve existing secret

new value supplied
→ replace encrypted secret
```

Avoid rendering existing secret values into:

```text
HTML inputs
page source
JavaScript
data attributes
hidden fields
```

unless the workflow explicitly requires revealing them and authorization has already been verified.

---

## 17. Secret Reveal Endpoints

Reveal operations are high risk.

For any route that returns plaintext credentials, verify:

```text
authentication
tool authorization
object authorization
request method
CSRF where applicable
audit logging
response caching behavior
error behavior
```

Do not expose secrets through:

```text
query strings
redirect URLs
flash messages
logs
exception messages
```

---

## 18. Vault Security

Vault is a high-sensitivity subsystem.

Before modifying Vault security, read:

```text
docs/systems/vault.md
docs/decisions/ADR-003-tool-authorization-model.md
docs/decisions/ADR-004-secrets-at-rest.md
docs/technical-debt/current.md
```

Pay special attention to:

```text
_can_access()
owner_id
shared
admin behavior
reveal
edit
delete
group administration
KeePass import
KeePass sync
temporary import files
VaultSyncConfig
```

Do not infer authorization from ownership fields alone.

Verify the route actually enforces the intended rule.

---

## 19. Vault Edit and Delete

Edit and delete require explicit review.

Do not assume:

```text
shared access
```

should imply:

```text
edit permission
delete permission
```

Read and edit/delete rights may differ.

When changing these routes, define the intended authorization behavior before implementation.

For example:

```text
View
→ owner / shared / admin

Edit
→ owner / admin

Delete
→ owner / admin
```

This is only an example.

Do not enforce it unless it matches the explicit product requirement.

---

## 20. Temporary Sensitive Files

If a workflow writes temporary files containing:

```text
passwords
notes
API keys
tokens
KeePass content
```

evaluate:

```text
where the file is stored
permissions
encryption
cleanup
crash behavior
abandoned-file behavior
filename predictability
lifetime
```

Prefer:

```text
in-memory state
encrypted temporary state
short-lived protected storage
```

over plaintext persistent temporary files.

Do not inspect real secret files during normal development.

---

## 21. External Credentials

When modifying VirusTotal or Umbrella credentials, determine:

```text
where they are persisted
which encryption mechanism protects them
where they are decrypted
how long plaintext exists
whether credentials enter logs
whether credentials are passed to threads
```

Do not log full provider responses if they may contain sensitive material.

Do not include credentials in exception text.

---

## 22. External API Authorization

Do not confuse:

```text
provider authentication
```

with:

```text
portal user authorization
```

Both must be correct.

Example:

```text
Umbrella API credential valid
```

does not mean:

```text
portal user is authorized to execute mutation
```

Verify portal authorization before performing external side effects.

---

## 23. External Mutations Are High Risk

Changes that can modify external services should consider:

```text
authorization
dry-run behavior
partial success
retries
duplicates
provider response interpretation
auditability
```

This particularly applies to Cisco Umbrella.

Do not automatically retry unsafe mutations without understanding idempotency.

---

## 24. Audit Logging

Security-sensitive operations should normally be auditable.

Examples:

```text
login changes
administrator actions
permission changes
Vault reveals
credential updates
sensitive exports
deletions
external mutations
```

Use the existing audit mechanism.

Do not create a second audit architecture unless required.

Remember that current `log_audit()` behavior may depend on the caller's transaction/commit flow.

Verify persistence instead of assuming audit rows are committed automatically.

---

## 25. Audit Content Must Not Contain Secrets

Audit logs may record:

```text
who
what
when
which object
result
```

They must not contain:

```text
password plaintext
API key plaintext
client secret
Vault secret
KeePass password
access token
full credential payload
```

Good:

```text
User updated Umbrella credentials.
```

Bad:

```text
User changed client_secret to abc123...
```

---

## 26. Logging

Application logs must not expose secrets.

When handling sensitive failures, log:

```text
operation
provider
object identifier when safe
error category
HTTP status
```

instead of:

```text
password
secret
authorization header
API key
token
encrypted payload plus key
```

Inspect existing log statements when modifying security-sensitive code.

---

## 27. Error Messages

User-facing errors should be useful without revealing internal secrets.

Avoid returning:

```text
database paths
secret values
stack traces
provider authorization headers
encryption keys
filesystem credentials
```

Detailed internal errors should also be sanitized before logging.

---

## 28. Input Validation

Security-sensitive inputs must be validated server-side.

Examples:

```text
filenames
uploaded files
URLs
IoCs
IDs
form choices
admin actions
paths
external provider labels
```

Client-side validation is only UX.

It is not a security boundary.

---

## 29. File Uploads

When modifying upload behavior, consider:

```text
file size
extension
actual format
temporary storage
path traversal
filename handling
cleanup
secret content
authorization
```

Do not trust:

```text
original filename
browser MIME type
extension alone
```

for security-sensitive decisions.

Follow existing upload restrictions unless explicitly changing them.

---

## 30. Filesystem Paths

Never construct sensitive filesystem paths directly from untrusted input without validation.

Avoid patterns such as:

```python
path = base_path + user_input
```

Prefer safe path joining and explicit allowed locations.

Be particularly careful with:

```text
KeePass paths
certificate paths
imports
exports
temporary files
```

---

## 31. Environment Variables

Do not:

```text
print .env
commit .env
log environment secrets
copy real secrets into examples
```

Environment-variable names may be documented when needed.

Values must remain private.

Protected variables currently include areas such as:

```text
SECRET_KEY
SECRET_KEY_DB
CREDENTIAL_MANAGER_KEY
VAULT_KEY
VAULT_KDBX_PASSWORD
```

Do not inspect their real values unless explicitly necessary.

---

## 32. Encryption Changes

Changing encryption behavior is a high-risk architectural change.

Before modifying encryption:

```text
identify current key
identify affected fields
identify ciphertext format
identify decrypt callers
identify existing stored data
define migration
define rollback
define failure behavior
```

Never simply rotate or replace an encryption key for existing data.

If persistent ciphertext exists:

```text
old key
→ decrypt
→ new key
→ re-encrypt
→ validate
→ retire old key
```

may be required.

Use `/plan-eng-review` and consider `/codex review` for significant encryption changes.

---

## 33. Security-Sensitive Database Changes

If a security change also modifies the database, use:

```text
portal-database-change
```

in addition to this skill.

Examples:

```text
new permission column
ownership relationship
per-user notification state
new encrypted field
credential table
authorization constraint
```

The two skills are complementary:

```text
portal-security-change
→ security boundary

portal-database-change
→ persistence/migration correctness
```

---

## 34. Git Safety

Before modifying security-sensitive files, inspect:

```bash
git status --short
```

Do not overwrite unrelated uncommitted work.

Do not use:

```bash
git reset --hard
git checkout -- .
git restore .
git clean -fd
```

without explicit approval.

For risky tasks, consider:

```text
/careful
```

or:

```text
/guard
```

---

## 35. Testing Authorization

Authorization tests should cover denied cases as well as allowed cases.

For example:

```text
anonymous denied
authenticated unauthorized user denied
authorized owner allowed
administrator allowed
shared-user behavior verified
direct URL behavior verified
```

Do not test only the happy path.

---

## 36. Testing Secret Handling

Where applicable, verify:

```text
plaintext not persisted
authorized decrypt works
unauthorized decrypt denied
invalid ciphertext fails safely
logs do not contain plaintext
audit does not contain plaintext
HTML does not expose plaintext unnecessarily
```

Use synthetic test credentials only.

---

## 37. Negative Testing

Security validation must include attempts that should fail.

Examples:

```text
edit another user's object
delete another user's object
directly open protected URL
submit admin endpoint as normal user
reveal a Vault secret without ownership
access tool route without UserTool permission
reuse malformed CSRF request
send manipulated object ID
```

A security change is not validated only by proving authorized access works.

---

## 38. Avoid Broad Security Refactors

Do not use a localized security bug as justification to redesign the whole auth system.

Prefer:

```text
smallest correct server-side fix
+
targeted tests
+
documentation update
```

If a broader redesign is genuinely necessary, stop and treat it as an architectural change.

---

## 39. Documentation Updates

After implementing a security change, check whether to update:

```text
docs/systems/<subsystem>.md
docs/systems/auth.md
docs/technical-debt/current.md
docs/decisions/
docs/PROJECT_MAP.md
```

Examples:

```text
Vault authorization fixed
→ update docs/systems/vault.md
→ update technical-debt/current.md

authorization architecture changed
→ new ADR

new shared security helper
→ update PROJECT_MAP.md
```

Do not create an ADR for ordinary security bug fixes.

---

## 40. Recommended Integration With gstack

For a security bug:

```text
/investigate
        ↓
identify root cause
        ↓
portal-security-change
        ↓
implement smallest fix
        ↓
/review
```

For a sensitive authorization change:

```text
/careful
        ↓
portal-security-change
        ↓
implementation
        ↓
/review
        ↓
/codex review
```

For a major security architecture change:

```text
/plan-eng-review
        ↓
portal-security-change
        ↓
possibly new ADR
        ↓
implementation
        ↓
/review
        ↓
/codex challenge
```

Do not invoke all workflows automatically.

Match the workflow to actual risk.

---

## 41. Required Pre-Implementation Summary

Before implementing a non-trivial security-sensitive change, summarize:

```md
## Security Change

### Objective

What security behavior needs to change.

### Current Enforcement

Where authentication and authorization are currently enforced.

### Intended Authorization

Who should be allowed and denied.

### Sensitive Data Impact

Whether passwords, secrets, credentials, encrypted fields, or sensitive files are involved.

### Proposed Change

The smallest server-side implementation that satisfies the requirement.

### Known Technical Debt Interaction

Relevant security debt only.

### Risks

Potential authorization bypass, secret exposure, regression, or privilege escalation risks.

### Validation

Allowed cases and denied cases that will be tested.
```

Keep the summary proportional to the task.

---

## 42. Completion Checklist

Before declaring a security-sensitive change complete, verify:

```text
[ ] Relevant subsystem documentation was read
[ ] Auth documentation was read when applicable
[ ] Relevant ADRs were respected
[ ] Known security debt was checked
[ ] Authentication and authorization were distinguished
[ ] Server-side enforcement exists
[ ] Direct URL access was considered
[ ] Tool permission was checked where applicable
[ ] Ownership/shared/admin behavior was defined
[ ] CSRF behavior remains correct
[ ] Secrets remain encrypted at rest
[ ] Plaintext is not unnecessarily exposed
[ ] Logs contain no secrets
[ ] Audit contains no secrets
[ ] Allowed cases were tested
[ ] Denied cases were tested
[ ] Existing unrelated behavior remains intact
[ ] Documentation was updated if needed
[ ] Final diff was reviewed
```

---

## 43. Core Rule

Never treat a security change as merely:

```text
hide button
add login_required
done
```

For this project, security means:

```text
authentication
+
tool authorization
+
object authorization
+
administrator boundaries
+
secret protection
+
CSRF
+
audit
+
negative testing
```

Enforce security on the server and verify both allowed and denied behavior.