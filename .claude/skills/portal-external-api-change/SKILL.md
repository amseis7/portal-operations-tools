---
name: portal-external-api-change
description: >
  Project-specific workflow for changes involving external services in Portal Operations Tools.
  Use when modifying integrations with VirusTotal, Cisco Umbrella, CSIRT external sources,
  KeePass-related external/file workflows, HTTP clients, retries, timeouts, authentication,
  provider responses, quotas, background API work, or external side effects. Complements
  gstack engineering workflows with repository-specific integration rules.
---

# Portal External API Change

## Purpose

Use this skill whenever a change affects communication with an external service or external operational dependency.

Examples:

- VirusTotal API changes;
- Cisco Umbrella API changes;
- CSIRT RSS or HTML scraping;
- provider authentication;
- API credentials;
- HTTP requests;
- timeouts;
- retries;
- rate limits;
- quotas;
- pagination;
- partial responses;
- provider errors;
- asynchronous API work;
- external mutations;
- dry-run behavior;
- response parsing;
- provider schema changes;
- network failure handling.

This skill provides project-specific integration rules.

It does not replace:

- `/investigate`
- `/plan-eng-review`
- `/review`
- `/careful`
- `/codex`

Those provide general engineering workflows.

---

## 1. Load Project Context First

Before modifying an external integration, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
```

Then identify the affected subsystem.

Read only the relevant current-system documentation.

Examples:

```text
VirusTotal
→ docs/systems/virustotal.md

Cisco Umbrella
→ docs/systems/umbrella.md

CSIRT sources
→ docs/systems/csirt.md

Vault / KeePass
→ docs/systems/vault.md
```

Do not load unrelated subsystem documentation automatically.

---

## 2. Check Relevant Architectural Decisions

If credentials or secrets are involved, read:

```text
docs/decisions/ADR-004-secrets-at-rest.md
```

If authorization determines who can trigger the external operation, also read:

```text
docs/decisions/ADR-003-tool-authorization-model.md
```

If persistence changes are required, also use:

```text
portal-database-change
```

Do not create a new integration architecture that conflicts with accepted project decisions.

---

## 3. Check Known Technical Debt

Inspect relevant entries in:

```text
docs/technical-debt/current.md
```

Current external-integration debt includes areas such as:

```text
non-durable VirusTotal background threads
non-durable Umbrella background threads
Umbrella HTTP 207 handling
provider error persistence
credentials passed into background threads
CSIRT incremental commits
```

Determine whether the requested change:

```text
does not affect known debt
preserves known debt
worsens known debt
partially resolves known debt
fully resolves known debt
```

Do not silently fix unrelated integration debt.

---

## 4. Establish Current Integration Behavior

Before changing code, determine:

```text
Which provider is called?
Which endpoint is used?
Which HTTP method is used?
How authentication works?
Where credentials come from?
What timeout is configured?
What retry behavior exists?
What rate or quota limitations exist?
How pagination works?
What is persisted?
What happens on partial success?
What happens on failure?
Is the call synchronous or background?
Does the call mutate the external system?
```

Verify these points in current source code.

Do not infer them from documentation alone.

---

## 5. External Calls Must Have Explicit Timeouts

Every network request must have a bounded timeout.

Do not introduce:

```python
requests.get(url)
```

without timeout behavior.

Use the existing subsystem convention where available.

Current integrations already use bounded timeouts in several places.

Preserve or improve explicit timeout behavior.

Do not set arbitrarily large timeouts without a concrete operational reason.

---

## 6. Retry Only When Safe

Before adding retries, classify the operation.

### Generally safer to retry

Examples:

```text
GET
read-only catalog lookup
status query
idempotent lookup
```

### Potentially unsafe to retry automatically

Examples:

```text
POST that creates something
PATCH that mutates provider state
DELETE
operations with unclear idempotency
```

For mutation retries, determine:

```text
Is the provider operation idempotent?
Could duplicate execution cause damage?
Can the request be safely replayed?
Does the provider expose an idempotency mechanism?
```

Do not add uncontrolled retry loops.

---

## 7. Retry Strategy

When retries are justified, use bounded retry behavior.

Consider:

```text
maximum attempts
initial delay
maximum delay
exponential backoff
retryable HTTP statuses
retryable network exceptions
```

Do not retry every error.

Typical retry candidates may include:

```text
429
500
502
503
504
temporary network errors
```

Authentication failures normally require different handling.

Do not repeatedly retry invalid credentials.

---

## 8. Rate Limits and Quotas

External providers may impose:

```text
request quotas
daily limits
per-minute limits
concurrency limits
provider-specific rate limits
```

Do not assume provider availability is unlimited.

For VirusTotal especially, preserve awareness of API quota behavior.

When receiving:

```text
429 Too Many Requests
```

handle it explicitly.

Do not convert rate-limit failures into generic unknown errors when better information is available.

---

## 9. Authentication

External authentication must be handled separately from portal authorization.

Examples:

```text
VirusTotal
→ API key

Cisco Umbrella
→ OAuth/client credentials
```

Before modifying authentication, determine:

```text
where the credential is stored
how it is encrypted
where it is decrypted
how it is transmitted
whether tokens are persisted
how refresh works
```

Do not hardcode credentials.

Do not add credentials to source files.

---

## 10. Credential Handling

Persistent credentials must remain encrypted at rest.

Current relevant encryption domains include:

```text
SECRET_KEY_DB
VAULT_KEY
```

External provider secrets should only exist in plaintext when required for the operation.

Do not expose credentials through:

```text
logs
audit details
exception messages
URLs
HTML
debug output
documentation
```

If credential storage behavior changes, also use:

```text
portal-security-change
```

---

## 11. Authorization Before External Side Effects

Before performing an external mutation, verify portal authorization first.

The correct order is:

```text
authenticate user
        ↓
authorize portal action
        ↓
validate request
        ↓
prepare provider operation
        ↓
call external service
```

Do not call the provider and only afterward determine whether the user was allowed.

---

## 12. Read vs Mutation

Always classify the operation as:

```text
read-only
```

or:

```text
external mutation
```

External mutations deserve stricter handling.

Examples:

```text
VirusTotal lookup
→ read-only

CSIRT RSS download
→ read-only

Umbrella label change
→ external mutation
```

External mutations require explicit attention to:

```text
authorization
dry-run
partial failure
retries
duplicates
audit
result persistence
```

---

## 13. Dry-Run Behavior

If a subsystem supports dry-run, preserve its semantics.

For Cisco Umbrella, dry-run may still legitimately perform:

```text
authentication
catalog retrieval
application resolution
validation
```

but must not perform the provider mutation.

Do not implement a fake dry-run that skips validation entirely if current behavior intentionally validates against the provider.

A dry-run should answer:

```text
What would happen?
```

without causing the external side effect.

---

## 14. Partial Success

External APIs may return partial success.

Do not reduce:

```text
some succeeded
some failed
```

to:

```text
all succeeded
```

or:

```text
all failed
```

unless the provider contract truly behaves atomically.

When partial results are possible, preserve per-item outcomes where reasonable.

This is particularly important for batch mutations.

---

## 15. Cisco Umbrella HTTP 207

Umbrella may return:

```text
HTTP 207 Multi-Status
```

Treat this carefully.

Do not automatically interpret the entire batch as successful without examining the provider response semantics.

Current simplified handling is known technical debt.

If a task touches this behavior:

```text
inspect actual provider response
identify per-item status
persist accurate outcomes
update technical debt if resolved
```

Do not redesign unrelated Umbrella behavior at the same time.

---

## 16. VirusTotal Integration

Before modifying VirusTotal behavior, read:

```text
docs/systems/virustotal.md
```

Pay attention to:

```text
per-user API keys
7-day local freshness behavior
cross-system cache reuse
14-day cross-record reuse
hash relationships
404 handling
unsupported IOC handling
background threads
CSIRT propagation
quota lookup
```

VirusTotal data is not isolated exclusively to the VirusTotal module.

Changes may affect CSIRT data.

---

## 17. VirusTotal Cache Behavior

Before changing when the provider is called, inspect existing cache/reuse logic.

Current behavior may reuse:

```text
same IOC value
matching hashes
VirusTotal records
CSIRT IOC records
```

Do not increase external API calls simply because a direct call is easier.

Preserve existing cache behavior unless the requirement explicitly changes it.

When modifying cache freshness:

```text
document old freshness
document new freshness
consider quota impact
consider stale-data impact
```

---

## 18. VirusTotal Result Propagation

VirusTotal analysis may update matching CSIRT IOC records.

Treat this as a cross-subsystem side effect.

Before changing provider-result persistence, verify:

```text
which records receive updates
what matching rule is used
what freshness applies
what fields are copied
```

Do not silently remove cross-system propagation.

---

## 19. Unsupported or Unanalyzable IOC Types

Do not repeatedly send unsupported values to an external API.

Preserve or explicitly redesign current handling for types such as:

```text
email
unsupported IOC types
invalid values
```

An unsupported item should have a deterministic outcome.

Avoid infinite retry behavior.

---

## 20. VirusTotal 404 vs Provider Failure

Differentiate:

```text
provider says object not found
```

from:

```text
provider request failed
```

A valid HTTP 404 may represent a legitimate result.

Do not treat every non-200 response as the same failure category.

Likewise, do not mark transient provider failures as permanently processed unless that is intentional.

---

## 21. Cisco Umbrella Integration

Before modifying Umbrella behavior, read:

```text
docs/systems/umbrella.md
```

Pay attention to:

```text
OAuth client credentials
token refresh
retry configuration
catalog loading
application resolution
ambiguous matches
dry-run
bulk PATCH
HTTP 207
job persistence
result ownership
background threads
```

Umbrella operations may alter an external production system.

Treat them as high-risk changes.

---

## 22. Umbrella Application Resolution

Preserve current safety behavior around application matching.

Current behavior favors:

```text
exact case-insensitive match
```

and treats some normalized/no-space matches as potentially ambiguous.

Do not introduce aggressive fuzzy matching without explicit approval.

Wrong application resolution can mutate the wrong external object.

For ambiguous matches:

```text
fail safely
```

rather than guessing.

---

## 23. Umbrella Mutation Batching

Current operations may batch provider changes.

Before changing chunk size or request behavior, consider:

```text
provider limits
partial responses
retry semantics
job progress
failure recovery
```

Do not increase batch size solely for performance without provider-contract evidence.

---

## 24. Umbrella Token Refresh

If changing OAuth behavior, preserve token refresh handling.

Distinguish:

```text
expired/invalid access token
```

from:

```text
invalid client credentials
```

Do not create infinite refresh loops.

A refreshed token should remain ephemeral unless persistence is explicitly required.

---

## 25. CSIRT External Sources

Before modifying CSIRT source ingestion, read:

```text
docs/systems/csirt.md
```

Current sources may include:

```text
RSS
HTML scraping
```

Treat provider/source HTML as unstable external input.

Do not assume page structure will remain unchanged.

---

## 26. Scraping Is Fragile

For HTML scraping:

```text
validate element existence
handle missing tables
handle changed structure
handle malformed content
handle empty result
```

Do not index blindly into parsed elements.

Avoid turning source-layout changes into unhandled 500 errors.

When practical, separate:

```text
network retrieval
parsing
business processing
```

so failures can be identified clearly.

---

## 27. RSS and HTML Precedence

If multiple sources describe the same alert, preserve documented precedence and merge behavior unless explicitly changing it.

Before changing deduplication or merge logic, inspect:

```text
RSS behavior
HTML behavior
nombre_alerta matching
existing records
```

Do not create duplicate alerts simply because two external sources returned the same event.

---

## 28. External Data Is Untrusted Input

Treat all provider responses as untrusted.

Validate:

```text
JSON shape
required keys
types
lists
status fields
URLs
identifiers
HTML structure
CSV content
```

Do not assume a successful HTTP status guarantees a valid response body.

---

## 29. JSON Parsing

Before accessing nested response data, account for:

```text
missing keys
null values
unexpected type
empty arrays
provider error object
different API version
```

Avoid deeply chained assumptions such as:

```python
response.json()["data"]["attributes"]["value"]
```

when the provider contract may return errors or missing objects.

Use the existing coding conventions of the subsystem.

---

## 30. Error Classification

Where useful, classify failures into categories such as:

```text
authentication
authorization
rate limit
timeout
network failure
provider 5xx
invalid provider response
not found
validation error
partial success
internal persistence failure
```

This makes logs and UI messages more useful.

Do not expose secrets while providing diagnostic information.

---

## 31. Provider Error Persistence

Be careful when storing provider error messages in the database.

Provider responses may contain:

```text
internal IDs
request information
unexpected sensitive details
large payloads
```

Persist only what is operationally necessary.

Do not store raw provider responses by default.

Known provider-error persistence issues should be treated as technical debt.

---

## 32. Logging

For external requests, useful logging may include:

```text
provider
operation
HTTP status
attempt number
elapsed time
safe resource identifier
error category
```

Do not log:

```text
API keys
client secrets
Authorization headers
access tokens
Vault credentials
full sensitive request bodies
```

Avoid dumping full HTTP request/response objects.

---

## 33. Background External Work

Some integrations currently use:

```text
threading.Thread
```

or:

```text
APScheduler
```

Before modifying external background work, determine:

```text
what starts the task
what happens if process restarts
whether duplicate execution is possible
whether progress is persisted
whether database sessions are safe
whether credentials are passed into the thread
whether provider mutations can be repeated
```

Do not introduce another background framework unless the requirement justifies it.

---

## 34. Thread Credentials

Avoid unnecessarily passing plaintext credentials through long-lived background contexts.

If current code does so and the task touches that behavior:

```text
understand why
minimize plaintext lifetime
avoid logging
avoid persistence
consider reloading encrypted credential inside worker if appropriate
```

Do not broaden scope unless needed for the requested change.

---

## 35. Job Durability

Current in-process workers may be lost if the application restarts.

Do not pretend they are durable.

If a requirement explicitly needs:

```text
guaranteed execution
resume after restart
cross-process coordination
reliable retry
```

then stop and evaluate whether the existing background architecture still satisfies the requirement.

That may require:

```text
/plan-eng-review
```

and potentially a new architectural decision.

---

## 36. Duplicate Execution

External mutations must consider duplicate execution.

Ask:

```text
Could the same job start twice?
Could a user submit twice?
Could a retry repeat the operation?
Could a process restart cause replay?
```

Where necessary, use:

```text
persistent job state
idempotent provider semantics
duplicate checks
safe status transitions
```

Do not solve duplication solely in the UI.

---

## 37. Database Transactions and External APIs

External calls and database transactions cannot usually be made truly atomic together.

Consider sequences such as:

```text
DB commit
        ↓
external call fails
```

and:

```text
external call succeeds
        ↓
DB commit fails
```

For external mutations, explicitly consider divergence between:

```text
provider state
portal state
```

Design failure handling accordingly.

Do not assume a SQL transaction can roll back an external provider action.

---

## 38. Commit Boundaries

Avoid holding database transactions open across slow external requests unless the current architecture explicitly requires it.

Long external operations can cause:

```text
locks
stale sessions
long transactions
poor failure recovery
```

Understand the existing transaction pattern before changing it.

---

## 39. Pagination

For paginated provider APIs:

```text
respect provider page size
detect final page correctly
avoid infinite loops
handle empty pages
handle repeated cursors/pages
```

Do not assume one request returns the entire dataset.

Preserve bounded behavior.

---

## 40. Large Provider Catalogs

If a provider catalog is expensive to load, consider existing cache behavior before optimizing.

Do not add caching automatically.

When proposing caching, define:

```text
cache lifetime
invalidations
scope
memory impact
provider freshness expectations
failure fallback
```

Optimization should follow evidence.

---

## 41. Network Availability

Assume external services can be unavailable.

The portal should fail predictably when:

```text
DNS fails
connection fails
TLS fails
request times out
provider returns 5xx
provider is rate-limited
provider returns invalid data
```

Do not allow temporary provider outages to corrupt persistent state.

---

## 42. TLS and Certificate Validation

Do not disable TLS verification merely to make an external request work.

Avoid:

```python
verify=False
```

unless there is an explicit, reviewed requirement.

Do not suppress certificate warnings globally.

If an internal provider requires custom certificate handling, treat it as a security-sensitive change.

Use:

```text
portal-security-change
```

as well.

---

## 43. User-Facing Progress

For background provider work, progress shown in the UI should represent actual persisted or reliably inferable state.

Do not report:

```text
100% complete
```

simply because a thread returned if individual records may still have failed.

Differentiate when possible:

```text
pending
running
completed
completed with errors
failed
```

Follow current project conventions unless explicitly redesigning job state.

---

## 44. Audit External Mutations

External mutations should normally be auditable.

Audit useful information such as:

```text
user
provider
operation
target
result
timestamp
```

Do not include credentials or secret request payloads.

For bulk changes, avoid enormous audit entries.

Prefer meaningful summaries.

---

## 45. API Version Changes

Treat provider API version changes as potentially breaking.

Before changing endpoint versions:

```text
identify changed endpoints
identify request schema changes
identify response schema changes
identify authentication changes
identify pagination changes
identify error-contract changes
```

Do not change only the URL and assume everything else is compatible.

---

## 46. Dependency Changes

Prefer existing HTTP libraries already used by the project.

Do not add a new API client library simply because one exists.

Before adding a provider SDK:

```text
compare with existing implementation
evaluate maintenance
evaluate dependency weight
evaluate security
evaluate actual benefit
```

Do not mix multiple HTTP/client approaches unnecessarily.

---

## 47. Mocking and Tests

External integrations should be tested without requiring real production credentials.

Use synthetic/mocked provider responses where practical.

Test important cases such as:

```text
success
timeout
429
401/403
404 when meaningful
500
invalid JSON
missing fields
partial success
retry exhaustion
```

Do not require real API calls for ordinary automated tests.

---

## 48. Test External Mutations Safely

For mutation integrations, prefer:

```text
mock
dry-run
test environment
provider sandbox
```

where available.

Do not run destructive provider operations merely to validate code.

If live mutation testing is unavoidable, require explicit user confirmation.

---

## 49. Test Retry Behavior

When changing retry logic, verify:

```text
correct errors trigger retry
non-retryable errors do not retry
maximum attempts respected
delay bounded
eventual success works
retry exhaustion produces useful failure
```

Avoid tests that actually sleep for long periods where delay mocking is practical.

---

## 50. Test Partial Success

For batch operations, include cases where:

```text
all succeed
some succeed
all fail
```

Verify that persisted job/results reflect reality.

Do not only test the all-success path.

---

## 51. Keep Changes Local

Do not refactor every provider client because one integration needs a change.

Prefer the smallest correct change inside the owning subsystem.

Do not create a generic abstraction like:

```text
UniversalApiClient
ProviderManager
ExternalServiceFramework
```

unless multiple concrete requirements justify it.

Existing duplication may be preferable to premature abstraction.

---

## 52. Shared External Utilities

If changing shared utilities, identify every subsystem that depends on them.

Potential cross-system areas may include:

```text
requests/session behavior
logging helpers
background helpers
IoC parsing
credential handling
```

Shared changes require broader regression validation.

---

## 53. Git Safety

Before changing an integration, run:

```bash
git status --short
```

Do not overwrite existing unrelated work.

Do not use destructive Git commands without explicit approval.

For risky external mutations or production-like work, consider:

```text
/careful
```

or:

```text
/guard
```

---

## 54. Documentation Updates

After changing external integration behavior, check whether to update:

```text
docs/systems/<subsystem>.md
docs/technical-debt/current.md
docs/PROJECT_MAP.md
docs/decisions/
```

Examples:

```text
VirusTotal cache behavior changed
→ update docs/systems/virustotal.md

Umbrella HTTP 207 debt resolved
→ update docs/systems/umbrella.md
→ update technical-debt/current.md

new provider introduced
→ update PROJECT_MAP.md

major integration architecture changed
→ consider ADR
```

Do not create ADRs for ordinary endpoint changes.

---

## 55. Recommended Integration With gstack

For an external API bug:

```text
/investigate
        ↓
identify root cause
        ↓
portal-external-api-change
        ↓
implementation
        ↓
/review
```

For a normal provider feature:

```text
portal-external-api-change
        ↓
implementation
        ↓
/review
```

For a risky external mutation:

```text
/careful
        ↓
portal-external-api-change
        ↓
implementation
        ↓
/review
        ↓
/codex review
```

For a major integration redesign:

```text
/plan-eng-review
        ↓
portal-external-api-change
        ↓
possibly new ADR
        ↓
implementation
        ↓
/review
        ↓
/codex challenge
```

Use only the workflows justified by the task.

---

## 56. Required Pre-Implementation Summary

Before implementing a non-trivial external integration change, summarize:

```md
## External Integration Change

### Objective

What provider behavior needs to change.

### Provider

Which external service and endpoint are involved.

### Current Behavior

How the portal currently performs the operation.

### Authentication

How provider credentials/tokens are handled.

### Proposed Change

The smallest implementation that satisfies the requirement.

### Retry / Timeout Impact

Any changes to network failure behavior.

### External Side Effects

Whether the operation reads or mutates provider state.

### Persistence Impact

What local data is created or updated.

### Partial Failure Behavior

How mixed provider outcomes are handled.

### Security Impact

Credential, authorization, or secret-handling implications.

### Risks

Concrete provider, network, data-consistency, or regression risks.

### Validation

How success, failure, retry, and partial-result behavior will be tested.
```

Keep the summary proportional to the task.

---

## 57. Completion Checklist

Before declaring an external integration change complete, verify:

```text
[ ] Relevant subsystem documentation was read
[ ] Current provider implementation was inspected
[ ] Endpoint and method were verified
[ ] Authentication flow was verified
[ ] Portal authorization was verified
[ ] Explicit timeout exists
[ ] Retry behavior is bounded
[ ] Retry safety/idempotency was considered
[ ] Rate limits/quotas were considered
[ ] Provider errors are classified appropriately
[ ] Invalid provider responses fail safely
[ ] Partial success is represented accurately
[ ] Credentials are not logged
[ ] External side effects cannot occur before authorization
[ ] Database/provider divergence was considered
[ ] Background restart behavior was considered if applicable
[ ] Duplicate execution was considered if applicable
[ ] Tests use synthetic/mocked credentials where possible
[ ] Success and failure paths were validated
[ ] Documentation was updated if behavior changed
[ ] Relevant technical debt was updated if resolved
[ ] Final diff was reviewed
```

---

## 58. Core Rule

Never treat an external API change as merely:

```text
send request
parse JSON
done
```

For this project, an external integration means:

```text
authentication
+
portal authorization
+
timeouts
+
bounded retries
+
rate limits
+
provider contracts
+
partial failure
+
external side effects
+
local persistence
+
background behavior
+
security
+
validation
```

Assume the network and the provider can fail.

Preserve local correctness even when they do.