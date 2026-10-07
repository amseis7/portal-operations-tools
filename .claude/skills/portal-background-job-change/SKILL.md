---
name: portal-background-job-change
description: >
  Project-specific workflow for changes involving background execution in Portal Operations Tools.
  Use when modifying threading.Thread workers, APScheduler jobs, long-running tasks,
  job persistence, progress tracking, retries, duplicate execution, restart behavior,
  scheduled work, external API jobs, background database access, or task status models.
  Complements portal-database-change, portal-security-change, and portal-external-api-change
  with repository-specific background-processing rules.
---

# Portal Background Job Change

## Purpose

Use this skill whenever a change affects work that continues outside a normal synchronous Flask request.

Examples:

- `threading.Thread`;
- APScheduler jobs;
- long-running operational tasks;
- asynchronous VirusTotal analysis;
- Umbrella bulk jobs;
- Vault synchronization;
- scheduled execution;
- job progress;
- background retries;
- restart recovery;
- duplicate execution;
- job persistence;
- background database access;
- worker failure handling.

This skill exists because background work has different correctness requirements from ordinary request/response code.

It does not replace:

- `portal-database-change`
- `portal-security-change`
- `portal-external-api-change`
- `/investigate`
- `/plan-eng-review`
- `/review`
- `/careful`
- `/codex`

Use them when their concerns also apply.

---

# 1. Load Project Context First

Before modifying background behavior, read:

```text
AGENTS.md
docs/PROJECT_MAP.md
docs/technical-debt/current.md
```

Then read the documentation for the affected subsystem.

Examples:

```text
VirusTotal background analysis
→ docs/systems/virustotal.md

Umbrella jobs
→ docs/systems/umbrella.md

Vault synchronization
→ docs/systems/vault.md

scheduled application work
→ inspect app initialization and scheduler configuration
```

Do not load unrelated subsystem documentation automatically.

---

# 2. Inspect the Actual Execution Path

Before changing background behavior, determine:

```text
what starts the task
which function performs the work
whether a Flask request starts it
whether APScheduler starts it
whether threading.Thread is used
whether application context is created
what data is passed into the worker
what database records represent progress
what happens when the worker succeeds
what happens when it fails
what happens if the application restarts
```

Do not infer background behavior solely from route names or documentation.

Trace the actual code path.

---

# 3. Classify the Work

Before implementation, classify the task.

Use one of these categories:

```text
short synchronous work

long-running in-process work

scheduled recurring work

external side-effect job

persistent/durable job
```

Do not use a background thread merely because a request takes several seconds.

Likewise, do not force a genuinely long-running operation into a synchronous HTTP request.

---

# 4. Existing Background Architecture

The project currently uses mechanisms such as:

```text
threading.Thread
APScheduler
database-backed job/status records
```

Preserve the existing architecture unless the requirement genuinely exceeds its capabilities.

Do not introduce:

```text
Celery
Redis
RQ
RabbitMQ
Kafka
separate worker service
```

merely because they are common background-job technologies.

A new queue architecture requires a concrete operational need.

---

# 5. Understand the Durability Requirement

For every background task, determine whether work is allowed to disappear if the application process stops.

Ask:

```text
Can the task safely be lost on restart?

Can the user simply retry?

Does external state already change before completion?

Must the task resume after restart?

Must execution be guaranteed?

Would duplicate execution be dangerous?
```

This determines whether the current in-process architecture is sufficient.

---

# 6. In-Process Threads Are Not Durable

A `threading.Thread` running inside the Flask process may disappear when:

```text
the application restarts
the process crashes
the machine reboots
the deployment replaces the process
the development server reloads
```

Do not describe such tasks as durable.

Do not imply:

```text
job persisted in DB
```

means:

```text
worker execution is persisted
```

These are different concepts.

---

# 7. Persistent Status Does Not Guarantee Persistent Execution

A database job record can survive a restart while its worker does not.

For example:

```text
Job.status = running
```

may remain indefinitely after the process that performed the work disappears.

When modifying job status behavior, consider stale states explicitly.

Possible states may include:

```text
pending
running
completed
completed_with_errors
failed
cancelled
interrupted
```

Do not add states unless the subsystem actually needs them.

---

# 8. Restart Behavior Must Be Explicit

For non-trivial jobs, define what happens when the application restarts.

Possible strategies include:

```text
job remains failed/interrupted
user manually retries
startup reconciliation marks stale jobs
worker resumes job
job is requeued
operation is intentionally non-resumable
```

Do not accidentally implement restart recovery without considering duplicate external actions.

---

# 9. Avoid False Recovery

Do not automatically rerun every job marked:

```text
running
```

after restart.

The external operation may already have succeeded before the local process died.

Blind replay could cause:

```text
duplicate provider mutations
duplicate records
duplicate notifications
duplicate imports
incorrect state
```

Recovery requires understanding idempotency.

---

# 10. Duplicate Execution

For each job, determine whether it can start more than once.

Possible causes:

```text
double click
multiple browser requests
retry
scheduler overlap
manual + scheduled execution
multiple app processes
application restart
duplicate worker startup
```

If duplicate execution matters, define protection explicitly.

Possible mechanisms include:

```text
persistent status checks
unique database constraints
job ownership
provider idempotency
locks
deduplication keys
safe repeated operations
```

Use the smallest mechanism appropriate to the risk.

---

# 11. UI Prevention Is Not Enough

Disabling a button after clicking it may improve UX.

It does not prevent duplicate backend execution.

Always assume a user or client can submit the request again.

Duplicate protection must exist server-side when correctness requires it.

---

# 12. Scheduled Jobs

For APScheduler tasks, determine:

```text
trigger type
schedule
timezone
startup behavior
overlap behavior
maximum instances
misfire behavior
what happens during downtime
```

Do not alter scheduler semantics without understanding these settings.

---

# 13. Scheduler Registration

Before adding a scheduled job, inspect where APScheduler is initialized and where current jobs are registered.

Follow the existing lifecycle.

Avoid registering the same job multiple times because:

```text
app factory is called more than once
debug reload occurs
multiple processes start
module import repeats
```

Job registration must be predictable.

---

# 14. Multiple Application Processes

In-process schedulers can behave differently when multiple web-server processes are used.

If every process registers the same APScheduler job, the task may execute multiple times.

Before adding important scheduled work, determine whether deployment can run:

```text
multiple workers
multiple processes
multiple app instances
```

Do not assume development-server behavior matches production.

If single-instance scheduling is required, make the limitation explicit.

---

# 15. Flask Application Context

Background threads do not automatically inherit Flask application context.

When the worker needs:

```text
db
current_app
application config
Flask extensions
```

ensure the correct application context is used.

Do not depend on:

```python
current_app
```

inside a thread unless context is intentionally established.

---

# 16. Request Context Does Not Survive Automatically

Do not assume background threads retain:

```text
request
session
current_user
form data
```

after the HTTP request ends.

Capture only the minimum immutable data required for execution.

Prefer passing:

```text
user_id
job_id
object_id
validated parameters
```

rather than request-bound objects.

---

# 17. Do Not Pass ORM Objects Blindly Into Threads

SQLAlchemy objects may be bound to a request/session that is no longer valid.

Prefer passing identifiers such as:

```text
job_id
user_id
entry_id
```

and reloading objects inside the worker's own application/database context.

This reduces:

```text
stale session
detached instance
cross-thread session
unexpected commit behavior
```

Follow existing subsystem patterns when they are correct.

---

# 18. Database Sessions

Each background execution context should use database sessions safely.

Do not share request-scoped SQLAlchemy sessions across threads.

After worker completion or failure, ensure session state is not left inconsistent.

Be careful with:

```text
partial commits
rollback behavior
exceptions
long transactions
```

---

# 19. Transaction Boundaries

Avoid keeping a database transaction open during long network or filesystem operations unless there is a concrete reason.

A safer conceptual flow is often:

```text
load state
        ↓
mark job running
        ↓
commit
        ↓
perform external work
        ↓
persist result
        ↓
commit
```

But this is not universally correct.

Consider the actual operation.

---

# 20. External Side Effects

If background work calls an external provider, also apply:

```text
portal-external-api-change
```

External mutations require particular care around:

```text
retries
duplicates
idempotency
partial success
network failure
local/provider divergence
```

Do not retry external mutations automatically just because the job runs in the background.

---

# 21. Local and External State Can Diverge

Consider:

```text
external operation succeeds
        ↓
process dies
        ↓
local database never records success
```

and:

```text
local job marked complete
        ↓
external operation was only partially successful
```

For external jobs, define how these inconsistencies are detected or represented.

Do not assume a SQL transaction can roll back provider state.

---

# 22. Progress Must Represent Reality

If a job exposes progress:

```text
0%
25%
50%
100%
```

define exactly what each value means.

Do not derive progress solely from time elapsed.

Prefer measurable work such as:

```text
processed_items / total_items
```

when applicable.

Do not mark 100% before final persistence and result handling complete.

---

# 23. Progress Updates

Avoid committing progress after every tiny operation if it creates excessive database overhead.

For large jobs, consider reasonable update granularity.

Examples:

```text
per batch
every N items
meaningful phase boundaries
```

Do not optimize this prematurely for small workloads.

---

# 24. Job Status Semantics

Define status transitions clearly.

Example:

```text
pending
   ↓
running
   ↓
completed
```

Failure:

```text
pending
   ↓
running
   ↓
failed
```

Partial outcome:

```text
running
   ↓
completed_with_errors
```

if the subsystem needs that distinction.

Avoid arbitrary transitions such as:

```text
failed → running
```

without explicit retry semantics.

---

# 25. Record Start and Completion Times

For operational jobs, timestamps may be useful for:

```text
troubleshooting
stale-job detection
duration
audit
user feedback
```

If adding them requires schema changes, use:

```text
portal-database-change
```

Do not add timestamps merely because they are conventional if the job model does not need them.

---

# 26. Error State

A worker failure should produce a deterministic job state.

Do not leave a job indefinitely:

```text
running
```

because an exception escaped.

Use:

```text
try
except
finally
```

carefully around worker state.

Do not hide unexpected exceptions.

Log them safely and update job status where appropriate.

---

# 27. Error Persistence

Persist only useful operational error information.

Do not store entire:

```text
stack traces
HTTP responses
credential payloads
secret values
```

in job records.

Prefer sanitized information such as:

```text
error category
safe provider message
safe summary
HTTP status
```

Avoid leaking sensitive data into the database.

---

# 28. Worker Logging

Useful worker logs may include:

```text
job ID
subsystem
phase
processed count
provider status
duration
error category
```

Do not log:

```text
API keys
passwords
tokens
Vault secrets
KeePass passwords
Authorization headers
sensitive imported content
```

Use job IDs to correlate events instead of dumping full payloads.

---

# 29. User Ownership

If jobs belong to users, define:

```text
who may create the job
who may inspect status
who may view results
who may retry
who may cancel
what admins may access
```

Do not assume access to a subsystem means access to every user's job.

If ownership/security changes are involved, use:

```text
portal-security-change
```

---

# 30. Job Result Authorization

Endpoints such as:

```text
/job/<id>
/job/<id>/status
/job/<id>/results
```

must validate authorization.

A numeric or UUID job ID is not an authorization mechanism.

Test direct access using another user's job ID.

---

# 31. Credentials in Workers

Avoid passing plaintext credentials unnecessarily into background threads.

Where practical:

```text
worker receives user/provider config ID
        ↓
worker reloads encrypted credential
        ↓
decrypts only when needed
        ↓
uses credential
        ↓
plaintext leaves scope
```

Do not persist decrypted credentials in job payloads.

---

# 32. Secret Lifetime

Background jobs can last longer than HTTP requests.

That makes secret handling more important.

Do not keep plaintext credentials in:

```text
global variables
long-lived scheduler objects
serialized job payloads
database status fields
logs
```

Limit plaintext to the operation that requires it.

---

# 33. VirusTotal Background Work

Before modifying VirusTotal background execution, read:

```text
docs/systems/virustotal.md
```

Pay attention to:

```text
background analysis
per-user API key
local result reuse
cross-record reuse
rate limits
CSIRT propagation
provider failures
job/result behavior
```

Do not increase VirusTotal calls merely because work is asynchronous.

Background execution does not remove provider quota limits.

---

# 34. Umbrella Background Work

Before modifying Umbrella jobs, read:

```text
docs/systems/umbrella.md
```

Pay particular attention to:

```text
job ownership
dry-run
bulk PATCH
retries
HTTP 207
partial results
external side effects
progress
background thread behavior
```

Umbrella can mutate an external production service.

Duplicate execution and retries require explicit review.

---

# 35. Vault Background Work

Before modifying Vault background/scheduled synchronization, read:

```text
docs/systems/vault.md
```

Also use:

```text
portal-vault-change
portal-security-change
```

when appropriate.

Consider:

```text
KeePass file locking
sync overlap
manual vs scheduled sync
credential lifetime
database/KDBX consistency
restart behavior
```

Do not allow overlapping KDBX writes without understanding corruption risk.

---

# 36. Scheduler + Manual Execution

If the same operation can be triggered:

```text
manually
+
scheduler
```

define overlap behavior.

Possible policies:

```text
allow both safely
reject second execution
queue second execution
skip scheduled run when already active
```

Do not leave this implicit if concurrent execution can cause damage.

---

# 37. Cancellation

Do not add a Cancel button unless the worker can actually stop safely.

Thread cancellation is not automatically available.

A UI status change from:

```text
running
```

to:

```text
cancelled
```

does not terminate the underlying work.

If cancellation is required, define cooperative cancellation explicitly.

---

# 38. Cooperative Cancellation

For safely cancellable iterative work, a worker may periodically check persistent cancellation state.

Conceptually:

```text
for item in items:
    check cancellation
    process item
```

Do not interrupt work at arbitrary points where doing so could corrupt:

```text
database state
files
provider state
```

Cancellation semantics must be designed per operation.

---

# 39. Retries

Retries may occur at several levels:

```text
HTTP client retry
item retry
job retry
user manual retry
scheduler retry
```

Avoid stacking retries unintentionally.

For example:

```text
HTTP client retries 5 times
×
job retries 3 times
```

may produce 15 provider attempts.

Map retry layers before adding another one.

---

# 40. Manual Retry

If users can retry failed jobs, determine whether retry means:

```text
continue unfinished work
restart entire job
retry failed items only
create a new job
reuse existing job
```

External side effects determine what is safe.

Do not simply call the same worker again without considering what already succeeded.

---

# 41. Batch Processing

For large item sets, background jobs may process batches.

Define:

```text
batch size
transaction scope
provider request size
progress updates
partial failures
retry scope
```

Do not choose batch sizes arbitrarily.

Provider limits and database behavior should inform the choice.

---

# 42. Partial Completion

A batch job may complete some items and fail others.

Represent this accurately.

Possible outcome:

```text
completed_with_errors
```

with per-item results.

Do not flatten mixed outcomes into:

```text
completed
```

unless the business logic explicitly considers partial success acceptable.

---

# 43. Per-Item Results

When useful, persist per-item outcomes such as:

```text
success
failed
skipped
not_found
unsupported
already_current
```

Do not persist excessively detailed provider payloads unless required.

Keep results operationally useful and safe.

---

# 44. Do Not Swallow Exceptions

Avoid patterns such as:

```python
try:
    ...
except Exception:
    pass
```

in background work.

Unexpected failures must be visible through:

```text
logging
job status
safe error information
```

while preserving application stability.

---

# 45. Failure Isolation

For batch work, determine whether one item failure should:

```text
stop entire job
skip item and continue
retry item
mark job partial
```

Do not choose one globally.

Use the semantics of the operational task.

---

# 46. Scheduler Failure

Scheduled jobs should not crash the entire application because one scheduled execution failed.

Failures should be isolated, logged, and represented appropriately.

Do not allow repeated scheduler failures to generate uncontrolled retries or log flooding.

---

# 47. Timezones

Scheduled times must have explicit timezone semantics.

Do not assume:

```text
server local time
user local time
UTC
```

are interchangeable.

If the current scheduler uses a defined timezone, preserve it.

Do not change timezone behavior incidentally.

---

# 48. Long-Running HTTP Requests

If a task currently runs synchronously and causes request timeouts, background execution may be appropriate.

Before moving it to a worker, identify everything the request currently relies on:

```text
current_user
request form
flash
redirect
database session
provider client
temporary files
```

Move only validated data into the worker.

Do not try to continue using request-local state after returning the HTTP response.

---

# 49. Thread-Safe Data

Values passed into a worker should preferably be:

```text
IDs
strings
numbers
immutable configuration
validated plain structures
```

Avoid passing:

```text
open file handles
request objects
SQLAlchemy sessions
mutable globals
browser session objects
```

unless explicitly designed for thread safety.

---

# 50. Shared Mutable State

Avoid using global Python dictionaries or lists as the sole source of truth for important job state.

They disappear on restart and may be unsafe across processes.

For operationally important status, prefer persisted state when appropriate.

Do not create database persistence for trivial ephemeral work unless needed.

---

# 51. Application Shutdown

Do not assume background threads will complete during normal application shutdown.

If graceful completion is required, the architecture must explicitly support it.

Do not use daemon-thread behavior without understanding its consequences.

---

# 52. Development Reloaders

Development servers can restart processes automatically.

This may:

```text
kill active threads
register scheduled jobs twice
repeat startup side effects
```

Do not validate background correctness solely under Flask debug mode.

Understand the production server lifecycle too.

---

# 53. Production Server Behavior

The portal may run through servers such as:

```text
Cheroot
Waitress
```

and development may use Flask's server.

Background behavior can differ depending on process/thread configuration.

Do not rely on a server implementation detail unless it is an explicit project requirement.

---

# 54. Database Schema Changes

If background behavior requires new fields such as:

```text
status
progress
started_at
completed_at
error
retry_count
owner_id
```

use:

```text
portal-database-change
```

Do not modify the database directly.

Create a new Alembic migration.

---

# 55. Security Changes

If background jobs modify authorization, ownership, credentials, or secret handling, use:

```text
portal-security-change
```

Examples:

```text
per-user jobs
admin-only jobs
provider credentials
Vault synchronization
sensitive result access
```

Background execution does not bypass normal security requirements.

---

# 56. External API Changes

If the job communicates with an external service, use:

```text
portal-external-api-change
```

Pay particular attention to:

```text
timeouts
retries
rate limits
partial success
idempotency
provider mutations
```

---

# 57. New Operational Tool

If background processing is part of a completely new portal tool, also use:

```text
portal-new-operational-tool
```

The background worker should fit the owning subsystem.

Do not create a standalone generic job subsystem unless requirements justify it.

---

# 58. Avoid Premature Queue Architecture

Do not introduce a distributed job queue just because current threads have limitations.

First identify the requirement.

A queue architecture becomes more reasonable if the application genuinely needs several of:

```text
durable execution
restart recovery
multiple workers
distributed processing
reliable retries
worker isolation
scheduled durable jobs
long-running execution
high job volume
```

One missing property alone may have a smaller solution.

---

# 59. When Current Architecture Is Insufficient

Stop and run:

```text
/plan-eng-review
```

if the requirement includes things such as:

```text
job must never be lost
job must resume after crash
multiple app servers must coordinate work
exactly-once execution is expected
long-lived workers must be independently scalable
reliable distributed retries are required
```

Do not quietly bolt durability assumptions onto `threading.Thread`.

---

# 60. Exactly-Once Is Difficult

Be cautious with requirements described as:

```text
run exactly once
```

Failures can happen between:

```text
external side effect
```

and:

```text
local persistence
```

True exactly-once behavior is often impossible across independent systems.

Prefer designing for:

```text
idempotency
deduplication
reconciliation
safe retry
```

where appropriate.

---

# 61. Reconciliation

For high-value external operations, consider whether a reconciliation step is needed.

Example:

```text
portal thinks mutation failed
        ↓
provider may actually have accepted it
        ↓
query provider state
        ↓
reconcile local result
```

Do not add reconciliation universally.

Use it only where inconsistent state has meaningful operational consequences.

---

# 62. Monitoring

Background jobs should be observable enough to diagnose failures.

Depending on importance, useful signals include:

```text
started
completed
failed
duration
processed count
failure count
provider error category
```

Do not add an entire monitoring platform merely for one workflow.

Use existing logs and persisted job state appropriately.

---

# 63. Stale Job Detection

If persistent jobs can remain incorrectly:

```text
running
```

after process termination, consider whether stale-job detection is needed.

Possible signals:

```text
started_at
last_progress_at
worker heartbeat
application startup reconciliation
```

Use the simplest strategy that satisfies actual operational requirements.

Do not implement heartbeat infrastructure speculatively.

---

# 64. Heartbeats

Heartbeats are useful only when:

```text
jobs are long enough
stale detection matters
workers are expected to survive independently
```

For short jobs, they may add unnecessary complexity.

Do not add heartbeats automatically.

---

# 65. Cleanup

Background tasks may create temporary artifacts.

Define cleanup behavior for:

```text
success
failure
cancellation
process crash
retry
```

Examples include:

```text
uploaded files
temporary JSON
exports
downloaded provider data
Vault import state
```

Security-sensitive temporary artifacts deserve particular attention.

---

# 66. Avoid Deleting Diagnostic Evidence Too Early

Cleanup should not remove the only information necessary to diagnose a failed operational job.

Distinguish:

```text
sensitive temporary payload
```

from:

```text
safe job metadata/error record
```

Delete secrets where appropriate while retaining safe diagnostic information.

---

# 67. Testing Background Work

Do not rely only on manually clicking the UI and waiting.

Where practical, test worker functions directly with controlled inputs.

Separate:

```text
route starts job
```

from:

```text
worker performs job
```

enough that each can be validated.

Do not over-refactor solely for testing if the current design can be tested safely.

---

# 68. Test Success

For affected background work, verify:

```text
job starts
status changes correctly
work executes
results persist
completion state is correct
user can retrieve result
```

---

# 69. Test Failure

Also verify:

```text
worker exception
provider timeout
provider failure
database error where practical
invalid input
partial item failure
```

The job should not remain falsely successful or indefinitely running.

---

# 70. Test Duplicate Execution

For high-risk tasks, verify what happens when execution is triggered twice.

Test:

```text
same user double-submits
scheduled run overlaps
retry occurs
```

according to the task's risk.

Do not assume this cannot happen.

---

# 71. Test Restart Semantics Conceptually

When restart behavior matters, verify or document:

```text
what persisted state remains
what worker state disappears
whether job is recoverable
whether retry is safe
```

If full restart testing is practical, perform it against synthetic data.

Do not claim restart resilience without testing or explicit architecture support.

---

# 72. Use Synthetic External Data

Do not use real production mutations simply to test background execution.

Prefer:

```text
mocked provider
dry-run
synthetic database data
temporary KeePass file
```

depending on the subsystem.

Live external mutation requires explicit user approval.

---

# 73. Documentation

After changing background behavior, determine whether to update:

```text
docs/systems/<subsystem>.md
docs/technical-debt/current.md
docs/PROJECT_MAP.md
docs/decisions/
```

Examples:

```text
job state behavior changed
→ update docs/systems/<subsystem>.md

non-durable job debt fixed
→ update docs/technical-debt/current.md

new shared worker architecture introduced
→ update PROJECT_MAP.md
→ likely ADR
```

Do not create an ADR for ordinary thread fixes.

---

# 74. Architectural Decisions

A new ADR may be appropriate if the project deliberately adopts a new background-processing architecture such as:

```text
durable queue
external worker process
job broker
distributed scheduler
persistent retry engine
```

Document:

```text
problem
decision
alternatives
tradeoffs
operational consequences
```

Do not introduce such architecture without explicit need.

---

# 75. Git Safety

Before modifying background infrastructure:

```bash
git status --short
```

Do not overwrite unrelated work.

Do not use destructive Git commands without explicit approval.

For high-risk changes consider:

```text
/careful
```

or:

```text
/guard
```

---

# 76. Keep Changes Scoped

Do not combine a background-job fix with:

```text
complete provider rewrite
database cleanup
authentication redesign
frontend redesign
dependency upgrades
unrelated refactoring
```

unless directly required.

Background behavior is already difficult to reason about.

Keep the diff focused.

---

# 77. Recommended Workflow for Background Bugs

For an existing background bug:

```text
/investigate
        ↓
trace task lifecycle
        ↓
portal-background-job-change
        ↓
relevant subsystem skill
        ↓
implement smallest fix
        ↓
/review
```

---

# 78. Recommended Workflow for External Background Jobs

For background work calling providers:

```text
portal-background-job-change
        +
portal-external-api-change
        ↓
implementation
        ↓
/review
```

If provider state is mutated:

```text
/careful
        ↓
portal-background-job-change
        ↓
portal-external-api-change
        ↓
implementation
        ↓
/review
        ↓
/codex review
```

---

# 79. Recommended Workflow for Persistent Job Changes

If schema/job persistence changes:

```text
portal-background-job-change
        +
portal-database-change
```

If job ownership or credentials are involved:

```text
+
portal-security-change
```

Use only the skills relevant to the change.

---

# 80. Recommended Workflow for Background Architecture Changes

For significant changes such as introducing durable workers:

```text
/plan-eng-review
        ↓
document requirements
        ↓
evaluate current architecture
        ↓
propose architecture
        ↓
create ADR if accepted
        ↓
implementation
        ↓
/review
        ↓
/codex challenge
        ↓
/qa
```

Do not implement the queue first and justify it afterward.

---

# 81. Required Pre-Implementation Summary

Before implementing a non-trivial background-processing change, summarize:

```md
## Background Job Change

### Objective

What long-running or scheduled behavior needs to change.

### Trigger

What starts the job: user request, scheduler, startup, or another event.

### Current Execution Model

Thread, scheduler, synchronous request, or other mechanism currently used.

### Job State

What persistent or in-memory state represents the job.

### Durability Requirement

Whether work may be lost on restart and whether resume/retry is required.

### Duplicate Execution

How duplicate starts, retries, overlaps, or restarts are handled.

### External Side Effects

Whether the job calls or mutates external systems.

### Database Behavior

Session, transaction, progress, and result persistence implications.

### Security

Job ownership, authorization, and credential handling.

### Failure Behavior

Timeout, exception, partial completion, restart, and retry semantics.

### Proposed Change

The smallest implementation satisfying the requirement.

### Risks

Duplicate execution, lost work, stale status, partial results, external divergence,
security, or data corruption risks.

### Validation

Success, failure, duplicate, partial, and restart-related behavior to test.
```

Keep the summary proportional to the task.

---

# 82. Completion Checklist

Before declaring a background-processing change complete, verify:

```text
[ ] Relevant subsystem documentation was read
[ ] Actual task lifecycle was traced
[ ] Trigger mechanism was identified
[ ] Execution mechanism was identified
[ ] Durability requirement was defined
[ ] Restart behavior was considered
[ ] Duplicate execution was considered
[ ] Scheduler overlap was considered if applicable
[ ] Flask application context is correct
[ ] Request context is not incorrectly reused
[ ] SQLAlchemy sessions are safe for the worker
[ ] Long database transactions were avoided where possible
[ ] Job status transitions are correct
[ ] Worker exceptions produce deterministic status
[ ] Progress reflects real work
[ ] Partial completion is represented accurately
[ ] External API timeouts exist if applicable
[ ] Retry layers were mapped
[ ] External mutation retry safety was considered
[ ] Credentials are not persisted/logged in plaintext
[ ] Job ownership/access is enforced if applicable
[ ] Temporary artifacts are cleaned appropriately
[ ] Success path was tested
[ ] Failure path was tested
[ ] Duplicate/retry behavior was tested when relevant
[ ] Restart limitation was tested or documented
[ ] Documentation was updated
[ ] Relevant technical debt was updated if resolved
[ ] Final diff was reviewed
```

---

# 83. Core Rule

Never treat background execution as merely:

```text
start thread
return response
done
```

For this project, background work means:

```text
trigger
+
execution lifecycle
+
application context
+
database session
+
job state
+
progress
+
failure handling
+
restart behavior
+
duplicate execution
+
external side effects
+
security
+
observability
+
validation
```

If work must survive process failure, guarantee retries, coordinate multiple workers,
or reliably resume, first verify that the current in-process architecture can actually
satisfy that requirement.