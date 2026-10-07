---
name: portal-git-and-change-scope
description: >
  Project-specific workflow for Git safety, change isolation, staging, commits,
  branch hygiene, diff review, sensitive-file protection, and scope control in
  Portal Operations Tools. Use before staging or committing changes, when a task
  touches files that already contain unrelated work, when generated/runtime files
  may exist, or when preparing a change for review or push. Complements gstack
  careful/guard/review workflows with repository-specific Git and scope rules.
---

# Portal Git and Change Scope

## Purpose

Use this skill whenever a task involves:

- modifying multiple files;
- staging changes;
- preparing commits;
- reviewing a diff;
- protecting unrelated uncommitted work;
- working on a branch with existing changes;
- avoiding generated/runtime artifacts;
- preventing secrets from entering Git;
- splitting unrelated work into logical commits;
- checking whether a change exceeded requested scope.

This skill defines repository-specific Git hygiene for Portal Operations Tools.

It does not replace:

- `/careful`
- `/guard`
- `/review`
- `/codex`
- normal Git knowledge

It complements them with project-specific constraints.

---

# 1. Start With Git State

Before any non-trivial change, inspect:

```bash
git status --short
```

Also identify the current branch:

```bash
git branch --show-current
```

Do not assume a clean working tree.

Do not assume existing modifications belong to the current task.

---

# 2. Existing User Work Is Protected

If files already contain changes before the current task:

```text
do not reset them
do not overwrite them
do not restore them
do not discard them
```

Understand whether the current task must modify the same files.

If yes, preserve existing intent while making the smallest compatible change.

Do not use destructive cleanup as a shortcut.

---

# 3. Never Use Destructive Git Commands Without Explicit Approval

Do not execute commands such as:

```bash
git reset --hard
git clean -fd
git restore .
git checkout -- .
git checkout -- path/to/file
```

when they may discard user work.

Only use destructive Git operations when:

```text
the user explicitly approves
the exact impact is understood
the affected files are known
```

Prefer non-destructive inspection first.

---

# 4. Do Not Blindly Stage Everything

Avoid:

```bash
git add .
```

or:

```bash
git add -A
```

when the repository may contain:

```text
runtime files
generated files
secrets
database files
temporary output
unrelated work
```

Prefer explicit staging:

```bash
git add path/to/file1 path/to/file2
```

or carefully selected directories.

---

# 5. Sensitive Files Must Not Be Committed

Never stage or commit protected runtime material such as:

```text
.env
instance/
*.db
*.sqlite
*.sqlite3
*.kdbx
*.keyx
private keys
runtime secret exports
temporary Vault plaintext files
credential dumps
access tokens
API key files
```

Do not inspect secret contents merely to decide whether they are sensitive.

Use filenames, paths, and repository policy.

---

# 6. Verify Ignore Rules

If a sensitive/runtime file exists locally, confirm Git ignores it when appropriate.

Useful:

```bash
git check-ignore -v .env
```

or:

```bash
git check-ignore -v path/to/file
```

If a protected file is not ignored:

```text
do not stage it
report the gap
consider updating .gitignore if appropriate
```

Do not add a secret merely because Git currently tracks or detects it.

---

# 7. Tracked Sensitive Files Require Special Care

If a sensitive file is already tracked, `.gitignore` will not automatically protect it.

Examples:

```text
private key
real certificate bundle containing secret key
database
runtime credential file
```

Do not expose its contents.

Do not automatically remove it from history.

Report the issue and require deliberate remediation.

Historical secret removal may require:

```text
key rotation
history rewrite
deployment coordination
```

Treat it as a security task.

---

# 8. Generated Files Are Not Source Changes

Avoid staging generated artifacts such as:

```text
build/
dist/
__pycache__/
*.pyc
venv/
.venv/
runtime logs
temporary exports
```

unless the repository intentionally tracks a specific generated artifact.

Prefer changing the source/configuration that generates them.

---

# 9. Experimental Directories

Treat experimental or third-party generated areas cautiously.

Examples may include:

```text
.opencode/
.opencode/node_modules/
```

Do not stage large experimental trees automatically.

Do not treat an experimental agent collection as canonical project architecture.

Inspect repository policy first.

---

# 10. Project-Local Claude Skills

Project-specific Claude skills belong in:

```text
.claude/skills/
```

Only commit real project skills.

Do not commit temporary test skills such as:

```text
portal-skill-test
```

once their purpose is complete.

Do not commit global skills stored in:

```text
~/.claude/skills/
```

Global gstack installation is outside the repository.

---

# 11. Third-Party Skill Content

If a third-party skill is installed inside the repository:

```text
determine whether it is intentionally vendored
check its size
check generated dependencies
check license/repository expectations
```

Do not commit:

```text
node_modules
build caches
downloaded package caches
```

unless intentionally required.

---

# 12. Scope Comes From the User Request

Before editing, define:

```text
requested behavior
affected subsystem
files likely required
validation needed
```

Do not expand scope because nearby code looks messy.

Examples of unrelated expansion:

```text
formatting whole module
renaming variables outside task
upgrading dependencies
moving files
rewriting helpers
fixing unrelated debt
```

Report unrelated issues separately.

---

# 13. Smallest Correct Change

Prefer:

```text
smallest diff
that fully satisfies the requested behavior
```

over:

```text
broad cleanup
while already in the file
```

A focused diff is easier to:

```text
review
test
revert
understand
merge
```

---

# 14. Existing Technical Debt Is Not Automatic Scope

Finding known debt during implementation does not automatically authorize fixing it.

Use:

```text
docs/technical-debt/current.md
```

to understand context.

If unrelated:

```text
leave it unchanged
mention it if relevant
```

If the requested change directly touches it:

```text
fix only what is required
update debt documentation if resolved
```

---

# 15. Avoid Formatting Churn

Do not reformat entire files for a localized change.

Avoid changing:

```text
quotes
line wrapping
import ordering
whitespace
template formatting
```

through unrelated sections unless necessary.

Formatting churn hides semantic changes.

---

# 16. Avoid Opportunistic Renames

Do not rename:

```text
functions
variables
files
routes
models
database fields
tool IDs
```

unless the task requires it.

Renames increase regression and merge risk.

This is especially important for persisted identifiers such as:

```text
UserTool identifiers
database columns
UUID semantics
route names used by templates
```

---

# 17. Avoid Dependency Drift

Do not modify:

```text
requirements.txt
Dockerfile
package configuration
```

unless the current change actually requires it.

If dependency changes are necessary, keep them explicit and minimal.

Do not upgrade unrelated packages.

---

# 18. Inspect Diff During Work

Do not wait until the end to discover scope creep.

Useful:

```bash
git diff
```

For a single file:

```bash
git diff -- path/to/file
```

Review periodically during non-trivial changes.

Look for:

```text
unexpected files
large formatting changes
debug code
accidental deletes
secret values
```

---

# 19. Review Untracked Files

`git diff` does not show untracked files.

Always combine it with:

```bash
git status --short
```

before committing.

Untracked files may include:

```text
new migrations
new documentation
new templates
temporary files
secret files
```

Do not overlook them.

---

# 20. New Migration Files

Database changes often create new files under:

```text
migrations/versions/
```

Ensure the intended new migration is staged.

Do not accidentally stage:

```text
database files
Alembic runtime artifacts
unrelated old migration edits
```

Historical migration files should normally remain unchanged.

---

# 21. Diff Review for Database Changes

When database-related files change, inspect:

```text
models
migration file
routes/business logic
tests
documentation
```

Confirm the diff does not include unrelated schema cleanup.

Use:

```text
portal-database-change
```

for schema correctness.

---

# 22. Diff Review for Security Changes

For security-sensitive diffs, search for accidental:

```text
removed decorators
broadened access
debug secret output
plaintext storage
CSRF exemptions
hardcoded credentials
```

Use:

```text
portal-security-change
```

when applicable.

---

# 23. Diff Review for External API Changes

Look for unintended changes to:

```text
endpoint
HTTP method
timeout
retry count
authentication
payload
response handling
```

Do not let a provider bug fix silently change production mutation semantics.

Use:

```text
portal-external-api-change
```

when applicable.

---

# 24. Diff Review for Background Changes

Look for:

```text
new thread creation
scheduler registration
duplicate worker startup
status transition changes
retry loops
credential capture
```

Use:

```text
portal-background-job-change
```

when applicable.

---

# 25. Diff Review for Runtime Changes

Look for:

```text
absolute paths
new environment requirements
server port changes
bind changes
certificate changes
startup migration changes
new dependencies
```

Use:

```text
portal-runtime-environment-change
```

when applicable.

---

# 26. Debug Code Must Not Reach Commit

Before staging, search mentally or explicitly for temporary code such as:

```python
print(...)
pprint(...)
breakpoint()
import pdb
pdb.set_trace()
```

and temporary logging such as:

```text
DEBUG TEST
TEMP
TODO REMOVE
```

Do not remove legitimate production logs merely because they resemble debug output.

Review context.

---

# 27. Temporary Test Files

Do not commit ad-hoc local artifacts such as:

```text
test_output.json
response_dump.txt
debug.html
sample_real_data.csv
temporary KDBX
manual DB copy
screenshots
```

unless explicitly intended as test fixtures and sanitized.

---

# 28. Fixtures Must Be Synthetic

If a file is intentionally committed as a fixture:

```text
use synthetic data
remove real credentials
remove personal information
remove production identifiers
```

Do not use real Vault/provider data.

---

# 29. Commit Logical Units

A commit should represent a coherent change.

Good examples:

```text
Fix Vault entry authorization
Add project-local database skill
Make server certificate paths portable
Add missing Flask-Migrate dependency
```

Avoid commits like:

```text
misc fixes
changes
updates
stuff
```

---

# 30. One Commit vs Multiple Commits

Use one commit when changes form one coherent unit.

Split commits when the working tree contains clearly independent work.

Example:

```text
Commit 1
Vault feature implementation

Commit 2
Claude project skills/documentation
```

Do not split tightly coupled code/migration/docs arbitrarily.

A migration and the model change it implements usually belong together.

---

# 31. Do Not Rewrite Existing User Commits Without Request

Avoid:

```bash
git commit --amend
git rebase
git reset --soft
git reset --mixed
```

on existing commits unless the user explicitly wants history rewritten.

Normal new commits are safer.

---

# 32. Do Not Force Push Without Explicit Approval

Never use:

```bash
git push --force
git push --force-with-lease
```

without explicit user approval and a clear explanation of impact.

Prefer normal push.

---

# 33. Branch Choice Is Separate From Change Correctness

Do not block valid work solely because the branch name is imperfect.

If the user intentionally continues on an existing branch:

```text
respect that choice
```

Do not create/switch branches without need.

Branch cleanup can be handled separately.

---

# 34. Check Branch Before Push

Before pushing:

```bash
git branch --show-current
```

Confirm the target is the branch the user intends.

Then:

```bash
git push origin "$(git branch --show-current)"
```

or equivalent.

Do not guess the branch.

---

# 35. Upstream State

Before important pushes, consider:

```bash
git status
```

and where appropriate:

```bash
git fetch
```

Then inspect whether the branch is:

```text
ahead
behind
diverged
```

Do not automatically merge/rebase remote changes without understanding them.

---

# 36. Pulling Remote Changes

Before `git pull`, inspect local uncommitted work.

Do not pull blindly over an unclear working tree.

If changes exist:

```text
understand them first
```

Avoid automatic conflict situations where possible.

---

# 37. Merge and Rebase Are Deliberate Operations

Do not choose between:

```text
merge
rebase
```

without considering repository history policy.

For existing user branches, do not rewrite public history casually.

If unsure, prefer non-destructive merge or ask before history rewrite.

---

# 38. Conflict Resolution

During conflicts:

```text
understand both sides
preserve intended behavior
do not choose ours/theirs blindly
```

After resolving:

```text
re-run relevant validation
review diff
```

Conflicts in:

```text
models
migrations
authorization
config
```

deserve especially careful review.

---

# 39. Migration Conflicts

If two branches created Alembic revisions from the same parent, do not simply delete one.

Determine whether:

```text
migration merge revision
manual sequencing
rebasing unpublished migration
```

is appropriate.

Use:

```text
portal-database-change
```

and inspect migration graph.

Do not rewrite published historical migrations casually.

---

# 40. Commit Messages

Use concise imperative or descriptive messages that identify the actual change.

Good:

```text
Fix Vault delete authorization
Add portal database change skill
Improve Mac runtime portability
Handle Umbrella partial success
```

Avoid:

```text
Update
Fix stuff
WIP
Final
Changes 2
```

unless a temporary WIP workflow was explicitly requested.

---

# 41. Commit Message Must Match Contents

Do not use:

```text
Fix Vault auth
```

for a commit that also:

```text
updates dependencies
rewrites runtime paths
adds skills
changes Umbrella logic
```

Either narrow the staged files or choose appropriate logical commits.

---

# 42. Stage Explicitly

A safe staging flow:

```bash
git status --short
git diff
git add <intended-files>
git diff --cached --stat
git diff --cached
```

Do not commit before reviewing staged content.

---

# 43. `git diff --cached` Is Mandatory Before Important Commits

Before committing non-trivial work:

```bash
git diff --cached
```

Review what Git will actually commit.

The unstaged diff and staged diff may differ.

Do not assume because working files look correct that staging is correct.

---

# 44. Review Staged File List

Use:

```bash
git status --short
```

or:

```bash
git diff --cached --name-only
```

Check for unexpected files.

Especially watch for:

```text
.env
database
private keys
generated files
huge dependency directories
runtime logs
temporary exports
```

---

# 45. Large File Sanity Check

If a new file is unexpectedly large, investigate before commit.

Examples:

```text
database
binary export
KDBX
build artifact
node_modules file
log dump
```

Do not commit large runtime artifacts accidentally.

---

# 46. Secret Sanity Check

Before security-sensitive commits, inspect staged diff for obvious secret assignments.

Search patterns may include:

```text
SECRET_KEY=
API_KEY=
PASSWORD=
TOKEN=
CLIENT_SECRET=
```

Do not print the user's real `.env`.

Review only staged source/doc content.

---

# 47. Documentation Can Leak Secrets Too

A secret can accidentally enter Git through:

```text
README
ADR
system doc
skill file
example config
comment
test fixture
```

Do not focus only on source code.

Synthetic placeholders must be clearly fake.

---

# 48. Avoid Real Internal Infrastructure Values When Unnecessary

Do not commit operationally sensitive values such as:

```text
real production IPs
internal hostnames
real usernames
real filesystem shares
real provider tenant IDs
```

unless they are intentionally public/project configuration and required.

Prefer placeholders in documentation/examples.

---

# 49. Review File Deletions

Before committing, check whether files were deleted.

Use:

```bash
git diff --cached --name-status
```

Unexpected `D` entries deserve inspection.

Do not commit accidental file deletions.

---

# 50. Renames

Git may infer renames.

Verify a rename was intentional and did not lose content.

Avoid mass rename churn during feature work.

---

# 51. File Permissions

On macOS/Linux, executable-bit changes can appear in Git.

Review unexpected mode changes such as:

```text
100644 → 100755
```

Do not commit accidental permission changes.

Shell scripts may legitimately require executable bits.

---

# 52. Line Ending Changes

Cross-platform work can produce large CRLF/LF diffs.

If a file appears completely changed with no semantic reason:

```text
check line endings
```

Do not commit massive line-ending churn during a small task.

Preserve repository conventions.

---

# 53. Case-Only Renames

macOS filesystems may be case-insensitive.

Be careful with changes such as:

```text
File.py → file.py
```

Git behavior may differ across platforms.

Use deliberate Git rename operations when needed.

Do not perform case-only renames incidentally.

---

# 54. `.gitignore` Changes

Only add ignore rules for genuine generated/runtime/sensitive patterns.

Do not ignore source files to hide unwanted Git status.

Bad:

```text
ignore migrations because they are noisy
```

Good:

```text
ignore local runtime database
ignore virtual environment
ignore generated build directory
```

---

# 55. Do Not Ignore Problems Away

If a file should be version-controlled but changes unexpectedly, investigate.

Do not add it to `.gitignore` merely to clean `git status`.

Examples of files that likely belong in Git:

```text
source
templates
migrations
requirements
docs
project-local skills
```

---

# 56. Shared Files Have Larger Scope

Changes to:

```text
app/__init__.py
app/extensions.py
app/models.py
app/utils.py
app/tools_config.py
config.py
base.html
```

can affect multiple subsystems.

Before committing, validate broader regression surface.

Use:

```text
portal-testing-and-validation
```

---

# 57. High-Risk Files

Treat changes to these areas carefully:

```text
authentication
authorization helpers
encryption helpers
migrations
Vault
server startup
database bootstrap
background execution
provider mutation clients
```

Consider:

```text
/careful
/review
/codex review
```

based on risk.

---

# 58. Do Not Mix Generated Documentation With Source Without Need

If a tool generates docs automatically, avoid manual changes that will be overwritten.

Commit the source generating them if that is the project convention.

If generated docs are intentionally tracked, regenerate deterministically.

---

# 59. User-Requested Snapshot Commits

Sometimes the user may intentionally want a broad checkpoint commit.

Even then:

```text
exclude secrets
exclude runtime artifacts
exclude generated junk
review staged diff
```

A snapshot is not permission to commit everything blindly.

---

# 60. Work-in-Progress Commits

If the user explicitly wants a WIP commit, it may contain incomplete behavior.

Still ensure:

```text
no secrets
no accidental runtime files
commit message says WIP
known broken state is understood
```

Do not present WIP as validated final work.

---

# 61. Final Commits Should Pass Validation

Before a final commit, use:

```text
portal-testing-and-validation
```

for relevant checks.

Do not commit a known broken final state unless the user explicitly requests preserving it for debugging.

---

# 62. Documentation Changes Belong With Behavior

When practical, stage relevant:

```text
system docs
technical debt updates
ADR
PROJECT_MAP changes
```

with the code they describe.

Do not leave docs stale after a verified behavior change.

Use:

```text
portal-docs-and-adr-maintenance
```

---

# 63. Skill Changes Should Be Reviewed as Code

Project-local skill files influence future agent behavior.

Before committing skill changes, review for:

```text
contradictory instructions
stale paths
dangerous Git commands
duplicate gstack responsibilities
overly broad authority
incorrect project architecture
```

Treat `.claude/skills/` as important project configuration.

---

# 64. Skill Scope

A project skill should not grant permission to:

```text
rewrite architecture automatically
fix all technical debt
read protected secrets
perform destructive Git operations
```

Skills should constrain agent behavior, not expand it unsafely.

---

# 65. Staged Documentation Review

Before committing documentation/skills:

```bash
git diff --cached -- docs AGENTS.md CLAUDE.md .claude/skills
```

Check for:

```text
real secrets
wrong paths
stale claims
accidental duplication
temporary skill test files
```

---

# 66. Commit Verification

After committing:

```bash
git status
```

Verify whether expected working changes remain.

Then inspect the commit if needed:

```bash
git show --stat --oneline HEAD
```

or:

```bash
git show HEAD
```

Do not assume commit contents were correct without checking important changes.

---

# 67. Push Is Separate From Commit

A successful commit is local.

To publish:

```bash
git push origin "$(git branch --show-current)"
```

or use GitHub Desktop.

Do not claim changes are on GitHub until push succeeds.

---

# 68. GitHub Desktop Is Valid

The user may use GitHub Desktop instead of CLI for:

```text
reviewing changes
staging/selecting files
committing
pushing
branch inspection
```

The same safety rules apply:

```text
review changed files
exclude secrets
exclude runtime artifacts
review commit contents
push intended branch
```

Do not force terminal-only workflows.

---

# 69. GitHub Desktop “No Local Changes”

If GitHub Desktop reports:

```text
No local changes
```

verify if needed with:

```bash
git status --short
```

Possible explanations:

```text
changes already committed
changes are in another repository path
changes are in another branch
files are ignored
```

Do not assume data loss.

---

# 70. Repository Path Verification

When terminal and GitHub Desktop disagree, confirm:

```bash
pwd
git rev-parse --show-toplevel
```

Ensure both tools point to the same repository.

Do not modify files in a duplicate clone accidentally.

---

# 71. Multiple Clones

If the project exists in more than one folder:

```text
identify canonical active clone
```

before editing or committing.

Do not assume similar folder names are the same working tree.

This is especially relevant after moving development to another machine.

---

# 72. Branch-Aware Validation

If current work is on a feature/refactor branch, validate against that branch's actual state.

Do not compare mentally only against `main`.

The branch may intentionally contain completed work not yet merged.

---

# 73. Do Not Force Branch Cleanup Mid-Task

If the user says branch organization is not currently important:

```text
focus on requested work
```

Do not derail the task into:

```text
merge strategy
branch rename
PR cleanup
```

unless branch state blocks safe work.

---

# 74. Before Creating a New Branch

Only create a branch when useful.

Good reasons:

```text
isolating major risky work
user explicitly requests it
parallel work requires it
current branch must remain stable
```

Do not create branches mechanically for every tiny change.

---

# 75. Commit Scope Summary

Before committing a non-trivial change, summarize internally:

```md
## Commit Scope

### Intended Change

What this commit is supposed to contain.

### Files

Which files belong to the change.

### Excluded Work

Existing unrelated modifications that must remain unstaged.

### Sensitive/Runtime Check

Protected files confirmed excluded.

### Validation

What was tested before commit.

### Documentation

Which docs/skills are included because behavior changed.
```

Keep this proportional to the task.

---

# 76. Recommended Safe Commit Flow

Use this default flow:

```bash
git status --short
```

Then inspect:

```bash
git diff
```

Stage only intended files:

```bash
git add <file1> <file2> ...
```

Review:

```bash
git diff --cached --stat
git diff --cached
```

Commit:

```bash
git commit -m "Concise meaningful message"
```

Verify:

```bash
git status
```

Push when intended:

```bash
git push origin "$(git branch --show-current)"
```

Adapt when using GitHub Desktop.

---

# 77. Recommended Flow for High-Risk Changes

For changes involving:

```text
security
encryption
database migrations
external production mutations
runtime bootstrap
```

use:

```text
/careful
        ↓
implementation
        ↓
portal-testing-and-validation
        ↓
git diff review
        ↓
/review
        ↓
/codex review when justified
        ↓
explicit staging
        ↓
commit
```

Do not stage first and inspect later.

---

# 78. Recommended Flow With Existing Unrelated Changes

If the working tree already contains unrelated edits:

```text
identify current-task files
        ↓
avoid touching unrelated files
        ↓
stage exact files/hunks only
        ↓
review cached diff
        ↓
commit current task
```

If one file contains both current-task and unrelated changes, consider:

```text
interactive staging
```

such as:

```bash
git add -p path/to/file
```

only if comfortable and safe.

Do not discard the unrelated hunks.

---

# 79. Interactive Staging

`git add -p` can be useful to separate logical changes within the same file.

Use it carefully.

Before committing, always inspect:

```bash
git diff --cached
```

Interactive staging can accidentally omit required dependent lines.

Do not use it blindly for migrations or tightly coupled edits.

---

# 80. Unstage Safely

If the wrong file is staged, use a non-destructive unstage command appropriate for the Git version, such as:

```bash
git restore --staged path/to/file
```

This should leave the working-tree edit intact.

Do not use destructive restore/reset variants unnecessarily.

---

# 81. Do Not Commit Broken Secrets Configuration

If source requires a newly introduced secret/configuration variable:

```text
update safe documentation/examples
```

but do not commit the actual value.

Ensure another developer can understand what must be configured.

---

# 82. Commit Runtime Fixes Reproducibly

If the fix required:

```bash
pip install package
```

ensure the repository records the dependency if appropriate.

The commit should not rely on undocumented local state.

Use:

```text
portal-runtime-environment-change
```

for these cases.

---

# 83. Review After Push

For important changes, verify remote publication through:

```bash
git status
```

and branch state, or GitHub Desktop/web.

Do not repeatedly push unrelated local changes accidentally.

---

# 84. Failed Push

If push is rejected:

```text
do not force push immediately
```

First determine:

```text
remote branch advanced
authentication issue
branch protection
network problem
upstream mismatch
```

Resolve safely.

---

# 85. Branch Protection and PRs

If remote policy requires a Pull Request:

```text
push feature branch
open PR
review CI/review feedback
```

Do not bypass branch protection.

Do not force direct push to protected `main`.

---

# 86. CI Failures

If CI fails after push:

```text
inspect failure
determine whether introduced by current commit
fix with a new commit unless history rewrite was explicitly requested
```

Do not amend/force-push public history by default.

---

# 87. Revert vs Reset

For already-published bad commits, prefer:

```text
git revert
```

when preserving history is important.

Do not use reset/force push by default.

Choose based on repository state and user instruction.

---

# 88. Commit History Is Part of Project Context

Good commit history helps future:

```text
debugging
bisecting
review
understanding architecture changes
```

Keep commits meaningful but do not over-engineer history.

Correctness and safety come first.

---

# 89. Completion Checklist

Before declaring Git/change-scope work complete, verify:

```text
[ ] Current branch identified
[ ] Initial git status inspected
[ ] Existing user changes preserved
[ ] No destructive Git commands used without approval
[ ] Requested scope defined
[ ] Unrelated refactoring avoided
[ ] Sensitive files excluded
[ ] Runtime/database files excluded
[ ] Generated artifacts excluded
[ ] Global skills excluded from repository
[ ] Temporary project skill tests excluded
[ ] Untracked files reviewed
[ ] Diff reviewed
[ ] Shared/high-risk files reviewed carefully
[ ] Relevant validation completed
[ ] Documentation included where behavior changed
[ ] Staging was explicit
[ ] Staged file list reviewed
[ ] git diff --cached reviewed
[ ] No secret values present in staged content
[ ] No accidental deletions present
[ ] No accidental file-mode/line-ending churn present
[ ] Commit message matches contents
[ ] Commit created on intended branch
[ ] Working tree checked after commit
[ ] Push performed only when intended
[ ] No force push used without explicit approval
```

---

# 90. Core Rule

Never treat Git as:

```text
change files
git add .
git commit
git push
done
```

For this project, safe Git work means:

```text
understand current state
+
protect existing user work
+
control scope
+
exclude secrets/runtime artifacts
+
review diff
+
validate behavior
+
stage explicitly
+
review staged content
+
commit logical change
+
push intentionally
```

The repository history must contain the intended source changes and nothing that
should have remained local, sensitive, generated, or unrelated.