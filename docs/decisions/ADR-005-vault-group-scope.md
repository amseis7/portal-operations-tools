# ADR-005: Vault Groups Have a Shared/Personal Scope

## Status

Accepted

## Context

`VaultGroup` had no ownership concept: every group was globally visible and
globally mutable by any user with the `vault` tool, with no distinction
between an organizational taxonomy (e.g. "Servidores", "Redes") and a single
user's own private organization of their non-shared credentials.

This was investigated as GAP #2 of the Vault authorization audit. The
investigation found this was a deliberate, documented design characteristic
(`docs/systems/vault.md` already described "No dedicated Vault ownership
exists for groups" and "Group creation/deletion is available to any
authenticated user"), not an accidental omission — `VaultGroup` has no
`owner_id`, and the KeePass export (`VaultSyncService._export()`) already
treats all groups as a single shared hierarchy exported to one `.kdbx` file.

However, leaving group creation/deletion open to any user with the `vault`
tool meant one user could disorganize another user's taxonomy, and there was
no way for a user to keep a private group structure for their own non-shared
credentials without it being visible to, and modifiable by, every other Vault
user.

## Decision

`VaultGroup` gains a `scope` column (`"shared"` | `"personal"`) and a
nullable `owner_id`:

```text
scope == "shared"   => owner_id IS NULL
scope == "personal" => owner_id IS NOT NULL
```

enforced by `ck_vault_group_scope_owner` (`CheckConstraint`).

### Shared groups

- Global, visible to every user with the `vault` tool.
- Creation and deletion: **admin-only**.
- Normal users may use a shared group when assigning a **shared** entry to
  it, but cannot create, rename, or delete one.

### Personal groups

- Belong to exactly one user (`owner_id`).
- Any user with the `vault` tool creates/deletes their own personal groups
  (`owner_id = current_user.id`, always server-side, never from form input).
- A normal user sees only their own personal groups, never another user's.
- Admin keeps today's existing administrative reach over entries: admin sees
  every user's personal group tree, clearly labeled per user, and may
  administer (including delete) any personal group — consistent with admin
  already having unrestricted access to every Vault entry regardless of
  ownership or `shared`. Admin does **not** get a "create a personal group
  on behalf of another user" capability; when admin creates a personal
  group, `owner_id = current_user.id` like any other user.

### Hierarchy

- A personal group's parent must be a personal group of the **same** owner.
- A shared group's parent must be a shared group.
- Mixing scopes in the same parent/child chain is not allowed.
- This is enforced in the application layer, not by a database
  `CheckConstraint` — a single-row CHECK cannot compare a row against its
  parent row's columns.

### Entry ↔ group compatibility

```text
entry.shared == True  => group is NULL or group.scope == "shared"
entry.shared == False => group is NULL or (group.scope == "personal"
                                            and group.owner_id == entry.owner_id)
```

Changing an entry's `shared` flag while it holds an incompatible group is
**rejected** (the whole submission fails validation before any mutation),
with the message: *"El grupo seleccionado no es compatible con el ámbito de
la credencial. Seleccione un grupo compatible o deje la credencial sin
grupo."* The group is never silently cleared.

### KeePass

The shared `.kdbx` export contains only `scope="shared"` groups and
`shared=True` entries. Personal groups and non-shared entries never reach the
shared KeePass file. KeePass import/sync only creates or reuses
`scope="shared"` groups (imported entries are already always `shared=True`).

### Historical data

Every `VaultGroup` row existing before this change is migrated as
`scope="shared"`, `owner_id=NULL` — no ownership is inferred, matching their
already-global, already-shared de facto behavior.

## Consequences

### Benefits

- Users can keep a private taxonomy for their own non-shared credentials
  without exposing or risking it to other Vault users.
- The destructive "any user can delete any group" gap (GAP #2) is closed as
  a side effect of giving shared groups an admin-only authority level,
  consistent with how KeePass import/sync are already admin-only.
- The KeePass export becomes more precise: it never carries personal data
  that was never meant to leave a single user's view.

### Costs

- The KeePass export now excludes non-shared entries and groups it
  previously (and arguably unintentionally) included — an explicit,
  intentional behavior change for operators to be aware of before deploying.
- Entry create/edit gains a new validation failure mode (incompatible
  group/scope) that did not exist before.
- Admin's personal-group view requires per-user labeling in the UI, a small
  but real UI complexity increase over the previous single flat tree.

## Agent Guidance

- Do not add ownership to shared groups.
- Do not implement "create a personal group for another user."
- Do not enforce parent/child scope coherence via a database
  `CheckConstraint` — that logic belongs in the application layer.
- Do not let `new()`/`edit()` trust a client-submitted `group_id` without
  revalidating scope/owner compatibility server-side, regardless of what the
  rendered dropdown offered.
- When extending KeePass import/export, preserve the shared-only rule above.
