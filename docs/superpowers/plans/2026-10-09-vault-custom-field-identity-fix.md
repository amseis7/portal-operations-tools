# Vault Custom Field Identity Fix (debt #38) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for every task below (failing test → implementation → passing test). Steps use checkbox (`- [ ]`) syntax for tracking. Vault work also requires `portal-vault-change` and `portal-security-change` during implementation, and `/review` before landing.
>
> **Revised after `/plan-eng-review` (native sections + Codex outside voice).** See "Review history" at the end for what changed and why. Do not implement from any earlier copy of this file.

**Goal:** Fix `docs/technical-debt/current.md` item #38 (P0): `_save_custom_fields()` in `app/vault/routes.py` can silently lose or swap a protected custom field's ciphertext on key rename, duplicate-`field_key` deletion, or reorder, because it matches prior ciphertext to submitted rows by `field_key` string equality against a pre-delete snapshot instead of by stable row identity.

**Root cause (confirmed by `/investigate`):** no `VaultEntryField.id` is ever rendered into the edit form, carried through the JS, or submitted back — the server deletes every row for the entry first, then tries to re-match submitted blank values to old ciphertext using only `field_key` text + FIFO order. Full findings in the preceding investigation (not reproduced here).

**Approved direction (Option A — user-confirmed):** round-trip the existing `VaultEntryField.id` through the edit form and match by that identity instead of by key. No schema change (the id already exists), no `UNIQUE(entry_id, field_key)` constraint (duplicate keys stay supported — identity makes them safe).

**Tech stack:** Flask / SQLAlchemy (existing). `unittest` + Flask test client (existing harness, `tests/base.py`, mirrors `tests/vault/test_custom_field_protection.py`). No new dependency.

---

## Global Constraints (from the approved decisions — do not deviate without asking)

1. **No migration. No `UNIQUE(entry_id, field_key)`.** Identity is the existing PK; duplicate keys remain explicitly supported.
2. **Fail closed on any `id` that isn't a current field of *this* entry** — unknown, stale (deleted concurrently), or foreign (belongs to another `VaultEntry`). Reject the **whole submit**, no silent demotion to "new field," no partial apply. Generic error, HTTP 409. Never reveal whether the id belongs to another entry or another user.
3. **Fail closed on duplicate `id` within the same POST.** Reject the whole submit. No first-wins, no last-wins. **This check must run for every item that carries a non-null `id`, regardless of whether that item's `key` is blank** (see Task 1 — a blank-key row used to bypass this check entirely in the first draft of this plan; fixed).
4. **Blank-value preserve applies only when the existing row was already `is_protected == True` *before this edit*.** A field that was unprotected before (its real value was visible in the form) and is blanked now means "save empty," even if the user also checks "Protegido" in the same submit. Do not extend preserve-semantics to that case.
5. **Atomicity, validate-before-mutate (not rollback-as-the-mechanism):** in `edit()`, call `_diff_custom_fields()` **before** any `entry.*` attribute is assigned and before any `db.session.flush()` — not after, with rollback cleaning up afterward. This makes "no mutation happens until validation fully passes" literally true in the code, not just true because a later rollback happens to undo it. Keep a defensive `db.session.rollback()` in the except-block anyway (cheap insurance against an unrelated pending state), but it is not the primary correctness mechanism. `new()` is the one exception — see Task 2's notes on why its ordering stays as create-then-validate-then-rollback-on-conflict.
6. **`id` type validation is a strict type check, not a coercion.** Accept only JSON integers for a non-null `id`. Reject (raise `CustomFieldConflict`) anything that is a `bool` (Python `bool` is an `int` subclass — `True`/`False` must not silently resolve to `1`/`0`), a float (`12.9` must not silently truncate to `12`), a string, or any other type. Never call bare `int(raw_id)` as the validation step.
7. **Priority confirmed P0.** Silent, irrecoverable secret loss/swap via a normal Vault edit.
8. **Debt #38 may only be marked RESOLVED after Tasks 1–2 are implemented, their tests are green, AND `/review` has actually run on the implementation** — not as part of this planning pass, and not simply because Task order places documentation last (see Task 3).
9. **Tasks 1's algorithm and Task 2's call-site/template changes ship together, in one deploy.** They cannot be separated — see Task 2's "Why this task was merged" for the concrete reason (shipping the new server algorithm against the old template would reproduce the exact secret-loss bug this plan fixes).

## Non-goals (explicitly out of scope for this fix)

- No change to `new.html` or the create flow's JS — `/vault/new` never has pre-existing rows, so every submitted item already has no `id`; the new diff algorithm treats that uniformly as "new field" with zero special-casing required.
- No change to the unprotected→protected blank-value behavior (Global Constraint 4 keeps it as-is).
- No change to KeePass import's custom-field creation path (`is_protected=False` on import is unrelated, untouched).
- No refactor of `_can_edit`/`_can_access`/unrelated Vault authorization.
- **No payload-versioning scheme** to detect "this POST came from a page rendered before the deploy." See Risks — this is an accepted, narrow, residual risk, not solved by new mechanism (flag this if you disagree; it was not asked for and would be new complexity for an internal, low-traffic admin tool).

## Review Focus (what a reviewer should specifically try to break)

- **Foreign-id IDOR via `/vault/new`.** A user creates a *new* entry and crafts `custom_fields_json` with a non-null `id` that actually belongs to someone else's existing `VaultEntryField`. Expected: `entry.custom_fields` is empty at this point, so the id is not found → whole submit rejected with 409, nothing persisted.
- **Blank-key smuggling (Codex finding, fixed in Task 1).** A payload where every item has `"key": ""` but carries a duplicate or foreign non-null `id`. Must still be rejected — blank key must never exempt an item from id validation.
- **Partial-apply under rollback.** A payload where item 1 is a legitimate rename+blank-preserve and item 2 carries a bogus id. Expected: the entry's title/other fields and item 1's custom field are **both** unchanged after the 409 — not just item 2 rejected while item 1 silently applied.
- **JS/server contract drift.** `serialize()` must emit the same `id` the page was rendered with for every untouched row, even after one or more `cf-del` clicks spliced the `fields` array. **The automated tests for this plan cannot actually exercise the browser JS** (Flask's test client never runs `syncFromDOM()`/`splice()`/`render()`/`serialize()` — see Task 2's required manual browser check).
- **Duplicate-key safety under identity.** Two protected fields sharing `field_key="TOKEN"`: delete either one, rename either one, swap their DOM order — the *other* one's ciphertext must never move, regardless of which one the user touched. Test assertions must check the **id → ciphertext mapping**, not just that the right *set* of plaintexts survived (a set comparison can't detect two siblings' values being swapped).

---

## Task 1: Pure diff/validate algorithm (no route/template changes yet)

**Files:**
- Modify: `app/vault/routes.py` — add `class CustomFieldConflict(Exception)`, add `_diff_custom_fields(entry, cf_json_str)`, add `_apply_custom_fields(entry, updates, new_items, delete_ids)`. Leave the old `_save_custom_fields()` in place but unused by routes yet (removed in Task 2).
- Test: `tests/vault/test_custom_field_identity.py` (new file — keeps the existing `test_custom_field_protection.py` focused on HTTP-level scenarios).

**`_diff_custom_fields(entry, cf_json_str)` contract:**

```
Input:  entry (VaultEntry, with entry.custom_fields already loaded/flushed)
        cf_json_str (raw request.form value)

Output: (updates, new_items, delete_ids)
  updates    = [(VaultEntryField, new_key, new_value, new_protected), ...]
  new_items  = [(key, value, protected), ...]
  delete_ids = set of VaultEntryField.id to remove

Raises: CustomFieldConflict  — on ANY of:
  - cf_json_str is not valid JSON, or not a list, or an item is not an object
  - an item's "id" is present, non-null, but is not a plain int (bool and float excluded)
  - the same non-null "id" appears more than once across the payload — checked
    for EVERY item carrying that id, independent of that item's key
  - a non-null "id" does not match any id in entry.custom_fields

Never mutates db.session. Pure read + classify.
```

**Corrected algorithm** (fixes the Codex-identified gap: validation used to run only for non-blank-key items, letting a blank-key row smuggle an unvalidated duplicate/foreign id past the fail-closed contract):

```python
def _diff_custom_fields(entry, cf_json_str):
    try:
        items = json_mod.loads(cf_json_str or "[]")
    except (ValueError, TypeError):
        raise CustomFieldConflict()
    if not isinstance(items, list):
        raise CustomFieldConflict()

    existing_by_id = {f.id: f for f in entry.custom_fields}
    seen_ids = set()
    updates, new_items, delete_ids = [], [], set()

    for raw in items:
        if not isinstance(raw, dict):
            raise CustomFieldConflict()

        raw_id = raw.get("id")
        key = str(raw.get("key", "")).strip()
        value = str(raw.get("value", ""))
        protected = bool(raw.get("protected", False))

        if raw_id is None:
            if key:
                new_items.append((key, value, protected))
            continue  # blank key + no id: genuinely inert, nothing to validate

        # Strict type check — never coerce. bool is an int subclass in
        # Python, so it must be excluded explicitly.
        if isinstance(raw_id, bool) or not isinstance(raw_id, int):
            raise CustomFieldConflict()

        # Duplicate-id check runs for EVERY non-null id, before the
        # blank-key branch below — this is the fix for the smuggling gap.
        if raw_id in seen_ids:
            raise CustomFieldConflict()
        seen_ids.add(raw_id)

        field = existing_by_id.get(raw_id)
        if field is None:
            raise CustomFieldConflict()

        if key:
            updates.append((field, key, value, protected))
        else:
            # Existing row, key blanked out by the user: explicit delete,
            # not "leave unchanged" (matches the pre-fix behavior where a
            # blank key meant "don't recreate this field").
            delete_ids.add(raw_id)

    # Rows never mentioned in the payload at all (user clicked the trash
    # button, removing the row from the DOM entirely) are also deleted.
    delete_ids |= (set(existing_by_id) - seen_ids)
    return updates, new_items, delete_ids
```

**`_apply_custom_fields(entry, updates, new_items, delete_ids)` contract:** only called after `_diff_custom_fields` returns successfully; always applies fully.

```python
for field, key, value, protected in updates:
    if not value and field.is_protected:   # pre-edit flag, read before overwritten
        field.field_key = key
        field.is_protected = protected
        # field.field_value_enc intentionally untouched
    else:
        field.field_key = key
        field.field_value_enc = encrypt(value)
        field.is_protected = protected

for key, value, protected in new_items:
    db.session.add(VaultEntryField(
        entry_id=entry.id, field_key=key,
        field_value_enc=encrypt(value), is_protected=protected,
    ))

if delete_ids:
    VaultEntryField.query.filter(
        VaultEntryField.entry_id == entry.id,
        VaultEntryField.id.in_(delete_ids),
    ).delete(synchronize_session=False)
```

- [ ] **Step 1: Write failing tests** in `tests/vault/test_custom_field_identity.py`, calling `_diff_custom_fields`/`_apply_custom_fields` directly against an in-memory `VaultEntry` with real flushed `VaultEntryField` rows. Cover at minimum:
  - rename (same id, new key, blank value) → `updates` has it, value preserved after apply, **and `field.id` is unchanged** (assert identity, not just ciphertext).
  - duplicate key, delete one of two by id → `delete_ids` has exactly the deleted one; the surviving one's own ciphertext is preserved (not the deleted sibling's) — assert by **id → ciphertext mapping**, not a sorted-value-set comparison.
  - unknown id → `CustomFieldConflict`.
  - foreign id (belongs to a *different* `VaultEntry`'s field) → `CustomFieldConflict`.
  - duplicate id in payload, both occurrences with non-blank keys → `CustomFieldConflict`.
  - **duplicate id in payload where one or both occurrences have a blank key** → `CustomFieldConflict` (the Codex-identified smuggling case — must fail, not silently skip).
  - **foreign id with a blank key** → `CustomFieldConflict` (same smuggling case, foreign-id variant).
  - `id: true` and `id: 12.9` → both `CustomFieldConflict` (strict type check, no coercion).
  - malformed JSON / non-list payload → `CustomFieldConflict`.
  - blank value on a field that was `is_protected=False` before → value wiped (encrypted empty), confirms Global Constraint 4.
  - new item (`id: null`) alongside existing updates → ends up in `new_items`, not matched against any existing row.
  - **a payload where every item has a blank key** (e.g. `[{"id": null, "key": "", ...}]` or no items reference any existing id) against an entry that has existing custom fields → confirm this correctly deletes every field via `delete_ids`, and that this is the **intended** explicit-delete-via-omission behavior, not a surprise (document it as such in the test name/docstring).
- [ ] **Step 2: Implement** `_diff_custom_fields`/`_apply_custom_fields` per the corrected contract above.
- [ ] **Step 3: Run the new test file, confirm all pass.** Do not touch `routes.py` call sites yet — that's Task 2.

## Task 2: Wire into `edit()`/`new()` + round-trip `id` through `edit.html` — single atomic unit

**Why this task was merged (Codex finding — this plan originally split this into two separate tasks/deploys):** the new `_diff_custom_fields()` treats a submitted item with no `id` as unconditionally "new." If the server-side algorithm (old Task 2) were deployed before the template/JS change that makes the browser actually send `id` (old Task 3), every edit submission — including from the project's own pre-existing tests, which POST id-less payloads — would have every existing row's `id` missing, causing the algorithm to treat **all of them as brand-new fields**: previously-protected fields with a blank value would get `encrypt("")` (since blank-preserve only applies within `updates`, never `new_items`), which is **exactly the secret-loss bug this plan exists to fix**, reintroduced via the deploy gap. The pre-existing tests (`test_blank_protected_field_preserves_existing_secret`, `test_nonblank_protected_field_replaces_secret`, `test_unchecking_protected_with_blank_value_preserves_secret_and_clears_flag`, `test_duplicate_key_blank_submissions_preserve_each_original_independently`) would also start failing once only the server half landed, since they currently POST id-less payloads by construction — so the "green suite" claim in the original plan was not achievable with the tasks split. Both halves land in the same commit/deploy, and the four listed existing tests are **rewritten** (not just "kept"/"extended") to fetch and submit the real `id` for each row, as part of this task.

**Files:**
- Modify: `app/vault/routes.py`:
  - `edit()`'s GET branch: `existing_cf` gains `"id": f.id` per item (alongside existing `key`/`value`/`protected`).
  - `edit()`'s POST branch, **reordered** per Global Constraint 5 — validate custom fields *before* touching any entry attribute:
    ```python
    if form.validate_on_submit():
        try:
            updates, new_items, delete_ids = _diff_custom_fields(
                entry, request.form.get("custom_fields_json", "[]")
            )
        except CustomFieldConflict:
            flash("No se pudieron guardar los cambios: los datos de la "
                  "entrada cambiaron. Recargue la página e intente "
                  "nuevamente.", "danger")
            existing_cf = [...]  # recomputed from entry's actual current state
            return render_template(
                "vault/edit.html", form=form, entry=entry,
                existing_cf=existing_cf,
            ), 409

        entry.title = form.title.data
        entry.category = form.category.data
        entry.username = form.username.data
        entry.url = form.url.data or None
        entry.shared = form.shared.data
        entry.group_id = int(form.group_id.data) if form.group_id.data else None
        entry.expires_at = _parse_expires_at(form.expires_at.data)
        if form.password.data:
            entry.password_enc = encrypt(form.password.data)
        entry.notes_enc = encrypt(form.notes.data) if form.notes.data else None

        db.session.flush()
        _apply_custom_fields(entry, updates, new_items, delete_ids)
        log_audit("vault", "edit", "entry", entry.id, entry.title)
        db.session.commit()
        vault_sync.trigger_async(current_app._get_current_object())
        flash("Entrada actualizada.", "success")
        return redirect(url_for("vault.detail", entry_id=entry.id))
    ```
    Nothing is mutated before `_diff_custom_fields()` succeeds, so a `CustomFieldConflict` here needs no `db.session.rollback()` to stay correct — there is nothing pending to discard. (Keep one anyway, directly before the `flash(...)` call, as cheap defense-in-depth against any unrelated pending session state; it is not load-bearing.)
  - `new()`'s POST branch **keeps its existing order** (create `VaultEntry`, `db.session.flush()` for the id, *then* validate custom fields) — unlike `edit()`, there is no "partial attribute mutation of a pre-existing row" risk here: the entry is either a fully-committed fresh row or, on `CustomFieldConflict`, a fully-rolled-back fresh row. `db.session.rollback()` here *is* load-bearing (it discards the pending `INSERT` for the new entry itself), so keep it:
    ```python
    db.session.add(entry)
    db.session.flush()
    try:
        updates, new_items, delete_ids = _diff_custom_fields(
            entry, request.form.get("custom_fields_json", "[]")
        )
    except CustomFieldConflict:
        db.session.rollback()
        flash("No se pudieron guardar los cambios: los datos enviados no "
              "son válidos. Vuelva a intentarlo.", "danger")
        return render_template("vault/new.html", form=form), 409
    _apply_custom_fields(entry, updates, new_items, delete_ids)
    log_audit("vault", "create", "entry", entry.id, entry.title)
    db.session.commit()
    ```
    This path is only reachable via a deliberately crafted request (Review Focus — foreign-id IDOR), since the real `/vault/new` page never sends an `id`.
  - **409 responses render the template directly; they never wrap `redirect(...)` with a non-3xx status.** (Codex finding: `return redirect(...), 409` keeps the redirect's `Location` header and near-empty body while claiming a 409 status — browsers don't follow a 409 as a redirect, and the flash message never reaches the user. Always `render_template(..., 409)` for this path, on both routes.)
  - Delete the old `_save_custom_fields()` function once both call sites are migrated and the full suite is green.
- Modify: `app/templates/vault/edit.html` — JS changes (no new visible input; `id` is carried in the in-memory `fields` array, never rendered to the DOM, never shown to the user):
  - `btnAddCf` click handler: new row objects get `{id: null, key:'', value:'', protected:false}`.
  - `serialize()`: must call `syncFromDOM()` first (writes the latest key/value/protected back into the `fields` array by index, as it already does for `btnAddCf`/`cf-del`), then build the submitted array from `fields` itself (`fields.map(f => ({id: f.id, key: f.key.trim(), value: f.value, protected: f.protected}))`, skipping empty-key-and-no-id rows), instead of re-querying the DOM for `key`/`value`/`protected` while having no DOM source for `id` at all.
  - `render()`: unaffected otherwise.
- No change to `app/templates/vault/new.html` (Non-goals).
- Test: **rewrite** the four existing tests in `tests/vault/test_custom_field_protection.py` named above to fetch the real `VaultEntryField.id` from the DB (or from the GET response) and include it in the POSTed `custom_fields_json`, instead of posting an id-less payload. Extend the same file with the new scenarios in the Full Test Matrix below.

**Required manual browser check (Codex finding — the automated tests below cannot exercise the real JS):** Flask's test client never runs `syncFromDOM()`/`splice()`/`render()`/`serialize()` — a Python test that extracts ids from the GET response HTML and hand-builds the POST body would pass even if the actual browser serializer were broken (e.g., forgot to include `id`, or misaligned on reorder). Before calling this task done, in a real browser against a running dev instance, on one entry:
1. Add two custom fields both keyed `TOKEN`, mark both protected, save, reload the edit page.
2. Delete the **first** `TOKEN` row (via the trash button), leave the second blank, save. Open the browser devtools Network tab *before* saving and confirm the POSTed `custom_fields_json` body contains exactly one `TOKEN` item, with the `id` of the row that was *not* deleted.
3. Repeat, deleting the **second** `TOKEN` row instead, keeping the first — confirm the submitted `id` is the other one's.
4. Rename a surviving protected field's key while leaving its value blank, save, reopen edit, confirm the field is still present and (via KeePass export or an equivalent synthetic check — never a real credential) still decrypts to its original value.
5. Add a brand-new field with the same key as an untouched existing protected field in the same submission; confirm in devtools that the new row's JSON item has `id: null` and the untouched row's item carries its real `id`.

- [ ] **Step 1: Write failing tests** per the Full Test Matrix below (pure-function cases already covered by Task 1; this step is the HTTP-level and end-to-end cases).
- [ ] **Step 2: Implement** the route reordering, 409 rendering, and `existing_cf`/JS changes above; delete the now-dead `_save_custom_fields()`.
- [ ] **Step 3: Run full `tests/vault/` suite, confirm green.** Then perform the required manual browser check above and record the result (pass/fail per step) before moving to Task 3.

## Task 3: Documentation updates

**Files:**
- `docs/technical-debt/current.md` — mark item #38 **RESOLVED**, following the exact format already used for items #1/#2/#4/#5 in that file (Status/Resolution/Files changed/Evidence), referencing the new test files and the id-based matching replacing string-key matching. **Only do this step after Tasks 1–2 are implemented, their tests are green, and `/review` has run on the actual diff** (Global Constraint 8) — do not mark RESOLVED speculatively.
- `docs/systems/vault.md` — rewrite §14 ("Custom Field Replacement"), which currently says `_save_custom_fields()` performs "delete all current fields... recreate fields... This is replace-all behavior. It does not calculate field-level differences." Replace with a description of the id-based diff/update/insert/delete behavior, and note the 409 fail-closed conflict path. Cross-check §15 (Protected Custom Fields) for consistency — no change expected there.
- No ADR needed — this is a bug fix within the existing architecture (ADR-004's secrets-at-rest and browser-exposure principles are unaffected).

- [ ] **Step 1:** Update `docs/technical-debt/current.md` item #38 → RESOLVED (only after Tasks 1–2 + `/review`).
- [ ] **Step 2:** Update `docs/systems/vault.md` §14.
- [ ] **Step 3:** Confirm `docs/systems/vault.md` §75–89 don't reference item #38 elsewhere needing a matching update — spot-check only.

---

## Full Test Matrix

| # | Scenario | Layer | Expected result |
|---|---|---|---|
| 1 | Rename + blank value, single occurrence | pure (`_diff`) | preserved under new key, **same `field.id`** |
| 2 | Duplicate key, delete older by id, keep newer blank | pure | survivor keeps *own* ciphertext (id→ciphertext mapping, not a set comparison) |
| 3 | Unknown id | pure | `CustomFieldConflict` |
| 4 | Foreign id (another `VaultEntry`'s field) | pure | `CustomFieldConflict` |
| 5 | Duplicate id in payload, non-blank keys | pure | `CustomFieldConflict` |
| 6 | Malformed JSON / non-list | pure | `CustomFieldConflict` |
| 7 | Blank value, previously unprotected | pure | wiped (encrypted empty) |
| 8 | New item (`id: null`) alongside updates | pure | classified as new, not matched |
| 9 | **Duplicate id where one/both occurrences have a blank key** | pure | `CustomFieldConflict` (Codex finding — smuggling case) |
| 10 | **Foreign id with a blank key** | pure | `CustomFieldConflict` (Codex finding — smuggling case) |
| 11 | `id: true`, `id: 12.9` | pure | `CustomFieldConflict` (strict type check, no coercion) |
| 12 | Every item has a blank key, entry has existing fields | pure | all existing fields deleted via `delete_ids` (documented intended behavior) |
| 13 | **Normal save, nothing touched** | HTTP | `field.id` values for every existing field are **identical** before and after (the key regression-distinguishing assertion vs. the old delete-recreate code) |
| 14 | Blank value, no rename, single occurrence | HTTP | preserved (existing test, rewritten to use real id) |
| 15 | Non-blank value | HTTP | replaced (existing test, rewritten to use real id) |
| 16 | Uncheck protected + blank | HTTP | preserved + flag cleared (existing test, rewritten to use real id) |
| 17 | Duplicate key, both blank, no delete/reorder | HTTP | both preserved independently, asserted by id→ciphertext mapping (existing test, rewritten) |
| 18 | **Foreign id via `/vault/new`** | HTTP | 409 (rendered, not a redirect-with-409), nothing persisted |
| 19 | **Partial-apply**: item 1 valid rename, item 2 bogus id | HTTP | 409; item 1's field **and** the entry's other submitted fields (title, etc.) all unchanged |
| 20 | Stale id (field deleted by a concurrent request between page load and submit) | HTTP | 409, generic message |
| 21 | Submit empty array | HTTP | all existing rows deleted, none orphaned |
| 22 | Create (`/vault/new`) with a protected field | HTTP | unaffected regression (existing test, keep) |
| 23 | End-to-end rename (ids read from real rendered page) | HTTP, full round trip | Case A fixed |
| 24 | End-to-end duplicate-key delete, **both deletion directions** (delete older keep newer, and delete newer keep older) | HTTP, full round trip | Case B fixed, survivor's identity verified both ways |
| 25 | End-to-end duplicate-key + new same-key field in one submit | HTTP, full round trip | Case C fixed |
| 26 | **Combined: rename + duplicate keys + delete + an add-after-delete in one submission** | HTTP, full round trip | end state matches exact per-id expectations, no cross-field ciphertext leakage (the investigation's original "full combo" case — must not be dropped) |
| 27 | 409 response body/status | HTTP | actual status code is 409 (not 3xx), response body contains the generic message, no partial persistence |
| — | JS add/delete/rename/reorder actually submits correct ids | **manual browser check** (Task 2) | not automatable in this test stack — see required steps in Task 2 |

---

## Risks

- **Scope creep into `_save_custom_fields()`'s callers' surrounding code** — mitigated by touching only the custom-fields call site, its immediate `try/except`, and the minimal reordering needed for Global Constraint 5.
- **Residual risk, accepted, not solved by this plan: a browser tab with the edit page already open *before* the Task 2 deploy, submitted *after* the deploy.** Its `custom_fields_json` would have no ids for any existing row, which the new algorithm treats as "all new" — reproducing the original bug for that one in-flight submission. Mitigated in practice by Tasks 1+2 shipping as a single atomic deploy (eliminates the risk for every submission *after* the deploy completes), leaving only the narrow window of tabs opened *before* and submitted *during/after* it. This is a known class of problem for any server-rendered-form contract change without payload versioning, not specific to this fix. **Explicitly not fixed here** (no versioning added) — flag if you want it hardened instead of accepted; the cost would be new complexity (a payload version field, rejected on mismatch) for a low-traffic internal admin tool.
- **JS correctness is not covered by the automated test suite** (no JS test runner exists in this repo) — mitigated by the Task 2 required manual browser check, which must be performed and recorded before the task is considered done.
- **False sense of completeness**: this fix does not address the separate, smaller Case E nuance (unprotected→protected blank-value wipe) differently from today — intentional per Global Constraint 4, called out again in the `docs/technical-debt/current.md` resolution text so it isn't mistaken for a remaining bug later.
- **No migration risk**: no schema changes, so a plain code revert is sufficient if this needs to be rolled back.

---

## Review history

**`/plan-eng-review` (native sections + Codex outside voice, this pass):** Scope Challenge: 6 files, 1 new exception class, well under the 8-file/2-class complexity gate — Section B's structure questions were skipped. Native Sections 1–4 found no architecture/performance issues and confirmed the id-based matching, fail-closed id validation, and `/vault/new` IDOR closure were each already correctly specified in the prior draft. Codex's outside pass found two blockers the native sections missed:

1. Blank-key rows bypassed id validation entirely (could smuggle a duplicate/foreign id past the fail-closed contract, or wipe every field in one request) — **fixed in Task 1's algorithm** (validation now runs for every non-null id regardless of key blankness).
2. The original plan split the server algorithm (old Task 2) and the template/JS id round-trip (old Task 3) into separately-deployable tasks, which would reproduce the exact secret-loss bug during the gap between them, and would break the plan's own existing-test regression claim — **fixed by merging them into one atomic Task 2**, with the four affected existing tests explicitly rewritten (not just kept) as part of that task.

Also fixed from Codex: the `redirect(...), 409` pattern doesn't work in Flask as intended (fixed to render-with-409); `int(raw_id)` coercion accepted `bool`/float inputs unsafely (fixed to a strict type check); the plan didn't explicitly gate debt #38's RESOLVED status on review having actually run (fixed, Global Constraint 8); the test matrix was missing an explicit id-stability assertion and the combined rename+duplicate+delete+reorder case from the original investigation (both added); and the plan's JS test coverage claim was overstated (now explicit that automated tests cannot cover this, with a required manual browser check added).

**Verdict: GO WITH CHANGES.** All changes from this review are incorporated above; this file is the current, implementable version. Do not begin Task 1 from any version of this plan that predates this review history section.
