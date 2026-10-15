import json as json_mod
import os
import uuid as uuid_mod
from datetime import datetime

from flask import (
    render_template, redirect, url_for, flash,
    abort, request, jsonify, session, current_app,
)
from flask_login import login_required, current_user
from werkzeug.exceptions import NotFound

from app.extensions import db
from app.models.user import User
from app.utils import admin_required, proteger_blueprint
from app.vault import bp, import_staging
from app.vault.models import VaultEntry, VaultGroup, VaultEntryField, VaultSyncConfig
from app.vault.crypto import encrypt, decrypt
from app.vault.forms import VaultEntryForm
from app.vault.sync import vault_sync
from app.models.audit import log_audit

proteger_blueprint(bp, 'vault')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_entry_or_404(entry_id):
    entry = db.session.get(VaultEntry, entry_id)
    if entry is None:
        raise NotFound()
    return entry


def _can_access(entry):
    if current_user.is_admin:
        return True
    return entry.owner_id == current_user.id or entry.shared


def _can_edit(entry):
    """Edit permission is owner-or-admin only. Deliberately does not reuse
    _can_access(): that helper represents view/reveal permission and
    includes entry.shared by design — shared visibility must not imply
    permission to modify the entry."""
    return current_user.is_admin or entry.owner_id == current_user.id


def _can_delete(entry):
    """Delete permission is owner-or-admin only, same criterion as
    _can_edit() but kept as its own helper: edit and delete are distinct
    permissions that happen to share a formula today, not one concept.
    Shared visibility must not imply permission to delete the entry."""
    return current_user.is_admin or entry.owner_id == current_user.id


def _build_group_tree(groups):
    """Return [(group, depth)] in hierarchical order for SELECT display."""
    by_parent = {}
    for g in groups:
        by_parent.setdefault(g.parent_id, []).append(g)

    result = []

    def visit(parent_id, depth):
        for g in sorted(by_parent.get(parent_id, []), key=lambda x: x.name):
            result.append((g, depth))
            visit(g.id, depth + 1)

    visit(None, 0)
    return result


def _build_existing_cf(entry):
    """Build the custom-fields list rendered into edit.html's embedded
    JS/JSON — includes each row's real id so the page can round-trip it
    back on submit (debt #38). Shared between the GET render and the 409
    conflict re-render so both always reflect entry's actual current
    state."""
    return [
        {
            "id": f.id,
            "key": f.field_key,
            "value": "" if f.is_protected else decrypt(f.field_value_enc),
            "protected": f.is_protected,
        }
        for f in entry.custom_fields
    ]


def _populate_group_choices(form, owner_id, shared):
    """Fill form.group_id.choices with exactly the groups compatible with
    this entry's (owner_id, shared) — the same pair _validate_group_
    assignment() is checked against (ADR-005), so the dropdown can never
    offer something the backend would then reject. owner_id must be the
    entry's REAL owner (current_user.id for new(), entry.owner_id for
    edit()) — never current_user.id in edit(), so an admin editing another
    user's entry sees that user's personal groups, not the admin's own."""
    if shared:
        groups = VaultGroup.query.filter_by(scope="shared").order_by(VaultGroup.name).all()
    else:
        groups = VaultGroup.query.filter_by(
            scope="personal", owner_id=owner_id
        ).order_by(VaultGroup.name).all()
    tree = _build_group_tree(groups)
    form.group_id.choices = [("", "— Sin grupo —")] + [
        (str(g.id), "  " * depth + g.name)
        for g, depth in tree
    ]


def _shared_group_tree():
    """[(group, depth)] for every scope="shared" group — visible to every
    Vault user, presented under the "Compartidas" root."""
    groups = VaultGroup.query.filter_by(scope="shared").order_by(VaultGroup.name).all()
    return _build_group_tree(groups)


def _personal_group_trees(user):
    """[(owner_id, label, tree)] for personal groups visible to `user`.

    Normal user: exactly one entry — their own tree (possibly empty), no
    other owner's personal groups anywhere in the result.

    Admin: one entry per user who owns at least one personal group, each
    with its own independently-built tree and a safe human label (never a
    raw id) — personal groups from different owners are never merged into
    a single ambiguous tree."""
    if user.is_admin:
        groups = VaultGroup.query.filter_by(scope="personal").all()
        by_owner = {}
        for g in groups:
            by_owner.setdefault(g.owner_id, []).append(g)
        result = []
        for owner_id, owner_groups in by_owner.items():
            owner = db.session.get(User, owner_id)
            label = (owner.nombre_completo or owner.username) if owner else "?"
            result.append((owner_id, label, _build_group_tree(owner_groups)))
        result.sort(key=lambda row: row[1].lower())
        return result
    else:
        groups = VaultGroup.query.filter_by(
            scope="personal", owner_id=user.id
        ).order_by(VaultGroup.name).all()
        return [(user.id, None, _build_group_tree(groups))]


def _group_new_parent_choices(user):
    """[(group_id, indented_label, scope)] for every group `user` could
    ever pick as a parent when creating a new group — rendered together in
    one <select>, with a small amount of client-side JS toggling which
    options are visible based on the chosen scope. Purely a UX convenience:
    _validate_group_parent() is the authority regardless of what this
    offers, so an unrendered/manipulated parent_id is still rejected
    server-side.

    Shared options are only included for an admin (only admin can ever
    create a shared group). Personal options are always just `user`'s own
    personal groups — never another user's, including when `user` is
    admin."""
    choices = []
    if user.is_admin:
        shared_groups = VaultGroup.query.filter_by(scope="shared").order_by(VaultGroup.name).all()
        for g, depth in _build_group_tree(shared_groups):
            choices.append((g.id, "  " * depth + g.name, "shared"))

    personal_groups = VaultGroup.query.filter_by(
        scope="personal", owner_id=user.id
    ).order_by(VaultGroup.name).all()
    for g, depth in _build_group_tree(personal_groups):
        choices.append((g.id, "  " * depth + g.name, "personal"))

    return choices


def _parse_expires_at(value):
    """Parse 'YYYY-MM-DD' string to datetime or None."""
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d")
    except ValueError:
        return None


class CustomFieldConflict(Exception):
    """Raised by _diff_custom_fields() when the submitted custom-fields
    payload is structurally invalid, carries a duplicate id, or references
    an id that does not belong to the entry being edited (unknown, stale,
    or foreign). The whole submit must be rejected — no partial apply, no
    silent fallback to treating the item as new."""


class VaultGroupAssignmentConflict(Exception):
    """Raised by _validate_group_assignment() when a submitted group_id is
    not compatible with the entry's shared flag and real owner (ADR-005).
    Also raised for a nonexistent/foreign group_id — never silently
    cleared to None. The whole submit must be rejected before any
    mutation, same contract as CustomFieldConflict."""


def _validate_group_assignment(owner_id, shared, group_id):
    """Validate a submitted group_id against the entry's REAL owner_id —
    never current_user.id. An admin editing another user's entry must
    still have that entry's personal-group compatibility checked against
    the ENTRY's owner, not the admin's own groups; tool/object
    authorization (can the actor touch this entry at all) is already
    handled separately by _can_edit()/_can_access() before this is ever
    called, and is not this function's concern.

        shared == True  => group is None or group.scope == "shared"
        shared == False => group is None or (group.scope == "personal"
                                              and group.owner_id == owner_id)

    Returns the validated VaultGroup, or None if group_id was blank.
    Fails closed (raises VaultGroupAssignmentConflict) on any
    incompatible, nonexistent, or foreign group_id — a client-manipulated
    group_id that isn't even in the rendered dropdown must be rejected the
    same way as one that is."""
    if group_id is None:
        return None

    group = db.session.get(VaultGroup, group_id)
    if group is None:
        raise VaultGroupAssignmentConflict()

    if shared:
        if group.scope != "shared":
            raise VaultGroupAssignmentConflict()
    else:
        if group.scope != "personal" or group.owner_id != owner_id:
            raise VaultGroupAssignmentConflict()

    return group


def _parse_optional_group_id(raw_value):
    """Parse a submitted group_id form value before it ever reaches
    _validate_group_assignment(). None/""/whitespace => None ("no group").
    A non-numeric value (a tampered client sending "abc") must fail closed
    the same way an incompatible/nonexistent group_id does — not raise an
    uncaught ValueError/500 — so it raises the SAME
    VaultGroupAssignmentConflict _validate_group_assignment() raises,
    meant to be caught by the same except block. "0" parses to the int 0
    and is deliberately NOT collapsed to None here — it is left for
    _validate_group_assignment() to reject as a nonexistent id, same as
    any other int that doesn't match a real VaultGroup row."""
    if raw_value is None:
        return None
    stripped = raw_value.strip()
    if not stripped:
        return None
    try:
        return int(stripped)
    except ValueError:
        raise VaultGroupAssignmentConflict()


class VaultGroupParentConflict(Exception):
    """Raised by _validate_group_parent() when a submitted parent_id is not
    compatible with the group being created/moved (ADR-005 hierarchy rule).
    Also raised for a nonexistent parent_id — never silently cleared to
    None. The whole submit must be rejected before any mutation, same
    contract as VaultGroupAssignmentConflict."""


def _validate_group_parent(scope, owner_id, parent_id):
    """Validate a submitted parent_id against the group's OWN scope/owner —
    never current_user. Deliberately takes no actor at all: whether this
    actor is authorized to create/delete a group of this scope is a
    separate question, resolved by the caller before this is ever called;
    this helper only decides whether the parent is a coherent fit.

        scope == "shared"   => parent is None or parent.scope == "shared"
        scope == "personal" => parent is None or (parent.scope == "personal"
                                                    and parent.owner_id == owner_id)

    Returns the validated parent VaultGroup, or None if parent_id was
    blank. Fails closed (raises VaultGroupParentConflict) on any
    incompatible, nonexistent, or foreign parent_id."""
    if parent_id is None:
        return None

    parent = db.session.get(VaultGroup, parent_id)
    if parent is None:
        raise VaultGroupParentConflict()

    if scope == "shared":
        if parent.scope != "shared":
            raise VaultGroupParentConflict()
    else:
        if parent.scope != "personal" or parent.owner_id != owner_id:
            raise VaultGroupParentConflict()

    return parent


def _diff_custom_fields(entry, cf_json_str):
    """Parse and validate a submitted custom-fields payload against
    entry's CURRENT VaultEntryField rows, classifying each submitted item
    as an update (matched by id), a new field (no id), or implicitly
    marking existing rows for deletion (never mentioned, or mentioned with
    a blanked-out key). Matches by VaultEntryField.id, not by field_key
    string equality, so renames, duplicate keys, and reordering can never
    cause ciphertext to be lost or swapped between rows (debt #38).

    Pure function: never touches db.session. Raises CustomFieldConflict on
    any structurally invalid payload, duplicate id, or id that is not a
    current field of THIS entry — validation runs for every item carrying
    a non-null id regardless of whether that item's key is blank, so a
    blank key can never be used to smuggle a duplicate or foreign id past
    this check.
    """
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
        # Explicit JSON null must behave as blank, not stringify to "None" —
        # same "never coerce" intent already applied to raw_id below.
        raw_key = raw.get("key")
        key = "" if raw_key is None else str(raw_key).strip()
        raw_value = raw.get("value")
        value = "" if raw_value is None else str(raw_value)
        protected = bool(raw.get("protected", False))

        if raw_id is None:
            if key:
                new_items.append((key, value, protected))
            continue  # blank key + no id: genuinely inert, nothing to validate

        # Strict type check — never coerce. bool is an int subclass in
        # Python, so it must be excluded explicitly; a float must not
        # silently truncate to a matching int id.
        if isinstance(raw_id, bool) or not isinstance(raw_id, int):
            raise CustomFieldConflict()

        if raw_id in seen_ids:
            raise CustomFieldConflict()
        seen_ids.add(raw_id)

        field = existing_by_id.get(raw_id)
        if field is None:
            raise CustomFieldConflict()

        if key:
            # A previously protected field going to unprotected with no new
            # value typed would make _apply_custom_fields preserve the old
            # ciphertext while dropping is_protected — detail() decrypts
            # unconditionally, so that preserved secret would render in
            # plaintext without the user ever re-entering it. Reject the
            # whole submit instead of silently exposing it.
            if field.is_protected and not protected and not value.strip():
                raise CustomFieldConflict()
            updates.append((field, key, value, protected))
        else:
            # Existing row, key blanked out by the user: explicit delete,
            # not "leave unchanged".
            delete_ids.add(raw_id)

    # Rows never mentioned in the payload at all (user removed the row
    # from the DOM entirely) are also deleted.
    delete_ids |= (set(existing_by_id) - seen_ids)
    return updates, new_items, delete_ids


def _apply_custom_fields(entry, updates, new_items, delete_ids):
    """Apply a successful _diff_custom_fields() classification. Expected to
    be called after _diff_custom_fields() returns without raising, but does
    not rely on that alone: the same protected-unprotect-blank rule is
    re-checked here, defensively, against every update before any mutation
    happens, so a future caller that builds `updates` without going through
    _diff_custom_fields() still fails closed instead of silently preserving
    a secret's ciphertext while dropping its protected flag."""
    for field, key, value, protected in updates:
        if field.is_protected and not protected and not value.strip():
            raise CustomFieldConflict()

    for field, key, value, protected in updates:
        # .strip() here only decides preserve-vs-replace — a whitespace-only
        # submission (e.g. an accidental space typed into a masked password
        # input) must count as blank, or it silently overwrites the real
        # secret with encrypt(" "). The stored value itself is never
        # stripped, so a deliberate non-blank value keeps any real
        # leading/trailing whitespace the user typed.
        if not value.strip() and field.is_protected:  # pre-edit flag, read before overwritten
            field.field_key = key
            field.is_protected = protected
            # field.field_value_enc intentionally untouched: blank value on
            # a previously-protected field preserves its existing ciphertext.
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


# ---------------------------------------------------------------------------
# Vault entries — index, create, detail, reveal, edit, delete
# ---------------------------------------------------------------------------

@bp.route("/")
@login_required
def index():
    shared_tree = _shared_group_tree()
    personal_trees = _personal_group_trees(current_user)
    parent_choices = _group_new_parent_choices(current_user)

    selected_group = request.args.get("group", type=int)

    if current_user.is_admin:
        base_q = VaultEntry.query
    else:
        base_q = VaultEntry.query.filter(
            (VaultEntry.owner_id == current_user.id) | (VaultEntry.shared == True)
        )

    if selected_group:
        entries = base_q.filter(VaultEntry.group_id == selected_group).order_by(VaultEntry.created_at.desc()).all()
    else:
        entries = base_q.order_by(VaultEntry.created_at.desc()).all()

    now = datetime.utcnow()
    db_cfg = VaultSyncConfig.query.first()
    sync_configured = bool(
        (db_cfg and db_cfg.kdbx_path) or current_app.config.get("VAULT_KDBX_PATH")
    )
    return render_template(
        "vault/index.html",
        entries=entries,
        shared_tree=shared_tree,
        personal_trees=personal_trees,
        parent_choices=parent_choices,
        selected_group=selected_group,
        now=now,
        sync_configured=sync_configured,
        sync_last_at=vault_sync.last_sync_at,
        sync_last_ok=vault_sync.last_sync_ok,
        sync_last_entries=vault_sync.last_sync_entries,
    )


@bp.route("/sync-ahora", methods=["POST"])
@login_required
@admin_required
def sync_ahora():
    vault_sync.trigger_async(current_app._get_current_object())
    flash("Sincronización con KeePass iniciada en segundo plano.", "info")
    return redirect(url_for("vault.index"))


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    form = VaultEntryForm()
    _populate_group_choices(form, current_user.id, form.shared.data)

    if form.validate_on_submit():
        if not form.password.data:
            form.password.errors.append("La contraseña es obligatoria.")
            return render_template("vault/new.html", form=form)

        try:
            group_id = _parse_optional_group_id(form.group_id.data)
            validated_group = _validate_group_assignment(current_user.id, form.shared.data, group_id)
        except VaultGroupAssignmentConflict:
            flash("El grupo seleccionado no es compatible con el ámbito de la "
                  "credencial. Seleccione un grupo compatible o deje la "
                  "credencial sin grupo.", "danger")
            return render_template("vault/new.html", form=form), 409

        entry = VaultEntry(
            title=form.title.data,
            category=form.category.data,
            username=form.username.data,
            password_enc=encrypt(form.password.data),
            url=form.url.data or None,
            notes_enc=encrypt(form.notes.data) if form.notes.data else None,
            shared=form.shared.data,
            owner_id=current_user.id,
            group_id=validated_group.id if validated_group else None,
            expires_at=_parse_expires_at(form.expires_at.data),
        )
        db.session.add(entry)
        db.session.flush()

        try:
            updates, new_items, delete_ids = _diff_custom_fields(
                entry, request.form.get("custom_fields_json", "[]")
            )
        except CustomFieldConflict:
            db.session.rollback()
            flash("No se pudieron guardar los cambios: los datos enviados "
                  "no son válidos. Vuelva a intentarlo.", "danger")
            return render_template("vault/new.html", form=form), 409

        _apply_custom_fields(entry, updates, new_items, delete_ids)
        log_audit("vault", "create", "entry", entry.id, entry.title)
        db.session.commit()

        vault_sync.trigger_async(current_app._get_current_object())

        flash("Entrada creada correctamente.", "success")
        return redirect(url_for("vault.detail", entry_id=entry.id))

    return render_template("vault/new.html", form=form)


@bp.route("/<int:entry_id>")
@login_required
def detail(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not _can_access(entry):
        abort(403)
    notes = decrypt(entry.notes_enc) if entry.notes_enc else None
    custom_fields = [
        {
            "key": f.field_key,
            "value": "" if f.is_protected else decrypt(f.field_value_enc),
            "protected": f.is_protected,
        }
        for f in entry.custom_fields
    ]
    log_audit("vault", "view", "entry", entry.id, entry.title)
    db.session.commit()
    now = datetime.utcnow()
    return render_template("vault/detail.html", entry=entry, notes=notes, custom_fields=custom_fields, now=now)


@bp.route("/<int:entry_id>/reveal", methods=["POST"])
@login_required
def reveal(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not _can_access(entry):
        return jsonify({"error": "Acceso denegado"}), 403
    plain = decrypt(entry.password_enc)
    log_audit("vault", "reveal", "entry", entry.id, entry.title)
    db.session.commit()
    return jsonify({"password": plain})


@bp.route("/<int:entry_id>/edit", methods=["GET", "POST"])
@login_required
def edit(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not _can_edit(entry):
        abort(403)

    form = VaultEntryForm(obj=entry)
    _populate_group_choices(form, entry.owner_id, form.shared.data)

    if request.method == "GET":
        form.password.data = ""
        form.notes.data = decrypt(entry.notes_enc) if entry.notes_enc else ""
        form.group_id.data = str(entry.group_id) if entry.group_id else ""
        form.expires_at.data = entry.expires_at.strftime("%Y-%m-%d") if entry.expires_at else ""

    if form.validate_on_submit():
        # Validate group assignment and custom fields BEFORE touching any
        # entry attribute or flushing — so "no mutation happens until
        # validation fully passes" is literally true, not merely true
        # because a later rollback happens to undo it (debt #38 fix,
        # Global Constraint 5). Group validation uses entry.owner_id — the
        # entry's REAL owner — never current_user.id: an admin editing
        # another user's entry must still be checked against that entry's
        # own owner for personal-group compatibility (ADR-005).
        try:
            submitted_group_id = _parse_optional_group_id(form.group_id.data)
            validated_group = _validate_group_assignment(
                entry.owner_id, form.shared.data, submitted_group_id
            )
        except VaultGroupAssignmentConflict:
            flash("El grupo seleccionado no es compatible con el ámbito de la "
                  "credencial. Seleccione un grupo compatible o deje la "
                  "credencial sin grupo.", "danger")
            return render_template(
                "vault/edit.html", form=form, entry=entry,
                existing_cf=_build_existing_cf(entry),
            ), 409

        try:
            updates, new_items, delete_ids = _diff_custom_fields(
                entry, request.form.get("custom_fields_json", "[]")
            )
        except CustomFieldConflict:
            flash("No se pudieron guardar los cambios: los datos de la "
                  "entrada cambiaron. Recargue la página e intente "
                  "nuevamente.", "danger")
            return render_template(
                "vault/edit.html", form=form, entry=entry,
                existing_cf=_build_existing_cf(entry),
            ), 409

        entry.title = form.title.data
        entry.category = form.category.data
        entry.username = form.username.data
        entry.url = form.url.data or None
        entry.shared = form.shared.data
        entry.group_id = validated_group.id if validated_group else None
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

    return render_template("vault/edit.html", form=form, entry=entry, existing_cf=_build_existing_cf(entry))


@bp.route("/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not _can_delete(entry):
        abort(403)
    title, eid = entry.title, entry.id
    log_audit("vault", "delete", "entry", eid, title)
    db.session.delete(entry)
    db.session.commit()

    vault_sync.trigger_async(current_app._get_current_object())

    flash("Entrada eliminada.", "info")
    return redirect(url_for("vault.index"))


# ---------------------------------------------------------------------------
# Group management
# ---------------------------------------------------------------------------

@bp.route("/grupos/nuevo", methods=["POST"])
@login_required
def group_new():
    """ADR-005: shared groups are admin-only and always owner_id=NULL;
    personal groups are creatable by any Vault user but always
    owner_id=current_user.id, server-side, regardless of what the client
    submits — "create a personal group on behalf of another user" is not a
    feature. Parent/scope coherence is delegated to
    _validate_group_parent(); whether THIS actor may create a group of
    THIS scope at all is decided here, not in that helper."""
    name = request.form.get("name", "").strip()
    scope = request.form.get("scope", "personal")
    raw_parent_id = request.form.get("parent_id", "").strip()

    if not name:
        flash("El nombre del grupo no puede estar vacío.", "danger")
        return redirect(url_for("vault.index"))

    if scope not in ("shared", "personal"):
        abort(400)

    # request.form.get("parent_id", type=int) would silently turn an
    # unparseable value like "abc" into None, indistinguishable from a
    # genuinely blank field — "no parent" must mean the field was actually
    # blank, not "couldn't be parsed", and 0 is a real (if never valid)
    # int that must still reach _validate_group_parent() to be rejected as
    # nonexistent rather than treated as blank.
    if raw_parent_id:
        try:
            parent_id = int(raw_parent_id)
        except ValueError:
            abort(400)
    else:
        parent_id = None

    if scope == "shared" and not current_user.is_admin:
        abort(403)

    owner_id = None if scope == "shared" else current_user.id

    try:
        parent = _validate_group_parent(scope, owner_id, parent_id)
    except VaultGroupParentConflict:
        abort(409)

    group = VaultGroup(
        name=name,
        parent_id=parent.id if parent else None,
        scope=scope,
        owner_id=owner_id,
    )
    db.session.add(group)
    db.session.commit()
    vault_sync.trigger_async(current_app._get_current_object())
    flash(f'Grupo "{name}" creado.', "success")
    return redirect(url_for("vault.index"))


@bp.route("/grupos/<int:group_id>/eliminar", methods=["POST"])
@login_required
def group_delete(group_id):
    """ADR-005: shared groups are admin-only to delete; personal groups are
    deletable by their owner or an admin (admin retains its existing
    unrestricted reach over every Vault object). Historical delete
    behavior is preserved: entries/children are detached, never deleted,
    and deletion is never recursive."""
    group = db.session.get(VaultGroup, group_id)
    if group is None:
        abort(404)

    if group.scope == "shared":
        if not current_user.is_admin:
            abort(403)
    else:
        if not (current_user.is_admin or group.owner_id == current_user.id):
            abort(403)

    VaultEntry.query.filter_by(group_id=group_id).update({"group_id": None})
    VaultGroup.query.filter_by(parent_id=group_id).update({"parent_id": None})
    db.session.delete(group)
    db.session.commit()
    vault_sync.trigger_async(current_app._get_current_object())
    flash(f'Grupo "{group.name}" eliminado. Las entradas y subgrupos quedaron sin grupo.', "info")
    return redirect(url_for("vault.index"))


# ---------------------------------------------------------------------------
# Import kdbx (admin only, 3-step flow)
# ---------------------------------------------------------------------------

@bp.route("/import", methods=["GET", "POST"])
@login_required
@admin_required
def import_kdbx():
    if request.method == "GET":
        return render_template("vault/import.html")

    file = request.files.get("kdbx_file")
    password = request.form.get("kdbx_password", "") or None
    keyfile_upload = request.files.get("kdbx_keyfile")

    if not file or not file.filename.endswith(".kdbx"):
        flash("Debes subir un archivo .kdbx válido.", "danger")
        return redirect(url_for("vault.import_kdbx"))

    if not password and (not keyfile_upload or not keyfile_upload.filename):
        flash("Debes proporcionar una contraseña, un archivo de clave, o ambos.", "danger")
        return redirect(url_for("vault.import_kdbx"))

    uid = uuid_mod.uuid4().hex
    tmp_kdbx = os.path.join(current_app.instance_path, f"import_{uid}.kdbx")
    tmp_key = None

    file.save(tmp_kdbx)

    if keyfile_upload and keyfile_upload.filename:
        tmp_key = os.path.join(current_app.instance_path, f"import_{uid}.keyx")
        keyfile_upload.save(tmp_key)

    try:
        from pykeepass import PyKeePass
        kp = PyKeePass(tmp_kdbx, password=password, keyfile=tmp_key)
    except Exception:
        flash("No se pudo abrir el archivo. Verifica la contraseña y/o el archivo de clave.", "danger")
        return redirect(url_for("vault.import_kdbx"))
    finally:
        if os.path.exists(tmp_kdbx):
            os.remove(tmp_kdbx)
        if tmp_key and os.path.exists(tmp_key):
            os.remove(tmp_key)

    existing_by_uuid = {e.uuid: e for e in VaultEntry.query.all()}

    new_entries = []
    conflicts = []

    for kp_entry in kp.entries:
        entry_uuid = str(kp_entry.uuid) if kp_entry.uuid else str(uuid_mod.uuid4())
        custom = {k: v for k, v in (kp_entry.custom_properties or {}).items()}
        group_path = [g for g in kp_entry.group.path if g] if kp_entry.group and hasattr(kp_entry.group, "path") else []

        entry_data = {
            "uuid": entry_uuid,
            "title": kp_entry.title or "(sin título)",
            "username": kp_entry.username or "",
            "password": kp_entry.password or "",
            "url": kp_entry.url or "",
            "notes": kp_entry.notes or "",
            "expires_at": (
                kp_entry.expiry_time.strftime("%Y-%m-%d")
                if kp_entry.expires and kp_entry.expiry_time else None
            ),
            "custom_fields": custom,
            "group_path": group_path,
        }

        if entry_uuid in existing_by_uuid:
            existing = existing_by_uuid[entry_uuid]
            conflicts.append({
                "kdbx": entry_data,
                "vault": {
                    "id": existing.id,
                    "title": existing.title,
                    "username": existing.username,
                    "updated_at": existing.updated_at.strftime("%Y-%m-%d %H:%M"),
                },
            })
        else:
            new_entries.append(entry_data)

    token = uuid_mod.uuid4().hex
    import_staging.store(token, {"new": new_entries, "conflicts": conflicts})

    session["vault_import_token"] = token
    return redirect(url_for("vault.import_preview"))


@bp.route("/import/preview")
@login_required
@admin_required
def import_preview():
    token = session.get("vault_import_token")
    if not token:
        flash("No hay una importación en progreso.", "warning")
        return redirect(url_for("vault.import_kdbx"))

    data = import_staging.retrieve(token)
    if data is None:
        flash("La sesión de importación expiró. Sube el archivo nuevamente.", "warning")
        return redirect(url_for("vault.import_kdbx"))

    # Deduplicate group paths for display in preview
    seen_paths: set = set()
    group_paths = []
    for entry in data["new"] + [c["kdbx"] for c in data["conflicts"]]:
        path = entry.get("group_path") or []
        if path:
            key = tuple(path)
            if key not in seen_paths:
                seen_paths.add(key)
                group_paths.append(path)

    return render_template(
        "vault/import_preview.html",
        new_entries=data["new"],
        conflicts=data["conflicts"],
        group_paths=group_paths,
    )


@bp.route("/import/confirm", methods=["POST"])
@login_required
@admin_required
def import_confirm():
    token = session.pop("vault_import_token", None)
    if not token:
        flash("Sesión de importación inválida.", "danger")
        return redirect(url_for("vault.index"))

    data = import_staging.retrieve(token)
    if data is None:
        flash("La sesión de importación expiró.", "danger")
        return redirect(url_for("vault.index"))
    import_staging.discard(token)

    selected_new_uuids = set(request.form.getlist("import_new"))

    created = 0
    updated = 0

    for entry_data in data["new"]:
        if entry_data["uuid"] not in selected_new_uuids:
            continue
        _create_entry_from_import(entry_data)
        created += 1

    for conflict in data["conflicts"]:
        choice = request.form.get(f'conflict_{conflict["kdbx"]["uuid"]}', "vault")
        if choice == "kdbx":
            existing = db.session.get(VaultEntry, conflict["vault"]["id"])
            if existing:
                _update_entry_from_import(existing, conflict["kdbx"])
                updated += 1

    db.session.commit()
    log_audit("vault", "import", "batch", 0, f"{created} nuevas, {updated} actualizadas")

    vault_sync.trigger_async(current_app._get_current_object())

    flash(f"Importación completada: {created} nuevas, {updated} actualizadas.", "success")
    return redirect(url_for("vault.index"))


@bp.route("/configuracion", methods=["GET", "POST"])
@login_required
@admin_required
def sync_settings():
    cfg = VaultSyncConfig.query.first()

    if request.method == "POST":
        path = request.form.get("kdbx_path", "").strip()
        password = request.form.get("kdbx_password", "").strip()
        keyfile_path = request.form.get("kdbx_keyfile_path", "").strip()

        if not path:
            flash("La ruta del archivo .kdbx es obligatoria.", "danger")
            return redirect(url_for("vault.sync_settings"))
        if not password and not keyfile_path:
            flash("Debes proporcionar una contraseña, una ruta de keyfile, o ambas.", "danger")
            return redirect(url_for("vault.sync_settings"))

        if cfg is None:
            cfg = VaultSyncConfig()
            db.session.add(cfg)

        cfg.kdbx_path = path
        cfg.kdbx_password_enc = encrypt(password) if password else None
        cfg.kdbx_keyfile_path = keyfile_path or None
        db.session.commit()

        log_audit("vault", "edit", "sync_config", 0, "Configuración de sync actualizada")
        flash("Configuración de sync guardada.", "success")
        return redirect(url_for("vault.index"))

    current_password = ""
    if cfg and cfg.kdbx_password_enc:
        try:
            current_password = decrypt(cfg.kdbx_password_enc)
        except Exception:
            current_password = ""

    return render_template("vault/sync_settings.html", cfg=cfg, current_password=current_password)


def _get_or_create_group_chain(path_list):
    """Find or create a VaultGroup hierarchy from a list of names, for
    KeePass import/sync. ADR-005: KeePass operates only on shared data —
    only scope="shared" groups are ever searched for reuse here, and any
    newly created group is explicitly scope="shared", owner_id=None
    (spelled out even though the column server_default already matches,
    so the intent is unambiguous in code). A personal group with a
    matching name/parent is never reused, even if one exists; if both a
    shared and a personal group share the name, the shared one is reused.
    Returns leaf group id or None."""
    if not path_list:
        return None
    parent_id = None
    for name in path_list:
        if not name:
            continue
        group = VaultGroup.query.filter_by(
            name=name, parent_id=parent_id, scope="shared"
        ).first()
        if not group:
            group = VaultGroup(name=name, parent_id=parent_id, scope="shared", owner_id=None)
            db.session.add(group)
            db.session.flush()
        parent_id = group.id
    return parent_id


def _create_entry_from_import(data):
    expires_at = None
    if data.get("expires_at"):
        try:
            expires_at = datetime.strptime(data["expires_at"], "%Y-%m-%d")
        except ValueError:
            pass

    entry = VaultEntry(
        uuid=data["uuid"],
        title=data["title"],
        category="other",
        username=data["username"],
        password_enc=encrypt(data["password"]),
        url=data["url"] or None,
        notes_enc=encrypt(data["notes"]) if data.get("notes") else None,
        shared=True,
        owner_id=current_user.id,
        expires_at=expires_at,
        group_id=_get_or_create_group_chain(data.get("group_path") or []),
    )
    db.session.add(entry)
    db.session.flush()

    for key, value in (data.get("custom_fields") or {}).items():
        db.session.add(VaultEntryField(
            entry_id=entry.id,
            field_key=key,
            field_value_enc=encrypt(str(value)),
            is_protected=False,
        ))


def _update_entry_from_import(entry, data):
    entry.title = data["title"]
    entry.username = data["username"]
    entry.password_enc = encrypt(data["password"])
    entry.url = data["url"] or None
    entry.notes_enc = encrypt(data["notes"]) if data.get("notes") else None
    entry.group_id = _get_or_create_group_chain(data.get("group_path") or [])
    if data.get("expires_at"):
        try:
            entry.expires_at = datetime.strptime(data["expires_at"], "%Y-%m-%d")
        except ValueError:
            pass

    VaultEntryField.query.filter_by(entry_id=entry.id).delete()
    for key, value in (data.get("custom_fields") or {}).items():
        db.session.add(VaultEntryField(
            entry_id=entry.id,
            field_key=key,
            field_value_enc=encrypt(str(value)),
            is_protected=False,
        ))
