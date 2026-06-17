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
from app.utils import admin_required
from app.vault import bp
from app.vault.models import VaultEntry, VaultGroup, VaultEntryField
from app.vault.crypto import encrypt, decrypt
from app.vault.forms import VaultEntryForm
from app.vault.sync import vault_sync
from app.models.audit import log_audit


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


def _populate_group_choices(form):
    """Fill form.group_id.choices from DB."""
    groups = VaultGroup.query.order_by(VaultGroup.name).all()
    tree = _build_group_tree(groups)
    form.group_id.choices = [("", "— Sin grupo —")] + [
        (str(g.id), "  " * depth + g.name)
        for g, depth in tree
    ]


def _parse_expires_at(value):
    """Parse 'YYYY-MM-DD' string to datetime or None."""
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d")
    except ValueError:
        return None


def _save_custom_fields(entry, cf_json_str):
    """Replace all custom fields for an entry from JSON string."""
    try:
        fields = json_mod.loads(cf_json_str or "[]")
    except (ValueError, TypeError):
        fields = []

    VaultEntryField.query.filter_by(entry_id=entry.id).delete()

    for item in fields:
        key = str(item.get("key", "")).strip()
        if not key:
            continue
        value = str(item.get("value", ""))
        protected = bool(item.get("protected", False))
        field = VaultEntryField(
            entry_id=entry.id,
            field_key=key,
            field_value_enc=encrypt(value),
            is_protected=protected,
        )
        db.session.add(field)


# ---------------------------------------------------------------------------
# Vault entries — index, create, detail, reveal, edit, delete
# ---------------------------------------------------------------------------

@bp.route("/")
@login_required
def index():
    groups = VaultGroup.query.order_by(VaultGroup.name).all()
    group_tree = _build_group_tree(groups)

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
    sync_configured = bool(current_app.config.get("VAULT_KDBX_PATH"))
    return render_template(
        "vault/index.html",
        entries=entries,
        group_tree=group_tree,
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
    _populate_group_choices(form)

    if form.validate_on_submit():
        if not form.password.data:
            form.password.errors.append("La contraseña es obligatoria.")
            return render_template("vault/new.html", form=form)

        group_id = int(form.group_id.data) if form.group_id.data else None
        entry = VaultEntry(
            title=form.title.data,
            category=form.category.data,
            username=form.username.data,
            password_enc=encrypt(form.password.data),
            url=form.url.data or None,
            notes_enc=encrypt(form.notes.data) if form.notes.data else None,
            shared=form.shared.data,
            owner_id=current_user.id,
            group_id=group_id,
            expires_at=_parse_expires_at(form.expires_at.data),
        )
        db.session.add(entry)
        db.session.flush()

        _save_custom_fields(entry, request.form.get("custom_fields_json", "[]"))
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
        {"key": f.field_key, "value": decrypt(f.field_value_enc), "protected": f.is_protected}
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
    if not (current_user.is_admin or entry.owner_id == current_user.id):
        abort(403)

    form = VaultEntryForm(obj=entry)
    _populate_group_choices(form)

    if request.method == "GET":
        form.password.data = ""
        form.notes.data = decrypt(entry.notes_enc) if entry.notes_enc else ""
        form.group_id.data = str(entry.group_id) if entry.group_id else ""
        form.expires_at.data = entry.expires_at.strftime("%Y-%m-%d") if entry.expires_at else ""

    if form.validate_on_submit():
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
        _save_custom_fields(entry, request.form.get("custom_fields_json", "[]"))
        log_audit("vault", "edit", "entry", entry.id, entry.title)
        db.session.commit()

        vault_sync.trigger_async(current_app._get_current_object())

        flash("Entrada actualizada.", "success")
        return redirect(url_for("vault.detail", entry_id=entry.id))

    existing_cf = [
        {"key": f.field_key, "value": decrypt(f.field_value_enc), "protected": f.is_protected}
        for f in entry.custom_fields
    ]
    return render_template("vault/edit.html", form=form, entry=entry, existing_cf=existing_cf)


@bp.route("/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not (current_user.is_admin or entry.owner_id == current_user.id):
        abort(403)
    title, eid = entry.title, entry.id
    log_audit("vault", "delete", "entry", eid, title)
    db.session.delete(entry)
    db.session.commit()

    vault_sync.trigger_async(current_app._get_current_object())

    flash("Entrada eliminada.", "info")
    return redirect(url_for("vault.index"))


# ---------------------------------------------------------------------------
# Group management (admin only)
# ---------------------------------------------------------------------------

@bp.route("/grupos/nuevo", methods=["POST"])
@login_required
@admin_required
def group_new():
    name = request.form.get("name", "").strip()
    parent_id = request.form.get("parent_id", type=int)
    if not name:
        flash("El nombre del grupo no puede estar vacío.", "danger")
        return redirect(url_for("vault.index"))
    group = VaultGroup(name=name, parent_id=parent_id or None)
    db.session.add(group)
    db.session.commit()
    vault_sync.trigger_async(current_app._get_current_object())
    flash(f'Grupo "{name}" creado.', "success")
    return redirect(url_for("vault.index"))


@bp.route("/grupos/<int:group_id>/eliminar", methods=["POST"])
@login_required
@admin_required
def group_delete(group_id):
    group = db.session.get(VaultGroup, group_id)
    if group is None:
        abort(404)
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
    tmp_json = os.path.join(current_app.instance_path, f"vault_import_{token}.json")
    with open(tmp_json, "w", encoding="utf-8") as f:
        json_mod.dump({"new": new_entries, "conflicts": conflicts}, f)

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

    tmp_json = os.path.join(current_app.instance_path, f"vault_import_{token}.json")
    if not os.path.exists(tmp_json):
        flash("La sesión de importación expiró. Sube el archivo nuevamente.", "warning")
        return redirect(url_for("vault.import_kdbx"))

    with open(tmp_json, encoding="utf-8") as f:
        data = json_mod.load(f)

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

    tmp_json = os.path.join(current_app.instance_path, f"vault_import_{token}.json")
    if not os.path.exists(tmp_json):
        flash("La sesión de importación expiró.", "danger")
        return redirect(url_for("vault.index"))

    with open(tmp_json, encoding="utf-8") as f:
        data = json_mod.load(f)
    os.remove(tmp_json)

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


def _get_or_create_group_chain(path_list):
    """Find or create VaultGroup hierarchy from a list of names. Returns leaf group id or None."""
    if not path_list:
        return None
    parent_id = None
    for name in path_list:
        if not name:
            continue
        group = VaultGroup.query.filter_by(name=name, parent_id=parent_id).first()
        if not group:
            group = VaultGroup(name=name, parent_id=parent_id)
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
        shared=False,
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
