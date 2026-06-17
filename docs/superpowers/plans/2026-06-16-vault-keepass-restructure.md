# Vault KeePass Restructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reestructurar el módulo vault para usar una estructura KeePass-compatible (grupos jerárquicos, UUID por entrada, expiración, campos personalizados), con exportación automática a .kdbx read-only en ruta de red y un importador de archivos .kdbx para admins.

**Architecture:** Se extiende el modelo `VaultEntry` existente con `uuid`, `group_id`, `expires_at` e `icon_id`. Se añaden dos nuevos modelos: `VaultGroup` (jerarquía de carpetas) y `VaultEntryField` (campos clave-valor cifrados). Un servicio `VaultSyncService` usa `pykeepass` para generar el .kdbx y escribirlo en la ruta de SharePoint configurada en `.env`, disparando el sync en un thread de fondo tras cada create/edit/delete. El import acepta un .kdbx existente, lo parsea en tres pasos (upload → preview/conflictos → confirmar) y los conflictos por UUID se resuelven interactivamente.

**Tech Stack:** Flask 3.1, SQLAlchemy 2, Flask-Migrate (Alembic/SQLite batch mode), Flask-WTF, pykeepass, Bootstrap 5, Bootstrap Icons, Python threading

---

## File Map

| Acción | Archivo |
|--------|---------|
| Modify | `requirements.txt` |
| Modify | `config.py` |
| Modify | `app/vault/models.py` |
| Create | `migrations/versions/<auto>_vault_keepass_schema.py` (via flask db migrate) |
| Create | `app/vault/sync.py` |
| Modify | `app/vault/forms.py` |
| Modify | `app/vault/routes.py` |
| Modify | `app/templates/vault/index.html` |
| Modify | `app/templates/vault/new.html` |
| Modify | `app/templates/vault/edit.html` |
| Modify | `app/templates/vault/detail.html` |
| Create | `app/templates/vault/import.html` |
| Create | `app/templates/vault/import_preview.html` |

---

## Task 1: Dependencia pykeepass y variables de entorno

**Files:**
- Modify: `requirements.txt`
- Modify: `config.py`

- [ ] **Step 1: Agregar pykeepass a requirements.txt**

Añadir al final de `requirements.txt`:
```
pykeepass>=4.0.0
```

- [ ] **Step 2: Instalar la dependencia**

```bash
pip install pykeepass>=4.0.0
```
Expected: `Successfully installed pykeepass-4.x.x`

- [ ] **Step 3: Agregar variables VAULT_KDBX_PATH y VAULT_KDBX_PASSWORD en config.py**

En `config.py`, dentro de la clase `Config`, después de la línea `VAULT_KEY = ...` (línea 26), agregar:

```python
    # Ruta de red al archivo .kdbx para sync con SharePoint (opcional)
    VAULT_KDBX_PATH = os.environ.get('VAULT_KDBX_PATH', '')
    # Master password del archivo .kdbx generado (opcional)
    VAULT_KDBX_PASSWORD = os.environ.get('VAULT_KDBX_PASSWORD', '')
```

- [ ] **Step 4: Documentar en .env (no commitear)**

Agregar a `.env` (el archivo real, no al control de versiones):
```
VAULT_KDBX_PATH=\\servidor\sharepoint\vault\portal-ops.kdbx
VAULT_KDBX_PASSWORD=MasterPasswordSeguro123
```

- [ ] **Step 5: Commit**

```bash
git add requirements.txt config.py
git commit -m "feat(vault): add pykeepass dependency and kdbx sync config vars"
```

---

## Task 2: Actualizar modelos del vault

**Files:**
- Modify: `app/vault/models.py`

El archivo actual tiene `VaultEntry` y `VaultAuditLog`. Se reemplaza completamente con:

- [ ] **Step 1: Reemplazar app/vault/models.py con los modelos extendidos**

```python
from datetime import datetime
from uuid import uuid4
from app.extensions import db


class VaultGroup(db.Model):
    __tablename__ = "vault_group"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid4()))
    name = db.Column(db.String(120), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("vault_group.id"), nullable=True)
    icon_id = db.Column(db.Integer, default=48)  # 48 = folder en KeePass
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    parent = db.relationship("VaultGroup", remote_side=[id], backref="children")
    entries = db.relationship("VaultEntry", back_populates="group")

    def __repr__(self):
        return f"<VaultGroup {self.id}: {self.name}>"


class VaultEntry(db.Model):
    __tablename__ = "vault_entry"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid4()))
    title = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # server | platform | api | other
    username = db.Column(db.String(120), nullable=False)
    password_enc = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(250), nullable=True)
    notes_enc = db.Column(db.Text, nullable=True)
    shared = db.Column(db.Boolean, default=False, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("vault_group.id"), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    icon_id = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = db.relationship("User", backref=db.backref("vault_entries", lazy="dynamic"))
    group = db.relationship("VaultGroup", back_populates="entries")
    custom_fields = db.relationship(
        "VaultEntryField",
        back_populates="entry",
        cascade="all, delete-orphan",
        order_by="VaultEntryField.id",
    )
    audit_logs = db.relationship(
        "VaultAuditLog",
        back_populates="entry",
        lazy="dynamic",
    )

    def __repr__(self):
        return f"<VaultEntry {self.id}: {self.title}>"


class VaultEntryField(db.Model):
    __tablename__ = "vault_entry_field"

    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(
        db.Integer,
        db.ForeignKey("vault_entry.id", ondelete="CASCADE"),
        nullable=False,
    )
    field_key = db.Column(db.String(100), nullable=False)
    field_value_enc = db.Column(db.Text, nullable=False)
    is_protected = db.Column(db.Boolean, default=False)

    entry = db.relationship("VaultEntry", back_populates="custom_fields")

    def __repr__(self):
        return f"<VaultEntryField entry={self.entry_id} key={self.field_key}>"


class VaultAuditLog(db.Model):
    __tablename__ = "vault_audit_log"

    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey("vault_entry.id", ondelete="SET NULL"), nullable=True)
    entry_title = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(30), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    entry = db.relationship("VaultEntry", back_populates="audit_logs")
    user = db.relationship("User", backref=db.backref("vault_audit_logs", lazy="dynamic"))

    def __repr__(self):
        return f"<VaultAuditLog entry={self.entry_id} action={self.action}>"
```

- [ ] **Step 2: Commit**

```bash
git add app/vault/models.py
git commit -m "feat(vault): add VaultGroup, VaultEntryField models; extend VaultEntry with uuid/group/expires"
```

---

## Task 3: Migración de base de datos

**Files:**
- Create: `migrations/versions/<auto>_vault_keepass_schema.py`

- [ ] **Step 1: Generar la migración**

```bash
flask db migrate -m "vault_keepass_schema"
```

Expected output: `Generating .../migrations/versions/XXXX_vault_keepass_schema.py ... done`

- [ ] **Step 2: Verificar el archivo generado**

Abrir el archivo generado en `migrations/versions/`. Debe contener:
- `op.create_table('vault_group', ...)` con columnas: id, uuid, name, parent_id, icon_id, created_at
- `op.create_table('vault_entry_field', ...)` con columnas: id, entry_id, field_key, field_value_enc, is_protected
- `op.add_column('vault_entry', sa.Column('uuid', ...))` 
- `op.add_column('vault_entry', sa.Column('group_id', ...))`
- `op.add_column('vault_entry', sa.Column('expires_at', ...))`
- `op.add_column('vault_entry', sa.Column('icon_id', ...))`

Si Alembic no detectó alguno de estos cambios, agregar manualmente dentro de `upgrade()`.

**Nota importante:** Para la columna `uuid` en entradas existentes, las filas ya creadas quedarán con NULL porque SQLite no puede aplicar defaults a filas existentes automáticamente. Agregar esta lógica al final de `upgrade()` para poblar UUID en entradas existentes:

```python
# Poblar uuid en entradas existentes
conn = op.get_bind()
existing = conn.execute(sa.text("SELECT id FROM vault_entry WHERE uuid IS NULL")).fetchall()
for row in existing:
    import uuid as _uuid
    conn.execute(
        sa.text("UPDATE vault_entry SET uuid = :u WHERE id = :i"),
        {"u": str(_uuid.uuid4()), "i": row[0]}
    )
```

También verificar que `vault_entry.uuid` tenga una restricción NOT NULL. Si Alembic la generó como nullable, actualizar manualmente a `nullable=False` usando batch mode:

```python
with op.batch_alter_table('vault_entry', recreate='always') as batch_op:
    batch_op.alter_column('uuid', nullable=False)
```

- [ ] **Step 3: Aplicar la migración**

```bash
flask db upgrade
```

Expected: `Running upgrade ... -> XXXX, vault_keepass_schema`

- [ ] **Step 4: Verificar**

```bash
python -c "from app import create_app; from app.vault.models import VaultGroup, VaultEntryField, VaultEntry; app=create_app(); ctx=app.app_context(); ctx.push(); print('uuid cols:', VaultEntry.query.first()); print('groups table exists:', VaultGroup.query.count()); ctx.pop()"
```

Expected: No errors, imprime algo como `uuid cols: None` (no hay entradas) o el primer VaultEntry.

- [ ] **Step 5: Commit**

```bash
git add migrations/
git commit -m "feat(vault): migrate DB schema for KeePass-compatible vault structure"
```

---

## Task 4: VaultSyncService

**Files:**
- Create: `app/vault/sync.py`

- [ ] **Step 1: Crear app/vault/sync.py**

```python
import os
import stat
import threading
from uuid import UUID

from flask import current_app

from app.vault.crypto import decrypt


class VaultSyncService:
    """Exports all vault entries to a .kdbx file on a network path (SharePoint).
    The file is set read-only after writing so KeePass opens it in read-only mode.
    Sync runs in a background daemon thread to avoid blocking HTTP responses.
    """

    _lock = threading.Lock()

    def trigger_async(self, app):
        """Dispatch sync in a background thread. Safe to call after db.session.commit()."""
        path = app.config.get("VAULT_KDBX_PATH", "")
        password = app.config.get("VAULT_KDBX_PASSWORD", "")
        if not path or not password:
            return  # Sync not configured — skip silently
        t = threading.Thread(target=self._run, args=(app,), daemon=True)
        t.start()

    def _run(self, app):
        with app.app_context():
            with self._lock:
                self._export()

    def _export(self):
        from app.vault.models import VaultEntry, VaultGroup
        from pykeepass import create_database

        path = current_app.config["VAULT_KDBX_PATH"]
        password = current_app.config["VAULT_KDBX_PASSWORD"]

        try:
            # Lift read-only attribute so we can overwrite the file
            if os.path.exists(path):
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)

            kp = create_database(path, password=password)

            # Build KeePass group hierarchy
            kp_groups = {}
            groups = VaultGroup.query.order_by(VaultGroup.id).all()
            for g in groups:
                parent_kp = kp_groups.get(g.parent_id) or kp.root_group
                kp_groups[g.id] = kp.add_group(parent_kp, g.name, icon=g.icon_id)

            ungrouped = kp.add_group(kp.root_group, "Sin Grupo", icon=48)

            # Add entries
            for entry in VaultEntry.query.all():
                kp_group = kp_groups.get(entry.group_id) or ungrouped
                e = kp.add_entry(
                    kp_group,
                    title=entry.title,
                    username=entry.username,
                    password=decrypt(entry.password_enc),
                    url=entry.url or "",
                    notes=decrypt(entry.notes_enc) if entry.notes_enc else "",
                )
                try:
                    e.uuid = UUID(entry.uuid)
                except Exception:
                    pass  # Keep generated UUID if stored one is malformed

                if entry.expires_at:
                    e.expiry_time = entry.expires_at
                    e.expires = True

                for field in entry.custom_fields:
                    try:
                        e.set_custom_property(
                            field.field_key,
                            decrypt(field.field_value_enc),
                            protect=field.is_protected,
                        )
                    except Exception:
                        pass

            kp.save()
            # Re-apply read-only after writing
            os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        except Exception as exc:
            current_app.logger.error("Vault kdbx sync failed: %s", exc)


vault_sync = VaultSyncService()
```

- [ ] **Step 2: Verificar que importa correctamente**

```bash
python -c "from app import create_app; app=create_app(); ctx=app.app_context(); ctx.push(); from app.vault.sync import vault_sync; print('OK:', vault_sync); ctx.pop()"
```

Expected: `OK: <app.vault.sync.VaultSyncService object at 0x...>`

- [ ] **Step 3: Commit**

```bash
git add app/vault/sync.py
git commit -m "feat(vault): add VaultSyncService for async kdbx export to SharePoint path"
```

---

## Task 5: Actualizar VaultEntryForm

**Files:**
- Modify: `app/vault/forms.py`

- [ ] **Step 1: Reemplazar app/vault/forms.py**

```python
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SelectField, TextAreaField,
    BooleanField, SubmitField,
)
from wtforms.validators import DataRequired, Length, Optional, URL


class VaultEntryForm(FlaskForm):
    title = StringField(
        "Título",
        validators=[DataRequired(), Length(max=120)],
    )
    category = SelectField(
        "Categoría",
        choices=[
            ("server", "Servidor"),
            ("platform", "Plataforma"),
            ("api", "API / Token"),
            ("other", "Otro"),
        ],
        validators=[DataRequired()],
    )
    group_id = SelectField(
        "Grupo",
        validators=[Optional()],
        default="",
    )
    username = StringField(
        "Usuario",
        validators=[DataRequired(), Length(max=120)],
    )
    password = PasswordField(
        "Contraseña",
        validators=[Optional(), Length(max=500)],
    )
    url = StringField(
        "URL",
        validators=[Optional(), URL(), Length(max=250)],
    )
    expires_at = StringField(
        "Fecha de expiración",
        validators=[Optional()],
    )
    notes = TextAreaField(
        "Notas",
        validators=[Optional(), Length(max=2000)],
    )
    shared = BooleanField("Compartir con todos los analistas", default=False)
    submit = SubmitField("Guardar")
```

`group_id` uses `SelectField` with `default=""`. Choices are populated per-request in the route (see Task 6). `expires_at` is a string field; the route parses it to `datetime`.

- [ ] **Step 2: Commit**

```bash
git add app/vault/forms.py
git commit -m "feat(vault): extend VaultEntryForm with group_id and expires_at fields"
```

---

## Task 6: Rutas — grupos, CRUD extendido, sync trigger e import

**Files:**
- Modify: `app/vault/routes.py`

Reemplazar el contenido completo de `app/vault/routes.py`:

- [ ] **Step 1: Escribir app/vault/routes.py**

```python
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
        (str(g.id), "  " * depth + g.name)
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

    # Remove existing
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
    return render_template(
        "vault/index.html",
        entries=entries,
        group_tree=group_tree,
        selected_group=selected_group,
        now=now,
    )


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
        db.session.flush()  # Get entry.id for custom fields + audit

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
    flash(f'Grupo "{name}" creado.', "success")
    return redirect(url_for("vault.index"))


@bp.route("/grupos/<int:group_id>/eliminar", methods=["POST"])
@login_required
@admin_required
def group_delete(group_id):
    group = db.session.get(VaultGroup, group_id)
    if group is None:
        abort(404)
    # Move entries in this group to ungrouped
    VaultEntry.query.filter_by(group_id=group_id).update({"group_id": None})
    # Move child groups to ungrouped
    VaultGroup.query.filter_by(parent_id=group_id).update({"parent_id": None})
    db.session.delete(group)
    db.session.commit()
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
    password = request.form.get("kdbx_password", "")

    if not file or not file.filename.endswith(".kdbx"):
        flash("Debes subir un archivo .kdbx válido.", "danger")
        return redirect(url_for("vault.import_kdbx"))

    # Save to temp path inside instance folder
    tmp_kdbx = os.path.join(
        current_app.instance_path,
        f"import_{uuid_mod.uuid4().hex}.kdbx",
    )
    file.save(tmp_kdbx)

    try:
        from pykeepass import PyKeePass
        kp = PyKeePass(tmp_kdbx, password=password)
    except Exception:
        flash("No se pudo abrir el archivo. Verifica que la contraseña sea correcta.", "danger")
        return redirect(url_for("vault.import_kdbx"))
    finally:
        if os.path.exists(tmp_kdbx):
            os.remove(tmp_kdbx)

    # Build lookup of existing UUIDs
    existing_by_uuid = {e.uuid: e for e in VaultEntry.query.all()}

    new_entries = []
    conflicts = []

    for kp_entry in kp.entries:
        entry_uuid = str(kp_entry.uuid) if kp_entry.uuid else str(uuid_mod.uuid4())
        custom = {k: v for k, v in (kp_entry.custom_properties or {}).items()}
        group_path = " / ".join(kp_entry.group.path) if kp_entry.group and hasattr(kp_entry.group, "path") else ""

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

    # Persist parsed data to temp JSON (avoids session size limits)
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

    return render_template(
        "vault/import_preview.html",
        new_entries=data["new"],
        conflicts=data["conflicts"],
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

    # Which new entries are selected (checkboxes named 'import_new')
    selected_new_uuids = set(request.form.getlist("import_new"))

    # Conflict choices: radio named 'conflict_<uuid>' with value 'vault' or 'kdbx'
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


def _create_entry_from_import(data):
    """Create a VaultEntry from parsed kdbx entry dict."""
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
    """Overwrite an existing VaultEntry from parsed kdbx entry dict."""
    entry.title = data["title"]
    entry.username = data["username"]
    entry.password_enc = encrypt(data["password"])
    entry.url = data["url"] or None
    entry.notes_enc = encrypt(data["notes"]) if data.get("notes") else None
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
```

- [ ] **Step 2: Verificar que Flask carga las rutas sin error**

```bash
python -c "from app import create_app; app=create_app(); print([r.endpoint for r in app.url_map.iter_rules() if 'vault' in r.endpoint])"
```

Expected: lista con `vault.index`, `vault.new`, `vault.detail`, `vault.reveal`, `vault.edit`, `vault.delete`, `vault.group_new`, `vault.group_delete`, `vault.import_kdbx`, `vault.import_preview`, `vault.import_confirm`

- [ ] **Step 3: Commit**

```bash
git add app/vault/routes.py
git commit -m "feat(vault): group CRUD, import 3-step flow, kdbx sync trigger in all mutation routes"
```

---

## Task 7: Rediseñar app/templates/vault/index.html

**Files:**
- Modify: `app/templates/vault/index.html`

- [ ] **Step 1: Reemplazar index.html completo**

```html
{% extends "base.html" %}

{% block title %}Vault de Credenciales — Portal de Operaciones{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item active">Vault de Credenciales</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h2 class="mb-0"><i class="bi bi-safe text-primary me-2"></i>Vault de Credenciales</h2>
  <div class="d-flex gap-2 align-items-center">
    {% if current_user.is_admin %}
    <a href="{{ url_for('vault.import_kdbx') }}" class="btn btn-outline-secondary btn-sm">
      <i class="bi bi-upload me-1"></i>Importar .kdbx
    </a>
    {% endif %}
    <a href="{{ url_for('vault.new') }}" class="btn btn-success btn-sm">
      <i class="bi bi-plus-lg me-1"></i>Nueva credencial
    </a>
  </div>
</div>

<div class="row g-3">

  <!-- SIDEBAR: Grupos -->
  <div class="col-12 col-lg-3">
    <div class="card shadow-sm">
      <div class="card-header d-flex justify-content-between align-items-center py-2">
        <span class="fw-semibold"><i class="bi bi-folder2 me-1"></i>Grupos</span>
        {% if current_user.is_admin %}
        <button class="btn btn-sm btn-outline-primary py-0 px-1" data-bs-toggle="collapse"
                data-bs-target="#collapseNuevoGrupo" title="Nuevo grupo">
          <i class="bi bi-plus"></i>
        </button>
        {% endif %}
      </div>

      {% if current_user.is_admin %}
      <div class="collapse" id="collapseNuevoGrupo">
        <div class="card-body border-bottom py-2">
          <form method="POST" action="{{ url_for('vault.group_new') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <div class="mb-2">
              <input type="text" class="form-control form-control-sm" name="name"
                     placeholder="Nombre del grupo" required maxlength="120">
            </div>
            <div class="mb-2">
              <select class="form-select form-select-sm" name="parent_id">
                <option value="">— Sin padre (raíz) —</option>
                {% for g, depth in group_tree %}
                <option value="{{ g.id }}">{{ '  ' * depth }}{{ g.name }}</option>
                {% endfor %}
              </select>
            </div>
            <button type="submit" class="btn btn-sm btn-primary w-100">Crear grupo</button>
          </form>
        </div>
      </div>
      {% endif %}

      <div class="list-group list-group-flush" id="groupTree">
        <a href="{{ url_for('vault.index') }}"
           class="list-group-item list-group-item-action py-2 {% if not selected_group %}active{% endif %}">
          <i class="bi bi-collection me-1"></i> Todas
        </a>
        {% for g, depth in group_tree %}
        <div class="d-flex align-items-center">
          <a href="{{ url_for('vault.index', group=g.id) }}"
             class="list-group-item list-group-item-action py-2 flex-grow-1 border-0
                    {% if selected_group == g.id %}active{% endif %}"
             style="padding-left: {{ 1 + depth * 1.2 }}rem;">
            <i class="bi bi-folder{% if selected_group == g.id %}-fill{% endif %} me-1"></i>
            {{ g.name }}
          </a>
          {% if current_user.is_admin %}
          <form method="POST" action="{{ url_for('vault.group_delete', group_id=g.id) }}"
                onsubmit="return confirm('¿Eliminar grupo «{{ g.name }}»? Las entradas quedarán sin grupo.');"
                class="m-0 me-1">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <button type="submit" class="btn btn-sm btn-link text-danger p-0" title="Eliminar grupo">
              <i class="bi bi-x"></i>
            </button>
          </form>
          {% endif %}
        </div>
        {% endfor %}
        {% if not group_tree %}
        <div class="list-group-item text-muted small py-2">Sin grupos creados</div>
        {% endif %}
      </div>
    </div>
  </div>

  <!-- MAIN: Tabla de credenciales -->
  <div class="col-12 col-lg-9">
    <!-- Filtros -->
    <div class="card shadow-sm mb-3">
      <div class="card-body py-2">
        <div class="row g-2">
          <div class="col-md-5">
            <div class="input-group input-group-sm">
              <span class="input-group-text"><i class="bi bi-search"></i></span>
              <input type="text" class="form-control" id="searchInput"
                     placeholder="Buscar por título o usuario...">
            </div>
          </div>
          <div class="col-md-3">
            <select class="form-select form-select-sm" id="filterCategory">
              <option value="">Todas las categorías</option>
              <option value="server">Servidor</option>
              <option value="platform">Plataforma</option>
              <option value="api">API</option>
              <option value="other">Otra</option>
            </select>
          </div>
          <div class="col-md-4">
            <select class="form-select form-select-sm" id="filterExpiry">
              <option value="">Todas las expiraciones</option>
              <option value="expired">Expiradas</option>
              <option value="soon">Expiran en 7 días</option>
              <option value="ok">Vigentes</option>
              <option value="none">Sin fecha</option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <!-- Tabla -->
    <div class="card shadow-sm">
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover table-striped mb-0 align-middle" id="vaultTable">
            <thead class="table-dark">
              <tr>
                <th>Título</th>
                <th>Categoría</th>
                <th>Grupo</th>
                <th>Expiración</th>
                <th class="text-center">Compartida</th>
                <th class="text-center">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {% if entries %}
                {% for entry in entries %}
                {% set days_left = ((entry.expires_at - now).days) if entry.expires_at else None %}
                <tr class="vault-row"
                    data-title="{{ entry.title | lower }}"
                    data-username="{{ entry.username | lower }}"
                    data-category="{{ entry.category }}"
                    data-expiry="{% if not entry.expires_at %}none{% elif days_left < 0 %}expired{% elif days_left <= 7 %}soon{% else %}ok{% endif %}">
                  <td>
                    <a href="{{ url_for('vault.detail', entry_id=entry.id) }}"
                       class="text-decoration-none fw-semibold text-dark">
                      <i class="bi bi-key me-1 text-secondary"></i>{{ entry.title }}
                    </a>
                  </td>
                  <td>
                    {% if entry.category == 'server' %}
                      <span class="badge bg-primary">Servidor</span>
                    {% elif entry.category == 'platform' %}
                      <span class="badge" style="background-color:#6f42c1;">Plataforma</span>
                    {% elif entry.category == 'api' %}
                      <span class="badge bg-warning text-dark">API</span>
                    {% else %}
                      <span class="badge bg-secondary">Otra</span>
                    {% endif %}
                  </td>
                  <td>
                    {% if entry.group %}
                      <span class="badge bg-light text-dark border">
                        <i class="bi bi-folder me-1"></i>{{ entry.group.name }}
                      </span>
                    {% else %}
                      <span class="text-muted">—</span>
                    {% endif %}
                  </td>
                  <td>
                    {% if not entry.expires_at %}
                      <span class="text-muted small">—</span>
                    {% elif days_left < 0 %}
                      <span class="badge bg-danger" title="Expirada el {{ entry.expires_at.strftime('%d/%m/%Y') }}">
                        <i class="bi bi-exclamation-triangle-fill me-1"></i>Expirada
                      </span>
                    {% elif days_left <= 7 %}
                      <span class="badge bg-warning text-dark" title="{{ days_left }} día(s) restantes">
                        <i class="bi bi-clock-fill me-1"></i>{{ days_left }}d
                      </span>
                    {% else %}
                      <span class="small text-muted">{{ entry.expires_at.strftime('%d/%m/%Y') }}</span>
                    {% endif %}
                  </td>
                  <td class="text-center">
                    {% if entry.shared %}
                      <span class="badge bg-success"><i class="bi bi-people-fill"></i> Sí</span>
                    {% else %}
                      <span class="badge bg-light text-dark border"><i class="bi bi-lock-fill"></i> No</span>
                    {% endif %}
                  </td>
                  <td class="text-center">
                    <div class="d-flex justify-content-center gap-1">
                      <a href="{{ url_for('vault.detail', entry_id=entry.id) }}"
                         class="btn btn-sm btn-primary" title="Ver">
                        <i class="bi bi-eye"></i>
                      </a>
                      {% if current_user.is_admin or entry.owner_id == current_user.id %}
                      <a href="{{ url_for('vault.edit', entry_id=entry.id) }}"
                         class="btn btn-sm btn-warning text-dark" title="Editar">
                        <i class="bi bi-pencil"></i>
                      </a>
                      <button type="button" class="btn btn-sm btn-danger" title="Eliminar"
                              data-bs-toggle="modal" data-bs-target="#modalEliminar"
                              data-entry-id="{{ entry.id }}" data-entry-title="{{ entry.title }}">
                        <i class="bi bi-trash"></i>
                      </button>
                      {% endif %}
                    </div>
                  </td>
                </tr>
                {% endfor %}
              {% else %}
                <tr id="emptyStateRow">
                  <td colspan="6">
                    <div class="text-center py-5 text-muted">
                      <i class="bi bi-safe" style="font-size:3rem;"></i>
                      <p class="mt-3 fw-semibold">No hay credenciales guardadas.</p>
                      <p class="small">Haz clic en "Nueva credencial" para agregar la primera.</p>
                    </div>
                  </td>
                </tr>
              {% endif %}
              <tr id="noResultsRow" class="d-none">
                <td colspan="6" class="text-center py-4 text-muted">
                  <i class="bi bi-search me-2"></i>No hay resultados para los filtros aplicados.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Modal Confirmar Eliminación -->
<div class="modal fade" id="modalEliminar" tabindex="-1" aria-labelledby="modalEliminarLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header bg-danger text-white">
        <h5 class="modal-title" id="modalEliminarLabel">Confirmar Eliminación</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <p>¿Eliminar la credencial <strong><span id="modalEliminarTitulo"></span></strong>?</p>
        <p class="text-danger small">Esta acción no se puede deshacer.</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
        <form id="formEliminar" method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
          <button type="submit" class="btn btn-danger"><i class="bi bi-trash me-1"></i>Eliminar</button>
        </form>
      </div>
    </div>
  </div>
</div>

<script>
(function () {
  var search = document.getElementById('searchInput');
  var filterCat = document.getElementById('filterCategory');
  var filterExp = document.getElementById('filterExpiry');
  var rows = document.querySelectorAll('.vault-row');
  var noResults = document.getElementById('noResultsRow');

  function applyFilters() {
    var q = search.value.trim().toLowerCase();
    var cat = filterCat.value;
    var exp = filterExp.value;
    var visible = 0;
    rows.forEach(function (row) {
      var match = (q === '' || row.dataset.title.includes(q) || row.dataset.username.includes(q))
                && (cat === '' || row.dataset.category === cat)
                && (exp === '' || row.dataset.expiry === exp);
      row.classList.toggle('d-none', !match);
      if (match) visible++;
    });
    if (noResults) noResults.classList.toggle('d-none', visible > 0 || rows.length === 0);
  }

  [search, filterCat, filterExp].forEach(function(el) {
    if (el) el.addEventListener('input', applyFilters);
    if (el) el.addEventListener('change', applyFilters);
  });
})();

(function () {
  var modal = document.getElementById('modalEliminar');
  if (!modal) return;
  modal.addEventListener('show.bs.modal', function (e) {
    var btn = e.relatedTarget;
    document.getElementById('modalEliminarTitulo').textContent = btn.dataset.entryTitle;
    document.getElementById('formEliminar').action =
      '{{ url_for("vault.delete", entry_id=0) }}'.replace('/0/', '/' + btn.dataset.entryId + '/');
  });
})();
</script>
{% endblock %}
```

- [ ] **Step 2: Commit**

```bash
git add app/templates/vault/index.html
git commit -m "feat(vault): redesign index with group sidebar, expiry badges, import button"
```

---

## Task 8: Actualizar new.html y edit.html

**Files:**
- Modify: `app/templates/vault/new.html`
- Modify: `app/templates/vault/edit.html`

Los dos formularios comparten la misma sección de campos nuevos (grupo, expiración, campos personalizados). Se muestran los cambios que van dentro del `<form>` de cada template.

### new.html

- [ ] **Step 1: Reemplazar app/templates/vault/new.html**

```html
{% extends "base.html" %}
{% block title %}Nueva Credencial — Vault{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('vault.index') }}">Vault</a></li>
    <li class="breadcrumb-item active">Nueva Credencial</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<div class="row justify-content-center">
  <div class="col-md-9 col-lg-7">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h2 class="mb-0"><i class="bi bi-plus-circle-fill text-success me-2"></i>Nueva Credencial</h2>
      <a href="{{ url_for('vault.index') }}" class="btn btn-outline-secondary btn-sm">
        <i class="bi bi-arrow-left me-1"></i>Volver
      </a>
    </div>

    <div class="card shadow-sm">
      <div class="card-header bg-dark text-white"><i class="bi bi-key me-2"></i>Datos de la credencial</div>
      <div class="card-body">
        <form method="POST" action="{{ url_for('vault.new') }}" novalidate>
          {{ form.hidden_tag() }}
          <input type="hidden" id="custom_fields_json" name="custom_fields_json" value="[]">

          <div class="row g-3 mb-3">
            <div class="col-md-8">
              {{ form.title.label(class="form-label fw-bold") }}
              {{ form.title(class="form-control" + (" is-invalid" if form.title.errors else ""),
                            placeholder="Ej: Servidor de Producción DB01") }}
              {% for e in form.title.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
            </div>
            <div class="col-md-4">
              {{ form.category.label(class="form-label fw-bold") }}
              {{ form.category(class="form-select" + (" is-invalid" if form.category.errors else "")) }}
            </div>
          </div>

          <div class="row g-3 mb-3">
            <div class="col-md-6">
              {{ form.group_id.label(class="form-label fw-bold") }}
              {{ form.group_id(class="form-select form-select-sm") }}
            </div>
            <div class="col-md-6">
              {{ form.expires_at.label(class="form-label fw-bold") }}
              {{ form.expires_at(class="form-control form-control-sm", type="date") }}
              <div class="form-text">Dejar vacío si no expira.</div>
            </div>
          </div>

          <div class="row g-3 mb-3">
            <div class="col-md-6">
              {{ form.username.label(class="form-label fw-bold", id="lbl_username") }}
              {{ form.username(class="form-control font-monospace" + (" is-invalid" if form.username.errors else ""),
                               placeholder="Ej: admin") }}
              {% for e in form.username.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
            </div>
            <div class="col-md-6">
              <label class="form-label fw-bold" id="lbl_password">Contraseña</label>
              <div class="input-group">
                {{ form.password(class="form-control font-monospace" + (" is-invalid" if form.password.errors else ""),
                                 id="passwordInput", type="password", placeholder="Contraseña") }}
                <button class="btn btn-outline-secondary" type="button" id="btnTogglePassword">
                  <i class="bi bi-eye" id="eyeIcon"></i>
                </button>
              </div>
              {% for e in form.password.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
            </div>
          </div>

          <div class="mb-3">
            {{ form.url.label(class="form-label fw-bold") }}
            {{ form.url(class="form-control" + (" is-invalid" if form.url.errors else ""),
                        placeholder="https://...") }}
            {% for e in form.url.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
          </div>

          <div class="mb-3">
            {{ form.notes.label(class="form-label fw-bold") }}
            {{ form.notes(class="form-control" + (" is-invalid" if form.notes.errors else ""),
                          rows=3, placeholder="Notas adicionales...") }}
          </div>

          <!-- Campos personalizados -->
          <div class="mb-3">
            <label class="form-label fw-bold">Campos personalizados</label>
            <div id="cfContainer"></div>
            <button type="button" class="btn btn-sm btn-outline-secondary mt-2" id="btnAddCf">
              <i class="bi bi-plus me-1"></i>Agregar campo
            </button>
          </div>

          <div class="mb-4">
            <div class="form-check">
              {{ form.shared(class="form-check-input") }}
              {{ form.shared.label(class="form-check-label fw-bold") }}
            </div>
            <div class="form-text">Si activas esta opción, todos los analistas pueden ver esta credencial.</div>
          </div>

          <hr>
          <div class="d-flex justify-content-end gap-2">
            <a href="{{ url_for('vault.index') }}" class="btn btn-secondary">
              <i class="bi bi-x-lg me-1"></i>Cancelar
            </a>
            <button type="submit" class="btn btn-success">
              <i class="bi bi-save me-1"></i>Guardar
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
  var container = document.getElementById('cfContainer');
  var jsonInput = document.getElementById('custom_fields_json');
  var fields = [];

  function render() {
    container.innerHTML = '';
    fields.forEach(function(f, i) {
      var row = document.createElement('div');
      row.className = 'input-group mb-2';
      row.innerHTML =
        '<input type="text" class="form-control cf-key" placeholder="Clave" value="'+escHtml(f.key)+'" maxlength="100">'
        +'<input type="text" class="form-control cf-value" placeholder="Valor" value="'+escHtml(f.value)+'">'
        +'<div class="input-group-text"><input class="form-check-input mt-0 cf-protected" type="checkbox" title="Protegido"'+(f.protected?' checked':'')+'>  <i class="bi bi-shield-lock ms-1 text-muted" title="Marcar como protegido"></i></div>'
        +'<button type="button" class="btn btn-outline-danger cf-del" data-idx="'+i+'"><i class="bi bi-trash"></i></button>';
      container.appendChild(row);
    });
    container.querySelectorAll('.cf-del').forEach(function(btn){
      btn.addEventListener('click', function(){ fields.splice(parseInt(this.dataset.idx),1); render(); });
    });
  }

  function serialize() {
    var result = [];
    container.querySelectorAll('.input-group').forEach(function(row){
      var key = row.querySelector('.cf-key').value.trim();
      if (!key) return;
      result.push({key:key, value:row.querySelector('.cf-value').value, protected:row.querySelector('.cf-protected').checked});
    });
    jsonInput.value = JSON.stringify(result);
  }

  function escHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }

  document.getElementById('btnAddCf').addEventListener('click', function(){ fields.push({key:'',value:'',protected:false}); render(); });
  document.querySelector('form').addEventListener('submit', serialize);
  render();
})();
</script>
<script>
(function(){
  var inp = document.getElementById('passwordInput');
  var btn = document.getElementById('btnTogglePassword');
  var ico = document.getElementById('eyeIcon');
  if (!btn) return;
  btn.addEventListener('click', function(){
    var show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    ico.className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
  });
})();
</script>
<script>
(function(){
  var cat = document.getElementById('category');
  var lblU = document.getElementById('lbl_username');
  var lblP = document.getElementById('lbl_password');
  if (!cat) return;
  function upd(){ var api=cat.value==='api'; lblU.textContent=api?'API Client':'Usuario'; lblP.textContent=api?'API Secret':'Contraseña'; }
  cat.addEventListener('change', upd); upd();
})();
</script>
{% endblock %}
```

### edit.html

- [ ] **Step 2: Reemplazar app/templates/vault/edit.html**

```html
{% extends "base.html" %}
{% block title %}Editar Credencial — Vault{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('vault.index') }}">Vault</a></li>
    <li class="breadcrumb-item"><a href="{{ url_for('vault.detail', entry_id=entry.id) }}">{{ entry.title }}</a></li>
    <li class="breadcrumb-item active">Editar</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<div class="row justify-content-center">
  <div class="col-md-9 col-lg-7">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h2 class="mb-0"><i class="bi bi-pencil-fill text-warning me-2"></i>Editar Credencial</h2>
      <a href="{{ url_for('vault.detail', entry_id=entry.id) }}" class="btn btn-outline-secondary btn-sm">
        <i class="bi bi-arrow-left me-1"></i>Volver
      </a>
    </div>

    <div class="alert alert-warning py-2">
      <i class="bi bi-pencil me-1"></i>Editando: <strong>{{ entry.title }}</strong>
    </div>

    <div class="card shadow-sm">
      <div class="card-header bg-dark text-white"><i class="bi bi-key me-2"></i>Datos de la credencial</div>
      <div class="card-body">
        <form method="POST" action="{{ url_for('vault.edit', entry_id=entry.id) }}" novalidate>
          {{ form.hidden_tag() }}
          <input type="hidden" id="custom_fields_json" name="custom_fields_json" value="[]">

          <div class="row g-3 mb-3">
            <div class="col-md-8">
              {{ form.title.label(class="form-label fw-bold") }}
              {{ form.title(class="form-control" + (" is-invalid" if form.title.errors else "")) }}
              {% for e in form.title.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
            </div>
            <div class="col-md-4">
              {{ form.category.label(class="form-label fw-bold") }}
              {{ form.category(class="form-select" + (" is-invalid" if form.category.errors else "")) }}
            </div>
          </div>

          <div class="row g-3 mb-3">
            <div class="col-md-6">
              {{ form.group_id.label(class="form-label fw-bold") }}
              {{ form.group_id(class="form-select form-select-sm") }}
            </div>
            <div class="col-md-6">
              {{ form.expires_at.label(class="form-label fw-bold") }}
              {{ form.expires_at(class="form-control form-control-sm", type="date") }}
            </div>
          </div>

          <div class="row g-3 mb-3">
            <div class="col-md-6">
              {{ form.username.label(class="form-label fw-bold", id="lbl_username") }}
              {{ form.username(class="form-control font-monospace" + (" is-invalid" if form.username.errors else "")) }}
            </div>
            <div class="col-md-6">
              <label class="form-label fw-bold" id="lbl_password">Contraseña</label>
              <div class="input-group">
                {{ form.password(class="form-control font-monospace",
                                 id="passwordInput", type="password",
                                 placeholder="Dejar vacío para no cambiar") }}
                <button class="btn btn-outline-secondary" type="button" id="btnTogglePassword">
                  <i class="bi bi-eye" id="eyeIcon"></i>
                </button>
              </div>
            </div>
          </div>

          <div class="mb-3">
            {{ form.url.label(class="form-label fw-bold") }}
            {{ form.url(class="form-control" + (" is-invalid" if form.url.errors else ""), placeholder="https://...") }}
            {% for e in form.url.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
          </div>

          <div class="mb-3">
            {{ form.notes.label(class="form-label fw-bold") }}
            {{ form.notes(class="form-control", rows=3) }}
          </div>

          <!-- Campos personalizados -->
          <div class="mb-3">
            <label class="form-label fw-bold">Campos personalizados</label>
            <div id="cfContainer"></div>
            <button type="button" class="btn btn-sm btn-outline-secondary mt-2" id="btnAddCf">
              <i class="bi bi-plus me-1"></i>Agregar campo
            </button>
          </div>

          <div class="mb-4">
            <div class="form-check">
              {{ form.shared(class="form-check-input") }}
              {{ form.shared.label(class="form-check-label fw-bold") }}
            </div>
          </div>

          <hr>
          <div class="d-flex justify-content-end gap-2">
            <a href="{{ url_for('vault.detail', entry_id=entry.id) }}" class="btn btn-secondary">
              <i class="bi bi-x-lg me-1"></i>Cancelar
            </a>
            <button type="submit" class="btn btn-warning text-dark">
              <i class="bi bi-save me-1"></i>Guardar cambios
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
  var container = document.getElementById('cfContainer');
  var jsonInput = document.getElementById('custom_fields_json');
  var fields = {{ existing_cf | tojson }};

  function render() {
    container.innerHTML = '';
    fields.forEach(function(f, i) {
      var row = document.createElement('div');
      row.className = 'input-group mb-2';
      row.innerHTML =
        '<input type="text" class="form-control cf-key" placeholder="Clave" value="'+escHtml(f.key)+'" maxlength="100">'
        +'<input type="text" class="form-control cf-value" placeholder="Valor" value="'+escHtml(f.value)+'">'
        +'<div class="input-group-text"><input class="form-check-input mt-0 cf-protected" type="checkbox" title="Protegido"'+(f.protected?' checked':'')+'>  <i class="bi bi-shield-lock ms-1 text-muted"></i></div>'
        +'<button type="button" class="btn btn-outline-danger cf-del" data-idx="'+i+'"><i class="bi bi-trash"></i></button>';
      container.appendChild(row);
    });
    container.querySelectorAll('.cf-del').forEach(function(btn){
      btn.addEventListener('click', function(){ fields.splice(parseInt(this.dataset.idx),1); render(); });
    });
  }

  function serialize() {
    var result = [];
    container.querySelectorAll('.input-group').forEach(function(row){
      var key = row.querySelector('.cf-key').value.trim();
      if (!key) return;
      result.push({key:key, value:row.querySelector('.cf-value').value, protected:row.querySelector('.cf-protected').checked});
    });
    jsonInput.value = JSON.stringify(result);
  }

  function escHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }

  document.getElementById('btnAddCf').addEventListener('click', function(){ fields.push({key:'',value:'',protected:false}); render(); });
  document.querySelector('form').addEventListener('submit', serialize);
  render();
})();
</script>
<script>
(function(){
  var inp=document.getElementById('passwordInput'),btn=document.getElementById('btnTogglePassword'),ico=document.getElementById('eyeIcon');
  if(!btn)return;
  btn.addEventListener('click',function(){var s=inp.type==='password';inp.type=s?'text':'password';ico.className=s?'bi bi-eye-slash':'bi bi-eye';});
})();
(function(){
  var cat=document.getElementById('category'),lblU=document.getElementById('lbl_username'),lblP=document.getElementById('lbl_password');
  if(!cat)return;
  function upd(){var api=cat.value==='api';lblU.textContent=api?'API Client':'Usuario';lblP.textContent=api?'API Secret':'Contraseña';}
  cat.addEventListener('change',upd);upd();
})();
</script>
{% endblock %}
```

- [ ] **Step 3: Commit**

```bash
git add app/templates/vault/new.html app/templates/vault/edit.html
git commit -m "feat(vault): add group picker, expiry date, custom fields to new/edit forms"
```

---

## Task 9: Actualizar detail.html

**Files:**
- Modify: `app/templates/vault/detail.html`

- [ ] **Step 1: Leer el contenido actual de detail.html**

Abrir `app/templates/vault/detail.html`. Localizar la sección que muestra los campos de la credencial (título, categoría, usuario, URL, notas, compartida, propietario, fecha).

- [ ] **Step 2: Agregar bloque de grupo y expiración después del campo Categoría**

Dentro de la tabla/lista de detalles, después del campo `Categoría`, agregar:

```html
<!-- Grupo -->
<tr>
  <th class="text-muted fw-normal" style="width:35%">Grupo</th>
  <td>
    {% if entry.group %}
      <span class="badge bg-light text-dark border">
        <i class="bi bi-folder me-1"></i>{{ entry.group.name }}
      </span>
    {% else %}
      <span class="text-muted">Sin grupo</span>
    {% endif %}
  </td>
</tr>

<!-- Expiración -->
{% set days_left = ((entry.expires_at - now).days) if entry.expires_at else None %}
<tr>
  <th class="text-muted fw-normal">Expira</th>
  <td>
    {% if not entry.expires_at %}
      <span class="text-muted">Sin fecha de expiración</span>
    {% elif days_left < 0 %}
      <span class="badge bg-danger"><i class="bi bi-exclamation-triangle-fill me-1"></i>Expirada el {{ entry.expires_at.strftime('%d/%m/%Y') }}</span>
    {% elif days_left <= 7 %}
      <span class="badge bg-warning text-dark"><i class="bi bi-clock-fill me-1"></i>Expira en {{ days_left }} día(s) — {{ entry.expires_at.strftime('%d/%m/%Y') }}</span>
    {% else %}
      <span>{{ entry.expires_at.strftime('%d/%m/%Y') }}</span>
    {% endif %}
  </td>
</tr>
```

- [ ] **Step 3: Agregar sección de campos personalizados antes del bloque de acciones**

```html
{% if custom_fields %}
<div class="card shadow-sm mt-3">
  <div class="card-header py-2 fw-semibold">
    <i class="bi bi-list-columns me-1"></i>Campos personalizados
  </div>
  <div class="card-body p-0">
    <table class="table table-sm mb-0">
      <tbody>
        {% for field in custom_fields %}
        <tr>
          <th class="text-muted fw-normal ps-3" style="width:35%">{{ field.key }}</th>
          <td>
            {% if field.protected %}
              <span class="font-monospace">••••••••</span>
              <span class="badge bg-light text-muted border ms-1">
                <i class="bi bi-shield-lock"></i>
              </span>
            {% else %}
              <span class="font-monospace">{{ field.value }}</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endif %}
```

- [ ] **Step 4: Commit**

```bash
git add app/templates/vault/detail.html
git commit -m "feat(vault): show group, expiry status and custom fields in detail view"
```

---

## Task 10: Crear import.html e import_preview.html

**Files:**
- Create: `app/templates/vault/import.html`
- Create: `app/templates/vault/import_preview.html`

### import.html (Step 1 del wizard)

- [ ] **Step 1: Crear app/templates/vault/import.html**

```html
{% extends "base.html" %}
{% block title %}Importar .kdbx — Vault{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('vault.index') }}">Vault</a></li>
    <li class="breadcrumb-item active">Importar KeePass</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<div class="row justify-content-center">
  <div class="col-md-7 col-lg-5">

    <!-- Progreso del wizard -->
    <div class="d-flex align-items-center mb-4 gap-3">
      <span class="badge bg-primary rounded-pill px-3 py-2">1 Subir</span>
      <div class="flex-grow-1 border-top border-2"></div>
      <span class="badge bg-light text-dark border rounded-pill px-3 py-2">2 Revisar</span>
      <div class="flex-grow-1 border-top border-2"></div>
      <span class="badge bg-light text-dark border rounded-pill px-3 py-2">3 Confirmar</span>
    </div>

    <div class="card shadow-sm">
      <div class="card-header bg-dark text-white">
        <i class="bi bi-upload me-2"></i>Importar archivo KeePass (.kdbx)
      </div>
      <div class="card-body">
        <div class="alert alert-info py-2 small">
          <i class="bi bi-info-circle me-1"></i>
          Solo administradores pueden importar. Las credenciales nuevas quedarán como propias.
          Los conflictos de UUID se resolverán en el siguiente paso.
        </div>

        <form method="POST" action="{{ url_for('vault.import_kdbx') }}"
              enctype="multipart/form-data" novalidate>
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>

          <div class="mb-3">
            <label for="kdbx_file" class="form-label fw-bold">Archivo .kdbx</label>
            <input type="file" class="form-control" id="kdbx_file" name="kdbx_file"
                   accept=".kdbx" required>
            <div class="form-text">Selecciona el archivo KeePass a importar.</div>
          </div>

          <div class="mb-4">
            <label for="kdbx_password" class="form-label fw-bold">Contraseña maestra del archivo</label>
            <div class="input-group">
              <input type="password" class="form-control" id="kdbx_password" name="kdbx_password"
                     placeholder="Contraseña del archivo .kdbx" required>
              <button class="btn btn-outline-secondary" type="button" id="btnTogglePw">
                <i class="bi bi-eye" id="pwEye"></i>
              </button>
            </div>
          </div>

          <div class="d-flex justify-content-end gap-2">
            <a href="{{ url_for('vault.index') }}" class="btn btn-secondary">
              <i class="bi bi-x-lg me-1"></i>Cancelar
            </a>
            <button type="submit" class="btn btn-primary">
              <i class="bi bi-arrow-right me-1"></i>Siguiente
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
  var inp=document.getElementById('kdbx_password'),btn=document.getElementById('btnTogglePw'),ico=document.getElementById('pwEye');
  btn.addEventListener('click',function(){var s=inp.type==='password';inp.type=s?'text':'password';ico.className=s?'bi bi-eye-slash':'bi bi-eye';});
})();
</script>
{% endblock %}
```

### import_preview.html (Step 2 del wizard)

- [ ] **Step 2: Crear app/templates/vault/import_preview.html**

```html
{% extends "base.html" %}
{% block title %}Revisar importación — Vault{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('vault.index') }}">Vault</a></li>
    <li class="breadcrumb-item"><a href="{{ url_for('vault.import_kdbx') }}">Importar KeePass</a></li>
    <li class="breadcrumb-item active">Revisar</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<!-- Progreso del wizard -->
<div class="d-flex align-items-center mb-4 gap-3" style="max-width:500px;">
  <span class="badge bg-success rounded-pill px-3 py-2"><i class="bi bi-check me-1"></i>1 Subir</span>
  <div class="flex-grow-1 border-top border-2 border-success"></div>
  <span class="badge bg-primary rounded-pill px-3 py-2">2 Revisar</span>
  <div class="flex-grow-1 border-top border-2"></div>
  <span class="badge bg-light text-dark border rounded-pill px-3 py-2">3 Confirmar</span>
</div>

<form method="POST" action="{{ url_for('vault.import_confirm') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>

  <!-- Entradas nuevas -->
  <div class="card shadow-sm mb-4">
    <div class="card-header d-flex justify-content-between align-items-center">
      <span class="fw-semibold">
        <i class="bi bi-plus-circle text-success me-1"></i>
        Entradas nuevas ({{ new_entries | length }})
      </span>
      {% if new_entries %}
      <div>
        <button type="button" class="btn btn-sm btn-outline-secondary" id="btnSelectAll">Seleccionar todas</button>
        <button type="button" class="btn btn-sm btn-outline-secondary ms-1" id="btnDeselectAll">Ninguna</button>
      </div>
      {% endif %}
    </div>
    <div class="card-body p-0">
      {% if new_entries %}
      <div class="table-responsive">
        <table class="table table-sm table-hover mb-0">
          <thead class="table-light">
            <tr>
              <th style="width:2rem;"></th>
              <th>Título</th>
              <th>Usuario</th>
              <th>Grupo (kdbx)</th>
              <th>Expira</th>
              <th>Campos extra</th>
            </tr>
          </thead>
          <tbody>
            {% for e in new_entries %}
            <tr>
              <td class="text-center">
                <input class="form-check-input new-check" type="checkbox"
                       name="import_new" value="{{ e.uuid }}" checked>
              </td>
              <td class="fw-semibold">{{ e.title }}</td>
              <td class="font-monospace small">{{ e.username or '—' }}</td>
              <td class="small text-muted">{{ e.group_path or '—' }}</td>
              <td class="small">{{ e.expires_at or '—' }}</td>
              <td class="small text-muted">{{ e.custom_fields | length }} campo(s)</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="text-center py-4 text-muted">
        <i class="bi bi-check-circle me-1"></i>No hay entradas nuevas en el archivo.
      </div>
      {% endif %}
    </div>
  </div>

  <!-- Conflictos -->
  {% if conflicts %}
  <div class="card shadow-sm mb-4">
    <div class="card-header">
      <span class="fw-semibold">
        <i class="bi bi-exclamation-triangle text-warning me-1"></i>
        Conflictos — UUID ya existe ({{ conflicts | length }})
      </span>
    </div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-sm mb-0">
          <thead class="table-light">
            <tr>
              <th>Título</th>
              <th>Vault actual</th>
              <th>KeePass importado</th>
              <th style="width:11rem;">¿Cuál conservar?</th>
            </tr>
          </thead>
          <tbody>
            {% for c in conflicts %}
            <tr class="align-middle">
              <td class="fw-semibold">{{ c.kdbx.title }}</td>
              <td class="small text-muted">
                Usuario: {{ c.vault.username }}<br>
                Modificado: {{ c.vault.updated_at }}
              </td>
              <td class="small text-muted">
                Usuario: {{ c.kdbx.username }}<br>
                Expira: {{ c.kdbx.expires_at or '—' }}
              </td>
              <td>
                <div class="d-flex flex-column gap-1">
                  <div class="form-check">
                    <input class="form-check-input" type="radio"
                           name="conflict_{{ c.kdbx.uuid }}" value="vault" checked
                           id="cv_{{ loop.index }}">
                    <label class="form-check-label small" for="cv_{{ loop.index }}">
                      <i class="bi bi-database me-1 text-primary"></i>Conservar Vault
                    </label>
                  </div>
                  <div class="form-check">
                    <input class="form-check-input" type="radio"
                           name="conflict_{{ c.kdbx.uuid }}" value="kdbx"
                           id="ck_{{ loop.index }}">
                    <label class="form-check-label small" for="ck_{{ loop.index }}">
                      <i class="bi bi-file-earmark-lock me-1 text-warning"></i>Usar KeePass
                    </label>
                  </div>
                </div>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {% endif %}

  <div class="d-flex justify-content-between">
    <a href="{{ url_for('vault.import_kdbx') }}" class="btn btn-secondary">
      <i class="bi bi-arrow-left me-1"></i>Volver a subir
    </a>
    <button type="submit" class="btn btn-success">
      <i class="bi bi-check-lg me-1"></i>Confirmar importación
    </button>
  </div>
</form>

<script>
(function(){
  var all = document.querySelectorAll('.new-check');
  var btnAll = document.getElementById('btnSelectAll');
  var btnNone = document.getElementById('btnDeselectAll');
  if (btnAll) btnAll.addEventListener('click', function(){ all.forEach(function(c){ c.checked=true; }); });
  if (btnNone) btnNone.addEventListener('click', function(){ all.forEach(function(c){ c.checked=false; }); });
})();
</script>
{% endblock %}
```

- [ ] **Step 3: Commit**

```bash
git add app/templates/vault/import.html app/templates/vault/import_preview.html
git commit -m "feat(vault): add 3-step kdbx import wizard templates"
```

---

## Task 11: Verificación end-to-end

- [ ] **Step 1: Arrancar el servidor de desarrollo**

```bash
python run.py
```

Expected: `* Running on http://127.0.0.1:5000`

- [ ] **Step 2: Verificar el index del vault**

Ir a `http://localhost:5000/vault/`. Verificar:
- Aparece el sidebar de grupos (inicialmente "Sin grupos creados")
- La tabla muestra columnas: Título, Categoría, Grupo, Expiración, Compartida, Acciones
- Los filtros de búsqueda, categoría y expiración funcionan
- El botón "Importar .kdbx" solo es visible para admins

- [ ] **Step 3: Verificar creación de grupo**

Como admin, expandir el formulario de nuevo grupo en el sidebar, crear "Servidores". Verificar que aparece en la lista.

- [ ] **Step 4: Verificar creación de credencial con campos nuevos**

Ir a "Nueva credencial". Verificar:
- El dropdown de grupo muestra "Servidores"
- El campo de fecha de expiración acepta formato `YYYY-MM-DD`
- La sección de campos personalizados permite agregar/eliminar campos dinámicamente
- Al guardar, la credencial se crea y aparece en el index con el grupo y fecha indicados

- [ ] **Step 5: Verificar detalle con campos nuevos**

Ir al detalle de la credencial creada. Verificar:
- Se muestra el grupo con ícono de carpeta
- Se muestra la fecha de expiración con badge de color según estado
- Se muestran los campos personalizados en tabla al fondo

- [ ] **Step 6: Verificar sync (si VAULT_KDBX_PATH está configurado)**

Si `.env` tiene `VAULT_KDBX_PATH` y `VAULT_KDBX_PASSWORD`, después de crear/editar una entrada:
- Verificar que el archivo `.kdbx` se genera en la ruta configurada
- Verificar que el archivo tiene atributo read-only (`icacls <ruta>` en Windows)
- Abrir el archivo en KeePass Desktop con la master password — debería abrirse en modo solo lectura

- [ ] **Step 7: Verificar import (admin)**

1. Generar un archivo `.kdbx` de prueba con KeePass Desktop con 2-3 entradas
2. Ir a `http://localhost:5000/vault/import`
3. Subir el archivo con su master password
4. Verificar que el wizard muestra el step 2 con las entradas detectadas
5. Seleccionar todas y confirmar
6. Verificar que las entradas aparecen en el vault

- [ ] **Step 8: Commit final de verificación**

```bash
git add .
git commit -m "feat(vault): complete KeePass-compatible vault restructure with groups, expiry, custom fields, sync and import"
```
