from flask import (render_template, redirect, url_for, flash,
                   abort, request, jsonify, current_app)
from flask_login import login_required, current_user
from werkzeug.exceptions import NotFound
from app.extensions import db
from app.vault import bp
from app.vault.models import VaultEntry, VaultAuditLog
from app.vault.crypto import encrypt, decrypt
from app.vault.forms import VaultEntryForm
from app.utils import admin_required


def _get_entry_or_404(entry_id):
    entry = db.session.get(VaultEntry, entry_id)
    if entry is None:
        raise NotFound()
    return entry


def _get_client_ip():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    return ip


def _log_audit(entry_id, action, user_id, ip, entry_title=None):
    log = VaultAuditLog(
        entry_id=entry_id, user_id=user_id, action=action,
        ip_address=ip, entry_title=entry_title,
    )
    db.session.add(log)


def _can_access(entry):
    if current_user.is_admin:
        return True
    return entry.owner_id == current_user.id or entry.shared


@bp.route('/')
@login_required
def index():
    if current_user.is_admin:
        entries = VaultEntry.query.order_by(VaultEntry.created_at.desc()).all()
    else:
        entries = VaultEntry.query.filter(
            (VaultEntry.owner_id == current_user.id) | (VaultEntry.shared == True)
        ).order_by(VaultEntry.created_at.desc()).all()
    return render_template('vault/index.html', entries=entries)


@bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    form = VaultEntryForm()
    if form.validate_on_submit():
        if not form.password.data:
            form.password.errors.append('La contraseña es obligatoria.')
            return render_template('vault/new.html', form=form)
        password_enc = encrypt(form.password.data)
        notes_enc = encrypt(form.notes.data) if form.notes.data else None
        entry = VaultEntry(
            title=form.title.data,
            category=form.category.data,
            username=form.username.data,
            password_enc=password_enc,
            url=form.url.data or None,
            notes_enc=notes_enc,
            shared=form.shared.data,
            owner_id=current_user.id,
        )
        db.session.add(entry)
        db.session.flush()
        _log_audit(entry.id, 'create', current_user.id, _get_client_ip())
        db.session.commit()
        flash('Entrada creada correctamente.', 'success')
        return redirect(url_for('vault.detail', entry_id=entry.id))
    return render_template('vault/new.html', form=form)


@bp.route('/<int:entry_id>')
@login_required
def detail(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not _can_access(entry):
        abort(403)
    notes = decrypt(entry.notes_enc) if entry.notes_enc else None
    _log_audit(entry.id, 'view', current_user.id, _get_client_ip(), entry_title=entry.title)
    db.session.commit()
    return render_template('vault/detail.html', entry=entry, notes=notes)


@bp.route('/<int:entry_id>/reveal', methods=['POST'])
@login_required
def reveal(entry_id):
    # JS debe enviar el token CSRF en el header X-CSRFToken,
    # disponible en el portal como <meta name="csrf-token">
    entry = _get_entry_or_404(entry_id)
    if not _can_access(entry):
        return jsonify({'error': 'Acceso denegado'}), 403
    plain = decrypt(entry.password_enc)
    _log_audit(entry.id, 'reveal', current_user.id, _get_client_ip(), entry_title=entry.title)
    db.session.commit()
    return jsonify({'password': plain})


@bp.route('/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not (current_user.is_admin or entry.owner_id == current_user.id):
        abort(403)
    form = VaultEntryForm(obj=entry)
    if request.method == 'GET':
        form.password.data = ''
        form.notes.data = decrypt(entry.notes_enc) if entry.notes_enc else ''
    if form.validate_on_submit():
        entry.title = form.title.data
        entry.category = form.category.data
        entry.username = form.username.data
        entry.url = form.url.data or None
        entry.shared = form.shared.data
        if form.password.data:
            entry.password_enc = encrypt(form.password.data)
        entry.notes_enc = encrypt(form.notes.data) if form.notes.data else None
        _log_audit(entry.id, 'edit', current_user.id, _get_client_ip())
        db.session.commit()
        flash('Entrada actualizada.', 'success')
        return redirect(url_for('vault.detail', entry_id=entry.id))
    return render_template('vault/edit.html', form=form, entry=entry)


@bp.route('/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete(entry_id):
    entry = _get_entry_or_404(entry_id)
    if not (current_user.is_admin or entry.owner_id == current_user.id):
        abort(403)
    title, eid = entry.title, entry.id
    # Null out FK on existing audit logs so they survive the entry deletion
    VaultAuditLog.query.filter_by(entry_id=eid).update({'entry_id': None})
    # Delete log preserves title for audit trail (entry_id is None since entry ceases to exist)
    _log_audit(None, 'delete', current_user.id, _get_client_ip(), entry_title=title)
    db.session.delete(entry)
    db.session.commit()
    flash('Entrada eliminada.', 'info')
    return redirect(url_for('vault.index'))


@bp.route('/audit')
@login_required
@admin_required
def audit():
    logs = VaultAuditLog.query.order_by(VaultAuditLog.timestamp.desc()).all()
    return render_template('vault/audit.html', logs=logs)
