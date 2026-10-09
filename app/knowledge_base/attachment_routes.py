import os
import time
import uuid as uuid_mod
from datetime import datetime

from flask import abort, current_app, jsonify, request, send_file
from flask_login import current_user, login_required

from app.extensions import db
from app.knowledge_base import bp
from app.knowledge_base.attachment_cleanup import purge_expired_drafts
from app.knowledge_base.attachment_storage import attachment_path, safe_unlink
from app.knowledge_base.attachment_validation import validate_upload, AttachmentValidationError
from app.knowledge_base.routes import _can_edit  # already exists, author-or-admin
from app.knowledge_base.scanning import get_scanner, ScanStatus
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment
from app.models.audit import log_audit


def _handle_attachment_upload(article_id, draft_token):
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "No se recibió ningún archivo."}), 400

    declared_ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if declared_ext not in current_app.config["KB_ATTACHMENT_ALLOWED_EXTENSIONS"]:
        return jsonify({"error": "Extensión no permitida."}), 400

    data = file.read()
    if len(data) > current_app.config["KB_ATTACHMENT_MAX_SIZE_BYTES"]:
        return jsonify({"error": "El archivo excede el tamaño máximo permitido."}), 400

    # Quota applies to both an existing article's attachments and an
    # as-yet-unpromoted draft's — otherwise a draft_token could accumulate
    # unlimited files before ever being promoted or abandoned. Infected
    # rows are excluded: their physical file is unlinked immediately (see
    # below), so they have no real disk footprint left to account for, and
    # counting them would let one infected upload permanently consume part
    # of the quota forever with no way to reclaim it.
    quota_filter = (
        KnowledgeAttachment.article_id == article_id
        if article_id is not None
        else KnowledgeAttachment.draft_token == draft_token
    )
    total = db.session.query(
        db.func.coalesce(db.func.sum(KnowledgeAttachment.size_bytes), 0)
    ).filter(quota_filter, KnowledgeAttachment.scan_status != ScanStatus.INFECTED.value).scalar()
    if total + len(data) > current_app.config["KB_ATTACHMENT_MAX_TOTAL_BYTES"]:
        error = (
            "El artículo alcanzó el límite total de adjuntos."
            if article_id is not None
            else "Se alcanzó el límite total de adjuntos para este borrador."
        )
        return jsonify({"error": error}), 400

    try:
        validated = validate_upload(data, declared_ext)
    except AttachmentValidationError as e:
        return jsonify({"error": str(e)}), 400

    stored_filename = f"{uuid_mod.uuid4().hex}.{validated.extension}"
    os.makedirs(current_app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
    path = attachment_path(current_app, stored_filename)
    with open(path, "wb") as f:
        f.write(data)

    scan_result = get_scanner().scan_file(path)

    attachment = KnowledgeAttachment(
        article_id=article_id,
        draft_token=draft_token,
        original_filename=file.filename[:255],
        stored_filename=stored_filename,
        mime_type=validated.mime_type,
        extension=validated.extension,
        size_bytes=validated.size_bytes,
        sha256=validated.sha256,
        is_image=validated.is_image,
        uploaded_by=current_user.id,
        scan_status=scan_result.status.value,
        scan_checked_at=datetime.utcnow(),
    )
    db.session.add(attachment)
    db.session.flush()

    log_audit("knowledge_base", "attachment_upload", "attachment", attachment.id, attachment.original_filename)

    if scan_result.status == ScanStatus.INFECTED:
        # Confirmed policy: never store malware just to keep evidence.
        # The row (for traceability) stays; the physical file does not.
        log_audit("knowledge_base", "malware_detected", "attachment", attachment.id, attachment.original_filename)
        safe_unlink(path)

    db.session.commit()

    return jsonify({
        "id": attachment.id,
        "view_url": f"/kb/attachments/{attachment.id}/view",
        "download_url": f"/kb/attachments/{attachment.id}/download",
        "is_image": attachment.is_image,
        "scan_status": attachment.scan_status,
        "original_filename": attachment.original_filename,
    })


# Mutable single-element list (not a plain module global) so tests can
# reset it without `global` statements. purge_expired_drafts() does a full
# table scan plus a per-row delete+commit loop — calling it unconditionally
# on every draft-upload request would duplicate the 24h scheduled job's
# work on a hot path. Throttling to once per interval keeps the "lazy,
# opportunistic" safety net (cleans up between scheduled runs) without
# paying that cost on every single request.
_last_lazy_purge_at = [0.0]
_LAZY_PURGE_MIN_INTERVAL_SECONDS = 300


@bp.route("/attachments/draft-upload", methods=["POST"])
@login_required
def attachment_draft_upload():
    now = time.monotonic()
    if now - _last_lazy_purge_at[0] > _LAZY_PURGE_MIN_INTERVAL_SECONDS:
        _last_lazy_purge_at[0] = now
        purge_expired_drafts(current_app._get_current_object())
    draft_token = request.form.get("draft_token", "").strip()
    if not draft_token:
        return jsonify({"error": "Falta draft_token."}), 400
    return _handle_attachment_upload(article_id=None, draft_token=draft_token)


@bp.route("/<int:article_id>/attachments/upload", methods=["POST"])
@login_required
def attachment_upload(article_id):
    article = KnowledgeArticle.query.get_or_404(article_id)
    if not _can_edit(article):
        abort(403)
    return _handle_attachment_upload(article_id=article_id, draft_token=None)


def _require_article_read_access(att):
    """Tool access is enough to read — Knowledge Base has no per-article
    ownership restriction on reading, same as detalle(). A draft attachment
    (no article_id yet) can only be read by its own uploader — there is no
    "article" to check permission against yet."""
    if att.article_id is None:
        if att.uploaded_by != current_user.id:
            abort(404)
    # else: knowledge_base tool access (already enforced by proteger_blueprint
    # at the blueprint level) is sufficient — no further object check, matching
    # detalle()'s own policy.


@bp.route("/attachments/<int:attachment_id>/view")
@login_required
def attachment_view(attachment_id):
    att = KnowledgeAttachment.query.get_or_404(attachment_id)
    _require_article_read_access(att)
    if not att.is_image or att.scan_status != ScanStatus.CLEAN.value:
        abort(404)
    path = attachment_path(current_app, att.stored_filename)
    try:
        resp = send_file(path, mimetype=att.mime_type, as_attachment=False)
    except FileNotFoundError:
        abort(404)
    resp.headers["Content-Disposition"] = f'inline; filename="{att.stored_filename}"'
    return resp


@bp.route("/attachments/<int:attachment_id>/download")
@login_required
def attachment_download(attachment_id):
    att = KnowledgeAttachment.query.get_or_404(attachment_id)
    _require_article_read_access(att)
    if att.scan_status != ScanStatus.CLEAN.value:
        abort(404)
    path = attachment_path(current_app, att.stored_filename)
    try:
        return send_file(
            path, mimetype=att.mime_type, as_attachment=True,
            download_name=att.original_filename,
        )
    except FileNotFoundError:
        abort(404)


@bp.route("/attachments/<int:attachment_id>/delete", methods=["POST"])
@login_required
def attachment_delete(attachment_id):
    att = KnowledgeAttachment.query.get_or_404(attachment_id)
    if att.article_id is not None:
        if not _can_edit(att.article):
            abort(403)
    else:
        if att.uploaded_by != current_user.id:
            abort(403)

    path = attachment_path(current_app, att.stored_filename)
    log_audit("knowledge_base", "attachment_delete", "attachment", att.id, att.original_filename)
    db.session.delete(att)
    db.session.commit()
    # Only unlink once the row deletion is actually committed — never the
    # other way around, so a failed commit can never leave a "clean" row
    # pointing at a file that no longer exists on disk.
    safe_unlink(path)
    return jsonify({"deleted": True})
