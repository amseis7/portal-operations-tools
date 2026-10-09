import uuid as uuid_mod

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from app.extensions import db
from app.knowledge_base import bp
from app.knowledge_base.attachment_storage import attachment_path, safe_unlink
from app.knowledge_base.forms import KnowledgeArticleForm
from app.knowledge_base.logic import distinct_values, escape_like, sync_tags
from app.models.audit import log_audit
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment, KnowledgeTag
from app.utils import proteger_blueprint

proteger_blueprint(bp, "knowledge_base")


@bp.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()
    client = request.args.get("client", "").strip()
    platform = request.args.get("platform", "").strip()
    tag = request.args.get("tag", "").strip()
    page = request.args.get("page", 1, type=int)

    query = KnowledgeArticle.query

    if q:
        escaped = escape_like(q)
        pattern = f"%{escaped}%"
        query = query.filter(
            db.or_(
                KnowledgeArticle.title.ilike(pattern, escape="\\"),
                KnowledgeArticle.problem_md.ilike(pattern, escape="\\"),
                KnowledgeArticle.solution_md.ilike(pattern, escape="\\"),
            )
        )
    if client:
        query = query.filter(KnowledgeArticle.client == client)
    if platform:
        query = query.filter(KnowledgeArticle.platform == platform)
    if tag:
        query = query.join(KnowledgeArticle.tags).filter(KnowledgeTag.name == tag)

    pagination = query.order_by(KnowledgeArticle.updated_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template(
        "knowledge_base/list.html",
        pagination=pagination,
        articles=pagination.items,
        q=q,
        client=client,
        platform=platform,
        tag=tag,
        clients=distinct_values(KnowledgeArticle.client),
        platforms=distinct_values(KnowledgeArticle.platform),
        tags=KnowledgeTag.query.order_by(KnowledgeTag.name).all(),
    )


@bp.route("/nuevo", methods=["GET", "POST"])
@login_required
def crear():
    form = KnowledgeArticleForm()

    if request.method == "GET":
        draft_token = uuid_mod.uuid4().hex
    else:
        # Preserve exactly what the client submitted — including on a
        # validation failure below, where this same value is re-rendered
        # back into the hidden field. Only falls back to a fresh uuid if
        # the hidden field was somehow stripped (defensive, not the
        # normal path), so a draft is never silently orphaned by a typo
        # in the rest of the form.
        draft_token = request.form.get("draft_token", "").strip() or uuid_mod.uuid4().hex

    if form.validate_on_submit():
        article = KnowledgeArticle(
            title=form.title.data,
            problem_md=form.problem_md.data,
            solution_md=form.solution_md.data,
            client=(form.client.data or "").strip() or None,
            platform=(form.platform.data or "").strip() or None,
            author_id=current_user.id,
        )
        db.session.add(article)
        db.session.flush()
        sync_tags(article, form.tags_raw.data)

        KnowledgeAttachment.query.filter_by(
            draft_token=draft_token, uploaded_by=current_user.id
        ).update({"article_id": article.id, "draft_token": None})

        log_audit("knowledge_base", "create", "article", article.id, article.title)
        db.session.commit()
        flash("Artículo creado.", "success")
        return redirect(url_for("knowledge_base.detalle", id=article.id))

    draft_attachments = KnowledgeAttachment.query.filter_by(
        draft_token=draft_token, uploaded_by=current_user.id
    ).order_by(KnowledgeAttachment.created_at).all()

    return render_template(
        "knowledge_base/form.html",
        form=form,
        heading="Nuevo artículo",
        draft_token=draft_token,
        draft_attachments=draft_attachments,
        article=None,
        clients=distinct_values(KnowledgeArticle.client),
        platforms=distinct_values(KnowledgeArticle.platform),
    )


def _can_edit(article):
    return current_user.is_admin or article.author_id == current_user.id


def _can_delete(article):
    return current_user.is_admin


@bp.route("/<int:id>")
@login_required
def detalle(id):
    article = KnowledgeArticle.query.get_or_404(id)
    return render_template(
        "knowledge_base/detail.html",
        article=article,
        can_edit=_can_edit(article),
        can_delete=_can_delete(article),
    )


@bp.route("/<int:id>/editar", methods=["GET", "POST"])
@login_required
def editar(id):
    article = KnowledgeArticle.query.get_or_404(id)
    if not _can_edit(article):
        abort(403)

    form = KnowledgeArticleForm(obj=article)
    if form.validate_on_submit():
        article.title = form.title.data
        article.problem_md = form.problem_md.data
        article.solution_md = form.solution_md.data
        article.client = (form.client.data or "").strip() or None
        article.platform = (form.platform.data or "").strip() or None
        sync_tags(article, form.tags_raw.data)
        log_audit("knowledge_base", "edit", "article", article.id, article.title)
        db.session.commit()
        flash("Artículo actualizado.", "success")
        return redirect(url_for("knowledge_base.detalle", id=article.id))

    if request.method == "GET":
        form.tags_raw.data = ", ".join(t.name for t in article.tags)

    return render_template(
        "knowledge_base/form.html",
        form=form,
        heading="Editar artículo",
        article=article,
        clients=distinct_values(KnowledgeArticle.client),
        platforms=distinct_values(KnowledgeArticle.platform),
    )


@bp.route("/<int:id>/eliminar", methods=["POST"])
@login_required
def eliminar(id):
    article = KnowledgeArticle.query.get_or_404(id)
    if not _can_delete(article):
        abort(403)

    # Capture the paths before deleting — cascade="all, delete-orphan" only
    # removes the attachment ROWS; it has no idea about the physical files.
    attachment_paths = [
        attachment_path(current_app, att.stored_filename) for att in article.attachments
    ]

    log_audit("knowledge_base", "delete", "article", article.id, article.title)
    db.session.delete(article)
    db.session.commit()

    # Only unlink once the delete is actually committed — never the other
    # way around, so a failed commit can never leave rows (article and its
    # attachments) pointing at files that no longer exist on disk.
    for path in attachment_paths:
        safe_unlink(path)

    flash("Artículo eliminado.", "success")
    return redirect(url_for("knowledge_base.index"))
