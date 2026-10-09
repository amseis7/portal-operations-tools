from datetime import datetime, timedelta

from app.knowledge_base.attachment_storage import attachment_path, safe_unlink


def purge_expired_drafts(app) -> int:
    from app.extensions import db
    from app.models.knowledge import KnowledgeAttachment

    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(hours=app.config["KB_ATTACHMENT_DRAFT_TTL_HOURS"])
        expired = KnowledgeAttachment.query.filter(
            KnowledgeAttachment.article_id.is_(None),
            KnowledgeAttachment.draft_token.isnot(None),
            KnowledgeAttachment.created_at < cutoff,
        ).all()

        deleted = 0
        for att in expired:
            att_id = att.id
            stored_filename = att.stored_filename

            # Atomic conditional delete: one DELETE ... WHERE article_id IS
            # NULL. The database engine — not a refresh()-then-check in
            # application code — provides the atomicity between "is this
            # still an unpromoted draft?" and "delete it", so there is no
            # window for a concurrent promotion (crear()'s bulk UPDATE in
            # routes.py) to land between a check and an act. If a second,
            # concurrent/duplicate purge run already removed this same row
            # (or crear() already promoted it), this matches zero rows and
            # raises nothing — no ObjectDeletedError, just rowcount == 0.
            rowcount = db.session.query(KnowledgeAttachment).filter(
                KnowledgeAttachment.id == att_id,
                KnowledgeAttachment.article_id.is_(None),
            ).delete(synchronize_session=False)
            db.session.commit()

            if rowcount:
                # Only unlink the file once the row deletion is actually
                # committed — never the other way around, so a failed/rolled
                # back delete can never leave a "clean" row pointing at a
                # file that no longer exists on disk.
                safe_unlink(attachment_path(app, stored_filename))
                deleted += 1

        return deleted
