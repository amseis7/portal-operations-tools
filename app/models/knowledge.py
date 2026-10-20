from datetime import datetime
from app.extensions import db


def visible_attachments(attachments):
    """Single source of truth for which attachments the "Adjuntos" UI
    shows — excludes kind="inline" rows (pasted into Markdown, served
    only via /view). Used by KnowledgeArticle.visible_attachments AND
    directly on draft_attachments lists (which have no article yet to
    hang a property off of), so both paths share one filter instead of
    duplicating the same condition in templates."""
    return [a for a in attachments if a.kind == "attachment"]


knowledge_article_tag = db.Table(
    "knowledge_article_tag",
    db.Column(
        "article_id",
        db.Integer,
        db.ForeignKey("knowledge_article.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "tag_id",
        db.Integer,
        db.ForeignKey("knowledge_tag.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class KnowledgeArticle(db.Model):
    __tablename__ = "knowledge_article"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    problem_md = db.Column(db.Text, nullable=False)
    solution_md = db.Column(db.Text, nullable=False)
    # "platform" is the persisted column name (unchanged since the original
    # KB migration) but is now the brand/"marca" the index grid groups by —
    # client-identifying data was removed entirely (product decision, see
    # docs/technical-debt/current.md debt #37 and the migration that dropped
    # `client`). Do not reintroduce a separate "cliente"/client concept here.
    platform = db.Column(db.String(120), nullable=True, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    author = db.relationship(
        "User", backref=db.backref("knowledge_articles", lazy="dynamic")
    )
    tags = db.relationship(
        "KnowledgeTag", secondary=knowledge_article_tag, back_populates="articles"
    )
    attachments = db.relationship(
        "KnowledgeAttachment", back_populates="article",
        cascade="all, delete-orphan", order_by="KnowledgeAttachment.created_at",
    )

    @property
    def visible_attachments(self):
        """Single source of truth for the "Adjuntos" UI filter. Deliberately
        NOT a replacement for `attachments` — eliminar() (routes.py) still
        needs the full, unfiltered relationship to clean up every physical
        file (including inline ones) when the article itself is deleted."""
        return visible_attachments(self.attachments)

    def __repr__(self):
        return f"<KnowledgeArticle {self.id}: {self.title}>"


class KnowledgeAttachment(db.Model):
    __tablename__ = "knowledge_attachment"
    __table_args__ = (
        db.CheckConstraint(
            "(article_id IS NOT NULL AND draft_token IS NULL) "
            "OR (article_id IS NULL AND draft_token IS NOT NULL)",
            name="ck_knowledge_attachment_exactly_one_owner",
        ),
        db.CheckConstraint(
            "kind IN ('attachment', 'inline')",
            name="ck_knowledge_attachment_kind",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(
        db.Integer, db.ForeignKey("knowledge_article.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    draft_token = db.Column(db.String(36), nullable=True, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(64), nullable=False, unique=True)
    mime_type = db.Column(db.String(100), nullable=False)
    extension = db.Column(db.String(10), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    is_image = db.Column(db.Boolean, default=False, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    scan_status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    scan_checked_at = db.Column(db.DateTime, nullable=True)
    # "attachment" (file-picker, shown in the "Adjuntos" list, downloadable)
    # vs "inline" (pasted into Markdown, served only via /view, never listed
    # as an Adjunto). UX intent captured at upload time — not inferred from
    # is_image or from Markdown content, which are different concerns.
    kind = db.Column(db.String(20), default="attachment", server_default="attachment", nullable=False)

    article = db.relationship("KnowledgeArticle", back_populates="attachments")
    uploader = db.relationship("User", backref=db.backref("knowledge_attachments", lazy="dynamic"))

    def __repr__(self):
        return f"<KnowledgeAttachment {self.id}: {self.original_filename}>"


class KnowledgeTag(db.Model):
    __tablename__ = "knowledge_tag"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)

    articles = db.relationship(
        "KnowledgeArticle", secondary=knowledge_article_tag, back_populates="tags"
    )

    def __repr__(self):
        return f"<KnowledgeTag {self.name}>"
