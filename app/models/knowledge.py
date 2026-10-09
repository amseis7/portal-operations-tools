from datetime import datetime
from app.extensions import db


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
    client = db.Column(db.String(120), nullable=True, index=True)
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
