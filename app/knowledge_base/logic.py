from app.extensions import db
from app.models.knowledge import KnowledgeTag


def sync_tags(article, tags_raw):
    """Replace article.tags with the normalized set parsed from tags_raw.
    Same 'replace the whole collection' approach as Vault's
    _save_custom_fields() — simplest correct option for a small per-article
    tag set."""
    names = sorted({t.strip().lower() for t in (tags_raw or "").split(",") if t.strip()})
    tags = []
    for name in names:
        tag = KnowledgeTag.query.filter_by(name=name).first()
        if tag is None:
            tag = KnowledgeTag(name=name)
            db.session.add(tag)
            db.session.flush()
        tags.append(tag)
    article.tags = tags


def escape_like(term):
    """Escape a user search term for safe use inside ilike(..., escape='\\')."""
    return term.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


def distinct_values(column):
    """Return sorted non-empty distinct values of a mapped column, for
    populating filter/autocomplete options without a master table."""
    rows = (
        db.session.query(column)
        .filter(column.isnot(None))
        .filter(column != "")
        .distinct()
        .order_by(column)
        .all()
    )
    return [row[0] for row in rows]
