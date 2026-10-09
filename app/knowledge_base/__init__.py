from flask import Blueprint

bp = Blueprint("knowledge_base", __name__)

from app.knowledge_base import routes  # noqa: E402,F401
from app.knowledge_base import attachment_routes  # noqa: E402,F401
from app.knowledge_base.markdown_render import render_markdown


@bp.app_template_filter("markdown")
def markdown_filter(raw_text):
    return render_markdown(raw_text)
