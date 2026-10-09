import re

import bleach
import markdown as _markdown
from markupsafe import Markup

# This is the ONLY function allowed to turn user-authored Markdown into
# HTML in this module. Never call markdown.markdown()/`|safe` directly from
# a template or route — always go through render_markdown(), which both
# converts and sanitizes before returning Markup.

_ALLOWED_TAGS = [
    "p", "br", "hr",
    "strong", "em", "b", "i", "u", "s", "del",
    "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "code", "pre", "span",
    "img",
]

_ALLOWED_PROTOCOLS = ["http", "https", "mailto"]

# bleach's tag/attribute allowlist does not restrict what an allowed
# attribute's VALUE may be — it only decides which tags/attributes survive
# at all. An <img> tag is otherwise allowed, so without this value-level
# check an attacker could smuggle <img src="https://evil/track.gif">
# (external tracking/exfiltration — a separate concern from the
# javascript: protocol, which _ALLOWED_PROTOCOLS already blocks). Only an
# exact match is accepted — not a prefix check — so a path-traversal-style
# suffix after a valid-looking prefix (e.g.
# "/kb/attachments/5/view/../../evil") cannot slip through.
_ALLOWED_IMG_SRC = re.compile(r"^/kb/attachments/\d+/view\Z")


def _allow_img_attribute(tag, name, value):
    if name == "alt":
        return True
    if name == "src":
        return bool(_ALLOWED_IMG_SRC.match(value))
    return False


_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "code": ["class"],
    "th": ["align"],
    "td": ["align"],
    "img": _allow_img_attribute,
}


def render_markdown(raw_text):
    if not raw_text:
        return Markup("")

    html = _markdown.markdown(
        raw_text,
        extensions=["tables", "fenced_code", "nl2br"],
        output_format="html5",
    )

    clean_html = bleach.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
    )

    return Markup(clean_html)
