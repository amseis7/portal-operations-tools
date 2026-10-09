import unittest
from app.knowledge_base.markdown_render import render_markdown


class TestMarkdownImgAllowlist(unittest.TestCase):
    def test_internal_attachment_image_renders(self):
        html = render_markdown("![captura](/kb/attachments/5/view)")
        self.assertIn('<img', html)
        self.assertIn('/kb/attachments/5/view', html)

    def test_external_image_src_is_stripped(self):
        html = render_markdown("![tracker](https://evil.example/track.gif)")
        self.assertNotIn("evil.example", html)

    def test_javascript_protocol_image_src_is_stripped(self):
        html = render_markdown('<img src="javascript:alert(1)">')
        self.assertNotIn("javascript:", html)

    def test_relative_path_outside_attachments_is_stripped(self):
        html = render_markdown('<img src="/static/js/app.js">')
        self.assertNotIn("/static/js/app.js", html)

    def test_attachment_src_with_extra_path_segments_is_stripped(self):
        # Must match exactly /kb/attachments/<id>/view, not merely start
        # with /kb/attachments/ — otherwise /kb/attachments/5/view/../../evil
        # or similar would slip through a naive prefix check.
        html = render_markdown('<img src="/kb/attachments/5/view/../../evil">')
        self.assertNotIn("evil", html)

    def test_attachment_src_with_trailing_newline_is_stripped(self):
        # re.match(..., "$") matches immediately before a trailing newline
        # at the end of the string (even without re.MULTILINE) — a true
        # exact-match anchor needs \Z, not $, or "<path>\n" would pass.
        html = render_markdown('<img src="/kb/attachments/5/view\n">')
        self.assertNotIn("src=", html)
