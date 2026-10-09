import unittest


class TestRenderMarkdown(unittest.TestCase):
    def test_basic_formatting(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown("**bold** and `code`")
        self.assertIn("<strong>bold</strong>", html)
        self.assertIn("<code>code</code>", html)

    def test_table_and_fenced_code(self):
        from app.knowledge_base.markdown_render import render_markdown

        raw = "| a | b |\n|---|---|\n| 1 | 2 |\n\n```bash\nls -la\n```\n"
        html = render_markdown(raw)
        self.assertIn("<table>", html)
        self.assertIn("<pre>", html)

    def test_strips_script_tag(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown("before <script>alert(1)</script> after")
        # bleach strips the tag itself (what makes it executable); leftover
        # inert text from inside it is a cosmetic non-issue, not XSS.
        self.assertNotIn("<script", html)

    def test_strips_javascript_protocol_link(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown("[click me](javascript:alert(1))")
        self.assertNotIn("javascript:", html)

    def test_strips_event_handler_attribute(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown('<img src="x" onerror="alert(1)">')
        self.assertNotIn("onerror", html)

    def test_empty_input_returns_empty_string(self):
        from app.knowledge_base.markdown_render import render_markdown

        self.assertEqual(render_markdown(""), "")
        self.assertEqual(render_markdown(None), "")

    def test_result_is_markup_safe(self):
        from markupsafe import Markup
        from app.knowledge_base.markdown_render import render_markdown

        self.assertIsInstance(render_markdown("hi"), Markup)
