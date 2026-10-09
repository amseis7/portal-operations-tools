import unittest


class TestNewDependencies(unittest.TestCase):
    def test_markdown_importable(self):
        import markdown  # noqa: F401

    def test_bleach_importable(self):
        import bleach  # noqa: F401
