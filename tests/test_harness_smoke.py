import unittest


class TestHarnessSmoke(unittest.TestCase):
    def test_portal_test_case_importable(self):
        from tests.base import PortalTestCase  # noqa: F401
