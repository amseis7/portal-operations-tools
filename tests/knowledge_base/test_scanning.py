import unittest
from app.knowledge_base.scanning import ScanStatus, NullScanner


class TestNullScanner(unittest.TestCase):
    def test_null_scanner_never_returns_clean(self):
        result = NullScanner().scan_file("/any/path")
        self.assertEqual(result.status, ScanStatus.NOT_SCANNED)
        self.assertNotEqual(result.status, ScanStatus.CLEAN)


from tests.base import PortalTestCase
from app.knowledge_base.scanning import get_scanner, NullScanner


class TestGetScanner(PortalTestCase):
    def test_default_config_returns_null_scanner(self):
        self.assertIsInstance(get_scanner(), NullScanner)

    def test_unknown_scanner_name_falls_back_to_null(self):
        self.app.config["KB_SCANNER"] = "something-not-registered"
        self.assertIsInstance(get_scanner(), NullScanner)
        self.app.config["KB_SCANNER"] = "null"  # restore
