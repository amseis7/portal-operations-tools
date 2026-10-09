import unittest
from tests.base import TestConfig


class TestAttachmentConfig(unittest.TestCase):
    def test_defaults_present(self):
        self.assertTrue(TestConfig.KB_ATTACHMENTS_DIR.endswith("kb_attachments"))
        self.assertEqual(TestConfig.KB_ATTACHMENT_MAX_SIZE_BYTES, 10 * 1024 * 1024)
        self.assertEqual(TestConfig.KB_ATTACHMENT_MAX_TOTAL_BYTES, 50 * 1024 * 1024)
        self.assertEqual(
            TestConfig.KB_ATTACHMENT_ALLOWED_EXTENSIONS,
            {"png", "jpg", "jpeg", "webp", "pdf", "docx", "xlsx", "xls", "csv", "txt"},
        )
        self.assertEqual(TestConfig.KB_ATTACHMENT_IMAGE_EXTENSIONS, {"png", "jpg", "jpeg", "webp"})
        self.assertEqual(TestConfig.KB_ATTACHMENT_DRAFT_TTL_HOURS, 24)
        self.assertEqual(TestConfig.KB_SCANNER, "null")
