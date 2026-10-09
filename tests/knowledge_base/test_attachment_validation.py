import io
import unittest
import zipfile

from app.knowledge_base.attachment_validation import validate_upload, AttachmentValidationError


def _make_office_zip(main_content_type: str, ext: str = "docx", include_main_part: bool = True) -> bytes:
    part_name = "word/document.xml" if ext == "docx" else "xl/workbook.xml"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            f'<?xml version="1.0"?><Types><Override PartName="/{part_name}" '
            f'ContentType="{main_content_type}"/></Types>',
        )
        if include_main_part:
            zf.writestr(part_name, "<fake-but-present/>")
    return buf.getvalue()


class TestValidateUpload(unittest.TestCase):
    def test_valid_png(self):
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        result = validate_upload(data, "png")
        self.assertEqual(result.mime_type, "image/png")
        self.assertTrue(result.is_image)
        self.assertEqual(len(result.sha256), 64)

    def test_valid_webp(self):
        data = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"\x00" * 10
        result = validate_upload(data, "webp")
        self.assertEqual(result.mime_type, "image/webp")

    def test_png_extension_with_executable_content_rejected(self):
        data = b"MZ" + b"\x00" * 100  # PE executable header
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "png")

    def test_valid_pdf(self):
        data = b"%PDF-1.7\n" + b"\x00" * 20
        result = validate_upload(data, "pdf")
        self.assertEqual(result.mime_type, "application/pdf")
        self.assertFalse(result.is_image)

    def test_valid_docx(self):
        data = _make_office_zip("application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
        result = validate_upload(data, "docx")
        self.assertEqual(result.extension, "docx")

    def test_valid_xlsx(self):
        data = _make_office_zip(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", ext="xlsx"
        )
        result = validate_upload(data, "xlsx")
        self.assertEqual(result.extension, "xlsx")

    def test_zip_without_real_office_part_is_rejected(self):
        # Forges a plausible [Content_Types].xml but never includes the
        # actual word/document.xml part — an arbitrary ZIP renamed to
        # .docx with a fake manifest, not a real Office container.
        data = _make_office_zip(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            include_main_part=False,
        )
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "docx")

    def test_arbitrary_zip_without_content_types_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("whatever.txt", "not an office document")
        with self.assertRaises(AttachmentValidationError):
            validate_upload(buf.getvalue(), "docx")

    def test_docm_renamed_to_docx_is_rejected(self):
        data = _make_office_zip("application/vnd.ms-word.document.macroEnabled.main+xml")
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "docx")

    def test_valid_xls_ole2(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 20
        result = validate_upload(data, "xls")
        self.assertEqual(result.mime_type, "application/vnd.ms-excel")

    def test_xls_with_vba_project_marker_is_rejected(self):
        # A real macro-enabled legacy .xls stores its VBA project in an
        # OLE2 directory entry conventionally named "Macros"/"VBA", whose
        # name is encoded UTF-16LE in the compound file. Checking for that
        # marker in the raw bytes (no full OLE2 directory parse, no new
        # dependency) catches the common case without extracting anything.
        data = (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 20
            + "VBA".encode("utf-16-le") + b"\x00" * 20
        )
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "xls")

    def test_valid_csv_text(self):
        data = "col1,col2\nval1,val2\n".encode("utf-8")
        result = validate_upload(data, "csv")
        self.assertEqual(result.mime_type, "text/csv")

    def test_csv_with_binary_content_rejected(self):
        data = b"col1,col2\n\x00\x01\x02binary"
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "csv")

    def test_unsupported_extension_rejected(self):
        with self.assertRaises(AttachmentValidationError):
            validate_upload(b"anything", "exe")

    def test_sha256_is_deterministic(self):
        data = b"%PDF-1.7\n" + b"same content"
        r1 = validate_upload(data, "pdf")
        r2 = validate_upload(data, "pdf")
        self.assertEqual(r1.sha256, r2.sha256)

    def test_content_types_decompression_bomb_is_rejected(self):
        # A highly-compressible [Content_Types].xml entry that is still
        # well-formed, valid-looking XML (a huge comment) but declares a
        # huge uncompressed size — a tiny .docx that would decompress to
        # tens of MB and parse "successfully" if read in full. Must be
        # rejected by inspecting the declared size *before* ever
        # reading/decompressing the member, not merely by XML validity.
        part_name = "word/document.xml"
        xml_prefix = (
            '<?xml version="1.0"?><Types><Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><!--'
        )
        padding = b"A" * (20 * 1024 * 1024)
        xml_suffix = b"--></Types>"
        content_types = xml_prefix.encode() + padding + xml_suffix
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types)
            zf.writestr(part_name, "<fake-but-present/>")
        with self.assertRaises(AttachmentValidationError):
            validate_upload(buf.getvalue(), "docx")
