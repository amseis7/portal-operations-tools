"""A-02: ExportTemplate.row_template used to be validated with a naive
regex (`\\{(\\w+)\\}`) that only recognized simple placeholders — it let
`{valor.__class__}` / `{valor[0]}` / etc. straight through, even though
`str.format(**variables)` (the render/export path, logic.py) DOES interpret
those as real attribute/item access. The historical claim that this let an
admin exfiltrate SECRET_KEY was investigated and could not be reproduced:
the values given to .format() are plain str/int, and str.format()'s mini
language cannot call methods — but the validator bypass itself was real,
and this is what it actually protects against now.

No real network call to VirusTotal anywhere in this file.
"""
from unittest.mock import Mock, patch

from tests.base import PortalTestCase
from app.extensions import db
from app.models.virustotal import ExportTemplate, VtIoc, VtTicket
from app.virustotal.logic import (
    validate_export_row_template,
    generar_exportacion_multiformato,
    TemplateValidationError,
    VARIABLES_PERMITIDAS,
)


class TestValidateExportRowTemplateUnit(PortalTestCase):
    """Pure unit tests of the canonical validator — no HTTP, no DB rows
    needed beyond what PortalTestCase already sets up."""

    # 1. every legitimate placeholder, individually
    def test_each_allowed_placeholder_is_accepted(self):
        for name in VARIABLES_PERMITIDAS:
            validate_export_row_template("{" + name + "}")  # must not raise

    # 2. multiple legitimate placeholders together
    def test_multiple_allowed_placeholders_accepted(self):
        validate_export_row_template("{tipo_real},{valor},{filename} - {ticket}")

    # 3. escaped braces preserved / not treated as a field
    def test_escaped_braces_are_not_treated_as_fields(self):
        validate_export_row_template("{{literal brace}} {valor} }}")

    # 4. unknown placeholder rejected
    def test_unknown_placeholder_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{desconocido}")

    # 5. attribute traversal rejected
    def test_attribute_traversal_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{valor.__class__}")

    # 6. chained attribute traversal rejected
    def test_chained_attribute_traversal_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{valor.__class__.__mro__}")

    # 7. item/index access rejected
    def test_item_index_access_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{valor[0]}")

    # 8. string-key access rejected
    def test_string_key_access_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{valor[key]}")

    # 9. conversion rejected (not a current functional requirement)
    def test_conversion_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{valor!r}")

    # 10. format spec rejected (not a current functional requirement)
    def test_format_spec_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{valor:>20}")

    # 11. nested replacement field inside a format spec rejected
    def test_nested_replacement_field_in_format_spec_is_rejected(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("{valor:{ticket}}")

    # 12. malformed brace syntax -> controlled error, never a raw parser crash
    def test_malformed_brace_syntax_raises_controlled_error(self):
        with self.assertRaises(TemplateValidationError):
            validate_export_row_template("texto con llave suelta {")

    # Error messages must not echo a huge payload verbatim.
    def test_error_message_bounds_long_field_name(self):
        huge = "A" * 5000
        try:
            validate_export_row_template("{" + huge + "}")
            self.fail("expected TemplateValidationError")
        except TemplateValidationError as exc:
            self.assertLess(len(str(exc)), 200)


class TestTemplateCreateEditValidation(PortalTestCase):
    """13/14: create and edit routes refuse to persist an invalid template."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_user("admin_vt_tpl", is_admin=True)
        self.login("admin_vt_tpl")

    def _csrf(self, url="/virustotal/admin/templates"):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def test_create_route_does_not_persist_invalid_template(self):
        token = self._csrf()
        self.client.post(
            "/virustotal/admin/templates",
            data={
                "nombre": "Plataforma Maliciosa",
                "vt_engine": "EngineX",
                "extension": "csv",
                "row_template": "{valor.__class__}",
                "supported_hashes": "md5,sha1,sha256",
                "csrf_token": token,
            },
        )

        self.assertIsNone(
            ExportTemplate.query.filter_by(nombre_plataforma="Plataforma Maliciosa").first()
        )

    def test_create_route_still_persists_valid_template(self):
        token = self._csrf()
        self.client.post(
            "/virustotal/admin/templates",
            data={
                "nombre": "Plataforma Válida",
                "vt_engine": "EngineX",
                "extension": "csv",
                "row_template": "{valor},{ticket}",
                "supported_hashes": "md5,sha1,sha256",
                "csrf_token": token,
            },
        )

        self.assertIsNotNone(
            ExportTemplate.query.filter_by(nombre_plataforma="Plataforma Válida").first()
        )

    def test_edit_route_does_not_persist_invalid_template(self):
        original = ExportTemplate(
            nombre_plataforma="Original", vt_engine_name="EngineX",
            row_template="{valor}", file_extension="csv",
        )
        db.session.add(original)
        db.session.commit()
        original_id = original.id

        token = self._csrf()
        self.client.post(
            f"/virustotal/admin/templates/editar/{original_id}",
            data={
                "nombre": "Original",
                "vt_engine": "EngineX",
                "extension": "csv",
                "row_template": "{valor[0]}",
                "supported_hashes": "md5,sha1,sha256",
                "csrf_token": token,
            },
        )

        reloaded = db.session.get(ExportTemplate, original_id)
        self.assertEqual(reloaded.row_template, "{valor}")  # unchanged


class TestLegacyTemplateExportSafety(PortalTestCase):
    """15: a row_template inserted directly into the DB (bypassing the
    form entirely — simulating one saved before this fix existed) must
    fail safely at export time, never executing attribute/item traversal.
    16: a normal template still produces exactly the expected output."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_user("admin_vt_export", is_admin=True)
        self.ticket = VtTicket(nombre="Caso de prueba", usuario_id=self.admin.id)
        db.session.add(self.ticket)
        db.session.flush()

        self.ioc = VtIoc(
            ticket_id=self.ticket.id, tipo="hash", valor="a" * 64,
            vt_sha256="a" * 64, vt_positives=0, vt_total=70,
        )
        self.ioc.set_motores({"EngineX": "clean", "filename": "archivo.exe"})
        db.session.add(self.ioc)
        db.session.commit()

    def _make_template(self, row_template, nombre="Legacy"):
        t = ExportTemplate(
            nombre_plataforma=nombre, vt_engine_name="EngineX",
            row_template=row_template, file_extension="csv",
        )
        db.session.add(t)
        db.session.commit()
        return t

    def test_legacy_invalid_template_is_skipped_without_traversal(self):
        bad = self._make_template("{valor.__class__.__mro__}", nombre="Legacy Malicioso")

        # If this ever executed real attribute traversal, .format() would
        # succeed and str(type) would appear in the zip; it must not.
        zip_buffer = generar_exportacion_multiformato(self.ticket.id, [bad.id], origen="caso")

        import zipfile
        with zipfile.ZipFile(zip_buffer) as zf:
            self.assertEqual(zf.namelist(), [])  # no file emitted for the unsafe template

    def test_legacy_valid_template_mixed_with_invalid_still_exports(self):
        bad = self._make_template("{valor[0]}", nombre="Legacy Malicioso")
        good = self._make_template("{tipo_real},{valor},{filename}", nombre="Legacy Válido")

        zip_buffer = generar_exportacion_multiformato(self.ticket.id, [bad.id, good.id], origen="caso")

        import zipfile
        with zipfile.ZipFile(zip_buffer) as zf:
            names = zf.namelist()
            self.assertEqual(len(names), 1)
            content = zf.read(names[0]).decode("utf-8")
            self.assertIn("a" * 64, content)
            self.assertIn("archivo.exe", content)
            self.assertNotIn("__class__", content)

    def test_normal_template_produces_exact_expected_row(self):
        good = self._make_template("{tipo_real},{valor},{filename}", nombre="Normal")

        zip_buffer = generar_exportacion_multiformato(self.ticket.id, [good.id], origen="caso")

        import zipfile
        with zipfile.ZipFile(zip_buffer) as zf:
            names = zf.namelist()
            self.assertEqual(len(names), 1)
            content = zf.read(names[0]).decode("utf-8")
            self.assertIn(f"sha256,{'a' * 64},archivo.exe", content)
