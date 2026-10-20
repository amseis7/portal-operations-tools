"""A-03: ExportTemplate.nombre_plataforma (admin-authored) used to be
interpolated directly into an inline onsubmit="confirm('...')" JS string in
admin_templates.html. Proves a malicious template name can no longer break
out of that string into executable code.
"""
from tests.base import PortalTestCase
from app.extensions import db
from app.models.virustotal import ExportTemplate

PAYLOAD = "');alert(document.cookie);//"


class TestAdminTemplatesXss(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("admin_vt", is_admin=True)

    def _make_template(self, nombre):
        t = ExportTemplate(
            nombre_plataforma=nombre, vt_engine_name="EngineX",
            row_template="{valor}", file_extension="csv",
        )
        db.session.add(t)
        db.session.commit()
        return t

    def test_malicious_template_name_does_not_break_out_of_inline_js(self):
        t = self._make_template(PAYLOAD)
        self.login("admin_vt")

        resp = self.client.get("/virustotal/admin/templates")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        # See tests/vault/test_group_name_xss.py for why the onsubmit/
        # data-confirm checks (not the raw-payload one) are what actually
        # proves this: Jinja HTML-escapes the quote either way, so the raw
        # payload never appears verbatim regardless of the fix.
        self.assertNotIn(PAYLOAD, body)
        self.assertNotIn('onsubmit="return confirm(', body)
        self.assertIn("data-confirm=", body)
        self.assertIn(f'action="/virustotal/admin/templates/eliminar/{t.id}"', body)
        self.assertIn('name="csrf_token"', body)

    def test_normal_template_name_still_renders(self):
        t = self._make_template("Plataforma Estándar")
        self.login("admin_vt")

        resp = self.client.get("/virustotal/admin/templates")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("Plataforma Estándar", body)
        self.assertIn(f'action="/virustotal/admin/templates/eliminar/{t.id}"', body)
