"""A-03: Alerta.ticket has no character restriction and can originate from
admin-uploaded historical CSV import or external alert sources.
csirt/index.html's admin-only delete-ticket confirmation used to interpolate
it directly into an inline onsubmit="confirm('...')" JS string. Proves a
malicious ticket value can no longer break out of that string into
executable code.
"""
from datetime import datetime

from tests.base import PortalTestCase
from app.extensions import db
from app.models.csirt import Alerta

PAYLOAD = "');alert(document.cookie);//"


class TestCsirtIndexTicketXss(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("admin_csirt", is_admin=True)

    def _make_alerta(self, ticket):
        alerta = Alerta(
            ticket=ticket, responsable="Analista", nombre_alerta="Alerta de prueba",
            tipo_alerta="AIA", fecha_realizacion=datetime.now(),
        )
        db.session.add(alerta)
        db.session.commit()
        return alerta

    def test_malicious_ticket_does_not_break_out_of_inline_js(self):
        self._make_alerta(PAYLOAD)
        self.login("admin_csirt")

        resp = self.client.get("/csirt/")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        # See tests/vault/test_group_name_xss.py for why the onsubmit/
        # data-confirm checks (not the raw-payload one) are what actually
        # proves this: Jinja HTML-escapes the quote either way, so the raw
        # payload never appears verbatim regardless of the fix.
        self.assertNotIn(PAYLOAD, body)
        self.assertNotIn('onsubmit="return confirm(', body)
        self.assertIn("data-confirm=", body)
        self.assertIn('name="csrf_token"', body)

    def test_normal_ticket_still_renders(self):
        self._make_alerta("TCK-2026-0001")
        self.login("admin_csirt")

        resp = self.client.get("/csirt/")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("TCK-2026-0001", body)
