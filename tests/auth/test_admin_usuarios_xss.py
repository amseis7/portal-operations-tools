"""A-03: User.username has no character restriction. admin_usuarios.html's
per-row delete confirmation used to interpolate it directly into an inline
onsubmit="confirm('...')" JS string. Proves the malicious username can no
longer break out of that string into executable code.
"""
from tests.base import PortalTestCase

PAYLOAD = "');alert(document.cookie);//"


class TestAdminUsuariosXss(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("admin_auth", is_admin=True)

    def test_malicious_username_does_not_break_out_of_inline_js(self):
        target = self.make_user(PAYLOAD, tools=["csirt"])
        self.login("admin_auth")

        resp = self.client.get("/auth/admin/usuarios")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        # See tests/vault/test_group_name_xss.py for why the onsubmit/
        # data-confirm checks (not the raw-payload one) are what actually
        # proves this: Jinja HTML-escapes the quote either way, so the raw
        # payload never appears verbatim regardless of the fix.
        self.assertNotIn(PAYLOAD, body)
        self.assertNotIn('onsubmit="return confirm(', body)
        self.assertIn("data-confirm=", body)
        self.assertIn(f'action="/auth/admin/usuarios/eliminar/{target.id}"', body)
        self.assertIn('name="csrf_token"', body)

    def test_normal_username_still_renders(self):
        target = self.make_user("ana.perez", tools=["csirt"])
        self.login("admin_auth")

        resp = self.client.get("/auth/admin/usuarios")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("ana.perez", body)
        self.assertIn(f'action="/auth/admin/usuarios/eliminar/{target.id}"', body)
