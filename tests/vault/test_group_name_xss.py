"""A-03: a non-admin user can name their own personal Vault group anything
(no character restriction). An admin browsing /vault/ sees every owner's
personal tree (_personal_group_trees()), including the delete-confirmation
form for each group. This proves a malicious group name can no longer break
out of the inline onsubmit="confirm('...')" JS string into executable code.
"""
from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultGroup

PAYLOAD = "');alert(document.cookie);//"


class TestVaultGroupNameXss(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("owner_vault", tools=["vault"])
        self.admin = self.make_user("admin_vault", is_admin=True)

    def _make_personal_group(self, name):
        group = VaultGroup(name=name, scope="personal", owner_id=self.owner.id)
        db.session.add(group)
        db.session.commit()
        return group

    def test_malicious_group_name_does_not_break_out_of_inline_js(self):
        self._make_personal_group(PAYLOAD)
        self.login("admin_vault")

        resp = self.client.get("/vault/")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        # Jinja HTML-escapes the quote either way (old or new template), so
        # the raw payload substring never appears verbatim in the response
        # body regardless of the fix — that check alone would prove nothing
        # (verified: it still passes against the pre-fix template). The real
        # proof is structural: the value must never land inside an
        # onsubmit=/onclick= attribute (a JS-execution context, where the
        # browser's HTML-entity-decoding of that same escaped quote hands a
        # real `'` to the JS engine, closing the string early) — only inside
        # data-confirm= (read as inert text via .dataset, never evaluated).
        self.assertNotIn(PAYLOAD, body)
        self.assertNotIn('onsubmit="return confirm(', body)
        self.assertIn("data-confirm=", body)

    def test_normal_group_name_still_renders_and_deletes_correctly(self):
        group = self._make_personal_group("Servidores de Producción")
        self.login("admin_vault")

        resp = self.client.get("/vault/")
        body = resp.get_data(as_text=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("Servidores de Producción", body)
        # CSRF token and the real delete action are both still present.
        self.assertIn(f'action="/vault/grupos/{group.id}/eliminar"', body)
        self.assertIn('name="csrf_token"', body)
