"""Technical debt #6: Vault Sync Password Rendered Back to UI.

sync_settings() used to decrypt the stored KeePass master password and
render it into the GET form's `value="..."` attribute — a real plaintext
secret exposure to the browser DOM/devtools/screen capture, for a value
that unlocks the entire shared .kdbx file.

The fix follows the same pattern already used by Umbrella's
editar_cliente() (app/umbrella/routes.py): the password field is never
pre-filled with the decrypted secret.

    GET:  password field always renders blank, regardless of whether a
          password is already configured.
    POST: blank password field => preserve the existing encrypted
          password unchanged.
          non-blank password field => replace the stored secret.

This also fixes a real (if latent) data-loss bug the exposure was
papering over: before this fix, a blank submission did not mean "leave
it as-is" at all — it set kdbx_password_enc to None, silently wiping the
configured password on any edit where the admin didn't retype it
(contradicting the form's own placeholder text, "Dejar en blanco para no
cambiarla").
"""
from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultSyncConfig  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt, decrypt


class TestSyncSettingsPasswordExposure(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("syncsettings_admin", is_admin=True)
        self.login("syncsettings_admin")

    def _csrf(self):
        page = self.client.get("/vault/configuracion")
        return self.extract_csrf(page.get_data(as_text=True))

    def _existing_cfg(self, password="Synthetic-KDBX-Master-Pass-1", path="\\\\server\\share\\vault.kdbx"):
        cfg = VaultSyncConfig(kdbx_path=path, kdbx_password_enc=encrypt(password))
        db.session.add(cfg)
        db.session.commit()
        return cfg

    def _post(self, path, password, keyfile_path=""):
        return self.client.post(
            "/vault/configuracion",
            data={
                "kdbx_path": path,
                "kdbx_password": password,
                "kdbx_keyfile_path": keyfile_path,
                "csrf_token": self._csrf(),
            },
            follow_redirects=False,
        )

    # -- GET must never expose the plaintext secret -------------------------

    def test_get_does_not_render_plaintext_password_when_configured(self):
        self._existing_cfg(password="Synthetic-Secret-Must-Not-Leak-1")

        resp = self.client.get("/vault/configuracion")

        self.assertNotIn(b"Synthetic-Secret-Must-Not-Leak-1", resp.data)

    def test_get_password_field_renders_with_no_value_attribute(self):
        self._existing_cfg(password="Synthetic-Secret-Must-Not-Leak-2")

        resp = self.client.get("/vault/configuracion")
        html = resp.get_data(as_text=True)

        self.assertIn('name="kdbx_password"', html)
        # No value="..." at all on this field, regardless of content —
        # mirrors Umbrella's client_secret field (app/umbrella/routes.py).
        self.assertNotRegex(html, r'name="kdbx_password"[^>]*value=')

    # -- POST: blank password preserves the existing secret -----------------

    def test_blank_password_on_edit_preserves_existing_secret(self):
        cfg = self._existing_cfg(password="Synthetic-Secret-Preserve-Me-1")

        resp = self._post("\\\\server\\share\\new-path.kdbx", password="")

        self.assertEqual(resp.status_code, 302)
        db.session.refresh(cfg)
        self.assertEqual(cfg.kdbx_path, "\\\\server\\share\\new-path.kdbx")
        self.assertEqual(decrypt(cfg.kdbx_password_enc), "Synthetic-Secret-Preserve-Me-1")

    def test_non_blank_password_on_edit_replaces_existing_secret(self):
        cfg = self._existing_cfg(password="Synthetic-Secret-Old-1")

        resp = self._post(cfg.kdbx_path, password="Synthetic-Secret-New-1")

        self.assertEqual(resp.status_code, 302)
        db.session.refresh(cfg)
        self.assertEqual(decrypt(cfg.kdbx_password_enc), "Synthetic-Secret-New-1")

    # -- validation: at least one of password/keyfile must end up configured

    def test_first_time_setup_blank_password_and_no_keyfile_is_rejected(self):
        resp = self._post("\\\\server\\share\\first-setup.kdbx", password="")

        self.assertEqual(resp.status_code, 302)
        self.assertIsNone(VaultSyncConfig.query.first())

    def test_blank_password_with_keyfile_only_is_accepted_on_first_setup(self):
        resp = self._post(
            "\\\\server\\share\\keyfile-only.kdbx", password="", keyfile_path="C:\\keys\\vault.keyx"
        )

        self.assertEqual(resp.status_code, 302)
        cfg = VaultSyncConfig.query.first()
        self.assertIsNotNone(cfg)
        self.assertIsNone(cfg.kdbx_password_enc)
        self.assertEqual(cfg.kdbx_keyfile_path, "C:\\keys\\vault.keyx")

    def test_blank_password_and_blank_keyfile_still_valid_when_password_already_configured(self):
        """Editing only the path, with an already-configured password and
        no keyfile, must not be rejected by the "at least one" validation
        — the existing password still counts, it's just not being
        replaced."""
        self._existing_cfg(password="Synthetic-Secret-Still-Counts-1")

        resp = self._post("\\\\server\\share\\path-only-edit.kdbx", password="", keyfile_path="")

        self.assertEqual(resp.status_code, 302)
