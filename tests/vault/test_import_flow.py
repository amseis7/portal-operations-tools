import glob
import io
import os
import tempfile

from pykeepass import create_database

from tests.base import PortalTestCase
from app.vault.models import VaultEntry  # noqa: F401
from app.vault import import_staging

SYNTHETIC_KDBX_PASSWORD = "Synthetic-KDBX-Pass-1"
SYNTHETIC_ENTRY_TITLE = "Entrada KeePass Sintetica"


def _make_synthetic_kdbx():
    """Build a throwaway .kdbx in the system temp dir (never under
    instance/) with one synthetic entry, and return its raw bytes."""
    fd, path = tempfile.mkstemp(suffix=".kdbx")
    os.close(fd)
    try:
        kp = create_database(path, password=SYNTHETIC_KDBX_PASSWORD)
        kp.add_entry(kp.root_group, SYNTHETIC_ENTRY_TITLE, "svc_kp", "Synthetic-Secret-Value")
        kp.save()
        with open(path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(path):
            os.remove(path)


class TestVaultImportFlow(PortalTestCase):
    def setUp(self):
        super().setUp()
        import_staging._staging.clear()
        self.make_user("admin_user", is_admin=True)
        self.login("admin_user")

    def tearDown(self):
        import_staging._staging.clear()
        super().tearDown()

    def _csrf(self, url="/vault/import"):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def _upload(self):
        token_csrf = self._csrf()
        kdbx_bytes = _make_synthetic_kdbx()
        return self.client.post(
            "/vault/import",
            data={
                "kdbx_file": (io.BytesIO(kdbx_bytes), "test.kdbx"),
                "kdbx_password": SYNTHETIC_KDBX_PASSWORD,
                "csrf_token": token_csrf,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def _staged_import_token(self):
        with self.client.session_transaction() as sess:
            return sess.get("vault_import_token")

    def _instance_files(self, pattern):
        return glob.glob(os.path.join(self.app.instance_path, pattern))

    # 1. upload -> preview -> confirm, full happy path
    def test_full_upload_preview_confirm_flow(self):
        upload_resp = self._upload()
        self.assertEqual(upload_resp.status_code, 200)
        self.assertIn(SYNTHETIC_ENTRY_TITLE.encode(), upload_resp.data)  # preview shows it

        import_token = self._staged_import_token()
        self.assertIsNotNone(import_token)
        staged = import_staging.retrieve(import_token)
        self.assertIsNotNone(staged)
        new_uuid = staged["new"][0]["uuid"]

        confirm_csrf = self.extract_csrf(upload_resp.get_data(as_text=True))
        confirm_resp = self.client.post(
            "/vault/import/confirm",
            data={"csrf_token": confirm_csrf, "import_new": new_uuid},
            follow_redirects=True,
        )

        self.assertEqual(confirm_resp.status_code, 200)
        self.assertIsNotNone(VaultEntry.query.filter_by(title=SYNTHETIC_ENTRY_TITLE).first())
        self.assertIsNone(import_staging.retrieve(import_token))  # discarded after confirm

    # 2. preview without a token in session
    def test_preview_without_token_redirects_to_upload_page(self):
        resp = self.client.get("/vault/import/preview", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.request.path, "/vault/import")

    # 3. preview / confirm with a token that doesn't exist in staging
    def test_preview_with_nonexistent_token_redirects_to_upload_page(self):
        with self.client.session_transaction() as sess:
            sess["vault_import_token"] = "token-that-was-never-staged"

        resp = self.client.get("/vault/import/preview", follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.request.path, "/vault/import")

    def test_confirm_with_nonexistent_token_redirects_to_index(self):
        with self.client.session_transaction() as sess:
            sess["vault_import_token"] = "token-that-was-never-staged"
        csrf = self._csrf()

        resp = self.client.post(
            "/vault/import/confirm", data={"csrf_token": csrf}, follow_redirects=True
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.request.path, "/vault/")

    # 7. no instance/vault_import_*.json file is ever created during the flow
    def test_no_vault_import_json_file_ever_created(self):
        self.assertEqual(self._instance_files("vault_import_*.json"), [])

        upload_resp = self._upload()
        self.assertEqual(self._instance_files("vault_import_*.json"), [])

        import_token = self._staged_import_token()
        staged = import_staging.retrieve(import_token)
        new_uuid = staged["new"][0]["uuid"]
        confirm_csrf = self.extract_csrf(upload_resp.get_data(as_text=True))
        self.client.post(
            "/vault/import/confirm",
            data={"csrf_token": confirm_csrf, "import_new": new_uuid},
            follow_redirects=True,
        )

        self.assertEqual(self._instance_files("vault_import_*.json"), [])

    # 8. abandoning the import leaves no files on disk
    def test_abandoned_import_leaves_no_files_on_disk(self):
        self._upload()  # upload, then never confirm

        self.assertEqual(self._instance_files("vault_import_*.json"), [])
        # the existing upload-temp-file cleanup (kdbx/.keyx) must still work too
        self.assertEqual(self._instance_files("import_*.kdbx"), [])
        self.assertEqual(self._instance_files("import_*.keyx"), [])

        # the data still lives in memory, reachable by the token (until TTL)
        import_token = self._staged_import_token()
        self.assertIsNotNone(import_staging.retrieve(import_token))
