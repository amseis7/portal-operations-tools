"""A-10: umbrella.ejecutar() is the only route that performs a real external
mutation (Cisco Umbrella PATCH). This covers the admin-only gate and the
duplicate-submission guard added to close it — never making a real network
call: the background launcher is mocked at its call site in routes.py, so
no thread/PATCH ever actually runs.
"""
import io
import threading
from unittest.mock import patch

import openpyxl

from tests.base import PortalTestCase
from app.extensions import db
from app.models.umbrella import UmbrellaCliente, UmbrellaHerramienta, UmbrellaJob


def _make_xlsx_bytes(app_names):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["App"])
    for name in app_names:
        ws.append([name])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()


class TestEjecutarAuthorizationAndDuplicateGuard(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("admin_umb", is_admin=True)
        self.normal_user = self.make_user("user_umb", tools=["umbrella"])

    def _create_cliente_y_herramienta(self, nombre="Cliente Test", slug_hint="tool"):
        cliente = UmbrellaCliente(nombre=nombre, created_by=self.admin.id)
        cliente.set_credentials("synthetic-client-id", "synthetic-client-secret")
        db.session.add(cliente)
        db.session.flush()

        herramienta = UmbrellaHerramienta(
            cliente_id=cliente.id, tipo="app_discovery", nombre=f"App Discovery — {nombre}",
            slug="__tmp__",
        )
        db.session.add(herramienta)
        db.session.flush()
        herramienta.generate_slug()
        db.session.commit()
        return cliente, herramienta

    def _ejecutar_url(self, herramienta):
        from flask import url_for
        with self.app.test_request_context():
            return url_for("umbrella.ejecutar", herramienta_slug=herramienta.slug)

    def _ver_herramienta_url(self, herramienta):
        from flask import url_for
        with self.app.test_request_context():
            return url_for("umbrella.ver_herramienta", herramienta_slug=herramienta.slug)

    def _post_ejecutar(self, herramienta, csrf_token=None, app_names=("App Uno", "App Dos")):
        if csrf_token is None:
            page = self.client.get(self._ver_herramienta_url(herramienta))
            csrf_token = self.extract_csrf(page.get_data(as_text=True))
        data = {
            "excel_file": (io.BytesIO(_make_xlsx_bytes(app_names)), "apps.xlsx"),
            "label_name": "notApproved",
            "column_name": "App",
            "csrf_token": csrf_token,
        }
        return self.client.post(
            self._ejecutar_url(herramienta), data=data, content_type="multipart/form-data"
        )

    # 1. anonymous cannot execute
    def test_anonymous_user_cannot_execute(self):
        _, herramienta = self._create_cliente_y_herramienta()

        # CSRF validation (global) runs before proteger_blueprint's
        # login_required check — a real token is needed here to actually
        # exercise the authentication boundary rather than just tripping
        # CSRF first.
        login_page = self.client.get("/auth/login")
        csrf_token = self.extract_csrf(login_page.get_data(as_text=True))

        with patch("app.umbrella.routes.lanzar_job_background") as mock_launch:
            resp = self._post_ejecutar(herramienta, csrf_token=csrf_token)

        self.assertEqual(resp.status_code, 302)
        self.assertIn("/auth/login", resp.headers.get("Location", ""))
        mock_launch.assert_not_called()
        self.assertEqual(UmbrellaJob.query.count(), 0)

    # 2. authenticated, umbrella tool, NOT admin -> 403
    def test_non_admin_with_tool_gets_403(self):
        self.login("user_umb")
        _, herramienta = self._create_cliente_y_herramienta()

        with patch("app.umbrella.routes.lanzar_job_background") as mock_launch:
            resp = self._post_ejecutar(herramienta)

        self.assertEqual(resp.status_code, 403)
        mock_launch.assert_not_called()
        self.assertEqual(UmbrellaJob.query.count(), 0)

    # 3 & 4. admin reaches the flow and creates exactly one job
    def test_admin_creates_exactly_one_job(self):
        self.login("admin_umb")
        _, herramienta = self._create_cliente_y_herramienta()

        with patch("app.umbrella.routes.lanzar_job_background") as mock_launch:
            resp = self._post_ejecutar(herramienta)

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(UmbrellaJob.query.filter_by(herramienta_id=herramienta.id).count(), 1)
        mock_launch.assert_called_once()
        job = UmbrellaJob.query.filter_by(herramienta_id=herramienta.id).first()
        self.assertEqual(job.status, "running")
        self.assertEqual(job.usuario_id, self.admin.id)

    # 5, 6, 7. second equivalent POST while the first is active: no second
    # job, no second worker, correct flash/redirect.
    def test_second_submit_while_active_does_not_create_second_job_or_worker(self):
        self.login("admin_umb")
        _, herramienta = self._create_cliente_y_herramienta()

        with patch("app.umbrella.routes.lanzar_job_background") as mock_launch:
            first = self._post_ejecutar(herramienta)
            second = self._post_ejecutar(herramienta)

        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(UmbrellaJob.query.filter_by(herramienta_id=herramienta.id).count(), 1)
        mock_launch.assert_called_once()  # not called a second time

        # Message/redirect: follow the second response and check the flash.
        follow = self.client.get(second.headers["Location"])
        self.assertIn("Ya existe una ejecución en curso".encode("utf-8"), follow.data)

    # 8. a finished job does not block a new legitimate execution
    def test_completed_job_does_not_block_new_execution(self):
        self.login("admin_umb")
        _, herramienta = self._create_cliente_y_herramienta()

        with patch("app.umbrella.routes.lanzar_job_background"):
            self._post_ejecutar(herramienta)

        # Simulate the background worker having finished (what _worker()
        # would normally do on completion), without running any real thread.
        job = UmbrellaJob.query.filter_by(herramienta_id=herramienta.id).first()
        job.status = "completed"
        db.session.commit()

        with patch("app.umbrella.routes.lanzar_job_background") as mock_launch:
            second = self._post_ejecutar(herramienta)

        self.assertEqual(second.status_code, 302)
        self.assertEqual(UmbrellaJob.query.filter_by(herramienta_id=herramienta.id).count(), 2)
        mock_launch.assert_called_once()

    # Fase 4: proves the lock primitive itself gives real mutual exclusion
    # under genuine thread concurrency — isolated from the HTTP test client
    # (whose own cookie jar is not thread-safe and would make a concurrent
    # self.client.post() test flaky for reasons unrelated to this fix).
    def test_lock_for_herramienta_gives_real_mutual_exclusion(self):
        import time
        from app.umbrella.routes import _lock_for_herramienta

        herramienta_id = 42
        holders_inside = []
        overlap_detected = threading.Event()

        def worker(tag):
            lock = _lock_for_herramienta(herramienta_id)
            with lock:
                holders_inside.append(tag)
                if len(holders_inside) > 1:
                    overlap_detected.set()
                time.sleep(0.05)
                holders_inside.remove(tag)

        threads = [threading.Thread(target=worker, args=(tag,)) for tag in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2)

        self.assertFalse(
            overlap_detected.is_set(),
            "both threads were inside the per-herramienta critical section at the same time",
        )
        # Same herramienta_id -> the same Lock instance every time (required
        # for the lock to actually serialize anything).
        self.assertIs(_lock_for_herramienta(herramienta_id), _lock_for_herramienta(herramienta_id))
        # A different herramienta_id must never share the same lock, or
        # independent tenants/tools would be serialized against each other.
        self.assertIsNot(_lock_for_herramienta(herramienta_id), _lock_for_herramienta(herramienta_id + 1))

    # 9. jobs for different tenants/tools don't block each other
    def test_different_herramientas_do_not_block_each_other(self):
        self.login("admin_umb")
        _, herramienta_a = self._create_cliente_y_herramienta("Cliente A", "a")
        _, herramienta_b = self._create_cliente_y_herramienta("Cliente B", "b")

        with patch("app.umbrella.routes.lanzar_job_background") as mock_launch:
            resp_a = self._post_ejecutar(herramienta_a)
            resp_b = self._post_ejecutar(herramienta_b)

        self.assertEqual(resp_a.status_code, 302)
        self.assertEqual(resp_b.status_code, 302)
        self.assertEqual(UmbrellaJob.query.filter_by(herramienta_id=herramienta_a.id).count(), 1)
        self.assertEqual(UmbrellaJob.query.filter_by(herramienta_id=herramienta_b.id).count(), 1)
        self.assertEqual(mock_launch.call_count, 2)

    # 10. CSRF remains active
    def test_missing_csrf_token_is_rejected(self):
        self.login("admin_umb")
        _, herramienta = self._create_cliente_y_herramienta()

        data = {
            "excel_file": (io.BytesIO(_make_xlsx_bytes(["App Uno"])), "apps.xlsx"),
            "label_name": "notApproved",
            "column_name": "App",
            # no csrf_token at all
        }
        with patch("app.umbrella.routes.lanzar_job_background") as mock_launch:
            resp = self.client.post(
                self._ejecutar_url(herramienta), data=data, content_type="multipart/form-data"
            )

        self.assertEqual(resp.status_code, 400)
        mock_launch.assert_not_called()
        self.assertEqual(UmbrellaJob.query.count(), 0)
