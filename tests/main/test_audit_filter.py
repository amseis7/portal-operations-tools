from tests.base import PortalTestCase
from app.extensions import db
from app.models.audit import AuditLog


class TestAuditModuleFilter(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("admin_audit", is_admin=True)
        self.login("admin_audit")
        db.session.add(AuditLog(module="csirt", action="view", object_name="ticket-1"))
        db.session.add(AuditLog(module="knowledge_base", action="create", object_name="articulo-1"))
        db.session.commit()

    def test_knowledge_base_filter_button_is_present(self):
        resp = self.client.get("/audit")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Base de Conocimiento", resp.data)
        self.assertIn(b"module=knowledge_base", resp.data)

    def test_filtering_by_knowledge_base_returns_only_those_records(self):
        resp = self.client.get("/audit?module=knowledge_base")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"articulo-1", resp.data)
        self.assertNotIn(b"ticket-1", resp.data)

    def test_todos_still_shows_every_module(self):
        resp = self.client.get("/audit")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"articulo-1", resp.data)
        self.assertIn(b"ticket-1", resp.data)
