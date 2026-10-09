from tests.base import PortalTestCase


class TestBlueprintToolGuard(PortalTestCase):
    def test_user_without_tool_is_redirected_away(self):
        self.make_user("sintool", tools=[])
        self.login("sintool")

        resp = self.client.get("/kb/", follow_redirects=False)

        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard", resp.headers.get("Location", ""))

    def test_user_with_tool_can_reach_index(self):
        self.make_user("contool", tools=["knowledge_base"])
        self.login("contool")

        resp = self.client.get("/kb/")

        self.assertEqual(resp.status_code, 200)

    def test_admin_can_reach_index_without_explicit_usertool(self):
        self.make_user("admin1", is_admin=True)
        self.login("admin1")

        resp = self.client.get("/kb/")

        self.assertEqual(resp.status_code, 200)
