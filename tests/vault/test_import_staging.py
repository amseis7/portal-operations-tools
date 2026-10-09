import unittest
from unittest.mock import patch

from app.vault import import_staging


class TestImportStaging(unittest.TestCase):
    def setUp(self):
        import_staging._staging.clear()

    def tearDown(self):
        import_staging._staging.clear()

    def test_store_and_retrieve_round_trip(self):
        import_staging.store("tok1", {"new": [], "conflicts": []})
        self.assertEqual(import_staging.retrieve("tok1"), {"new": [], "conflicts": []})

    def test_retrieve_nonexistent_token_returns_none(self):
        self.assertIsNone(import_staging.retrieve("does-not-exist"))

    def test_discard_removes_token(self):
        import_staging.store("tok1", {"x": 1})
        import_staging.discard("tok1")
        self.assertIsNone(import_staging.retrieve("tok1"))

    def test_discard_nonexistent_token_is_a_noop(self):
        import_staging.discard("never-existed")  # must not raise

    # 4. TTL expired -> retrieve() returns None
    def test_expired_token_retrieve_returns_none(self):
        with patch.object(import_staging.time, "time", return_value=1000.0):
            import_staging.store("tok1", {"x": 1})
        with patch.object(
            import_staging.time, "time",
            return_value=1000.0 + import_staging._TTL_SECONDS + 1,
        ):
            self.assertIsNone(import_staging.retrieve("tok1"))

    # 5. a later staging operation purges other expired tokens
    def test_store_purges_other_expired_tokens(self):
        with patch.object(import_staging.time, "time", return_value=1000.0):
            import_staging.store("old", {"x": 1})
        with patch.object(
            import_staging.time, "time",
            return_value=1000.0 + import_staging._TTL_SECONDS + 1,
        ):
            import_staging.store("new", {"y": 2})
        self.assertNotIn("old", import_staging._staging)
        self.assertIn("new", import_staging._staging)

    def test_retrieve_purges_other_expired_tokens(self):
        with patch.object(import_staging.time, "time", return_value=1000.0):
            import_staging.store("old1", {"x": 1})
            import_staging.store("old2", {"y": 2})
        with patch.object(
            import_staging.time, "time",
            return_value=1000.0 + import_staging._TTL_SECONDS + 1,
        ):
            import_staging.retrieve("unrelated-token")  # triggers purge as a side effect
        self.assertNotIn("old1", import_staging._staging)
        self.assertNotIn("old2", import_staging._staging)

    # 6. two distinct tokens remain isolated
    def test_two_tokens_remain_isolated(self):
        import_staging.store("tokA", {"who": "A"})
        import_staging.store("tokB", {"who": "B"})
        self.assertEqual(import_staging.retrieve("tokA"), {"who": "A"})
        self.assertEqual(import_staging.retrieve("tokB"), {"who": "B"})
