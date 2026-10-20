"""A-06: the HTTP 429 handler in consultar_virustotal_ioc() used to raise a
bare NameError when obtener_uso_api() returned None (any network failure or
non-200 response from the quota endpoint) — usado/limite were only assigned
inside `if cuota:` but read unconditionally afterward.

No real network call is ever made here: requests.get (both the main VT call
and, where relevant, obtener_uso_api itself) and time.sleep are mocked.
"""
from unittest.mock import Mock, patch

from tests.base import PortalTestCase
from app.extensions import db
from app.models.virustotal import VtIoc
from app.virustotal.logic import consultar_virustotal_ioc


def _resp(status_code, json_data=None, text=""):
    m = Mock()
    m.status_code = status_code
    m.json.return_value = json_data or {}
    m.text = text
    return m


class TestQuota429Handling(PortalTestCase):
    def _make_ioc(self, valor="a" * 64):
        ioc = VtIoc(tipo="hash", valor=valor)
        db.session.add(ioc)
        db.session.commit()
        return ioc

    # 1. HTTP 429 + obtener_uso_api() returns a valid, NOT-exhausted quota:
    #    existing behavior preserved — pauses, retries, succeeds on 200.
    @patch("app.virustotal.logic.time.sleep")
    @patch("app.virustotal.logic.obtener_uso_api")
    @patch("app.virustotal.logic.requests.get")
    def test_429_with_valid_quota_not_exhausted_retries_and_succeeds(
        self, mock_get, mock_cuota, mock_sleep
    ):
        ioc = self._make_ioc()
        mock_cuota.return_value = {"diario_usado": 10, "diario_limite": 500}
        mock_get.side_effect = [
            _resp(429),
            _resp(200, {"data": {"attributes": {
                "last_analysis_results": {}, "last_analysis_stats": {"malicious": 0, "suspicious": 0},
            }}}),
        ]

        result = consultar_virustotal_ioc(ioc, forzar=True, api_key="synthetic-key")

        self.assertTrue(result)
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_once_with(60)

    # 1b. HTTP 429 + valid quota that IS exhausted: existing abort behavior
    #     preserved (raises, carries VT_QUOTA_EXCEEDED).
    @patch("app.virustotal.logic.time.sleep")
    @patch("app.virustotal.logic.obtener_uso_api")
    @patch("app.virustotal.logic.requests.get")
    def test_429_with_valid_quota_exhausted_raises_quota_exceeded(
        self, mock_get, mock_cuota, mock_sleep
    ):
        ioc = self._make_ioc()
        mock_cuota.return_value = {"diario_usado": 500, "diario_limite": 500}
        mock_get.return_value = _resp(429)

        with self.assertRaises(Exception) as ctx:
            consultar_virustotal_ioc(ioc, forzar=True, api_key="synthetic-key")

        self.assertIn("VT_QUOTA_EXCEEDED", str(ctx.exception))
        mock_sleep.assert_not_called()  # aborts before the rate-limit pause

    # 2. HTTP 429 + obtener_uso_api() returns None: no NameError, degrades
    #    safely (treated like the rate-limit pause), recovers on retry.
    @patch("app.virustotal.logic.time.sleep")
    @patch("app.virustotal.logic.obtener_uso_api")
    @patch("app.virustotal.logic.requests.get")
    def test_429_with_quota_unavailable_does_not_raise_nameerror(
        self, mock_get, mock_cuota, mock_sleep
    ):
        ioc = self._make_ioc()
        mock_cuota.return_value = None  # non-200 or network failure inside obtener_uso_api
        mock_get.side_effect = [
            _resp(429),
            _resp(200, {"data": {"attributes": {
                "last_analysis_results": {}, "last_analysis_stats": {"malicious": 0, "suspicious": 0},
            }}}),
        ]

        try:
            result = consultar_virustotal_ioc(ioc, forzar=True, api_key="synthetic-key")
        except NameError:
            self.fail("consultar_virustotal_ioc raised NameError (A-06 regression)")

        self.assertTrue(result)
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_once_with(60)

    # 3. Same as above, representing a network failure while checking quota
    #    (obtener_uso_api already collapses that to None) — persistent 429
    #    across all 3 attempts: no NameError, no fabricated exhaustion,
    #    returns False (safe degradation) instead of crashing.
    @patch("app.virustotal.logic.time.sleep")
    @patch("app.virustotal.logic.obtener_uso_api")
    @patch("app.virustotal.logic.requests.get")
    def test_429_persistent_with_quota_unavailable_returns_false_safely(
        self, mock_get, mock_cuota, mock_sleep
    ):
        ioc = self._make_ioc()
        mock_cuota.return_value = None
        mock_get.return_value = _resp(429)  # every attempt hits 429

        try:
            result = consultar_virustotal_ioc(ioc, forzar=True, api_key="synthetic-key")
        except NameError:
            self.fail("consultar_virustotal_ioc raised NameError (A-06 regression)")

        self.assertFalse(result)
        self.assertEqual(mock_get.call_count, 3)  # bounded retry loop, not infinite
        self.assertEqual(mock_sleep.call_count, 3)

    # 4 & 5 implicit in the above: no fabricated usado/limite is ever used to
    # claim exhaustion when quota is unavailable (no VT_QUOTA_EXCEEDED raised
    # in tests 2/3), and the 429/rate-limit signal is still honored (sleep(60)
    # is still called — it is not silently swallowed as a generic error).

    # Regression guard: normal HTTP 200 path is unaffected by this fix.
    @patch("app.virustotal.logic.time.sleep")
    @patch("app.virustotal.logic.requests.get")
    def test_normal_200_response_unaffected(self, mock_get, mock_sleep):
        ioc = self._make_ioc()
        mock_get.return_value = _resp(200, {"data": {"attributes": {
            "last_analysis_results": {"EngineX": {"category": "malicious"}},
            "last_analysis_stats": {"malicious": 1, "suspicious": 0},
            "reputation": -5,
            "md5": "m" * 32, "sha1": "s" * 40, "sha256": "a" * 64,
        }}})

        result = consultar_virustotal_ioc(ioc, forzar=True, api_key="synthetic-key")

        self.assertTrue(result)
        self.assertEqual(ioc.vt_positives, 1)
        mock_sleep.assert_not_called()

    # Regression guard: a non-429, non-200, non-404 error path is unaffected.
    @patch("app.virustotal.logic.time.sleep")
    @patch("app.virustotal.logic.requests.get")
    def test_other_http_error_unaffected(self, mock_get, mock_sleep):
        ioc = self._make_ioc()
        mock_get.return_value = _resp(500, text="Internal Server Error")

        result = consultar_virustotal_ioc(ioc, forzar=True, api_key="synthetic-key")

        self.assertFalse(result)
        mock_sleep.assert_not_called()
