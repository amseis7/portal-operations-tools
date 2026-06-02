import logging
import os
import time

import requests
from requests.auth import HTTPBasicAuth

_log = logging.getLogger(__name__)

BASE_URL = "https://api.umbrella.com"

VALID_LABELS = {"unreviewed", "approved", "notApproved", "underAudit"}

_DEFAULT_TIMEOUT = 30


class AppNotFoundError(Exception):
    pass


class AmbiguousAppError(Exception):
    pass


_RETRYABLE_EXCEPTIONS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.SSLError,
)


def _request_with_retry(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    retry_max = int(os.getenv("UMBRELLA_RETRY_MAX", "3"))
    initial_delay = float(os.getenv("UMBRELLA_RETRY_INITIAL_DELAY", "2"))
    max_delay = float(os.getenv("UMBRELLA_RETRY_MAX_DELAY", "8"))
    kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)

    last_response = None
    last_exc = None

    for attempt in range(retry_max + 1):
        try:
            response = session.request(method, url, **kwargs)
            last_exc = None
        except _RETRYABLE_EXCEPTIONS as exc:
            last_exc = exc
            last_response = None
            if attempt < retry_max:
                delay = min(initial_delay * (2 ** attempt), max_delay)
                _log.warning("Network error on %s — retry %d/%d in %.0fs: %s", url, attempt + 1, retry_max, delay, exc)
                time.sleep(delay)
            continue

        if response.status_code not in (429, 500, 502, 503, 504):
            return response
        last_response = response
        if attempt < retry_max:
            delay = min(initial_delay * (2 ** attempt), max_delay)
            _log.warning("HTTP %s on %s — retry %d/%d in %.0fs", response.status_code, url, attempt + 1, retry_max, delay)
            time.sleep(delay)

    if last_exc is not None:
        raise last_exc
    return last_response


class UmbrellaClient:
    def __init__(self, client_id: str, client_secret: str):
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = requests.Session()
        self._refresh_token()

    def _refresh_token(self) -> None:
        self._token = self._fetch_token(self._client_id, self._client_secret)
        self._session.headers.update({"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"})

    def _fetch_token(self, client_id: str, client_secret: str) -> str:
        url = f"{BASE_URL}/auth/v2/token"
        resp = self._session.post(
            url,
            auth=HTTPBasicAuth(client_id, client_secret),
            data={"grant_type": "client_credentials", "scope": "reports.appDiscovery:read reports.appDiscovery:write"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=_DEFAULT_TIMEOUT,
        )
        if not resp.ok:
            raise RuntimeError(f"Authentication failed (HTTP {resp.status_code}): {resp.text}")
        return resp.json()["access_token"]

    def _api_request(self, method: str, url: str, **kwargs) -> requests.Response:
        resp = _request_with_retry(self._session, method, url, **kwargs)
        if resp.status_code in (401, 403):
            _log.warning("HTTP %s — refreshing token and retrying", resp.status_code)
            self._refresh_token()
            resp = _request_with_retry(self._session, method, url, **kwargs)
        return resp

    def _load_catalog(self) -> dict:
        url = f"{BASE_URL}/reports/v2/appDiscovery/applications"
        limit = 100
        offset = 0
        index: dict = {}
        nospace: dict = {}

        _log.info("Loading app catalog from Umbrella...")
        while True:
            resp = self._api_request("GET", url, params={"limit": limit, "offset": offset})
            if not resp.ok:
                raise RuntimeError(f"Catalog fetch failed (HTTP {resp.status_code}): {resp.text}")
            items = resp.json().get("items", [])
            for item in items:
                name = item.get("name", "").strip()
                app_id = item.get("id")
                if not name or not app_id:
                    continue
                key = name.lower()
                index.setdefault(key, []).append({
                    "id": app_id,
                    "label": item.get("label", "unreviewed"),
                    "category": item.get("category", ""),
                })
                ns_key = key.replace(" ", "")
                nospace.setdefault(ns_key, []).append(key)
            if len(items) < limit:
                break
            offset += limit
            time.sleep(0.5)

        _log.info("Catalog loaded: %d unique app names", len(index))
        self._nospace_index = nospace
        return index

    def load_catalog(self) -> None:
        if not hasattr(self, "_catalog"):
            self._catalog = self._load_catalog()

    def search_app(self, app_name: str) -> dict:
        if not hasattr(self, "_catalog"):
            self._catalog = self._load_catalog()

        name_lower = app_name.strip().lower()
        matches = self._catalog.get(name_lower, [])
        if matches:
            if len(matches) > 1:
                raise AmbiguousAppError(f"Ambiguous: {len(matches)} apps matched '{app_name}'")
            return matches[0]

        catalog_keys = self._nospace_index.get(name_lower.replace(" ", ""), [])
        nospace_matches = []
        for key in catalog_keys:
            nospace_matches.extend(self._catalog[key])

        if not nospace_matches:
            raise AppNotFoundError(f"App '{app_name}' not found in Umbrella catalog")

        raise AmbiguousAppError(
            f"App '{app_name}' not found by exact name — possible match: {catalog_keys} — verify exact catalog name"
        )

    def assign_label(self, app_ids: list, label: str) -> int:
        url = f"{BASE_URL}/reports/v2/appDiscovery/applications"
        resp = self._api_request("PATCH", url, json={"label": label, "applicationsList": app_ids})
        if not resp.ok:
            _log.error("PATCH returned %s for %d app(s) — body: %s", resp.status_code, len(app_ids), resp.text)
        return resp.status_code

    def get_catalog_size(self) -> int:
        if not hasattr(self, "_catalog"):
            return 0
        return len(self._catalog)
