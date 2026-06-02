import logging
from dataclasses import dataclass, field
from typing import Literal, Optional

from app.umbrella.client import AmbiguousAppError, AppNotFoundError, UmbrellaClient

_log = logging.getLogger(__name__)

PATCH_CHUNK_SIZE = 50


@dataclass
class AppResult:
    app_name: str
    status: Literal["labeled", "skipped", "failed", "dry_run"]
    label: Optional[str] = None
    category: Optional[str] = None
    http_code: Optional[int] = None
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "app_name": self.app_name,
            "status": self.status,
            "label": self.label,
            "category": self.category or "",
            "http_code": self.http_code,
            "error_message": self.error_message or "",
        }


def run_batch(app_names: list, client: UmbrellaClient, label_name: str, dry_run: bool = False) -> list:
    """Process a list of app names and assign label_name in Umbrella.

    Returns a list of AppResult objects.
    """
    results = []
    to_label: list = []

    # Phase 1: resolve every app against the in-memory catalog
    for app_name in app_names:
        result = None
        try:
            app = client.search_app(app_name)
        except (AppNotFoundError, AmbiguousAppError) as exc:
            result = AppResult(app_name=app_name, status="failed", label=label_name, error_message=str(exc))
        else:
            category = app.get("category") or ""
            if app["label"].lower() == label_name.lower():
                result = AppResult(
                    app_name=app_name, status="skipped", label=label_name, category=category,
                    error_message="Ya tenía la etiqueta asignada"
                )
            elif dry_run:
                result = AppResult(app_name=app_name, status="dry_run", label=label_name, category=category)
            else:
                to_label.append((app_name, app["id"], category))

        if result is not None:
            results.append(result)

    # Phase 2: bulk PATCH in chunks
    for chunk_start in range(0, len(to_label), PATCH_CHUNK_SIZE):
        chunk = to_label[chunk_start: chunk_start + PATCH_CHUNK_SIZE]
        app_ids = [app_id for _, app_id, _ in chunk]
        _log.info("Bulk assign chunk %d-%d of %d app(s)...", chunk_start + 1, chunk_start + len(chunk), len(to_label))
        try:
            http_code = client.assign_label(app_ids, label_name)
            if http_code == 207:
                _log.warning("Partial success (HTTP 207) — verify individual apps")
                status, error = "labeled", "Éxito parcial (HTTP 207) — verifique apps individuales"
            elif 200 <= http_code < 300:
                status, error = "labeled", None
            else:
                _log.warning("Bulk assign failed (HTTP %s) for app_ids %s", http_code, app_ids)
                status = "failed"
                error = f"Fallo en asignación masiva (HTTP {http_code})"
        except Exception as exc:
            _log.warning("Assign error for app_ids %s: %s", app_ids, exc)
            http_code, status, error = None, "failed", f"Error de asignación: {exc}"

        for app_name, _, category in chunk:
            results.append(AppResult(
                app_name=app_name,
                status=status,
                label=label_name,
                category=category,
                http_code=http_code,
                error_message=error,
            ))

    return results


def summarize(results: list) -> dict:
    total = len(results)
    labeled = sum(1 for r in results if r.status == "labeled")
    skipped = sum(1 for r in results if r.status == "skipped")
    failed = sum(1 for r in results if r.status == "failed")
    dry_run = sum(1 for r in results if r.status == "dry_run")
    return {"total": total, "labeled": labeled, "skipped": skipped, "failed": failed, "dry_run": dry_run}
