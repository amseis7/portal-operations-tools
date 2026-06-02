import logging
import threading

from flask import current_app

logger = logging.getLogger(__name__)


def _worker(app, job_id: int, app_names: list, client_id: str, client_secret: str,
            label_name: str, dry_run: bool) -> None:
    with app.app_context():
        from app.extensions import db
        from app.models.umbrella import UmbrellaAppResultado, UmbrellaJob
        from app.umbrella.client import UmbrellaClient
        from app.umbrella.logic import run_batch, summarize

        job = db.session.get(UmbrellaJob, job_id)
        if not job:
            return

        try:
            client = UmbrellaClient(client_id, client_secret)
            client.load_catalog()

            results = run_batch(app_names, client, label_name, dry_run=dry_run)
            summary = summarize(results)

            job.labeled = summary['labeled']
            job.skipped = summary['skipped']
            job.failed = summary['failed']
            job.status = 'completed'

            for r in results:
                db.session.add(UmbrellaAppResultado(
                    job_id=job_id,
                    app_name=r.app_name,
                    category=r.category,
                    status=r.status,
                    label=r.label,
                    http_code=r.http_code,
                    error_message=r.error_message,
                ))

        except Exception as exc:
            logger.exception("Error en background job Umbrella %s", job_id)
            job.status = 'failed'
            job.error_message = str(exc)

        db.session.commit()


def lanzar_job_background(app_names: list, job_id: int, client_id: str,
                           client_secret: str, label_name: str, dry_run: bool) -> None:
    app = current_app._get_current_object()
    t = threading.Thread(
        target=_worker,
        args=(app, job_id, app_names, client_id, client_secret, label_name, dry_run),
        daemon=True,
    )
    t.start()
