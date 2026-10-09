import os
import logging

logger = logging.getLogger(__name__)


def attachment_path(app, stored_filename):
    return os.path.join(app.config["KB_ATTACHMENTS_DIR"], stored_filename)


def safe_unlink(path):
    """Delete a file, tolerant of it already being gone (a concurrent
    cleanup run, or a prior partial run, must not raise)."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning("No se pudo eliminar archivo de adjunto: %s", e)
