import sys
import logging
from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models import User
from flask_migrate import upgrade, stamp
from sqlalchemy import inspect

logger = logging.getLogger(__name__)

app = create_app()


def inicializar_db():
    """
    Ejecuta migraciones de base de datos al arrancar.
    Si falla, aborta el proceso para evitar DB inconsistente.
    """
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            tablas_existentes = inspector.get_table_names()

            if not tablas_existentes:
                logger.info("[INIT] Base de datos vacía. Se creará con las migraciones.")
            elif 'user' in tablas_existentes and 'alembic_version' not in tablas_existentes:
                logger.warning("[INIT] DB existente sin versionado. Marcando como actual (stamp)...")
                stamp()
                logger.info("[INIT] Stamp aplicado correctamente.")

            try:
                upgrade()
                logger.info("[INIT] Migraciones aplicadas correctamente.")
            except Exception as e_upgrade:
                logger.critical(f"[FATAL] Falló flask db upgrade: {e_upgrade}")
                logger.critical("[FATAL] El servidor no puede arrancar con la DB en estado inconsistente.")
                sys.exit(1)

            if not User.query.filter_by(is_admin=True).first():
                logger.info("[INIT] Estado: Esperando instalación vía Web.")

        except Exception as e:
            logger.critical(f"[FATAL] Error en inicialización de DB: {e}")
            sys.exit(1)


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

if __name__ == '__main__':
    inicializar_db()
    app.run(debug=True, host='0.0.0.0')