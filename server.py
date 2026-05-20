import sys
import os
import socket
import logging
from dotenv import load_dotenv
from cheroot.wsgi import Server as WSGIServer
from cheroot.ssl.builtin import BuiltinSSLAdapter
from flask_migrate import upgrade, stamp
from sqlalchemy import inspect
from app import create_app, db
from app.models import User

logger = logging.getLogger(__name__)

PORT = 8443
THREADS = 10

CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

load_dotenv(os.path.join(BASE_DIR, '.env'))

INSTANCE_PATH = os.path.join(BASE_DIR, 'instance')

if not os.path.exists(INSTANCE_PATH):
    try:
        os.makedirs(INSTANCE_PATH)
    except OSError:
        pass

app = create_app(instance_path=INSTANCE_PATH)

if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def inicializar_sistema():
    logger.info("[INIT] Arrancando sistema...")
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


def obtener_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    inicializar_sistema()
    ip = obtener_ip()

    cert_path = os.path.join(BASE_DIR, CERT_FILE)
    key_path = os.path.join(BASE_DIR, KEY_FILE)

    usar_ssl = False
    if os.path.exists(cert_path) and os.path.exists(key_path):
        usar_ssl = True
    else:
        logger.warning("[ADVERTENCIA] No se encontraron cert.pem o key.pem.")
        logger.warning("El servidor funcionará en modo HTTP inseguro.\n")
        PORT = 8080

    print("------------------------------------------------")
    print(" PORTAL DE OPERACIONES - CSIRT V1.0.0")
    print("------------------------------------------------")
    print(f" STATUS:  EN LINEA ({'SEGURO HTTPS' if usar_ssl else 'INSEGURO HTTP'})")
    if usar_ssl:
        print(f" LOCAL:   https://localhost:{PORT}")
        print(f" RED:     https://{ip}:{PORT}")
    else:
        print(f" LOCAL:   http://localhost:{PORT}")
        print(f" RED:     http://{ip}:{PORT}")
    print("------------------------------------------------")

    server = WSGIServer(('0.0.0.0', PORT), app, numthreads=THREADS)

    if usar_ssl:
        server.ssl_adapter = BuiltinSSLAdapter(cert_path, key_path)

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()