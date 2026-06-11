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

try:
    app = create_app(instance_path=INSTANCE_PATH)
except Exception as _startup_err:
    _err_path = os.path.join(BASE_DIR, 'startup_error.log')
    with open(_err_path, 'w', encoding='utf-8') as _f:
        import traceback
        _f.write(traceback.format_exc())
    print(f"[FATAL] create_app() falló. Ver: {_err_path}", file=sys.stderr)
    sys.exit(1)

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
            tablas_app = [t for t in tablas_existentes if t != 'alembic_version']

            if not tablas_app:
                # Instalación nueva: crear esquema completo desde los modelos
                logger.info("[INIT] Instalación nueva detectada. Creando esquema completo...")
                db.create_all()
                stamp()  # Marca la DB como en la versión más reciente
                logger.info("[INIT] Esquema creado y versionado correctamente.")
            else:
                # DB existente: aplicar migraciones pendientes
                if 'alembic_version' not in tablas_existentes:
                    logger.warning("[INIT] DB existente sin versionado. Marcando como actual...")
                    stamp()

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

def _diag(msg):
    """Escribe en startup.log Y en stdout para diagnóstico."""
    line = f"{msg}\n"
    try:
        with open(os.path.join(BASE_DIR, 'startup.log'), 'a', encoding='utf-8') as _f:
            _f.write(line)
    except Exception:
        pass
    print(line, end='', flush=True)


if __name__ == "__main__":
    _diag("=== STARTUP ===")
    _diag(f"BASE_DIR: {BASE_DIR}")
    _diag(f"frozen: {getattr(sys, 'frozen', False)}")

    try:
        _diag("Llamando inicializar_sistema()")
        inicializar_sistema()
        _diag("inicializar_sistema() OK")

        ip = obtener_ip()
        _diag(f"IP local: {ip}")

        cert_path = os.path.join(BASE_DIR, CERT_FILE)
        key_path = os.path.join(BASE_DIR, KEY_FILE)

        usar_ssl = False
        if os.path.exists(cert_path) and os.path.exists(key_path):
            usar_ssl = True
            _diag("SSL habilitado")
        else:
            _diag("Sin certs SSL, usando HTTP en puerto 8080")
            PORT = 8080

        print("------------------------------------------------")
        print(" PORTAL DE OPERACIONES - CSIRT V1.5.0")
        print("------------------------------------------------")
        print(f" STATUS:  EN LINEA ({'SEGURO HTTPS' if usar_ssl else 'INSEGURO HTTP'})")
        if usar_ssl:
            print(f" LOCAL:   https://localhost:{PORT}")
            print(f" RED:     https://{ip}:{PORT}")
        else:
            print(f" LOCAL:   http://localhost:{PORT}")
            print(f" RED:     http://{ip}:{PORT}")
        print("------------------------------------------------")
        sys.stdout.flush()

        _diag(f"Iniciando WSGIServer en 0.0.0.0:{PORT}")
        server = WSGIServer(('0.0.0.0', PORT), app, numthreads=THREADS)

        if usar_ssl:
            server.ssl_adapter = BuiltinSSLAdapter(cert_path, key_path)

        _diag("server.start() ...")
        server.start()

    except KeyboardInterrupt:
        _diag("Detenido por usuario (KeyboardInterrupt)")
        try:
            server.stop()
        except Exception:
            pass
    except Exception as _e:
        import traceback
        _diag(f"EXCEPCION FATAL: {_e}")
        _diag(traceback.format_exc())
        sys.exit(1)