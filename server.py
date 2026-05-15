import sys
import os
import socket
import logging
from dotenv import load_dotenv
from cheroot.wsgi import Server as WSGIServer
from cheroot.ssl.builtin import BuiltinSSLAdapter
from app import create_app, db
from app.models import User
from flask_migrate import upgrade, stamp
from sqlalchemy import inspect

logger = logging.getLogger(__name__)

# Configuración
PORT = 8443
THREADS = 10

CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

# --- LÓGICA HÍBRIDA DE RUTAS ---
if getattr(sys, 'frozen', False):
    # Estamos en EXE
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Estamos en Python normal (Docker/Dev)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

load_dotenv(os.path.join(BASE_DIR, '.env'))

INSTANCE_PATH = os.path.join(BASE_DIR, 'instance')

if not os.path.exists(INSTANCE_PATH):
    try:
        os.makedirs(INSTANCE_PATH)
    except:
        pass
# -------------------------------

# Iniciamos la app pasándole la ruta calculada
app = create_app(instance_path=INSTANCE_PATH)

# Ajuste de consola solo para Windows (Evita error Unicode en Docker Linux)
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass


def inicializar_sistema():
    logger.info("[INIT] Arrancando sistema...")
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            tablas_existentes = inspector.get_table_names()
            
            if 'user' in tablas_existentes and 'alembic_version' not in tablas_existentes:
                logger.warning("[INIT] DETECTADO: Base de datos existente sin versionado.")
                logger.info("[INIT] ACCIÓN: Marcando base de datos como 'actual' (Stamp)...")
                stamp()
            
            try:
                upgrade()
                logger.info("[INIT] Upgrade ejecutado.")
            except Exception as e_up:
                logger.warning(f"[ADVERTENCIA] Upgrade falló (posible en EXE): {e_up}")

            if not User.query.filter_by(is_admin=True).first():
                 logger.info("[INIT] Estado: Esperando instalación vía Web.")
                 
        except Exception as e:
            logger.error(f"[ERROR CRÍTICO] Fallo en inicialización de DB: {e}")

def obtener_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
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
        logger.warning("\n[ADVERTENCIA] No se encontraron cert.pem o key.pem.")
        logger.warning("El servidor funcionará en modo HTTP inseguro.\n")
        PORT = 8080 # Fallback a puerto HTTP

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