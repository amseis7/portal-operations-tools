import sys
import os
import socket
from waitress import serve
from app import create_app, db
from app.models import User

# Configuración
PORT = 8080
THREADS = 6

# --- LÓGICA HÍBRIDA DE RUTAS ---
if getattr(sys, 'frozen', False):
    # Estamos en EXE
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Estamos en Python normal (Docker/Dev)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

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
    print("[INIT] Arrancando sistema...")
    with app.app_context():
        try:
            db.create_all()
            # Verificación silenciosa
            if not User.query.filter_by(is_admin=True).first():
                 print("[INIT] Estado: Esperando instalacion via Web.")
        except Exception as e:
            print(f"[ERROR] DB: {e}")

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
    
    print("------------------------------------------------")
    print(" PORTAL DE OPERACIONES - CSIRT V1.0.0")
    print("------------------------------------------------")
    print(f" STATUS:  EN LINEA")
    print(f" LOCAL:   http://localhost:{PORT}")
    print(f" RED:     http://{ip}:{PORT}")
    print("------------------------------------------------")
    
    serve(app, host='0.0.0.0', port=PORT, threads=THREADS)