import sys
import os
import socket
from waitress import serve
from app import create_app, db
from app.models import User
from flask_migrate import upgrade, stamp
# AGREGAMOS 'text' A LOS IMPORTS
from sqlalchemy import inspect, text 

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

# --- NUEVA FUNCIÓN DE PARCHE SQL DIRECTO ---
def parchear_base_datos(app):
    """
    Se ejecuta automáticamente al iniciar la app.
    Verifica y repara tablas 'user' e 'ioc' agregando columnas faltantes.
    """
    with app.app_context():
        try:
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
            print(f"--- [INIT] Conectando a BD: {db_uri} ---")
            
            # 1. Crear tablas nuevas si no existen (ej: vt_ticket, vt_ioc)
            db.create_all()

            inspector = inspect(db.engine)
            
            # --- PARCHE 1: Tabla USER (API Key) ---
            if inspector.has_table("user"):
                cols_user = [col['name'] for col in inspector.get_columns('user')]
                if 'virustotal_api_key' not in cols_user:
                    print("--- [ALERTA] Reparando tabla 'user'... ---")
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE user ADD COLUMN virustotal_api_key VARCHAR(255)"))
                        conn.commit()
            
            # --- PARCHE 2: Tabla IOC (Datos VirusTotal en CSIRT) ---
            if inspector.has_table("ioc"):
                cols_ioc = [col['name'] for col in inspector.get_columns('ioc')]
                
                # Lista de columnas nuevas que deben existir
                nuevas_columnas = [
                    ("vt_last_check", "DATETIME"),
                    ("vt_reputation", "INTEGER"),
                    ("vt_positives", "INTEGER DEFAULT 0"),
                    ("vt_total", "INTEGER DEFAULT 0"),
                    ("vt_permalink", "VARCHAR(255)"),
                    ("vt_md5", "VARCHAR(32)"),
                    ("vt_sha1", "VARCHAR(40)"),
                    ("vt_sha256", "VARCHAR(64)"),
                    ("vt_motores_json", "TEXT")
                ]
                
                with db.engine.connect() as conn:
                    cambios = False
                    for col_nombre, col_tipo in nuevas_columnas:
                        if col_nombre not in cols_ioc:
                            print(f"--- [ALERTA] Agregando columna '{col_nombre}' a tabla 'ioc'... ---")
                            conn.execute(text(f"ALTER TABLE ioc ADD COLUMN {col_nombre} {col_tipo}"))
                            cambios = True
                    
                    if cambios:
                        conn.commit()
                        print("--- [EXITO] Tabla 'ioc' reparada correctamente. ---")
                    else:
                        print("--- [OK] Tabla 'ioc' está al día. ---")

        except Exception as e:
            print(f"--- [ERROR SILENCIOSO] Falló parche DB: {e} ---")

def inicializar_sistema():
    print("[INIT] Arrancando sistema...")
    with app.app_context():
        try:
            # 1. Intentamos la lógica de Alembic (Migraciones formales)
            inspector = inspect(db.engine)
            tablas_existentes = inspector.get_table_names()
            
            if 'user' in tablas_existentes and 'alembic_version' not in tablas_existentes:
                print("[INIT] DETECTADO: Base de datos existente sin versionado.")
                print("[INIT] ACCIÓN: Marcando base de datos como 'actual' (Stamp)...")
                stamp()
            
            print("[INIT] Verificando esquema de base de datos (Upgrade)...")
            try:
                upgrade()
                print("[INIT] Upgrade ejecutado.")
            except Exception as e_up:
                print(f"[ADVERTENCIA] Upgrade falló (posible en EXE): {e_up}")

            # ----------------------------------------
            # 2. EJECUTAMOS EL PARCHE DE SEGURIDAD
            # Esto asegura que la columna exista sí o sí antes de consultar User
            parchear_base_datos(app)
            # ----------------------------------------

            # 3. Verificación de Admin (Ahora es seguro hacerlo)
            if not User.query.filter_by(is_admin=True).first():
                 print("[INIT] Estado: Esperando instalación vía Web.")
                 
        except Exception as e:
            print(f"[ERROR CRÍTICO] Fallo en inicialización de DB: {e}")

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