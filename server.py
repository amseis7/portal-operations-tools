from waitress import serve
from app import create_app, db
import socket
import os

# Config
PORT = 8080
THREADS = 6

app = create_app()

def inicializar_sistema():
    print(" [INIT] ⚙️ Iniciando secuencia de arranque...")
    
    # --- NUEVO BLOQUE: Crear carpeta instance ---
    # Esto es vital para Docker y servidores nuevos
    instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
    if not os.path.exists(instance_path):
        try:
            os.makedirs(instance_path)
            print(f" [INIT] 📁 Carpeta 'instance' creada en: {instance_path}")
        except OSError as e:
            print(f" [INIT] ❌ Error creando carpeta instance: {e}")
    # --------------------------------------------

# Solo nos aseguramos de que las tablas existan
with app.app_context():
    try:
        db.create_all()
        print(" [INIT] Base de datos verificada.")
    except Exception as e:
        print(f" [ERROR] No se pudo conectar a la DB: {e}")

def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    mi_ip = obtener_ip_local()
    
    print("╔════════════════════════════════════════════════════════════╗")
    print("║           PORTAL DE OPERACIONES - CSIRT V1.0.0             ║")
    print("╠════════════════════════════════════════════════════════════╣")
    print(f"║  [STATUS]  ✅ EN LÍNEA (Producción)                        ║")
    print(f"║  [WEB]     http://{mi_ip}:{PORT}                           ║")
    print("╚════════════════════════════════════════════════════════════╝")

    serve(app, host='0.0.0.0', port=PORT, threads=THREADS)