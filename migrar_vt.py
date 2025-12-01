import sqlite3
import os

# Detectar ruta de la DB (igual que en tu config)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'app.db')

# Las columnas nuevas que definimos en models.py
nuevas_columnas = [
    ("vt_last_check", "DATETIME"),
    ("vt_reputation", "INTEGER"),
    ("vt_permalink", "VARCHAR(255)"),
    ("vt_md5", "VARCHAR(32)"),
    ("vt_sha1", "VARCHAR(40)"),
    ("vt_sha256", "VARCHAR(64)"),
    ("vt_motores_json", "TEXT")
]

def migrar():
    print(f"--- Iniciando migración en: {DB_PATH} ---")
    
    if not os.path.exists(DB_PATH):
        print("❌ ERROR: No se encuentra el archivo de base de datos.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for columna, tipo in nuevas_columnas:
        try:
            # Comando SQL para agregar columna
            query = f"ALTER TABLE ioc ADD COLUMN {columna} {tipo}"
            cursor.execute(query)
            print(f"✅ Columna agregada: {columna}")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e):
                print(f"ℹ️  La columna '{columna}' ya existía. (Saltando)")
            else:
                print(f"Error agregando '{columna}': {e}")

    conn.commit()
    conn.close()
    print("--- Migración Finalizada ---")

if __name__ == "__main__":
    migrar()