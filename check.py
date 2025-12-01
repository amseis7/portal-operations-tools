# Crea un archivo temporal check.py y ejecútalo
from app import create_app, db
import sqlite3

app = create_app()
with app.app_context():
    try:
        # Intentamos leer la columna
        conn = sqlite3.connect('instance/app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT virustotal_api_key FROM user LIMIT 1")
        print("✅ La columna YA EXISTE. El problema era el código.")
    except Exception as e:
        print(f"❌ La columna NO EXISTE. Error: {e}")
        print("Intentando crearla...")
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN virustotal_api_key VARCHAR(100)")
            conn.commit()
            print("✅ ¡Columna creada con éxito ahora mismo!")
        except Exception as e2:
            print(f"Error fatal: {e2}")