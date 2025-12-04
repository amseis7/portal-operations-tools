import sqlite3
import os

# Busca la base de datos en la carpeta 'instance'
db_path = os.path.join('instance', 'app.db')

print(f"--- Conectando a: {db_path} ---")

if not os.path.exists(db_path):
    print("❌ ERROR: No se encuentra el archivo app.db")
else:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 1. Agregar columna a la tabla IOC (CSIRT)
        try:
            cursor.execute("ALTER TABLE ioc ADD COLUMN vt_positives INTEGER DEFAULT 0")
            print("✅ Columna 'vt_positives' agregada a tabla 'ioc'.")
        except sqlite3.OperationalError as e:
            print(f"ℹ️  Tabla 'ioc': {e} (Probablemente ya existe).")

        # 2. Agregar columna a la tabla VT_IOC (Investigaciones)
        try:
            cursor.execute("ALTER TABLE vt_ioc ADD COLUMN vt_positives INTEGER DEFAULT 0")
            print("✅ Columna 'vt_positives' agregada a tabla 'vt_ioc'.")
        except sqlite3.OperationalError as e:
            print(f"ℹ️  Tabla 'vt_ioc': {e} (Probablemente ya existe).")

        conn.commit()
        conn.close()
        print("\n--- Proceso finalizado con éxito ---")

    except Exception as e:
        print(f"❌ Error inesperado: {e}")