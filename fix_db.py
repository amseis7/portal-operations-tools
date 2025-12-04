import sqlite3
import os

# Asegúrate de que la ruta sea correcta. Si usas Docker, puede ser diferente.
db_path = os.path.join('instance', 'app.db') 

conn = sqlite3.connect(db_path)
c = conn.cursor()

# Intentamos agregar la columna vt_total a la tabla ioc
try:
    c.execute("ALTER TABLE ioc ADD COLUMN vt_total INTEGER DEFAULT 0")
    print("✅ Columna 'vt_total' agregada a tabla 'ioc'.")
except sqlite3.OperationalError as e:
    print(f"ℹ️  Tabla 'ioc': {e}")

# Hacemos lo mismo para vt_ioc por si acaso
try:
    c.execute("ALTER TABLE vt_ioc ADD COLUMN vt_total INTEGER DEFAULT 0")
    print("✅ Columna 'vt_total' agregada a tabla 'vt_ioc'.")
except sqlite3.OperationalError as e:
    print(f"ℹ️  Tabla 'vt_ioc': {e}")

conn.commit()
conn.close()