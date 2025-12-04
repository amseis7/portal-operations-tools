# Guarda como update_templates_hash.py y ejecuta
from app import create_app, db
import sqlite3
import os

app = create_app()
db_path = os.path.join('instance', 'app.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
try:
    cursor.execute("ALTER TABLE export_template ADD COLUMN supported_hashes VARCHAR(100) DEFAULT 'md5,sha1,sha256'")
    print("✅ Columna 'supported_hashes' agregada.")
except Exception as e:
    print(f"ℹ️  {e}")
conn.commit()
conn.close()