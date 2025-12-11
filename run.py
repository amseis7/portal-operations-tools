from app import create_app, db
from app.models import User
from sqlalchemy import text, inspect

app = create_app()

# --- FUNCIÓN DE AUTO-REPARACIÓN (PARCHE) ---
def parchear_base_datos():
    """
    Verifica manualmente si faltan columnas críticas y las agrega.
    Se ejecuta al iniciar para asegurar que la DB sea compatible.
    """
    print("[INIT] Verificando integridad de la base de datos...")
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            # Obtenemos las tablas actuales
            tablas = inspector.get_table_names()
            
            if 'user' in tablas:
                # Obtenemos las columnas de la tabla 'user'
                columnas = [col['name'] for col in inspector.get_columns('user')]
                
                # VERIFICACIÓN: ¿Falta virustotal_api_key?
                if 'virustotal_api_key' not in columnas:
                    print("[ALERTA] Columna 'virustotal_api_key' faltante. Aplicando parche SQL...")
                    with db.engine.connect() as conn:
                        # Ejecutamos el SQL directo para arreglarlo
                        conn.execute(text("ALTER TABLE user ADD COLUMN virustotal_api_key VARCHAR(255)"))
                        conn.commit()
                    print("[ÉXITO] Columna agregada correctamente.")
                else:
                    print("[OK] La tabla 'user' ya tiene la columna virustotal_api_key.")
            else:
                # Si no existen las tablas, las creamos todas
                db.create_all()
                print("[OK] Tablas creadas desde cero.")
                    
        except Exception as e:
            print(f"[ERROR PARCHE] No se pudo parchear la DB: {e}")
# -------------------------------------------

# Esto permite usar el comando 'flask shell' con contexto cargado
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

if __name__ == '__main__':
    # 1. EJECUTAMOS EL PARCHE ANTES DE ARRANCAR
    parchear_base_datos()
    
    # 2. ARRANCAMOS EL SERVIDOR
    # Nota: debug=True puede ocultar errores de inicio, pero es útil en desarrollo
    app.run(debug=True, host='0.0.0.0')