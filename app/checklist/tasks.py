# app/checklist/tasks.py
from app import db
from app.models import ChecklistService
from app.checklist.plugins import get_plugin_class
from datetime import datetime
import traceback

def ejecutar_barrido_checklist(app):
    """
    Función maestra. Recorre TODOS los servicios configurados y ejecuta sus plugins.
    Recibe 'app' para poder crear el contexto de Flask manualmente si es necesario.
    """
    print("--- [CHECKLIST] Iniciando actualización masiva ---")
    
    # Necesitamos el contexto de la app para acceder a la DB fuera de una ruta web
    with app.app_context():
        servicios = ChecklistService.query.all()

        for svc in servicios:
            print(f" > Procesando: {svc.nombre_cliente} ({svc.tipo_tecnologia})")
            
            try:
                # 1. Buscar el Plugin correspondiente (ej: DemoPlugin)
                PluginClass = get_plugin_class(svc.tipo_tecnologia)
                
                if not PluginClass:
                    svc.estado_actual = 'error'
                    svc.mensaje_error = f"Plugin '{svc.tipo_tecnologia}' no existe en el sistema."
                    db.session.commit()
                    continue

                # 2. Desencriptar credenciales de la DB
                credenciales = svc.get_config()

                # 3. Instanciar el plugin y EJECUTAR la lógica
                plugin = PluginClass(credenciales)
                
                # Ejecutamos los chequeos (esto devuelve el diccionario con 'status', 'details', etc)
                resultado = plugin.run_checks()

                # 4. Actualizar la Base de Datos con la "Foto" nueva
                svc.ultima_data = resultado # Guardamos el JSON completo
                svc.estado_actual = resultado.get('status', 'unknown') # online/warning/offline
                svc.mensaje_error = None # Limpiamos errores viejos si hubo éxito
                svc.fecha_actualizacion = datetime.now()
                
                print(f"   [OK] Estado: {svc.estado_actual}")

            except Exception as e:
                # Si algo falla (ej: credenciales mal, API caída), no detenemos todo el bucle
                print(f"   [ERROR] Falló {svc.nombre_cliente}: {e}")
                # traceback.print_exc() # Descomentar para ver el error completo en consola
                
                svc.estado_actual = 'error_auth' # O 'offline'
                svc.mensaje_error = str(e)
                svc.fecha_actualizacion = datetime.now()

            # Guardamos cambios servicio por servicio
            db.session.commit()

    print("--- [CHECKLIST] Finalizado ---")