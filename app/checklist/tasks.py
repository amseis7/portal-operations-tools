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
                # 1. Buscar el Plugin correspondiente
                PluginClass = get_plugin_class(svc.tipo_tecnologia)
                
                if not PluginClass:
                    svc.estado_actual = 'error'
                    svc.mensaje_error = f"Plugin '{svc.tipo_tecnologia}' no existe."
                    db.session.commit()
                    continue

                # 2. Desencriptar credenciales de la DB
                credenciales = svc.get_config()

                # 3. Instanciar el plugin y EJECUTAR la lógica
                plugin = PluginClass(credenciales)
                resultado = plugin.run_checks()

                # --- LÓGICA BLINDADA DE RESPUESTA ---
                data_json = {} # Por defecto vacío

                # Caso A: El plugin es NUEVO (Devuelve Tupla de 3: estado, msg, json)
                if isinstance(resultado, tuple) and len(resultado) == 3:
                    estado, mensaje, data_json = resultado
                
                # Caso B: El plugin es VIEJO (Devuelve Tupla de 2: estado, msg)
                elif isinstance(resultado, tuple) and len(resultado) == 2:
                    estado, mensaje = resultado
                
                # Caso C: El plugin devuelve un DICCIONARIO (Formato antiguo legacy)
                elif isinstance(resultado, dict):
                    estado = resultado.get('status', 'error')
                    mensaje = resultado.get('message', 'Sin mensaje')
                    # Si el dict trae una llave 'details', la usamos; si no, guardamos todo el dict
                    data_json = resultado.get('details', resultado)

                else:
                    estado = 'error'
                    mensaje = f"Formato de retorno desconocido: {type(resultado)}"

                # --- 3.5 NORMALIZACIÓN Y SEGURIDAD (Rich Details Support) ---
                import json
                
                # Asegurar que data_json sea dict para consistencia
                if not isinstance(data_json, dict):
                    data_json = {"raw_data": data_json}

                # Validación de Tamaño (Safety Check) - Límite 500KB
                try:
                    json_str = json.dumps(data_json)
                    limit_bytes = 500 * 1024 # 500KB
                    
                    if len(json_str.encode('utf-8')) > limit_bytes:
                        print(f"   [WARN] Payload demasiado grande para {svc.nombre_cliente} ({len(json_str)} bytes)")
                        # Truncamos y guardamos error
                        svc.ultima_data = {
                            "error": "payload_too_large", 
                            "message": "El detalle de la alerta excede el límite de 500KB.",
                            "original_size_bytes": len(json_str) 
                        }
                        svc.mensaje_error = f"{mensaje} (Data Truncada > 500KB)"
                    else:
                        svc.ultima_data = data_json
                        svc.mensaje_error = mensaje 
                        
                except Exception as json_err:
                     print(f"   [ERROR] Falló serialización JSON para {svc.nombre_cliente}: {json_err}")
                     svc.ultima_data = {"error": "serialization_error", "details": str(json_err)}
                     svc.mensaje_error = "Error de serialización JSON"

                # 4. Actualizar la Base de Datos
                svc.estado_actual = estado    # online/warning/offline
                svc.fecha_actualizacion = datetime.now()

                db.session.commit()
                
                print(f"   [OK] Estado: {svc.estado_actual}")

            except Exception as e:
                db.session.rollback()
                print(f"   [ERROR] Falló {svc.nombre_cliente}: {e}")
                # traceback.print_exc() 
                
                svc.estado_actual = 'offline' # Usamos 'offline' para que salga rojo en el dashboard
                svc.mensaje_error = str(e)
                svc.fecha_actualizacion = datetime.now()
                db.session.commit()

    print("--- [CHECKLIST] Finalizado ---")