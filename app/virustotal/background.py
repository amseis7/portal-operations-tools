import threading
import time
from flask import current_app
from app.extensions import db
from app.models import User, VtIoc, VtTicket
from app.virustotal.logic import consultar_virustotal_ioc

def _worker_analisis(app, caso_id, user_id, force):
    """
    Código que corre en el hilo separado con manejo robusto de errores.
    """
    with app.app_context():
        print(f"--- [BACKGROUND] Iniciando análisis Caso ID: {caso_id} ---")
        
        user = User.query.get(user_id)
        if not user: return
        
        api_key = user.get_vt_key()
        if not api_key: return

        # Obtenemos solo los IoCs que no tienen resultado (o todos si es forzado)
        # Esto optimiza para no re-consultar lo que ya estaba listo si se corta.
        query = VtIoc.query.filter_by(ticket_id=caso_id)
        if not force:
            query = query.filter(VtIoc.vt_last_check == None)
            
        iocs = query.all()
        total = len(iocs)
        print(f"--- [BACKGROUND] Se procesarán {total} IoCs pendientes ---")
        
        procesados = 0
        fallidos = 0

        stop_process = False

        for ioc in iocs:
            if stop_process:
                print(f"[SKIP] Saltando {ioc.valor} por aborto de proceso.")
                continue

            try:
                # Intentamos analizar
                exito = consultar_virustotal_ioc(ioc, forzar=force, api_key=api_key)
                
                if exito:
                    procesados += 1
                else:
                    fallidos += 1
                    ioc.set_motores({"ERROR": "Fallo consulta (Posible Cuota Excedida)"})
                    db.session.commit()
                    print(f"[WARN] IoC {ioc.valor} falló. Marcado como error.")

            except Exception as e:
                if "VT_QUOTA_EXCEEDED" in str(e):
                    print("--- [BACKGROUND] ALERTA: Cuota diaria excedida. Abortando resto del lote. ---")
                    stop_process = True # Activamos freno de mano
                
                    try:
                        ioc.set_motores({"ERROR": "Cuota Diaria Excedida - Análisis Abortado"})
                        db.session.commit()
                    except:
                        db.session.rollback()

                    fallidos += 1
                    break
                else:
                    fallidos += 1
                    print(f"[ERROR CRÍTICO] IoC {ioc.id}: {e}")
                    try:
                        ioc.set_motores({"ERROR": f"Excepción interna: {str(e)}"})
                        db.session.commit()
                    except:
                        db.session.rollback()
            # Pequeña pausa para no saturar si la lógica interna no durmió
            time.sleep(0.5)
        
        estado_final = "ABORTADO" if stop_process else "FINALIZADO"
        print(f"--- [BACKGROUND] Caso {caso_id} {estado_final}. Éxito: {procesados} | Fallos: {fallidos} ---")

def lanzar_analisis_background(caso_id, user_id, force=False):
    """Llama a esta función desde la ruta para iniciar el proceso"""
    app = current_app._get_current_object()
    hilo = threading.Thread(target=_worker_analisis, args=(app, caso_id, user_id, force))
    hilo.start()