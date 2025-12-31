import requests
import time
import logging
import base64
import json
import zipfile
import re
from io import BytesIO
from datetime import datetime, timedelta
from flask import flash
from flask_login import current_user
from sqlalchemy import or_
from app.extensions import db
from app.models import Ioc, VtIoc, Alerta, ExportTemplate, VtTicket

logger = logging.getLogger(__name__)

def buscar_resultado_freco_en_db(valor, dias_validez=14):
    fecha_limite = datetime.now() - timedelta(days=dias_validez)

    candidato = VtIoc.query.filter(
        VtIoc.valor == valor,
        VtIoc.vt_last_check >= fecha_limite
    ).order_by(VtIoc.vt_last_check.desc()).first()

    if candidato:
        return candidato
    
    candidato_csirt = Ioc.query.filter(
        Ioc.valor == valor,
        Ioc.vt_last_check >= fecha_limite
    ).order_by(Ioc.vt_last_check.desc()).first()

    if candidato_csirt:
        return candidato_csirt
    
    return None

def consultar_virustotal_ioc(ioc_obj, forzar=False, api_key=None):
    """Consulta VT para un objeto (Ioc o VtIoc)."""
    
    if not forzar and ioc_obj.vt_last_check:
        tiempo = datetime.now() - ioc_obj.vt_last_check
        if tiempo.days < 7:
            return True
        
    if not forzar:
        resultado_previo = buscar_resultado_freco_en_db(ioc_obj.valor)

        if resultado_previo:
            ioc_obj.vt_last_check = resultado_previo.vt_last_check
            ioc_obj.vt_reputation = resultado_previo.vt_reputation
            ioc_obj.vt_positives = resultado_previo.vt_positives
            ioc_obj.vt_total = resultado_previo.vt_total
            ioc_obj.vt_permalink = resultado_previo.vt_permalink
            ioc_obj.vt_md5 = resultado_previo.vt_md5
            ioc_obj.vt_sha1 = resultado_previo.vt_sha1
            ioc_obj.vt_sha256 = resultado_previo.vt_sha256

            ioc_obj.vt_motores_json = resultado_previo.vt_motores_json

            db.session.commit()
            return True
        
    if not api_key:
        try:
            if current_user.is_authenticated:
                api_key = current_user.get_vt_key()
        except:
            pass
        
    if not api_key: return False
    
    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"
    
    tipo_db = ioc_obj.tipo.lower()
    valor_original = ioc_obj.valor.strip()
    endpoint = ""

    # 3. ENDPOINTS
    if tipo_db in ['hash', 'md5', 'sha1', 'sha256']:
        endpoint = f"{base_url}/files/{valor_original}"
    elif tipo_db == 'ip':
        endpoint = f"{base_url}/ip_addresses/{valor_original}"
    elif tipo_db == 'dominio':
        valor_limpio = valor_original.replace("https://", "").replace("http://", "").split("/")[0]
        endpoint = f"{base_url}/domains/{valor_limpio}"
    elif tipo_db == 'url':
        try:
            url_id = base64.urlsafe_b64encode(valor_original.encode()).decode().strip("=")
            endpoint = f"{base_url}/urls/{url_id}"
        except: return False
    else:
        return False 

    # 4. EJECUCIÓN
    try:
        for _ in range(3):
            response = requests.get(endpoint, headers=headers, timeout=15)
            
            if response.status_code == 429:
                print(f"[VT LIMIT] Cuota excedida (429) para {valor_original}. Verificando cuota real...") # <--- DIAGNÓSTICO
                cuota = obtener_uso_api(api_key)

                if cuota:
                    usado = cuota.get('diario_usado', 0)
                    limite = cuota.get('diario_limite', 0)

                if isinstance(limite, int) and usado >= limite:
                    print(f"[VT ABORT] Cuota diaria agotada ({usado}/{limite}). Deteniendo análisis.")
                    # Lanzamos una excepción específica para detener el bucle en background
                    raise Exception("VT_QUOTA_EXCEEDED")

                print(f"[VT LIMIT] Pausa de 60s por límite de velocidad (Rate Limit)...")
                time.sleep(60)
                continue
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                last_analysis = attrs.get("last_analysis_results", {})
                stats = attrs.get("last_analysis_stats", {})

                # Estadísticas
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                ioc_obj.vt_positives = malicious + suspicious
                ioc_obj.vt_total = sum(stats.values())
                
                # Datos Generales
                ioc_obj.vt_last_check = datetime.now()
                ioc_obj.vt_reputation = attrs.get("reputation", 0)
                ioc_obj.vt_md5 = attrs.get("md5")
                ioc_obj.vt_sha1 = attrs.get("sha1")
                ioc_obj.vt_sha256 = attrs.get("sha256")
                
                # Permalink
                type_link = 'file' 
                id_ref = valor_original
                if tipo_db == 'url': 
                    type_link = 'url'
                    id_ref = base64.urlsafe_b64encode(valor_original.encode()).decode().strip("=")
                elif tipo_db == 'dominio': type_link = 'domain'; id_ref = endpoint.split('/')[-1]
                elif tipo_db == 'ip': type_link = 'ip-address'

                ioc_obj.vt_permalink = f"https://www.virustotal.com/gui/{type_link}/{id_ref}"

                # Motores
                resultados_motores = {}
                for motor_name, motor_data in last_analysis.items():
                    resultados_motores[motor_name] = motor_data.get("category", "unknown")
                
                resultados_motores["filename"] = attrs.get("meaningful_name", attrs.get("title", "-"))
                ioc_obj.set_motores(resultados_motores)
                
                if isinstance(ioc_obj, VtIoc):
                    # Buscamos si existe este mismo valor en la tabla Ioc de CSIRT
                    iocs_csirt = Ioc.query.filter_by(valor=valor_original).all()
                    for ioc_original in iocs_csirt:
                        # Copiamos los resultados frescos al original
                        ioc_original.vt_last_check = ioc_obj.vt_last_check
                        ioc_original.vt_positives = ioc_obj.vt_positives
                        ioc_original.vt_total = ioc_obj.vt_total
                        ioc_original.vt_reputation = ioc_obj.vt_reputation
                        ioc_original.vt_permalink = ioc_obj.vt_permalink
                        ioc_original.set_motores(resultados_motores)
                
                db.session.commit()
                return True

            elif response.status_code == 404:
                ioc_obj.vt_last_check = datetime.now()
                ioc_obj.vt_reputation = 0
                ioc_obj.vt_positives = 0
                ioc_obj.set_motores({"ERROR": "Not Found in VirusTotal"})
                ioc_obj.vt_permalink = f"https://www.virustotal.com/gui/search/{valor_original}"
                db.session.commit()
                return True
            
            else:
                print(f"[VT ERROR] Fallo con código {response.status_code}: {response.text}")
                return False

    except Exception as e:
        if "VT_QUOTA_EXCEEDED" in str(e):
            raise e
        
        logger.error(f"Excepción VT: {e}")
        return False
    return False

def procesar_importacion_csirt(nombre_ticket_csirt, iocs_origen):
    # 1. Buscar o Crear el Caso
    nombre_caso = f"CSIRT: {nombre_ticket_csirt}"
    caso_vt = VtTicket.query.filter_by(nombre=nombre_caso).first()
    
    if not caso_vt:
        caso_vt = VtTicket(
            nombre=nombre_caso,
            descripcion=f"Caso generado automáticamente desde el Ticket CSIRT {nombre_ticket_csirt}",
            usuario_id=current_user.id
        )
        db.session.add(caso_vt)
        db.session.commit()
        flash(f'Se creó un nuevo Caso de Investigación: {nombre_caso}', 'info')

    # 2. Migrar IoCs (Append)
    nuevos = 0
    # Lista de objetos VtIoc que vamos a analizar (ya sean nuevos o existentes)
    vt_iocs_a_analizar = []

    for ioc_c in iocs_origen:
        # Verificar duplicados en el destino
        existe = VtIoc.query.filter_by(ticket_id=caso_vt.id, valor=ioc_c.valor).first()
        
        if not existe:
            nuevo_vt_ioc = VtIoc(
                ticket_id=caso_vt.id,
                tipo=ioc_c.tipo,
                valor=ioc_c.valor
                # Nota: No copiamos el resultado anterior para forzar una validación fresca 
                # o dejar que consultar_virustotal_ioc use su caché de fecha.
            )
            db.session.add(nuevo_vt_ioc)
            vt_iocs_a_analizar.append(nuevo_vt_ioc)
            nuevos += 1
        else:
            vt_iocs_a_analizar.append(existe)
    
    db.session.commit()

    """if not current_user.virustotal_api_key:
        flash('IoCs importados, pero NO analizados. Configura tu API Key.', 'warning')
        return caso_vt.id  # <--- IMPORTANTE: Retornar ID

    cont_exito = 0
    # Obtenemos 'force' del request global de Flask
    force = request.args.get('force') == 'true'
    
    for ioc_vt in vt_iocs_a_analizar:
        if consultar_virustotal_ioc(ioc_vt, forzar=force):
            cont_exito += 1
            
    flash(f'Proceso completado. {nuevos} IoCs importados. {cont_exito} analizados en VT.', 'success')"""
    
    return caso_vt.id

def generar_exportacion_multiformato(id_origen, lista_ids_templates, origen='caso'):
    """Genera ZIP inteligente con limpieza de etiquetas XML vacías."""
    
    if origen == 'caso':
        ticket_obj = VtTicket.query.get(id_origen)
        nombre_ref = ticket_obj.nombre if ticket_obj else f"Caso_{id_origen}"
        iocs = VtIoc.query.filter_by(ticket_id=id_origen).all()
    else:
        nombre_ref = id_origen
        iocs = db.session.query(Ioc).join(Alerta).filter(Alerta.ticket == id_origen).all()
    
    zip_buffer = BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        
        for template_id in lista_ids_templates:
            template = ExportTemplate.query.get(template_id)
            if not template: continue
            
            config_hashes = (template.supported_hashes or "md5,sha1,sha256").lower()
            tipos_permitidos = [t.strip() for t in config_hashes.split(',')]
            
            contenido_archivo = []
            if template.header_content:
                contenido_archivo.append(template.header_content)
            
            count_agregados = 0
            for ioc in iocs:
                motores = ioc.get_motores()
                estado_motor = motores.get(template.vt_engine_name, 'not_scanned')
                
                if estado_motor in ['malicious', 'suspicious']:
                    continue

                # Lógica de Hash Inteligente
                valor_final = ioc.valor
                tipo_final = ioc.tipo
                es_hash = ioc.tipo in ['hash', 'md5', 'sha1', 'sha256']
                
                if es_hash:
                    encontrado = False
                    if 'sha256' in tipos_permitidos and ioc.vt_sha256:
                        valor_final = ioc.vt_sha256; tipo_final = 'sha256'; encontrado = True
                    elif 'sha1' in tipos_permitidos and ioc.vt_sha1 and not encontrado:
                        valor_final = ioc.vt_sha1; tipo_final = 'sha1'; encontrado = True
                    elif 'md5' in tipos_permitidos and ioc.vt_md5 and not encontrado:
                        valor_final = ioc.vt_md5; tipo_final = 'md5'; encontrado = True

                    if not encontrado:
                        largo = len(ioc.valor.strip())
                        tipo_detectado = 'unknown'
                        if largo == 32: tipo_detectado = 'md5'
                        elif largo == 40: tipo_detectado = 'sha1'
                        elif largo == 64: tipo_detectado = 'sha256'
                        
                        if tipo_detectado in tipos_permitidos:
                            valor_final = ioc.valor
                            tipo_final = tipo_detectado
                            encontrado = True
                    
                    if not encontrado: continue 

                # Fallback de Hashes Vacíos
                val_md5 = ioc.vt_md5 or (ioc.valor if ioc.tipo == 'md5' or len(ioc.valor)==32 else '')
                val_sha1 = ioc.vt_sha1 or (ioc.valor if ioc.tipo == 'sha1' or len(ioc.valor)==40 else '')
                val_sha256 = ioc.vt_sha256 or (ioc.valor if ioc.tipo == 'sha256' or len(ioc.valor)==64 else '')
                
                nombre_archivo_vt = motores.get('filename', 'Desconocido')
                if nombre_archivo_vt == '-': nombre_archivo_vt = 'Desconocido'

                variables = {
                    'valor': valor_final,
                    'tipo': ioc.tipo,
                    'tipo_real': tipo_final,
                    'ticket': nombre_ref,
                    'filename': nombre_archivo_vt,
                    'md5': val_md5,
                    'sha1': val_sha1,
                    'sha256': val_sha256,
                    'positives': ioc.vt_positives,
                    'total': ioc.vt_total,
                    'estado_motor': estado_motor
                }
                
                try:
                    linea = template.row_template.format(**variables)
                    
                    linea = re.sub(r'<([a-zA-Z0-9]+)>0x</\1>\s*', '', linea)

                    if linea.strip():
                        contenido_archivo.append(linea)
                        count_agregados += 1
                        
                except Exception as e:
                    logger.error(f"Error template {template.nombre_plataforma}: {e}")

            if template.footer_content:
                contenido_archivo.append(template.footer_content)
            
            if count_agregados > 0:
                safe_name = "".join([c for c in template.nombre_plataforma if c.isalnum() or c in (' ', '_')]).rstrip()
                nombre_archivo_zip = f"Bloqueo_{nombre_ref}_{safe_name}.{template.file_extension}"
                zf.writestr(nombre_archivo_zip, "\n".join(contenido_archivo))

    zip_buffer.seek(0)
    return zip_buffer

def obtener_uso_api(api_key):
    """
    Consulta directa al endpoint de Usuario para obtener las cuotas oficiales.
    """
    # En VT API v3, puedes usar tu propia API Key como ID de usuario para ver tus datos
    url = f"https://www.virustotal.com/api/v3/users/{api_key}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            quotas = data.get("quotas", {}).get("api_requests_daily", {})
            quotas_hourly = data.get("quotas", {}).get("api_requests_hourly", {})
            quotas_monthly = data.get("quotas", {}).get("api_requests_monthly", {})

            return {
                "diario_usado": quotas.get("used", 0),
                "diario_limite": quotas.get("allowed", "N/A"),
                "hora_usado": quotas_hourly.get("used", 0),
                "hora_limite": quotas_hourly.get("allowed", "N/A"),
                "mensual_usado": quotas_monthly.get("used", 0),
                "mensual_limite": quotas_monthly.get("allowed", "N/A")
            }
        else:
            logger.error(f"Error VT Quota: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logger.error(f"Excepción consultando cuota VT: {e}")
        return None