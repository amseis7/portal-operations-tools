import requests
import time
import logging
import base64
import csv
import zipfile
import re # <--- NUEVO IMPORT NECESARIO
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from flask import current_app
from flask_login import current_user
from sqlalchemy import func, or_
from app.extensions import db
from app.models import Ioc, ManualCheck, VtIoc, User, Alerta, ExportTemplate, VtTicket

logger = logging.getLogger(__name__)

# ... (Las funciones buscar_resultado_previo, consultar_virustotal_ioc, etc. SIGUEN IGUAL, no las borres) ...
# (Por brevedad, aquí pongo solo la función que cambia, pero tú mantén el resto del archivo)

def buscar_resultado_previo(valor_hash):
    # ... (Mismo código de antes) ...
    existente = Ioc.query.filter(
        or_(Ioc.vt_md5 == valor_hash, Ioc.vt_sha1 == valor_hash, Ioc.vt_sha256 == valor_hash, Ioc.valor == valor_hash),
        Ioc.vt_last_check != None
    ).order_by(Ioc.vt_last_check.desc()).first()

    if not existente:
        existente = VtIoc.query.filter(
            or_(VtIoc.vt_md5 == valor_hash, VtIoc.vt_sha1 == valor_hash, VtIoc.vt_sha256 == valor_hash, VtIoc.valor == valor_hash),
            VtIoc.vt_last_check != None
        ).order_by(VtIoc.vt_last_check.desc()).first()
    return existente

def consultar_virustotal_ioc(ioc_obj, forzar=False):
    """Consulta VT para un objeto (Ioc o VtIoc)."""
    
    # 1. CACHÉ
    if not forzar and ioc_obj.vt_last_check:
        tiempo = datetime.now() - ioc_obj.vt_last_check
        if tiempo.days < 7:
            return True

    # 2. API KEY
    api_key = current_user.get_vt_key()
    if not api_key: return False
    
    motores_interes = current_app.config['VT_MOTORES_INTERES']
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
                return False

    except Exception as e:
        logger.error(f"Excepción VT: {e}")
        return False
    return False

def consultar_vt_y_guardar(valor, tipo, user_id):
    # ... (Mismo código de antes) ...
    pass

def analizar_vt_ioc_objeto(ioc_obj):
    # ... (Mismo código de antes) ...
    pass

def generar_blacklist_caso(id_origen, motor_objetivo, origen='caso'):
    # ... (Mismo código de antes) ...
    pass

# --- AQUÍ ESTÁ LA CORRECCIÓN IMPORTANTE ---

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
                    
                    # --- LIMPIEZA AUTOMÁTICA PARA XML (NUEVO) ---
                    # Si la plantilla generó algo como <SHA1Hash>0x</SHA1Hash> (vacío), lo borramos.
                    # La regex busca: <Etiqueta>0x</Etiqueta> y lo reemplaza por nada.
                    linea = re.sub(r'<([a-zA-Z0-9]+)>0x</\1>\s*', '', linea)
                    # --------------------------------------------

                    # Solo agregamos la línea si no quedó vacía después de la limpieza
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