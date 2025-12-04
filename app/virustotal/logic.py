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
    # ... (Mismo código de antes, asegúrate de copiar la versión FINAL que te di con vt_positives y stats) ...
    # ... (Si ya lo tienes bien, no hace falta cambiarlo, solo enfócate en la función de exportación abajo) ...
    # Para no hacer el mensaje eterno, asumo que esta parte ya la tienes correcta.
    # Si necesitas el archivo COMPLETO de nuevo dímelo.
    
    # REEMPLAZO RÁPIDO: Aquí va la lógica de consultar VT que ya funcionaba bien.
    # ...
    pass # (Placeholder para no repetir 200 líneas)

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