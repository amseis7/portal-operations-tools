import requests
import time
import logging
import base64
from datetime import datetime
from flask import current_app
from flask_login import current_user
from app.extensions import db
from app.models import Ioc, ManualCheck, VtIoc

logger = logging.getLogger(__name__)

def consultar_virustotal_ioc(ioc_obj, forzar=False):
    # --- LÓGICA DE CACHÉ (AHORRO DE CUOTA) ---
    if not forzar and ioc_obj.vt_last_check:
        tiempo_transcurrido = datetime.time - ioc_obj.vt_last_check

        if tiempo_transcurrido.days < 7:
            logger.info(f"IoC {ioc_obj.valor} analizado hace {tiempo_transcurrido.days} días. Usando caché.")
            return True

    # 1. Obtener API Key
    api_key = current_user.get_vt_key()
    if not api_key: return False
    
    motores_interes = current_app.config['VT_MOTORES_INTERES']
    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"
    
    # 2. Preparación y Limpieza de Datos
    tipo_db = ioc_obj.tipo.lower()
    valor_original = ioc_obj.valor.strip() # Quitar espacios
    endpoint = ""

    # --- LÓGICA DE HASHES ---
    if tipo_db in ['hash', 'md5', 'sha1', 'sha256']:
        endpoint = f"{base_url}/files/{valor_original}"

    # --- LÓGICA DE IPs ---
    elif tipo_db == 'ip':
        endpoint = f"{base_url}/ip_addresses/{valor_original}"

    # --- LÓGICA DE DOMINIOS (Limpieza agresiva) ---
    elif tipo_db == 'dominio':
        # Problema común: El scraper guarda 'https://sitio.com/'. VT quiere solo 'sitio.com'
        valor_limpio = valor_original.replace("https://", "").replace("http://", "").split("/")[0]
        endpoint = f"{base_url}/domains/{valor_limpio}"

    # --- LÓGICA DE URLs (Codificación Base64) ---
    elif tipo_db == 'url':
        try:
            # VT exige: URL -> Base64 -> Sin el padding '=' al final
            url_id = base64.urlsafe_b64encode(valor_original.encode()).decode().strip("=")
            endpoint = f"{base_url}/urls/{url_id}"
        except Exception as e:
            logger.error(f"Error codificando URL {valor_original}: {e}")
            return False
            
    else:
        # Tipo desconocido
        return False

    # 3. Ejecución de la Consulta
    try:
        # print(f"--- [DEBUG VT] Consultando: {endpoint} ---") # Descomentar si quieres ver la URL generada

        for _ in range(3): # Reintentos
            response = requests.get(endpoint, headers=headers, timeout=15)
            
            if response.status_code == 429:
                time.sleep(60) # Espera por cuota
                continue
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                last_analysis = attrs.get("last_analysis_results", {})
                
                # A. Datos Generales
                ioc_obj.vt_last_check = datetime.now()
                ioc_obj.vt_reputation = attrs.get("reputation", 0)
                
                # B. Hashes (Recuperamos los hashes incluso si buscamos por URL/IP)
                # Usamos .get() porque no siempre vienen todos
                ioc_obj.vt_md5 = attrs.get("md5")
                ioc_obj.vt_sha1 = attrs.get("sha1")
                ioc_obj.vt_sha256 = attrs.get("sha256")
                
                # C. Permalink (Enlace al reporte)
                # Reconstruimos el link según el tipo para que el usuario vaya directo
                type_link = 'file' 
                id_ref = valor_original
                
                if tipo_db == 'url': 
                    type_link = 'url'
                    # Para el link web, VT usa el hash SHA256 de la URL o el ID Base64
                    # Usamos el ID Base64 que calculamos arriba que es más seguro
                    id_ref = base64.urlsafe_b64encode(valor_original.encode()).decode().strip("=")
                elif tipo_db == 'dominio': 
                    type_link = 'domain'
                    id_ref = valor_original.replace("https://", "").replace("http://", "").split("/")[0]
                elif tipo_db == 'ip': 
                    type_link = 'ip-address'

                ioc_obj.vt_permalink = f"https://www.virustotal.com/gui/{type_link}/{id_ref}"

                # D. Guardar Motores
                resultados_motores = {}
                for motor in motores_interes:
                    datos_motor = last_analysis.get(motor)
                    if datos_motor:
                        resultados_motores[motor] = datos_motor.get("category", "unknown")
                    else:
                        resultados_motores[motor] = "not_scanned"
                
                # Nombre del archivo/página si existe
                resultados_motores["filename"] = attrs.get("meaningful_name", attrs.get("title", "-"))

                ioc_obj.set_motores(resultados_motores)
                db.session.commit()
                return True

            elif response.status_code == 404:
                # Manejo de "No Encontrado"
                ioc_obj.vt_last_check = datetime.now()
                ioc_obj.vt_reputation = 0
                ioc_obj.set_motores({"ERROR": "Not Found in VirusTotal"})
                
                # Link de búsqueda genérica
                ioc_obj.vt_permalink = f"https://www.virustotal.com/gui/search/{valor_original}"
                
                db.session.commit()
                return True
            
            else:
                # Otros errores (401, 500)
                # logger.error(f"Error VT {response.status_code}: {response.text}")
                return False

    except Exception as e:
        logger.error(f"Excepción conectando a VT: {e}")
        return False
    
    return False

def consultar_vt_y_guardar(valor, tipo, user_id):
    """
    Consulta VT y guarda el resultado en la tabla ManualCheck.
    """
    # 1. Obtener Key del usuario (necesitamos el objeto user o pasamos la key)
    # Para simplificar, asumimos que 'user_id' es el ID del usuario actual
    user = User.query.get(user_id)
    api_key = user.get_vt_key()
    
    if not api_key:
        return {'valor': valor, 'status': 'error_key'}

    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"
    motores_interes = current_app.config['VT_MOTORES_INTERES']

    # Construir Endpoint (igual que antes)
    valor = valor.strip()
    endpoint = ""
    if tipo == 'ip': endpoint = f"{base_url}/ip_addresses/{valor}"
    elif tipo == 'dominio': endpoint = f"{base_url}/domains/{valor}"
    else: endpoint = f"{base_url}/files/{valor}"

    # Objeto a guardar
    registro = ManualCheck(
        valor=valor,
        tipo=tipo,
        usuario_id=user_id
    )

    try:
        resp = requests.get(endpoint, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            attrs = data['data']['attributes']
            stats = attrs['last_analysis_stats']
            
            # Llenar datos
            registro.vt_score = f"{stats['malicious']}/{stats['malicious'] + stats['harmless']}"
            registro.vt_permalink = f"https://www.virustotal.com/gui/search/{valor}"
            
            # Motores específicos
            last_analysis = attrs.get('last_analysis_results', {})
            motores_res = {}
            for motor in motores_interes:
                res = last_analysis.get(motor)
                motores_res[motor] = res['category'] if res else 'not_scanned'
            
            registro.set_motores(motores_res)
            db.session.add(registro)
            db.session.commit()
            
            return {'valor': valor, 'status': 'ok', 'obj': registro}

        elif resp.status_code == 404:
            registro.vt_score = "Not Found"
            registro.vt_permalink = f"https://www.virustotal.com/gui/search/{valor}"
            db.session.add(registro)
            db.session.commit()
            return {'valor': valor, 'status': 'not_found', 'obj': registro}
            
    except Exception as e:
        logger.error(f"Error manual VT: {e}")
        return {'valor': valor, 'status': 'error'}

    return {'valor': valor, 'status': 'error'}

def analizar_vt_ioc_objeto(ioc_obj):
    return consultar_virustotal_ioc(ioc_obj)