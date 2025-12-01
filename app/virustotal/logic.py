import requests
import time
import logging
import base64
from datetime import datetime
from flask import current_app
from flask_login import current_user
from app.extensions import db
from app.models import Ioc

logger = logging.getLogger(__name__)

def consultar_virustotal_ioc(ioc_obj):
    api_key = current_user.get_vt_key()
    # --- DEBUG TEMPORAL (Borrar luego) ---
    # Imprime los primeros 5 caracteres para ver si es válida sin revelarla toda
    print(f"--- [DEBUG VT] Usando API Key: {api_key[:5]}... (Largo: {len(api_key)}) ---")
    # -------------------------------------
    if not api_key: return False
    
    motores_interes = current_app.config['VT_MOTORES_INTERES']
    headers = {"x-apikey": api_key}
    
    tipo = ioc_obj.tipo.lower()
    valor = ioc_obj.valor.strip()
    base_url = "https://www.virustotal.com/api/v3"
    
    # --- CORRECCIÓN DE ENDPOINTS ---
    if tipo in ['hash', 'md5', 'sha1', 'sha256']:
        endpoint = f"{base_url}/files/{valor}"
        
    elif tipo == 'ip':
        endpoint = f"{base_url}/ip_addresses/{valor}"
        
    elif tipo == 'dominio':
        endpoint = f"{base_url}/domains/{valor}"
        
    elif tipo == 'url':
        # VT exige: base64 del URL, y quitar los '=' del final
        try:
            url_id = base64.urlsafe_b64encode(valor.encode()).decode().strip("=")
            endpoint = f"{base_url}/urls/{url_id}"
        except:
            return False

    elif tipo == 'email':
        # VT no escanea emails directamente, solo dominios. Saltamos para no dar error.
        print(f"--- [DEBUG] Saltando Email {valor} (No soportado por API VT) ---")
        return False
        
    else:
        return False

    try:
        # Lógica de reintento (Tu código original)
        for _ in range(3):
            response = requests.get(endpoint, headers=headers, timeout=15)
            
            if response.status_code == 429: # Cuota excedida
                logger.warning("Cuota VT excedida. Esperando 60s...")
                time.sleep(60)
                continue
            
            if response.status_code == 200:
                data = response.json()
                
                # Parsear resultados
                attrs = data.get("data", {}).get("attributes", {})
                last_analysis = attrs.get("last_analysis_results", {})
                
                # 1. Datos Generales
                ioc_obj.vt_last_check = datetime.now()
                ioc_obj.vt_reputation = attrs.get("reputation", 0)
                ioc_obj.vt_md5 = attrs.get("md5")
                ioc_obj.vt_sha1 = attrs.get("sha1")
                ioc_obj.vt_sha256 = attrs.get("sha256")
                
                # El link varía según tipo
                type_link = 'file' if tipo in ['hash', 'md5', 'sha1'] else 'ip-address' if tipo == 'ip' else 'domain'
                ioc_obj.vt_permalink = f"https://www.virustotal.com/gui/{type_link}/{valor}"

                # 2. Motores Específicos (Tu requerimiento clave)
                resultados_motores = {}
                for motor in motores_interes:
                    # Buscamos si el motor está en el análisis
                    # El formato de VT suele ser "McAfee", "TrendMicro-HouseCall", etc.
                    # A veces el nombre en el config no coincide exacto, hay que tener ojo ahí.
                    motor_data = last_analysis.get(motor)
                    
                    if motor_data:
                        # Guardamos el resultado: "malicious", "clean", "undetected"
                        resultados_motores[motor] = motor_data.get("category", "unknown")
                    else:
                        resultados_motores[motor] = "not_scanned"
                
                # Guardamos el JSON en la BD
                ioc_obj.set_motores(resultados_motores)
                
                db.session.commit()
                return True
            
            elif response.status_code == 404:
                logger.info(f"IoC {valor} no encontrado en VT.")
                return False
            else:
                logger.error(f"Error VT {response.status_code}: {response.text}")
                return False
                
    except Exception as e:
        logger.error(f"Excepción conectando a VT: {e}")
        return False
    
    return False