import requests
import re
import logging
from bs4 import BeautifulSoup
from datetime import datetime
import locale
from app.extensions import db
from app.models import Alerta, Ioc, Notification
from sqlalchemy import func

# Configuración de logging
logger = logging.getLogger(__name__)

# Intentamos configurar locale para fechas en español (ej: "10 de Enero")
try:
    locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_TIME, 'es_ES')
    except:
        logger.warning("No se pudo configurar locale es_ES. El parseo de fechas podría fallar si están en texto.")

# --- FUNCIONES AUXILIARES (TUS HERRAMIENTAS) ---

def decrypt_cfemail(cfemail):
    """Tu función original para desencriptar emails de Cloudflare"""
    try:
        key = int(cfemail[:2], 16)
        return ''.join(chr(int(cfemail[i:i+2], 16) ^ key) for i in range(2, len(cfemail), 2))
    except Exception:
        return ""

def convert_date(date_str):
    """
    Convierte fechas del CSIRT (ej: "12 de Enero de 2024") a objeto datetime.
    """
    try:
        # Limpieza básica
        date_str = date_str.strip().replace("  ", " ")
        # Intentamos formato con locale (ej: 12 de enero de 2024)
        # Nota: Ajustar el formato según cómo venga exactamente en la web
        return datetime.strptime(date_str, "%d de %B de %Y")
    except ValueError:
        # Fallback: Si falla, devolvemos fecha actual o intentamos otro formato
        try:
            return datetime.strptime(date_str, "%d-%m-%Y")
        except:
            return datetime.now()

def obtener_ultimos_ids_db():
    """
    Retorna diccionario con el último ID registrado por tipo.
    Ej: {'AIA': '13CN24-00150', 'ACF': '13CN24-00148'}
    """
    resultados = db.session.query(
        Alerta.tipo_alerta,
        func.max(Alerta.nombre_alerta)
    ).group_by(Alerta.tipo_alerta).all()

    return {tipo: nombre for tipo, nombre in resultados if tipo and nombre}

# --- FASE 1: ESCANEO ---

def escanear_y_guardar_alertas(ticket_gestion, responsable, simulacion=False):
    """
    Versión corregida con TU lógica original y TU regex.
    """
    # 1. Obtenemos lo último que tenemos en la BD (Equivalente a tu last_csirt_in_sheets)
    # Retorna ej: {'AIA': 'AIA-23-001', 'ACF': 'ACF-23-999'}
    referencia_db = obtener_ultimos_ids_db()
    
    # 2. Lista de tipos que ya encontramos (Equivalente a tu filter_csirt)
    # Si 'AIA' entra aquí, dejamos de guardar AIAs.
    # Se agrega AVC para no guardar alertas de vulnerabilidad pero sacar si se requiere procesar a futuro
    tipos_bloqueados = ['AVC'] 
    
    url_base = "https://www.csirt.gob.cl/alertas/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    alertas_nuevas_guardadas = []
    logger.info(f"Iniciando escaneo. Últimos registros en BD: {referencia_db}")

    for page in range(1, 11):
        try:
            resp = requests.get(f"{url_base}?p={page}", headers=headers, timeout=10)
            resp.raise_for_status() # Importante para detectar errores 404/500
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Tu selector original: buscar <a> que empiece con /alertas/
            items = soup.find_all('a', href=lambda x: x and x.startswith('/alertas/'))

            for item in items:
                # Evitar imágenes (tu check de 'picture')
                if item.find('picture'):
                    continue

                # Extraer Título (Link)
                # Tu código busca el h3 dentro del a
                h3_tag = item.find('h3')
                if not h3_tag:
                    continue
                
                # Nombre de la alerta (Ej: "8FPH23-00776...")
                nombre_alerta = h3_tag.get_text(strip=True).upper()
                
                # --- TU REGEX ORIGINAL PARA EL TIPO ---
                # Busca 3 letras seguidas de 2 dígitos (Ej: FPH23 -> FPH, AIA23 -> AIA)
                match_tipo = re.search(r'(?:(?<=\b)\d)?(\w{3})(?=\d{2})', nombre_alerta)
                
                if not match_tipo:
                    # Si no cumple el patrón (ej: una noticia sin código), la saltamos
                    continue
                
                tipo_detectado = match_tipo.group(1) # Ej: "AIA", "ACF", "FPH"

                # --- TU LÓGICA DE PARADA (ADAPTADA) ---
                
                # 1. ¿Este tipo ya está bloqueado? (Ya encontramos la última vieja)
                if tipo_detectado in tipos_bloqueados:
                    continue

                # 2. Obtenemos la última alerta de este tipo que tenemos en BD
                # (Usamos 'values' porque tu lógica comparaba values, aquí es directo por key)
                ultimo_en_db = referencia_db.get(tipo_detectado, "")

                # 3. Comparación: ¿Es esta alerta IGUAL a la que tengo en la BD?
                # Nota: Tu código usaba "in" (substring). Aquí hacemos lo mismo por seguridad.
                coincide = False
                if ultimo_en_db and ultimo_en_db in nombre_alerta:
                    coincide = True
                
                if coincide:
                    # ¡Encontramos la frontera!
                    logger.info(f"Tope encontrado para {tipo_detectado}: {nombre_alerta}. Dejando de buscar este tipo.")
                    print(f"Tope encontrado para {tipo_detectado}: {nombre_alerta}. Dejando de buscar este tipo.")
                    tipos_bloqueados.append(tipo_detectado)
                    continue

                # --- SI LLEGA AQUÍ, ES NUEVA ---
                print(nombre_alerta)
                # Extraer Fecha (Tu lógica de time)
                fecha_obj = datetime.now()
                time_tag = item.find('time')
                if time_tag:
                    try:
                        # Usamos tu replace(" ", "") y convert_date
                        fecha_str = time_tag.get_text().replace(" ", "")
                        # Aquí llamamos a una función auxiliar para parsear
                        # O usamos un genérico:
                        fecha_obj = convert_date(fecha_str) # Asegúrate que convert_date esté importada o definida
                    except:
                        pass

                # Guardado
                if not Alerta.query.filter_by(nombre_alerta=nombre_alerta).first():
                    nueva_alerta = Alerta(
                        nombre_alerta=nombre_alerta,
                        ticket=ticket_gestion,
                        tipo_alerta=tipo_detectado,
                        responsable=responsable,
                        fecha_realizacion=fecha_obj
                    )
                    
                    if simulacion:
                        logger.info(f"[SIM] Se guardaría: {nombre_alerta} ({tipo_detectado})")
                        alertas_nuevas_guardadas.append((nueva_alerta, item['href']))
                    else:
                        db.session.add(nueva_alerta)
                        alertas_nuevas_guardadas.append((nueva_alerta, item['href']))

            # Si NO es simulación, commit por página
            if not simulacion:
                db.session.commit()

        except Exception as e:
            logger.error(f"Error en página {page}: {e}")
            continue # Tu script original usaba continue en error de página

    return alertas_nuevas_guardadas

# --- FASE 2: DESCARGA DE IOCS ---

def descargar_iocs_para_alerta(alerta_obj, url_suffix, simulacion=False):
    """
    Recibe un objeto Alerta (ya guardado) y su URL parcial.
    Descarga los IOCs usando TU lógica de tabla y los guarda en BD.
    """
    full_url = f"https://www.csirt.gob.cl{url_suffix}"
    count_iocs = 0
    
    try:
        resp = requests.get(full_url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        table = soup.find('table')
        
        if not table:
            return 0

        # Tu lógica exacta de iteración de filas
        for row in table.find_all('tr'):
            cols = row.find_all(['th', 'td'])
            clean = []
            
            for cell in cols:
                encrypted = cell.find('a', class_='__cf_email__')
                if encrypted:
                    clean.append(decrypt_cfemail(encrypted['data-cfemail']))
                else:
                    clean.append(cell.get_text(strip=True))
            
            if len(clean) < 2: # Necesitamos al menos Tipo y Valor
                continue
            
            # Mapeo de tus columnas a nuestro modelo DB
            # clean[0] = Tipo (ipv4, url, etc), clean[1] = Valor
            tipo_raw = clean[0].lower()
            valor_raw = clean[1]
            descripcion = clean[2].lower()
            
            # Normalización de tipos para la BD
            tipo_db = 'otro'
            if 'ipv4' in tipo_raw or 'ip:' in tipo_raw:
                if 'smtp' in descripcion:
                    tipo_db = 'smtp'
                else:
                    tipo_db = 'ip'
            elif 'url' in tipo_raw:
                tipo_db = 'url'
            elif 'email' in tipo_raw:
                if 'asunto' in tipo_raw:
                    continue
                else:
                    tipo_db = 'email'
            elif 'sha' in tipo_raw or 'md5' in tipo_raw:
                tipo_db = 'hash'
            elif 'dominio' in tipo_raw:
                tipo_db = 'dominio'

            if tipo_db == 'otro':
                continue

            # Guardar IOC
            nuevo_ioc = Ioc(
                tipo=tipo_db,
                valor=valor_raw,
                alerta=alerta_obj # Relación SQLAlchemy mágica
            )
            if simulacion:
                print(f"[SIMULACION] Encontrado: {nuevo_ioc}")
            else:
                db.session.add(nuevo_ioc)
            count_iocs += 1

        if not simulacion:
            db.session.commit()
    
    except Exception as e:
        logger.error(f"Error descargando IOCs de {alerta_obj.nombre_alerta}: {e}")
    
    return count_iocs

# --- FUNCIÓN PRINCIPAL (ORQUESTADOR) ---

def ejecutar_proceso_csirt(ticket_rf, responsable, simulacion=False):
    """
    Esta es la función que llamará la Ruta.
    """
    # 1. Escanear y crear alertas
    lista_nuevas = escanear_y_guardar_alertas(ticket_rf, responsable, simulacion)
 
    if not lista_nuevas:
        return {"status": "sin_novedad", "msg": "No se encontraron alertas nuevas."}
    
    # 2. Descargar IOCs para las nuevas
    total_iocs = 0
    alertas_procesadas = []

    for alerta_obj, url_suffix in lista_nuevas:
        if "AVC" in alerta_obj.tipo_alerta or "AVC" in alerta_obj.nombre_alerta:
            logger.info(f"Saltando descarga de IoCs para {alerta_obj.nombre_alerta} (Tipo AVC)")
            continue

        c = descargar_iocs_para_alerta(alerta_obj, url_suffix, simulacion)
        total_iocs += c
        alertas_procesadas.append(alerta_obj.nombre_alerta)

     # Si es simulación, paramos aquí y avisamos
    if simulacion:
        return {
            "status": "exito", 
            "msg": f"[MODO PRUEBA] Simulación completa. Se detectaron {len(lista_nuevas)} alertas y se habrían extraído {total_iocs} IOCs. NO SE GUARDÓ NADA.",
            "alertas": alertas_procesadas
        }
        
    return {
        "status": "exito", 
        "msg": f"Se encontraron {len(lista_nuevas)} alertas nuevas y {total_iocs} IOCs.",
        "alertas": [a[0].nombre_alerta for a in lista_nuevas]
    }

# En app/csirt/logic.py

def actualizar_iocs_faltantes(ticket_id):
    """
    Busca todas las alertas de un ticket que NO tengan IoCs y trata de descargarlos.
    Retorna: (Alertas Actualizadas, Total IoCs Bajados)
    """
    # 1. Buscar alertas del ticket que no sean AVC (Vulnerabilidades)
    alertas = Alerta.query.filter(
        Alerta.ticket == ticket_id,
        Alerta.tipo_alerta != 'AVC' # Ignoramos AVCs
    ).all()
    
    alertas_actualizadas = 0
    total_iocs = 0
    
    for alerta in alertas:
        # 2. Verificar si ya tiene IoCs (Si tiene, la saltamos)
        if len(alerta.iocs) > 0:
            continue
            
        # 3. Construir la URL (Ingeniería inversa del nombre)
        # El sitio del CSIRT suele usar: /alertas/nombre-en-minusculas
        # Ej: ACF25-00155 -> /alertas/acf25-00155
        url_suffix = f"/alertas/{alerta.nombre_alerta.lower()}"
        
        logger.info(f"Intentando recuperar IoCs para {alerta.nombre_alerta} desde {url_suffix}")
        
        # 4. Reutilizamos tu función existente de descarga
        # Pasamos simulacion=False para que guarde de verdad
        cantidad = descargar_iocs_para_alerta(alerta, url_suffix, simulacion=False)
        
        if cantidad > 0:
            alertas_actualizadas += 1
            total_iocs += cantidad
            
    return alertas_actualizadas, total_iocs

def generador_actualizacion_masiva():
    """
    Generador que va reportando el progreso paso a paso.
    Yields: Strings con el estado actual.
    """
    # 1. Buscar alertas candidatas
    yield "Analizando base de datos buscando alertas sin IoCs...\n"
    
    alertas = Alerta.query.filter(Alerta.tipo_alerta != 'AVC').order_by(Alerta.fecha_realizacion.desc()).all()
    candidatas = [a for a in alertas if len(a.iocs) == 0]
    total = len(candidatas)
    
    if total == 0:
        yield "No se encontraron alertas pendientes de actualización.\n"
        return

    yield f"Se encontraron {total} alertas pendientes. Iniciando descarga...\n"
    
    actualizados = 0
    total_iocs = 0

    for i, alerta in enumerate(candidatas, 1):
        url_suffix = f"/alertas/{alerta.nombre_alerta.lower()}"
        
        try:
            # Mensaje de progreso
            yield f"[{i}/{total}] Procesando: {alerta.nombre_alerta}... "
            
            # Usamos la función de descarga existente (sin simulacion)
            cantidad = descargar_iocs_para_alerta(alerta, url_suffix, simulacion=False)
            
            if cantidad > 0:
                yield f"OK (+{cantidad} IoCs)\n"
                actualizados += 1
                total_iocs += cantidad
            else:
                yield "Sin IoCs (o error 404)\n"
                
        except Exception as e:
            yield f"ERROR: {str(e)}\n"
            logger.error(f"Fallo en masivo {alerta.nombre_alerta}: {e}")

    yield f"\n--- PROCESO FINALIZADO ---\n"
    yield f"Resumen: {actualizados} alertas actualizadas, {total_iocs} nuevos IoCs guardados.\n"

def vigilar_nuevas_alertas(app):
    """
    Versión DEPURACIÓN: Imprime todo en consola para verificar funcionamiento.
    """
    with app.app_context():
        print("\n--- [VIGILANTE] Iniciando ronda de vigilancia ---")
        
        # 1. Obtener referencia DB
        referencia_db = obtener_ultimos_ids_db()
        print(f"[VIGILANTE] Últimos en BD: {referencia_db}")
        
        url_base = "https://www.csirt.gob.cl/alertas/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        nuevas_detectadas = 0
        tipos_vistos = []

        try:
            print(f"[VIGILANTE] Conectando a {url_base}...")
            resp = requests.get(url_base, headers=headers, timeout=10)
            
            if resp.status_code != 200:
                print(f"[VIGILANTE] Error HTTP: {resp.status_code}")
                return

            soup = BeautifulSoup(resp.text, 'html.parser')
            items = soup.find_all('a', href=lambda x: x and x.startswith('/alertas/'))
            
            print(f"[VIGILANTE] Se encontraron {len(items)} enlaces a alertas. Analizando...")

            for item in items:
                # Evitar fotos
                if item.find('picture'): continue
                
                # Buscar título
                h3 = item.find('h3')
                if not h3: continue
                
                nombre = h3.get_text(strip=True).upper()
                
                # --- CORRECCIÓN: USAR TU REGEX PROBADA ---
                # Buscamos el TIPO (Ej: AIA, ACF)
                match_tipo = re.search(r'(?:(?<=\b)\d)?(\w{3})(?=\d{2})', nombre)
                
                if not match_tipo: 
                    # print(f"[VIGILANTE] Ignorando: {nombre} (No cumple formato)")
                    continue
                
                tipo = match_tipo.group(1)
                alerta_id = nombre # Usamos el nombre completo como ID para comparar

                if "AVC" in tipo or "AVC" in nombre:
                    print(f"[VIGILANTE] Ignorando alerta de Vulnerabilidad: {nombre}")
                    continue

                # Si ya revisamos este tipo en esta ronda, saltamos
                if tipo in tipos_vistos: continue

                # COMPARACIÓN
                ultimo_db = referencia_db.get(tipo, "")
                
                # Debug de comparación
                # print(f"[VIGILANTE] Comparando Web '{alerta_id}' vs DB '{ultimo_db}' ({tipo})")

                if ultimo_db == "" or alerta_id > ultimo_db:
                    # ¡ALERTA NUEVA!
                    # Ojo: Si la DB está vacía para ese tipo, alerta_id siempre será "mayor" a ""
                    if alerta_id != ultimo_db: # Doble chequeo simple
                        print(f"[VIGILANTE] 🔥 ¡NUEVA DETECTADA!: {alerta_id}")
                        nuevas_detectadas += 1
                        tipos_vistos.append(tipo)
                else:
                    # Ya encontramos una vieja, dejamos de mirar este tipo
                    tipos_vistos.append(tipo)
            
            # 3. Crear Notificación
            if nuevas_detectadas > 0:
                msg = f"⚠️ El sistema detectó {nuevas_detectadas} nuevas alertas CSIRT disponibles."
                
                # Verificar si ya existe notificación pendiente
                existe = Notification.query.filter_by(message=msg, is_read=False).first()
                
                if not existe:
                    notif = Notification(
                        message=msg,
                        category="csirt",
                        link="/csirt"
                    )
                    db.session.add(notif)
                    db.session.commit()
                    print(f"[VIGILANTE] Notificación guardada en DB.")
                else:
                    print("[VIGILANTE] Ya existe aviso pendiente. No duplicamos.")
            else:
                print("[VIGILANTE] Sin novedades. Todo al día.")

        except Exception as e:
            print(f"[VIGILANTE] ERROR CRÍTICO: {e}")