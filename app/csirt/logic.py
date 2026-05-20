import requests
import re
import logging
import xml.etree.ElementTree as ET
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
except Exception:
    try:
        locale.setlocale(locale.LC_TIME, 'es_ES')
    except Exception:
        logger.warning("No se pudo configurar locale es_ES. El parseo de fechas podría fallar si están en texto.")

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
        except Exception:
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

def obtener_alertas_desde_rss(max_items=10):
    """
    Extrae alertas desde el feed RSS oficial de CSIRT.
    Retorna lista de dicts: {id, tipo, fecha, titulo, url_suffix} o None si falla.
    RSS es estándar W3C, no depende de HTML.
    """
    url_rss = "https://www.csirt.gob.cl/rss/alertas"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    try:
        resp = requests.get(url_rss, headers=headers, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"[RSS] Error fetching feed: {e}")
        return None

    try:
        root = ET.fromstring(resp.content)
        channel = root.find('channel')
        items = channel.findall('item')[:max_items]
    except Exception as e:
        logger.error(f"[RSS] Error parsing XML: {e}")
        return None

    alertas = []
    for item in items:
        link = item.findtext('link', '')
        pubdate_str = item.findtext('pubDate', '')

        alert_id = link.strip('/').split('/')[-1].upper()

        match_tipo = re.search(r'(?:(?<=\b)\d)?(\w{3})(?=\d{2})', alert_id)
        if not match_tipo:
            continue
        tipo = match_tipo.group(1)

        try:
            dt = datetime.strptime(pubdate_str, '%a, %d %b %Y %H:%M:%S %z')
            fecha = dt.replace(tzinfo=None)
        except Exception:
            fecha = datetime.now()

        alertas.append({
            'id': alert_id,
            'tipo': tipo,
            'fecha': fecha,
            'titulo': item.findtext('title', ''),
            'url_suffix': f"/alertas/{alert_id.lower()}/"
        })

    logger.info(f"[RSS] Se obtuvieron {len(alertas)} alertas del feed RSS")
    return alertas


def escanear_y_guardar_alertas_desde_html(max_paginas=10):
    """
    Extrae alertas desde HTML usando la URL para obtener el ID.
    No depende de selectores CSS (h2, h3, etc).
    """
    url_base = "https://www.csirt.gob.cl/alertas/"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    alertas = []

    for page in range(1, max_paginas + 1):
        try:
            resp = requests.get(f"{url_base}?p={page}", headers=headers, timeout=10)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')

            hrefs_vistos = set()
            for link in soup.find_all('a', href=lambda x: x and x.startswith('/alertas/')):
                href = link['href']
                if href in hrefs_vistos:
                    continue
                hrefs_vistos.add(href)

                alert_id = href.strip('/').split('/')[-1].upper()
                match_tipo = re.search(r'(?:(?<=\b)\d)?(\w{3})(?=\d{2})', alert_id)
                if not match_tipo:
                    continue

                time_tag = link.find('time')
                fecha = datetime.now()
                if time_tag:
                    try:
                        fecha = convert_date(time_tag.get_text())
                    except Exception:
                        pass

                alertas.append({
                    'id': alert_id,
                    'tipo': match_tipo.group(1),
                    'fecha': fecha,
                    'url_suffix': href
                })
        except Exception as e:
            logger.error(f"[HTML Fallback] Error en página {page}: {e}")
            continue

    logger.info(f"[HTML Fallback] Se obtuvieron {len(alertas)} alertas del HTML")
    return alertas


def escanear_y_guardar_alertas(ticket_gestion, responsable, simulacion=False, user_id=None):
    """
    Extrae alertas del CSIRT y guarda las nuevas.
    Estrategia: RSS + HTML en paralelo, merge por ID.
    """
    referencia_db = obtener_ultimos_ids_db()
    logger.info(f"Iniciando escaneo. Últimos registros en BD: {referencia_db}")

    # --- RSS (rápido, confiable, ~10 items recientes) ---
    alertas_rss = obtener_alertas_desde_rss() or []

    # --- HTML con URL extraction (cobertura completa, 10 páginas ~90 items) ---
    alertas_html = escanear_y_guardar_alertas_desde_html(max_paginas=10) or []

    # --- MERGE: combinar ambas fuentes, priorizar RSS (tiene fecha real), deduplicar por ID ---
    vistos = set()
    alertas_raw = []
    for a in alertas_html + alertas_rss:
        if a['id'] not in vistos:
            vistos.add(a['id'])
            alertas_raw.append(a)

    if not alertas_raw:
        return []

    # --- LÓGICA COMÚN: Guardar alertas nuevas ---
    alertas_nuevas_guardadas = []
    tipos_bloqueados = ['AVC', 'AIC']  # Vulnerabilidades e Incidentes en Curso: sin IoCs bloqueables

    for alerta in alertas_raw:
        if alerta['tipo'] in tipos_bloqueados:
            continue

        # Verificar si ya existe en DB
        if Alerta.query.filter_by(nombre_alerta=alerta['id']).first():
            continue

        # Verificar si es el tope (último registro conocido en DB)
        ultimo_en_db = referencia_db.get(alerta['tipo'], "")
        if ultimo_en_db and ultimo_en_db in alerta['id']:
            logger.info(f"Tope encontrado para {alerta['tipo']}: {alerta['id']}. Dejando de buscar este tipo.")
            tipos_bloqueados.append(alerta['tipo'])
            continue

        # Crear nueva alerta
        logger.info(f"Alerta nueva detectada: {alerta['id']}")
        nueva_alerta = Alerta(
            nombre_alerta=alerta['id'],
            ticket=ticket_gestion,
            tipo_alerta=alerta['tipo'],
            responsable=responsable,
            fecha_realizacion=alerta['fecha'],
            user_id=user_id
        )

        if simulacion:
            logger.info(f"[SIM] Se guardaría: {alerta['id']} ({alerta['tipo']})")
        else:
            db.session.add(nueva_alerta)
            db.session.commit()

        alertas_nuevas_guardadas.append((nueva_alerta, alerta['url_suffix']))

    return alertas_nuevas_guardadas

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
                logger.info(f"[SIMULACION] Encontrado: {nuevo_ioc}")
            else:
                db.session.add(nuevo_ioc)
            count_iocs += 1

        if not simulacion:
            db.session.commit()
    
    except Exception as e:
        logger.error(f"Error descargando IOCs de {alerta_obj.nombre_alerta}: {e}")
    
    return count_iocs

def ejecutar_proceso_csirt(ticket_rf, responsable, simulacion=False, user_id=None):
    """
    Esta es la función que llamará la Ruta.
    """
    # 1. Escanear y crear alertas
    lista_nuevas = escanear_y_guardar_alertas(ticket_rf, responsable, simulacion, user_id=user_id)
 
    if not lista_nuevas:
        return {"status": "sin_novedad", "msg": "No se encontraron alertas nuevas."}
    
    # 2. Descargar IOCs para las nuevas
    total_iocs = 0
    alertas_procesadas = []

    for alerta_obj, url_suffix in lista_nuevas:
        if alerta_obj.tipo_alerta in ('AVC', 'AIC') or 'AVC' in alerta_obj.nombre_alerta or 'AIC' in alerta_obj.nombre_alerta:
            logger.info(f"Saltando descarga de IoCs para {alerta_obj.nombre_alerta} (Tipo {alerta_obj.tipo_alerta})")
            continue

        c = descargar_iocs_para_alerta(alerta_obj, url_suffix, simulacion)

        if "AIA" in alerta_obj.tipo_alerta and c == 0 and not simulacion:
            db.session.delete(alerta_obj)
            db.session.commit()
            logger.info(f"AIA sin IoCs eliminada: {alerta_obj.nombre_alerta}")
            continue

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

def actualizar_iocs_faltantes(ticket_id):
    """
    Busca todas las alertas de un ticket que NO tengan IoCs y trata de descargarlos.
    Retorna: (Alertas Actualizadas, Total IoCs Bajados)
    """
    # 1. Buscar alertas del ticket que no sean AVC (Vulnerabilidades)
    alertas = Alerta.query.filter(
        Alerta.ticket == ticket_id,
        Alerta.tipo_alerta.notin_(['AVC', 'AIC'])  # Sin IoCs bloqueables
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
    
    alertas = Alerta.query.filter(
        Alerta.tipo_alerta.notin_(['AVC', 'AIC'])
    ).order_by(Alerta.fecha_realizacion.desc()).all()
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
    Vigila nuevas alertas CSIRT y crea notificaciones.
    Usa RSS como fuente principal, con fallback HTML.
    """
    with app.app_context():
        logger.info("\n--- [VIGILANTE] Iniciando ronda de vigilancia ---")
        
        referencia_db = obtener_ultimos_ids_db()
        logger.info(f"[VIGILANTE] Últimos en BD: {referencia_db}")
        
        # --- ESTRATEGIA 1: RSS ---
        alertas_raw = obtener_alertas_desde_rss(max_items=5)
        
        # --- ESTRATEGIA 2: Fallback HTML ---
        if alertas_raw is None:
            logger.warning("[VIGILANTE] RSS falló, usando fallback HTML")
            alertas_raw = escanear_y_guardar_alertas_desde_html(max_paginas=1)
        
        if not alertas_raw:
            logger.info("[VIGILANTE] No se pudieron obtener alertas.")
            return
        
        nuevas_detectadas = 0
        tipos_vistos = []
        
        for alerta in alertas_raw:
            if alerta['tipo'] in tipos_vistos:
                continue
            if alerta['tipo'] in ('AVC', 'AIC'):
                continue
            
            ultimo_db = referencia_db.get(alerta['tipo'], "")
            
            if not ultimo_db or alerta['id'] > ultimo_db:
                if alerta['id'] != ultimo_db:
                    logger.info(f"[VIGILANTE] ¡NUEVA DETECTADA!: {alerta['id']}")
                    nuevas_detectadas += 1
                    tipos_vistos.append(alerta['tipo'])
            else:
                tipos_vistos.append(alerta['tipo'])
        
        # Crear Notificación
        if nuevas_detectadas > 0:
            msg = f"⚠️ El sistema detectó {nuevas_detectadas} nuevas alertas CSIRT disponibles."
            existe = Notification.query.filter_by(message=msg, is_read=False).first()
            if not existe:
                notif = Notification(message=msg, category="csirt", link="/csirt")
                db.session.add(notif)
                db.session.commit()
                logger.info(f"[VIGILANTE] Notificación guardada en DB.")
            else:
                logger.info("[VIGILANTE] Ya existe aviso pendiente. No duplicamos.")
        else:
            logger.info("[VIGILANTE] Sin novedades. Todo al día.")

def obtener_mapa_recurrencia(lista_iocs):
    if not lista_iocs:
        return {}

    valores_en_pantalla = [ioc.valor for ioc in lista_iocs]
    
    # Consulta agrupada optimizada
    stats = db.session.query(Ioc.valor, func.count(Ioc.id))\
        .filter(Ioc.valor.in_(valores_en_pantalla))\
        .group_by(Ioc.valor).all()
    
    return {item[0]: item[1] for item in stats}