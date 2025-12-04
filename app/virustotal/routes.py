from flask import render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from datetime import datetime
from app.extensions import db
from app.models import VtTicket, VtIoc, ExportTemplate, Alerta, Ioc # <--- Importar ExportTemplate
from app.virustotal import bp
from app.virustotal.logic import consultar_virustotal_ioc, generar_exportacion_multiformato
import re

# --- RUTAS DE GESTIÓN DE CASOS ---

@bp.route('/')
@login_required
def index():
    tickets = VtTicket.query.order_by(VtTicket.fecha_creacion.desc()).all()
    return render_template('virustotal/index.html', tickets=tickets, titulo_navbar="Investigaciones VT")

@bp.route('/crear_caso', methods=['POST'])
@login_required
def crear_caso():
    nombre = request.form.get('nombre')
    descripcion = request.form.get('descripcion')
    nuevo = VtTicket(nombre=nombre, descripcion=descripcion, usuario_id=current_user.id)
    db.session.add(nuevo)
    db.session.commit()
    flash('Caso creado.', 'success')
    return redirect(url_for('virustotal.ver_caso', caso_id=nuevo.id))

@bp.route('/caso/<int:caso_id>', methods=['GET', 'POST'])
@login_required
def ver_caso(caso_id):
    # ... (Tu código actual de ver_caso) ...
    caso = VtTicket.query.get_or_404(caso_id)
    
    if request.method == 'POST':
        raw = request.form.get('hashes_input')
        tipo_seleccionado = request.form.get('tipo_ioc')
        
        if raw:
            items = [line.strip() for line in raw.splitlines() if line.strip()]
            count = 0
            errores = 0
            
            patron_ip = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
            patron_hash = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
            
            for item in items:
                es_valido = True
                valor_limpio = item

                if tipo_seleccionado == 'ip':
                    if not re.match(patron_ip, item): es_valido = False
                elif tipo_seleccionado == 'hash':
                    if not re.match(patron_hash, item): es_valido = False
                elif tipo_seleccionado == 'dominio':
                    valor_limpio = item.replace("https://", "").replace("http://", "").split("/")[0]
                    if '.' not in valor_limpio: es_valido = False

                if es_valido:
                    existe = VtIoc.query.filter_by(ticket_id=caso.id, valor=valor_limpio).first()
                    if not existe:
                        nuevo_ioc = VtIoc(ticket_id=caso.id, tipo=tipo_seleccionado, valor=valor_limpio)
                        db.session.add(nuevo_ioc)
                        count += 1
                else:
                    errores += 1
            
            db.session.commit()
            if errores > 0:
                flash(f'Se agregaron {count}. Ignorados {errores} por formato.', 'warning')
            else:
                flash(f'{count} IoCs agregados.', 'success')
            return redirect(url_for('virustotal.ver_caso', caso_id=caso.id))

    templates_export = ExportTemplate.query.all()
    return render_template('virustotal/detalle_caso.html', caso=caso, titulo_navbar=f"Caso #{caso.id}", templates_export=templates_export)

@bp.route('/analizar_caso/<int:caso_id>', methods=['POST'])
@login_required
def analizar_caso(caso_id):
    # ... (Tu código existente para analizar un caso VT manual) ...
    # Asegúrate de mantener este endpoint porque lo usas dentro de ver_caso
    if not current_user.virustotal_api_key:
        flash('Error: Configura tu API Key primero.', 'danger')
        return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))

    caso = VtTicket.query.get_or_404(caso_id)
    tipo_filtro = request.args.get('tipo')
    
    query = VtIoc.query.filter_by(ticket_id=caso_id)
    if tipo_filtro:
        if tipo_filtro == 'hash':
            query = query.filter(VtIoc.tipo.in_(['hash', 'md5', 'sha1', 'sha256']))
        else:
            query = query.filter(VtIoc.tipo == tipo_filtro)
            
    iocs = query.all()
    if not iocs:
        flash('No hay IoCs para analizar.', 'warning')
        return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))

    cont_exito = 0
    force = request.args.get('force') == 'true'
    for ioc in iocs:
        if consultar_virustotal_ioc(ioc, forzar=force):
            cont_exito += 1
            
    flash(f'Análisis finalizado. {cont_exito}/{len(iocs)} actualizados.', 'success')
    return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))

# ==============================================================================
#  NUEVAS RUTAS DE INTEGRACIÓN CSIRT -> VT (IMPORTACIÓN AUTOMÁTICA)
# ==============================================================================

def _procesar_importacion_csirt(nombre_ticket_csirt, iocs_origen):
    """
    Función auxiliar que:
    1. Busca/Crea un Caso VT con el nombre del ticket CSIRT.
    2. Copia los IoCs de CSIRT a ese Caso VT (si no existen).
    3. Ejecuta el análisis en VT para los IoCs del Caso.
    4. Retorna el ID del caso VT para redirección.
    """
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
    
    # 3. Analizar
    if not current_user.virustotal_api_key:
        flash('IoCs importados, pero NO analizados. Configura tu API Key.', 'warning')
        return caso_vt.id

    cont_exito = 0
    force = request.args.get('force') == 'true'
    
    for ioc_vt in vt_iocs_a_analizar:
        if consultar_virustotal_ioc(ioc_vt, forzar=force):
            cont_exito += 1
            
    flash(f'Proceso completado. {nuevos} IoCs importados. {cont_exito} analizados en VT.', 'success')
    return caso_vt.id


@bp.route('/analizar_ticket_csirt/<ticket_id>', methods=['POST'])
@login_required
def analizar_ticket_csirt(ticket_id):
    """
    Toma IoCs de un Ticket CSIRT (RF-...), crea un Caso VT y analiza.
    """
    # 1. Obtener IoCs origen
    query = db.session.query(Ioc).join(Alerta).filter(Alerta.ticket == ticket_id)

    # Filtros
    tipo_filtro = request.args.get('tipo')
    if tipo_filtro:
        if tipo_filtro == 'hash':
            query = query.filter(Ioc.tipo.in_(['hash', 'md5', 'sha1', 'sha256']))
        elif tipo_filtro == 'url':
            query = query.filter(Ioc.tipo.in_(['url', 'dominio']))
        else:
            query = query.filter(Ioc.tipo == tipo_filtro)

    iocs_csirt = query.all()
    
    if not iocs_csirt:
        flash(f'No se encontraron IoCs para importar en {ticket_id}.', 'warning')
        return redirect(url_for('csirt.ver_gestion', ticket_id=ticket_id))

    # 2. Procesar (Importar -> Analizar)
    caso_vt_id = _procesar_importacion_csirt(ticket_id, iocs_csirt)

    # 3. Redirigir al CASO VT (Nueva pantalla)
    return redirect(url_for('virustotal.ver_caso', caso_id=caso_vt_id))


@bp.route('/analizar_alerta/<int:alerta_id>', methods=['POST'])
@login_required
def analizar_alerta(alerta_id):
    """
    Toma IoCs de una Alerta específica, crea/actualiza el Caso VT del Ticket padre y analiza.
    """
    # 1. Obtener Alerta para saber el Ticket Padre
    alerta = Alerta.query.get_or_404(alerta_id)
    ticket_padre = alerta.ticket # Ej: RF-123456
    
    # 2. Obtener IoCs origen
    query = Ioc.query.filter_by(alerta_id=alerta_id)
    
    # Filtros
    tipo_filtro = request.args.get('tipo')
    if tipo_filtro:
        if tipo_filtro == 'hash':
            query = query.filter(Ioc.tipo.in_(['hash', 'md5', 'sha1', 'sha256']))
        elif tipo_filtro == 'url':
            query = query.filter(Ioc.tipo.in_(['url', 'dominio']))
        else:
            query = query.filter(Ioc.tipo == tipo_filtro)
            
    iocs_csirt = query.all()

    if not iocs_csirt:
        flash('No hay IoCs en esta alerta para importar.', 'warning')
        return redirect(url_for('csirt.ver_iocs_alerta', alerta_id=alerta_id))

    # 3. Procesar (Usamos el ticket del padre para agrupar todo en el mismo caso)
    caso_vt_id = _procesar_importacion_csirt(ticket_padre, iocs_csirt)

    # 4. Redirigir al CASO VT
    return redirect(url_for('virustotal.ver_caso', caso_id=caso_vt_id))

# ... (Resto de rutas admin_templates, eliminar_caso, etc.) ...
@bp.route('/eliminar_caso/<int:caso_id>', methods=['POST'])
@login_required
def eliminar_caso(caso_id):
    # (Mantén tu código de eliminación aquí)
    caso = VtTicket.query.get_or_404(caso_id)
    if caso.usuario_id != current_user.id and not current_user.is_admin:
        flash('No tienes permiso.', 'danger')
        return redirect(url_for('virustotal.index'))
    try:
        db.session.delete(caso)
        db.session.commit()
        flash('Caso eliminado.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {e}', 'danger')
    return redirect(url_for('virustotal.index'))

@bp.route('/exportar_zip/<int:caso_id>', methods=['POST'])
@login_required
def exportar_zip(caso_id):
    # (Mantén tu código de exportación aquí)
    selected = request.form.getlist('templates_seleccionados')
    if not selected:
        return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))
    zip_file = generar_exportacion_multiformato(caso_id, selected)
    fecha = datetime.now().strftime('%Y%m%d')
    return Response(zip_file, mimetype="application/zip", headers={"Content-disposition": f"attachment; filename=Pack_{caso_id}_{fecha}.zip"})
@bp.route('/admin/templates', methods=['GET', 'POST'])
@login_required
def admin_templates():
    if not current_user.is_admin:
        return redirect(url_for('virustotal.index'))
        
    if request.method == 'POST':
        t = ExportTemplate(
            nombre_plataforma=request.form.get('nombre'),
            vt_engine_name=request.form.get('vt_engine'),
            file_extension=request.form.get('extension'),
            header_content=request.form.get('header'),
            row_template=request.form.get('row_template'),
            supported_hashes=request.form.get("supported_hashes"),
            footer_content=request.form.get('footer')
        )
        db.session.add(t)
        db.session.commit()
        flash('Plantilla creada.', 'success')
    
    templates = ExportTemplate.query.all()
    return render_template('virustotal/admin_templates.html', templates=templates)

@bp.route('/admin/templates/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_template(id):
    if not current_user.is_admin: return redirect(url_for('virustotal.index'))
    t = ExportTemplate.query.get_or_404(id)
    db.session.delete(t)
    db.session.commit()
    return redirect(url_for('virustotal.admin_templates'))

@bp.route('/admin/templates/editar/<int:id>', methods=['POST'])
@login_required
def editar_template(id):
    # Seguridad: Solo admin
    if not current_user.is_admin: 
        return redirect(url_for('virustotal.index'))
    
    t = ExportTemplate.query.get_or_404(id)
    
    try:
        # Actualizar campos
        t.nombre_plataforma = request.form.get('nombre')
        t.vt_engine_name = request.form.get('vt_engine')
        t.file_extension = request.form.get('extension')
        t.supported_hashes = request.form.get('supported_hashes')
        t.header_content = request.form.get('header')
        t.row_template = request.form.get('row_template')
        t.footer_content = request.form.get('footer')
        
        db.session.commit()
        flash(f'Plantilla "{t.nombre_plataforma}" actualizada correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar: {e}', 'danger')
        
    return redirect(url_for('virustotal.admin_templates'))