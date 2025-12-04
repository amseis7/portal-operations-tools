from flask import render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from datetime import datetime
from app.extensions import db
from app.models import VtTicket, VtIoc, ExportTemplate # <--- Importar ExportTemplate
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
    caso = VtTicket.query.get_or_404(caso_id)
    
    if request.method == 'POST':
        raw = request.form.get('hashes_input')
        tipo_seleccionado = request.form.get('tipo_ioc')
        
        if raw:
            items = [line.strip() for line in raw.splitlines() if line.strip()]
            count = 0
            errores = 0
            
            # Regex en Python
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
    """
    Recorre los IoCs del caso VT y consulta a VirusTotal.
    Soporta filtro opcional ?tipo=hash|ip|url.
    """
    # Validar API Key
    if not current_user.virustotal_api_key:
        flash('Error: Configura tu API Key en "Mi Cuenta" antes de analizar.', 'danger')
        return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))

    caso = VtTicket.query.get_or_404(caso_id)
    
    # --- LÓGICA DE FILTRADO ---
    tipo_filtro = request.args.get('tipo')
    query = VtIoc.query.filter_by(ticket_id=caso_id)
    
    if tipo_filtro:
        if tipo_filtro == 'hash':
            query = query.filter(VtIoc.tipo.in_(['hash', 'md5', 'sha1', 'sha256']))
        else:
            query = query.filter(VtIoc.tipo == tipo_filtro)
            
    iocs = query.all()
    # --------------------------
    
    if not iocs:
        flash(f'No hay IoCs para analizar (Filtro: {tipo_filtro or "Todo"}).', 'warning')
        return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))

    # Ejecución del análisis
    cont_exito = 0
    # Detectar si se pidió forzar
    forzar_analisis = request.args.get('force') == 'true'
    
    for ioc in iocs:
        # Usamos la función lógica que ya es compatible con VtIoc
        if consultar_virustotal_ioc(ioc, forzar=forzar_analisis):
            cont_exito += 1
            
    flash(f'Análisis finalizado. {cont_exito}/{len(iocs)} IoCs actualizados.', 'success')
    return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))

@bp.route('/eliminar_caso/<int:caso_id>', methods=['POST'])
@login_required
def eliminar_caso(caso_id):
    """
    Elimina un caso de investigación y todos sus IoCs asociados.
    """
    caso = VtTicket.query.get_or_404(caso_id)
    
    # Seguridad: Solo el dueño del caso o un Admin pueden borrarlo
    if caso.usuario_id != current_user.id and not current_user.is_admin:
        flash('No tienes permiso para eliminar este caso.', 'danger')
        return redirect(url_for('virustotal.index'))

    try:
        # Borrado en cascada (gracias a la relación en models.py)
        db.session.delete(caso)
        db.session.commit()
        flash(f'Caso "{caso.nombre}" eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el caso: {str(e)}', 'danger')

    return redirect(url_for('virustotal.index'))


# --- RUTAS NUEVAS: EXPORTACIÓN Y ADMINISTRACIÓN ---

@bp.route('/exportar_zip/<int:caso_id>', methods=['POST'])
@login_required
def exportar_zip(caso_id):
    # Capturar los IDs de los switches activados
    selected_templates = request.form.getlist('templates_seleccionados')
    
    if not selected_templates:
        flash('Selecciona al menos una plataforma para exportar.', 'warning')
        return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))
    
    # Generar ZIP
    zip_file = generar_exportacion_multiformato(caso_id, selected_templates)
    
    fecha = datetime.now().strftime('%Y%m%d')
    return Response(
        zip_file,
        mimetype="application/zip",
        headers={"Content-disposition": f"attachment; filename=Pack_Bloqueo_Caso_{caso_id}_{fecha}.zip"}
    )

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