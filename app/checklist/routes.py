from flask import render_template, request, flash, redirect, url_for, jsonify
from datetime import datetime, date
from app import db, csrf
from flask_wtf.csrf import CSRFProtect
from flask_login import current_user
from app.checklist import bp
from app.utils import proteger_blueprint, admin_required
from app.models import ChecklistService, ChecklistReview
from app.checklist.plugins import AVAILABLE_PLUGINS, get_plugin_class

# Import Temporal
from flask import current_app
from app.checklist.tasks import ejecutar_barrido_checklist

proteger_blueprint(bp, 'checklist')

@bp.route('/')
def index():
    """
    Dashboard checklist con las tarjetas de estado.
    """
    servicios = ChecklistService.query.all()
    hoy = date.today()

    # Logica para saber si ya se revisó hoy
    # Inyectaremos atributos temporales a los objetos 'svc' para usarlos en el HTML
    for svc in servicios:
        # Buscamos la última revisión de este servicio
        ultima_revision = svc.reviews.order_by(ChecklistReview.timestamp.desc()).first()

        svc.revisado_hoy = False
        svc.ultimo_revisor = None
        svc.hora_revision = None

        if ultima_revision:
            # Comparamos fechas (solo día, mes, año)
            if ultima_revision.timestamp.date() == hoy:
                svc.revisado_hoy = True
                svc.ultimo_revisor = ultima_revision.user.username # Asumiendo relación con User
                svc.hora_revision = ultima_revision.timestamp.strftime('%H:%M')
                svc.comentario_revision = ultima_revision.comentario
    
    return render_template('checklist/index.html', 
                           titulo_navbar="Estado de Plataformas",
                           servicios=servicios)

# --- RUTA 1: VISTA PRINCIPAL DE CONFIGURACIÓN ---
@bp.route('/config')
@admin_required # ¡Solo admins pueden ver/tocar credenciales!
def config():
    # Listamos los servicios existentes
    servicios = ChecklistService.query.all()

    configs_map = {}
    for svc in servicios:
        datos = svc.get_config()
        configs_map[svc.id] = datos
    
    # Preparamos la lista de plugins para el <select> del HTML
    plugins_info = []
    plugin_defs_js = {}
    for slug, plugin_class in AVAILABLE_PLUGINS.items():
        campos = plugin_class.get_form_fields()
        plugins_info.append({
            'slug': slug,
            'nombre': plugin_class.nombre,
            'fields': plugin_class.get_form_fields()
        })
        plugin_defs_js[slug] = campos
        
    return render_template('checklist/admin_config.html', 
                           servicios=servicios, 
                           plugins=plugins_info,
                           saved_configs=configs_map,
                           plugin_defs_js=plugin_defs_js)

# --- RUTA 2: API PARA OBTENER CAMPOS (AJAX) ---
@bp.route('/api/get_fields/<slug>')
@admin_required
def api_get_fields(slug):
    """Retorna qué campos necesita un plugin específico (para dibujar el form)"""
    plugin_class = get_plugin_class(slug)
    if not plugin_class:
        return jsonify({'error': 'Plugin no encontrado'}), 404
    
    return jsonify(plugin_class.get_form_fields())

# --- RUTA 3: PROBAR CONEXIÓN (AJAX) ---
@bp.route('/api/test_connection', methods=['POST'])
@admin_required
def api_test_connection():
    data = request.json
    slug = data.get('plugin_slug')
    credenciales = data.get('credentials', {})

    plugin_class = get_plugin_class(slug)
    if not plugin_class:
        return jsonify({'success': False, 'message': 'Plugin inválido'})

    # Instanciamos el plugin con los datos del formulario
    try:
        plugin = plugin_class(credenciales)
        exito, mensaje = plugin.test_connection()
        return jsonify({'success': exito, 'message': mensaje})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# --- RUTA 4: GUARDAR SERVICIO ---
@bp.route('/guardar', methods=['POST'])
@admin_required
#@csrf.exempt
def guardar_servicio():
    try:
        # Datos fijos
        service_id = request.form.get('service_id')
        nombre_cliente = request.form.get('nombre_cliente')
        plugin_slug = request.form.get('plugin_slug')
        
        # Datos dinámicos (Credenciales)
        # Recorremos los campos que pide el plugin para extraerlos del request.form
        plugin_class = get_plugin_class(plugin_slug)
        if not plugin_class:
            flash('Error: Plugin no valido.', 'danger')
            return redirect(url_for('checklist.config'))
        
        campos_requeridos = plugin_class.get_form_fields()

        if service_id:
            servicio = ChecklistService.query.get_or_404(service_id)
            old_config = servicio.get_config()

            servicio.nombre_cliente = nombre_cliente
            flash_msg = f'Servicio {nombre_cliente} actualizado correctamente.'
        else:
            servicio = ChecklistService()
            servicio.nombre_cliente = nombre_cliente
            servicio.tipo_tecnologia = plugin_slug
            old_config = {}

            db.session.add(servicio)
            flash_msg = f'Servicio {nombre_cliente} creado correctamente.'
        
        new_config = {}
        for campo in campos_requeridos:
            key = campo['name']
            valor_form = request.form.get(key)

            if campo['type'] == 'password' and not valor_form:
                new_config[key] = old_config.get(key, '')
            else:
                new_config[key] = valor_form
            
        servicio.set_config(new_config)

        db.session.commit()
        flash(flash_msg, 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error guardando servicio: {str(e)}', 'danger')
        
    return redirect(url_for('checklist.config'))

# --- RUTA 5: ELIMINAR (Opcional por ahora, pero útil) ---
@bp.route('/eliminar/<int:id>', methods=['POST'])
@admin_required
def eliminar_servicio(id):
    svc = ChecklistService.query.get_or_404(id)
    db.session.delete(svc)
    db.session.commit()
    flash('Servicio eliminado.', 'success')
    return redirect(url_for('checklist.config'))

# --- RUTA 6: GUARDAR EL CHECK ---
@bp.route('/marcar_revisado/<int:service_id>', methods=['POST'])
def marcar_revisado(service_id):
    try:
        # Verificar que existe
        servicio = ChecklistService.query.get_or_404(service_id)

        comentario_texto = request.form.get('comentario', '').strip()
        
        # Crear la revisión
        nueva_revision = ChecklistReview(
            service_id=servicio.id,
            user_id=current_user.id,
            timestamp=datetime.now(),
            comentario=comentario_texto
        )
        
        db.session.add(nueva_revision)
        db.session.commit()
        
        flash(f'Validación registrada para {servicio.nombre_cliente}.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error al guardar revisión: {e}', 'danger')

    return redirect(url_for('checklist.index'))

# --- RUTA TEMPORAL: FORZAR ACTUALIZACION MANUAL ---
@bp.route('/forzar_actualizacion')
@admin_required
def forzar_actualizacion():
    # Truco: Pasamos current_app._get_current_object() para que la tarea tenga acceso a la config real
    try:
        ejecutar_barrido_checklist(current_app._get_current_object())
        flash('Actualización forzada ejecutada correctamente.', 'success')
    except Exception as e:
        flash(f'Error ejecutando tarea: {e}', 'danger')
    
    return redirect(request.referrer or url_for('checklist.index'))