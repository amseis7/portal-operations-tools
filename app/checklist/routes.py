from flask import render_template, request, flash, redirect, url_for, jsonify
from datetime import datetime, date
from app import db
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
    
    # Preparamos la lista de plugins para el <select> del HTML
    plugins_info = []
    for slug, plugin_class in AVAILABLE_PLUGINS.items():
        plugins_info.append({
            'slug': slug,
            'nombre': plugin_class.nombre
        })
        
    return render_template('checklist/admin_config.html', 
                           servicios=servicios, 
                           plugins=plugins_info)

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
def guardar_servicio():
    try:
        # Datos fijos
        nombre_cliente = request.form.get('nombre_cliente')
        plugin_slug = request.form.get('plugin_slug')
        
        # Datos dinámicos (Credenciales)
        # Recorremos los campos que pide el plugin para extraerlos del request.form
        plugin_class = get_plugin_class(plugin_slug)
        campos_requeridos = plugin_class.get_form_fields()
        
        credenciales_dict = {}
        for campo in campos_requeridos:
            key = campo['name']
            credenciales_dict[key] = request.form.get(key)
            
        # Creamos la instancia en DB
        nuevo_servicio = ChecklistService(
            nombre_cliente=nombre_cliente,
            tipo_tecnologia=plugin_slug
        )
        # Encriptamos y guardamos
        nuevo_servicio.set_config(credenciales_dict)
        
        db.session.add(nuevo_servicio)
        db.session.commit()
        
        flash(f'Servicio para {nombre_cliente} creado correctamente.', 'success')
        
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
    
    return redirect(url_for('checklist.config'))