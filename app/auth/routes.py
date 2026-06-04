from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from urllib.parse import urlparse
from app.models.user import User, UserTool
from app.extensions import db, limiter
from app.virustotal.logic import obtener_uso_api
from app.auth import bp
from app.utils import admin_required
import re
import logging
logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def validar_email(email):
    if not email:
        return True
    return bool(EMAIL_REGEX.match(email))

def validar_complejidad_password(password):
    """
    Verifica que la contreaseña cumpla con los estándares de seguridad:
    - Mínimo 8 caracteres
    - Al menos 1 número
    - Al menos 1 mayúscula
    - Al menos 1 símbolo especial
    """
    if len(password) < 8:
        return False, "La contraseña es muy corta. Debe tener al menos 8 caracteres."
    
    if not re.search(r"\d", password):
        return False, "La contraseña debe incluir al menos un número."
    
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña debe incluir al menos un alerta mayúscula."
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "La contraseña debe incluir al menos un simbolo especial (ej: !@#$).)"
    
    return True, ""

@bp.route('/setup', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def setup():
    admin_existente = User.query.filter_by(is_admin=True).first()
    if admin_existente:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        nombre = request.form.get('nombre', '').strip()
        email = request.form.get('email', '').strip()

        if not username or not password or not nombre:
            flash('Usuario, contraseña y nombre son obligatorio.', 'danger')

        es_valida, mensaje_error = validar_complejidad_password(password)
        if not es_valida:
            flash(mensaje_error, 'danger')
            return render_template('auth/setup.html')
        
        if User.query.filter_by(username=username).first():
            flash('Ese nombre de usuario ya existe.', 'danger')
            return render_template('auth/setup.html')

        # 3. Crear el Super Admin
        admin = User(
            username=username,
            nombre_completo=nombre,
            email=email,
            is_admin=True,
            must_change_password=False
        )
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.flush()

        from app.tools_config import TOOLS
        for tool_name in TOOLS.keys():
            db.session.add(UserTool(user_id=admin.id, tool_name=tool_name))
        
        db.session.commit()
        
        flash('¡Sistema inicializado correctamente! Inicia sesión.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/setup.html')

@bp.before_app_request
def check_password_change_needed():
    # Si el usuario está logueado
    if current_user.is_authenticated:
        # Y tiene la bandera activada
        if current_user.must_change_password:
            # Lista de rutas permitidas (Para que no entre en bucle infinito)
            # Debe poder ver: la página de cambio, el logout y archivos estáticos (css/js)
            allowed_endpoints = ['auth.cambiar_password_inicial', 'auth.logout', 'static']
            
            if request.endpoint not in allowed_endpoints:
                flash('Por seguridad, debes cambiar tu contraseña inicial antes de continuar.', 'warning')
                return redirect(url_for('auth.cambiar_password_inicial'))

@bp.route('/cambiar_password_inicial', methods=['GET', 'POST'])
@login_required
def cambiar_password_inicial():
    if request.method == 'POST':
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')

        if new_pass != confirm_pass:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('auth.cambiar_password_inicial'))
        
        es_valida, mensaje_error = validar_complejidad_password(new_pass)
        if not es_valida:
            flash(mensaje_error, 'danger')
            return redirect(url_for('auth.cambiar_password_inicial'))

        # 1. Cambiar contraseña
        current_user.set_password(new_pass)
        
        # 2. APAGAR LA BANDERA (Liberar al usuario)
        current_user.must_change_password = False 
        
        db.session.commit()
        
        flash('¡Contraseña actualizada! Bienvenido al sistema.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/cambiar_inicial.html')

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # Si el usuario ya esta logueando, lo mandamos al dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    # Si enviaron el formulario (Metodo POST)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Buscar usuario en BD
        user = User.query.filter_by(username=username).first()

        # Verificar contraseña
        if user is None or not user.check_password(password):
            flash('Usuario o contraseña invalidos', 'danger')
            return redirect(url_for('auth.login'))
        
        # Login Exitoso
        login_user(user)
        flash(f'Bienvenido, {user.username}!', 'success')

        # Redirigir a la pagina que intentaba ver o al dashboard
        next_page = request.args.get('next')
        if next_page:
            parsed = urlparse(next_page)
            if parsed.netloc != '' or not next_page.startswith('/'):
                next_page = url_for('main.dashboard')
        else:
            next_page = url_for('main.dashboard')
        return redirect(next_page)

    # Si es metodo GET, mostramos el HTML
    return render_template('auth/login.html')

@bp.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    datos_cuota = None
    if request.method == 'POST':
        try:
            # --- BLOQUE 1: DATOS BÁSICOS (Siempre se guardan) ---
            nombre = request.form.get('nombre_completo')
            email = request.form.get('email')
            vt_key = request.form.get('vt_key')

            if not validar_email(email):
                flash('El formato del email no es válido.', 'danger')
                return redirect(url_for('auth.perfil'))

            current_user.nombre_completo = nombre
            current_user.email = email
            
            if vt_key and "****" not in vt_key: # Evitamos guardar los asteriscos si el usuario no la cambió
                current_user.set_vt_key(vt_key.strip()) # <--- Usamos el método seguro

            # Guardamos los cambios básicos INMEDIATAMENTE
            db.session.add(current_user)
            db.session.commit()

            # --- BLOQUE 2: CONTRASEÑA (Opcional) ---
            current_pass = request.form.get('current_password')
            new_pass = request.form.get('new_password')
            confirm_pass = request.form.get('confirm_password')

            # Solo entramos aquí si el usuario intentó escribir algo
            if (current_pass and current_pass.strip()) or (new_pass and new_pass.strip()):
                
                if not current_user.check_password(current_pass):
                    flash('Error: La contraseña actual no es correcta.', 'danger')
                    return render_template('auth/perfil.html', datos_cuota=datos_cuota, has_vt_key=bool(current_user.get_vt_key()))
                
                elif new_pass != confirm_pass:
                    flash('Error: Las nuevas contraseñas no coinciden.', 'warning')
                    # CAMBIO: Renderizamos directamente
                    return render_template('auth/perfil.html', datos_cuota=datos_cuota, has_vt_key=bool(current_user.get_vt_key()))
                    
                else:
                    es_valida, mensaje_error = validar_complejidad_password(new_pass)
                    if not es_valida:
                        flash(mensaje_error, 'danger')
                        return render_template('auth/perfil.html', datos_cuota=datos_cuota, has_vt_key=bool(current_user.get_vt_key()))
                    
                    current_user.set_password(new_pass)
                    db.session.commit() # Segundo commit solo para pass
                    flash('Contraseña actualizada correctamente.', 'success')

            flash('Información de perfil actualizada.', 'success')

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error guardando perfil de {current_user.username}: {e}")
            flash('Ocurrió un error interno. Contacte al administrador.', 'danger')

        return redirect(url_for('auth.perfil'))
    
    # Solo consultamos si viene el parámetro ?ver_cuota=1 en la URL
    vt_key = current_user.get_vt_key()
    if request.args.get('ver_cuota') == '1' and vt_key:
        datos_cuota = obtener_uso_api(vt_key)
        if not datos_cuota:
            flash('No se pudo obtener la cuota. Verifica tu API Key.', 'warning')
        else:
            flash('Cuota actualizada correctamente.', 'success')

    return render_template('auth/perfil.html', datos_cuota=datos_cuota, has_vt_key=bool(current_user.get_vt_key()))

@bp.route('/admin/usuarios')
@login_required
@admin_required
def admin_usuarios():
    usuarios = User.query.all()
    all_tools = UserTool.query.all()
    tools_por_usuario = {}
    for t in all_tools:
        tools_por_usuario.setdefault(t.user_id, []).append(t.tool_name)
    return render_template('auth/admin_usuarios.html', usuarios=usuarios, tools_por_usuario=tools_por_usuario)

# --- ACCIÓN CREAR USUARIO ---
@bp.route('/admin/usuarios/crear', methods=['POST'])
@login_required
@admin_required
def crear_usuario():
    username = request.form.get('username')
    password = request.form.get('password')
    nombre_completo = request.form.get('nombre_completo')
    email = request.form.get('email')
    is_admin = request.form.get('is_admin') == 'on'

    if not validar_email(email):
        flash('El formato del email no es válido.', 'danger')
        return redirect(url_for('auth.admin_usuarios'))

    if User.query.filter_by(username=username).first():
        flash(f'El usuario {username} ya existe.', 'warning')
        return redirect(url_for('auth.admin_usuarios'))

    es_valida, mensaje_error = validar_complejidad_password(password)
    if not es_valida:
        flash(f'Error al crear usuario: {mensaje_error}', 'danger')
        usuarios = User.query.all()
        return render_template('auth/admin_usuarios.html', usuarios=usuarios)

    nuevo_user = User(
        username=username,
        nombre_completo=nombre_completo,
        email=email,
        is_admin=is_admin
    )
    nuevo_user.set_password(password)
    
    db.session.add(nuevo_user)
    db.session.flush()

    lista_herramientas = request.form.getlist('tools')
    for tool_name in lista_herramientas:
        db.session.add(UserTool(user_id=nuevo_user.id, tool_name=tool_name))

    db.session.commit()
    
    flash(f'Usuario {nombre_completo} ({username}) creado correctamente.', 'success')
    return redirect(url_for('auth.admin_usuarios'))

# --- ACCIÓN EDITAR USUARIO ---
@bp.route('/admin/usuarios/editar/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def editar_usuarios(user_id):
    user = User.query.get_or_404(user_id)

    # 1. Captura datos basicos
    user.username = request.form.get("username")
    user.nombre_completo = request.form.get("nombre_completo")
    user.email = request.form.get('email')
    user.is_admin = request.form.get('is_admin') == 'on'

    # 2. Capturar Herramientas
    lista_herramientas = request.form.getlist('tools')
    UserTool.query.filter_by(user_id=user.id).delete()
    for tool_name in lista_herramientas:
        db.session.add(UserTool(user_id=user.id, tool_name=tool_name))

    # 3. Lógica de Contraseña (Opcional)
    new_password = request.form.get('password')
    if new_password and new_password.strip():
        user.set_password(new_password)
        flash(f'Datos y contraseña de {user.username} actualizados.', 'success')
    else:
        flash(f'Datos de {user.username} actualizados (contraseña sin cambios).', 'success')

    db.session.commit()
    return redirect(url_for('auth.admin_usuarios'))

# --- ACCIÓN ELIMINAR USUARIO ---
@bp.route('/admin/usuarios/eliminar/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def eliminar_usuario(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('No puedes eliminarte a ti mismo.', 'danger')
        return redirect(url_for('auth.admin_usuarios'))

    db.session.delete(user)
    db.session.commit()
    flash(f'Usuario {user.username} eliminado.', 'success')
    return redirect(url_for('auth.admin_usuarios'))

@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))