from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from app.models import User, db
from app.virustotal.logic import obtener_uso_api
from app.auth import bp
from app.utils import admin_required
import re

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
def setup():
    # 1. SEGURIDAD: Verificar si ya existe un admin
    # Si ya existe, no permitimos entrar aquí y mandamos al login
    admin_existente = User.query.filter_by(is_admin=True).first()
    if admin_existente:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        # 2. Capturar datos del formulario
        username = request.form.get('username')
        password = request.form.get('password')
        nombre = request.form.get('nombre')
        email = request.form.get('email')

        # 3. Crear el Super Admin
        admin = User(
            username=username,
            nombre_completo=nombre,
            email=email,
            is_admin=True,         # ¡Importante!
            authorized_tools='all', # Full acceso
            must_change_password = False
        )
        admin.set_password(password)
        
        db.session.add(admin)
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
        if not next_page or not next_page.startswith('/'):
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

            current_user.nombre_completo = nombre
            current_user.email = email
            
            if vt_key and "****" not in vt_key: # Evitamos guardar los asteriscos si el usuario no la cambió
                current_user.set_vt_key(vt_key.strip()) # <--- Usamos el método seguro

            # Guardamos los cambios básicos INMEDIATAMENTE
            db.session.add(current_user)
            db.session.commit()
            flash('Información de perfil actualizada.', 'success')

            # --- BLOQUE 2: CONTRASEÑA (Opcional) ---
            current_pass = request.form.get('current_password')
            new_pass = request.form.get('new_password')
            confirm_pass = request.form.get('confirm_password')

            # Solo entramos aquí si el usuario intentó escribir algo
            if (current_pass and current_pass.strip()) or (new_pass and new_pass.strip()):
                
                if not current_user.check_password(current_pass):
                    flash('Error: La contraseña actual no es correcta.', 'danger')
                    return render_template('auth/perfil.html', datos_cuota=datos_cuota)
                
                elif new_pass != confirm_pass:
                    flash('Error: Las nuevas contraseñas no coinciden.', 'warning')
                    # CAMBIO: Renderizamos directamente
                    return render_template('auth/perfil.html', datos_cuota=datos_cuota)
                    
                else:
                    es_valida, mensaje_error = validar_complejidad_password(new_pass)
                    if not es_valida:
                        flash(mensaje_error, 'danger')
                        return render_template('auth/perfil.html', datos_cuota=datos_cuota)
                    
                    current_user.set_password(new_pass)
                    db.session.commit() # Segundo commit solo para pass
                    flash('Contraseña actualizada correctamente.', 'success')

        except Exception as e:
            db.session.rollback()
            print(f"Error guardando perfil: {e}")
            flash(f'Error interno al guardar: {e}', 'danger')

        return redirect(url_for('auth.perfil'))
    
    # Solo consultamos si viene el parámetro ?ver_cuota=1 en la URL
    if request.args.get('ver_cuota') == '1' and current_user.virustotal_api_key:
        api_key_real = current_user.get_vt_key()
        if api_key_real:
            datos_cuota = obtener_uso_api(api_key_real)
            if not datos_cuota:
                flash('No se pudo obtener la cuota. Verifica tu API Key.', 'warning')
            else:
                flash('Cuota actualizada correctamente.', 'success')

    return render_template('auth/perfil.html', datos_cuota=datos_cuota)

@bp.route('/admin/usuarios')
@login_required
@admin_required
def admin_usuarios():    
    usuarios = User.query.all()
    return render_template('auth/admin_usuarios.html', usuarios=usuarios)

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
    lista_herramientas = request.form.getlist('tools')

    tools_string = ",".join(lista_herramientas)

    if User.query.filter_by(username=username).first():
        flash(f'El usuario {username} ya existe.', 'warning')
        return redirect(url_for('auth.admin_usuarios'))

    es_valida, mensaje_error = validar_complejidad_password(password)
    if not es_valida:
        flash(f'Error al crear usuario: {mensaje_error}', 'danger')
        usuarios = User.query.all()
        return render_template('auth/admin_usuarios.html', usuarios=usuarios)

    # Creamos usuario con todos los datos
    nuevo_user = User(
        username=username, 
        nombre_completo=nombre_completo,
        email=email,
        is_admin=is_admin, 
        authorized_tools=tools_string
    )
    nuevo_user.set_password(password)
    
    db.session.add(nuevo_user)
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

    # 2. Capturar Herramientas (Misma corrección de antes)
    lista_herramientas = request.form.getlist('tools')
    user.authorized_tools = ",".join(lista_herramientas)

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

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))