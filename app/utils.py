from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user, login_required

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            #abort(403)
            flash('Acceso denegado.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def proteger_blueprint(bp, nombre_permiso):
    """
    Aplica seguridad a todo un blueprint de forma autentica.
    """
    @bp.before_request
    @login_required
    def verificar_acceso():
        if current_user.is_admin:
            return None
        
        permisos = current_user.authorized_tools or ""
        if nombre_permiso not in permisos:
            flash(f'No tienes acceso al módulo de {nombre_permiso}.', 'warning')
            return redirect(url_for('main.dashboard'))