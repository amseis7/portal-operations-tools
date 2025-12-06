from flask import Flask, request, redirect, url_for
import os
from app.models import User
from config import Config
from app.extensions import db, login_manager, csrf
from flask_apscheduler import APScheduler

# Aceptamos instance_path como opcional (None por defecto)
def create_app(config_class=Config, instance_path=None):
    
    # Si nos pasan una ruta específica (PyInstaller), la usamos.
    if instance_path:
        app = Flask(__name__, instance_path=instance_path)
    else:
        # Si no (Docker/PyCharm), Flask usa su comportamiento estándar.
        app = Flask(__name__)
        
    app.config.from_object(config_class)

    # Asegurar que la carpeta instance exista (Funciona para ambos)
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Inicializar extensiones
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'  # <--- "Si no está logueado, mándalo aquí"
    login_manager.login_message = "Por favor inicia sesión para acceder."
    login_manager.login_message_category = "warning"
    csrf.init_app(app)
    
    # Scheduler
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    
    # Tarea del vigilante
    from app.csirt.logic import vigilar_nuevas_alertas
    scheduler.add_job(
        id='vigilante_csirt',
        func=vigilar_nuevas_alertas,
        args=[app],
        trigger='interval',
        minutes=60
    )

    # Blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)
    
    from app.csirt import bp as csirt_bp
    app.register_blueprint(csirt_bp, url_prefix='/csirt')

    from app.virustotal import bp as vt_bp
    app.register_blueprint(vt_bp, url_prefix='/virustotal')

    # El Portero (Redirección a Setup)
    from flask import request, redirect, url_for
    from app.models import User

    @app.before_request
    def check_setup_needed():
        if request.endpoint and ('static' in request.endpoint or 'auth.setup' in request.endpoint):
            return
        try:
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count == 0:
                return redirect(url_for('auth.setup'))
        except:
            pass

    return app