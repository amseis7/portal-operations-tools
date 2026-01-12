from flask import Flask
import os, sys
from config import Config
from app.extensions import db, login_manager, csrf, migrate
from flask_apscheduler import APScheduler

# Aceptamos instance_path como opcional (None por defecto)
def create_app(config_class=Config, instance_path=None):
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
    
    if getattr(sys, 'frozen', False):
        # Si estamos corriendo desde el .exe, buscamos en la carpeta temporal
        migration_dir = os.path.join(sys._MEIPASS, 'migrations')
    else:
        # Si estamos en desarrollo, usamos la carpeta normal
        migration_dir = 'migrations'

    try:
        migrate.init_app(app, db, directory=migration_dir)

        with app.app_context():
            db.create_all()

    except Exception as e:
        print(f"Advertencia: No se pudo iniciar Flask-Migrate: {e}")
    
    # Scheduler
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    
    # --- TAREA 1: Tarea del vigilante nuevas alertas csirt
    from app.csirt.logic import vigilar_nuevas_alertas
    scheduler.add_job(
        id='vigilante_csirt',
        func=vigilar_nuevas_alertas,
        args=[app],
        trigger='interval',
        minutes=60
    )

    # -- TAREA 2: Tarea de verificacion status checklist
    from app.checklist.tasks import ejecutar_barrido_checklist

    scheduler.add_job(
        id='tarea_checklist_automatica',
        func=ejecutar_barrido_checklist,
        args=[app],
        trigger='interval',
        minutes=30, # Se puede cambiar
        replace_existing=True
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

    from app.checklist import bp as checklist_bp
    app.register_blueprint(checklist_bp, url_prefix='/checklist')

    # --- CONFIGURACIÓN DE Y NUEVOS MODULOS A AGREGAR ---
    from app.tools_config import TOOLS

    @app.context_processor
    def inject_tools():
        return dict(lista_herramientas=TOOLS)

    # El Portero (Redirección a Setup) Valida si existe una cuenta admin, si no, mandará a la pagina de setup inicial para crear una cuenta administrativa
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