from flask import Flask, request, redirect, url_for
from app.models import User
from config import Config
from app.extensions import db, login_manager
from flask_apscheduler import APScheduler

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Inicializar extensiones con la app creada
    db.init_app(app)
    login_manager.init_app(app)

    # --- CONFIGURACIÓN SCHEDULER ---
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()

    # Registrarmos la tarea
    from app.csirt.logic import vigilar_nuevas_alertas

    # Añadir trabajo: Correr cada X minutos
    # (Para probar ponle 'seconds=30' y mira la consola)
    scheduler.add_job(
        id='vigilante_csirt',
        func=vigilar_nuevas_alertas,
        args=[app], # Le pasamos la app para el contexto
        trigger='interval',
        hours= 6
    )
    
    # Configuración de redirección si no estás logueado
    # (Esto nos enviará a la ruta 'auth.login' que crearemos luego)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'

    # Registrar Blueprints (Las partes de tu app)
    # Los importamos AQUÍ dentro para evitar errores de importación circular
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.csirt import bp as csirt_bp
    app.register_blueprint(csirt_bp, url_prefix='/csirt')

    @app.before_request
    def check_setup_needed():
        # Lista de rutas permitidas (archivos estáticos CSS/JS y la propia página de setup)
        if request.endpoint and ('static' in request.endpoint or 'auth.setup' in request.endpoint):
            return

        # Verificamos si hay usuarios (Optimizamos contando, es más rápido)
        try:
            # Si la tabla no existe dará error, lo capturamos abajo
            admin_count = User.query.filter_by(is_admin=True).count()
            
            if admin_count == 0:
                # Si no hay admins, forzamos ir al setup
                return redirect(url_for('auth.setup'))
        except:
            pass # Si la DB no está lista aun, dejamos pasar (lo manejará el server.py)
    # ----------------------------------------------

    return app