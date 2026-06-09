import logging
import os, sys
from flask import Flask
from config import Config
from app.extensions import db, login_manager, csrf, migrate, limiter
from flask_apscheduler import APScheduler

logger = logging.getLogger(__name__)

def create_app(config_class=Config, instance_path=None):
    if instance_path:
        app = Flask(__name__, instance_path=instance_path)
    else:
        app = Flask(__name__)
        
    app.config.from_object(config_class)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Por favor inicia sesión para acceder."
    login_manager.login_message_category = "warning"
    csrf.init_app(app)
    limiter.init_app(app)
    
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        return response
    
    if getattr(sys, 'frozen', False):
        migration_dir = os.path.join(sys._MEIPASS, 'migrations')
    else:
        migration_dir = 'migrations'

    try:
        migrate.init_app(app, db, directory=migration_dir)
    except Exception as e:
        logger.warning(f"No se pudo iniciar Flask-Migrate: {e}")
    
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    
    from app.csirt.logic import vigilar_nuevas_alertas
    scheduler.add_job(
        id='vigilante_csirt',
        func=vigilar_nuevas_alertas,
        args=[app],
        trigger='interval',
        minutes=60
    )

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)
    
    from app.csirt import bp as csirt_bp
    app.register_blueprint(csirt_bp, url_prefix='/csirt')

    from app.virustotal import bp as vt_bp
    app.register_blueprint(vt_bp, url_prefix='/virustotal')

    from app.umbrella import bp as umbrella_bp
    app.register_blueprint(umbrella_bp, url_prefix='/umbrella')

    from app.vault import bp as vault_bp
    app.register_blueprint(vault_bp, url_prefix='/vault')

    from app.tools_config import TOOLS

    @app.context_processor
    def inject_tools():
        return dict(lista_herramientas=TOOLS)

    from flask import request, redirect, url_for
    from app.models.user import User

    @app.before_request
    def check_setup_needed():
        if request.endpoint and ('static' in request.endpoint or 'auth.setup' in request.endpoint):
            return
        try:
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count == 0:
                return redirect(url_for('auth.setup'))
        except Exception:
            pass

    return app