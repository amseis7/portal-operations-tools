from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

# Instanciamos las extensiones vacías
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()