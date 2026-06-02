import os
import sys
from dotenv import load_dotenv

# Load .env from current directory if exists
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise RuntimeError("ERROR CRÍTICO: La variable de entorno SECRET_KEY no está definida.")
    
    SECRET_KEY_DB = os.environ.get('SECRET_KEY_DB')
    if not SECRET_KEY_DB:
        raise RuntimeError("ERROR CRÍTICO: La variable de entorno SECRET_KEY_DB no está definida.")
    # Fernet requere bytes
    SECRET_KEY_DB = SECRET_KEY_DB.encode() if isinstance(SECRET_KEY_DB, str) else SECRET_KEY_DB
    # Key para el módulo CredentialManager (Debe estar en .env para prod)
    CREDENTIAL_MANAGER_KEY = os.environ.get('CREDENTIAL_MANAGER_KEY')
    if not CREDENTIAL_MANAGER_KEY:
        raise RuntimeError("ERROR CRÍTICO: La variable de entorno CREDENTIAL_MANAGER_KEY no está definida.")
    
    # --- LÓGICA HÍBRIDA (La magia) ---
    # Preguntamos: ¿Estamos empaquetados en un EXE?
    if getattr(sys, 'frozen', False):
        # SÍ: Estamos en un EXE. La ruta base es donde está el ejecutable.
        _base_dir = os.path.dirname(sys.executable)
    else:
        # NO: Estamos en Docker o PyCharm. La ruta base es donde está este archivo.
        _base_dir = os.path.abspath(os.path.dirname(__file__))
        
    # Definimos la carpeta instance basada en la decisión anterior
    _instance_path = os.path.join(_base_dir, 'instance')
    # ---------------------------------

    # Configuraciones Generales
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(_instance_path, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCHEDULER_API_ENABLED = True