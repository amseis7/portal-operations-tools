import os
import sys

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '-pjY4,Ni>66W,Kdi^:XaTxxe=}X_6@w672ZF+qy'
    SECRET_KEY_DB = b'dCDYmze1H8KQ6hNlhKBsa8jUh8hOBohj1nio7Qbj6FQ='
    
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