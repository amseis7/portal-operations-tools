import os
import sys

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '-pjY4,Ni>66W,Kdi^:XaTxxe=}X_6@w672ZF+qy'

    VIRUSTOTAL_API_KEY = os.environ.get('VT_QPI_KEY') or 'TU_API_KEY'
    VT_MOTORES_INTERES = [
        'TrendMicro', 'Trellix ENS', 'Symantec', 'CrowdStrike',
        'Kaspersky', 'Sophos', 'Microsoft', 'Google'
    ]
    
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