import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Clave secreta para firmar cookies y sesiones (Cambiar en produccion)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'clave-super-secreta-desarrollo'

    INSTANCE_PATH = os.path.join(basedir, 'instance')

    # Configuracion de la base de datos sQLite
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(INSTANCE_PATH, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False