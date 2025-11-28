from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app.extensions import db, login_manager

# UserMixin nos da métodos predeterminados par ael login (is_authenticated, etc.)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    authorized_tools = db.Column(db.String(200), default="")
    nombre_completo = db.Column(db.String(100))
    email = db.Column(db.String(120))
    must_change_password = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        """Cifra la contrasela y la guarda"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica si la contraseña ingresada coincide con el hash"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'User {self.username}'
    
# Funcion requerida por Flask-Login para cargar un usuario por ID
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class Alerta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket = db.Column(db.String(50), nullable=False)      # RF del Ticket
    responsable = db.Column(db.String(100))                # Nombre del analista
    fecha_realizacion = db.Column(db.DateTime, default=datetime.utcnow)
    nombre_alerta = db.Column(db.String(200))              # Ej: ACF-0000000
    tipo_alerta = db.Column(db.String(10))
    
    # Relación: Una alerta tiene muchos IOCs
    iocs = db.relationship('Ioc', backref='alerta', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Alerta {self.ticket}>'
    
class Ioc(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50))   # hash, url, ip, dominio, email
    valor = db.Column(db.Text)        # El valor en sí (Text por si es una URL larga)
    
    # Llave foránea que conecta con la tabla Alerta
    alerta_id = db.Column(db.Integer, db.ForeignKey('alerta.id'), nullable=False)

    def __repr__(self):
        nombre_padre = self.alerta.nombre_alerta if self.alerta else "Sin Alerta"
        return f'<IOC [{nombre_padre}] {self.tipo}: {self.valor}>'
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    message = db.Column(db.String(255))
    category = db.Column(db.String(50))
    is_read = db.Column(db.Boolean, default=False)
    link = db.Column(db.String(200))

    def __repr__(self):
        return f'Notif {self.message}'