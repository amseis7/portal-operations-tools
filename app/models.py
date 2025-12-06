from datetime import datetime
from cryptography.fernet import Fernet
import base64
from flask import current_app
import json
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
    virustotal_api_key = db.Column(db.String(255))

    def set_password(self, password):
        """Cifra la contrasela y la guarda"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica si la contraseña ingresada coincide con el hash"""
        return check_password_hash(self.password_hash, password)
    
    def _get_cipher(self):
        """Genera el cifrador usando la SECRET_KEY de la app"""
        # Fernet necesita una key de 32 bytes en base64.
        # Usamos la secret_key de la app, la ajustamos a 32 bytes y codificamos.
        key_raw = current_app.config['SECRET_KEY'].ljust(32)[:32]
        key_b64 = base64.urlsafe_b64encode(key_raw.encode())
        return Fernet(key_b64)
    
    def set_vt_key(self, plain_key):
        """Encripta y guarda la key"""
        if not plain_key:
            self.virustotal_api_key = None
            return
        cipher = self._get_cipher()
        encrypted = cipher.encrypt(plain_key.encode()).decode('utf-8')
        self.virustotal_api_key = encrypted

    def get_vt_key(self):
        """Desencripta y devuelve la key real"""
        if not self.virustotal_api_key:
            return None
        try:
            cipher = self._get_cipher()
            decrypted = cipher.decrypt(self.virustotal_api_key.encode()).decode('utf-8')
            return decrypted
        except Exception:
            # Si falla (ej: cambio de SECRET_KEY o dato viejo plano), devolvemos None o el dato raw
            return None
    
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
    valor = db.Column(db.String(255), index=True)        # El valor en sí (Text por si es una URL larga)
    alerta_id = db.Column(db.Integer, db.ForeignKey('alerta.id'), nullable=False) # Llave foránea que conecta con la tabla Alerta

    # --- CAMPOS VIRUSTOTAL ---
    vt_last_check = db.Column(db.DateTime)
    vt_reputation = db.Column(db.Integer) # Score general (-10 a 100)
    vt_positives = db.Column(db.Integer, default=0)
    vt_total = db.Column(db.Integer, default=0)
    vt_permalink = db.Column(db.String(255))

    # Hashes (Siempre es útil tenerlos a mano)
    vt_md5 = db.Column(db.String(32))
    vt_sha1 = db.Column(db.String(40))
    vt_sha256 = db.Column(db.String(64))

    # Aquí guardaremos el diccionario de tus motores:
    # Ej: {"TrendMicro": "Detected", "McAfee": "Clean"}
    vt_motores_json = db.Column(db.Text)

    def set_motores(self, datos_dict):
        self.vt_motores_json = json.dumps(datos_dict)

    def get_motores(self):
        if not self.vt_motores_json: return {}
        return json.loads(self.vt_motores_json)

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

class VtTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False) # Ej: "Investigación Phishing RRHH"
    descripcion = db.Column(db.Text)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relación con el usuario creador
    creador = db.relationship('User', backref='vt_tickets')
    
    # Relación con los IoCs
    iocs = db.relationship('VtIoc', backref='ticket', lazy=True, cascade="all, delete-orphan")

class VtIoc(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('vt_ticket.id'), nullable=False)
    
    tipo = db.Column(db.String(50)) # ip, hash, domain
    valor = db.Column(db.String(255), index=True)
    
    # Datos de VT (Reutilizamos la estructura que ya conoces)
    vt_last_check = db.Column(db.DateTime)
    vt_reputation = db.Column(db.Integer)
    vt_positives = db.Column(db.Integer, default=0)
    vt_total = db.Column(db.Integer, default=0)
    vt_permalink = db.Column(db.String(255))
    vt_md5 = db.Column(db.String(32))
    vt_sha1 = db.Column(db.String(40))
    vt_sha256 = db.Column(db.String(64))
    vt_motores_json = db.Column(db.Text)

    def set_motores(self, datos_dict):
        import json
        self.vt_motores_json = json.dumps(datos_dict)

    def get_motores(self):
        import json
        if not self.vt_motores_json: return {}
        return json.loads(self.vt_motores_json)
    
class ExportTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_plataforma = db.Column(db.String(100), nullable=False) # Ej: "TrendMicro Apex"
    vt_engine_name = db.Column(db.String(100), nullable=False)    # Ej: "TrendMicro" (Nombre exacto en VT)
    
    supported_hashes = db.Column(db.String(100), default="md5,sha1,sha256")

    file_extension = db.Column(db.String(10), default="csv")      # csv, xml, txt
    
    # Estructura del archivo
    header_content = db.Column(db.Text, default="") # Cabecera (Ej: "IP,Category,Action")
    row_template = db.Column(db.Text, nullable=False) # Plantilla por fila (Ej: "{valor},Malware,Block")
    footer_content = db.Column(db.Text, default="") # Pie de página (Para XML/JSON)

    def __repr__(self):
        return f'<Template {self.nombre_plataforma}>'