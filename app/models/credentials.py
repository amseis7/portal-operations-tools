from app.extensions import db
from datetime import datetime
from cryptography.fernet import Fernet
from flask import current_app
import base64

class CredentialGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255))
    
    credentials = db.relationship('Credential', backref='group', lazy=True)

    def __repr__(self):
        return f'<Group {self.name}>'

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('credential_group.id'), nullable=True) # Nullable por si no tienen grupo
    title = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200)) # Encrypted? Requerimiento dice solo password encrypted, pero username podría ser sensible. De momento texto plano segun plan.
    url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    
    # Campo CRÍTICO: Password encriptada
    password_encrypted = db.Column(db.Text, nullable=False)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def _get_cipher(self):
        """Genera el cifrador usando la CREDENTIAL_MANAGER_KEY"""
        key_raw = current_app.config.get('CREDENTIAL_MANAGER_KEY')
        
        if not key_raw:
            # Fallback seguro O ERROR EXPLICITO. 
            # Segun plan: lanzar error si no existe en prod, pero para evitar crash en dev si no setean env,
            # usaremos una logica similar a lo que ya tienen o un hardcoded MUY obvio de development warning.
            # OJO: El usuario pidio seguridad critica. Lanzaré error si no hay key.
            raise ValueError("CREDENTIAL_MANAGER_KEY no configurada! No se puede encriptar/desencriptar.")

        # Asegurarnos de que sea bytes
        if isinstance(key_raw, str):
            key_raw = key_raw.encode()
            
        return Fernet(key_raw)

    def set_password(self, plain_password):
        if not plain_password:
            self.password_encrypted = None
            return
            
        cipher = self._get_cipher()
        encrypted = cipher.encrypt(plain_password.encode()).decode('utf-8')
        self.password_encrypted = encrypted

    def get_password(self):
        if not self.password_encrypted:
            return None
            
        try:
            cipher = self._get_cipher()
            decrypted = cipher.decrypt(self.password_encrypted.encode()).decode('utf-8')
            return decrypted
        except Exception as e:
            # Si la llave cambió o el dato está corrupto
            return f"[ERROR: {str(e)}]"

    def __repr__(self):
        return f'<Credential {self.title}>'
