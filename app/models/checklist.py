from datetime import datetime
from cryptography.fernet import Fernet
from flask import current_app
from sqlalchemy.dialects.mysql import JSON, TEXT
from app.extensions import db
import json

class ChecklistService(db.Model):
    __tablename__ = "checklist_services"

    id = db.Column(db.Integer, primary_key=True)
    nombre_cliente = db.Column(db.String(100), nullable=False)
    tipo_tecnologia = db.Column(db.String(50), nullable=False)

    _config_encrypted = db.Column(TEXT)
    estado_actual = db.Column(db.String(20), default="pending")
    mensaje_error = db.Column(db.String(255))
    ultima_data = db.Column(JSON)
    fecha_actualizacion = db.Column(db.DateTime)

    reviews = db.relationship(
        "ChecklistReview",
        backref="service",
        lazy="dynamic"
    )

    def set_config(self, config: dict):
        key = current_app.config["SECRET_KEY_DB"]
        f = Fernet(key)
        self._config_encrypted = f.encrypt(
            json.dumps(config).encode()
        ).decode()

    def get_config(self):
        try:
            key = current_app.config["SECRET_KEY_DB"]
            f = Fernet(key)
            return json.loads(
                f.decrypt(self._config_encrypted.encode()).decode()
            )
        except Exception:
            return {}

class ChecklistReview(db.Model):
    __tablename__ = "checklist_reviews"

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("checklist_services.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    comentario = db.Column(db.String(200))
