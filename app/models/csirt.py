from datetime import datetime
from app.extensions import db
import json

class Alerta(db.Model):
    __tablename__ = "alerta"

    id = db.Column(db.Integer, primary_key=True)
    ticket = db.Column(db.String(50), nullable=False)
    responsable = db.Column(db.String(100))
    fecha_realizacion = db.Column(db.DateTime, default=datetime.utcnow)

    nombre_alerta = db.Column(db.String(200))
    tipo_alerta = db.Column(db.String(10))

    iocs = db.relationship(
        "Ioc",
        backref="alerta",
        cascade="all, delete-orphan",
        lazy=True
    )

    def __repr__(self):
        return f"<Alerta {self.ticket}>"

class Ioc(db.Model):
    __tablename__ = "ioc"

    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50), index=True)
    valor = db.Column(db.String(255), index=True)

    alerta_id = db.Column(
        db.Integer,
        db.ForeignKey("alerta.id"),
        nullable=False
    )

    vt_last_check = db.Column(db.DateTime)
    vt_reputation = db.Column(db.Integer)
    vt_positives = db.Column(db.Integer, default=0)
    vt_total = db.Column(db.Integer, default=0)
    vt_permalink = db.Column(db.String(255))

    vt_md5 = db.Column(db.String(32))
    vt_sha1 = db.Column(db.String(40))
    vt_sha256 = db.Column(db.String(64))

    vt_motores_json = db.Column(db.Text)

    def set_motores(self, data: dict):
        self.vt_motores_json = json.dumps(data)

    def get_motores(self):
        return json.loads(self.vt_motores_json or "{}")

    def __repr__(self):
        return f"<IOC {self.tipo}:{self.valor}>"
