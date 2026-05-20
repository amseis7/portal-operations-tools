from datetime import datetime
from app.extensions import db
from app.models.mixins import VtInfoMixin


class Alerta(db.Model):
    __tablename__ = "alerta"
    __table_args__ = (
        db.Index('ix_alerta_ticket_tipo', 'ticket', 'tipo_alerta'),
    )

    id = db.Column(db.Integer, primary_key=True)
    ticket = db.Column(db.String(50), nullable=False, index=True)
    responsable = db.Column(db.String(100), index=True)
    fecha_realizacion = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    nombre_alerta = db.Column(db.String(200), index=True)
    tipo_alerta = db.Column(db.String(10), index=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    creator = db.relationship("User", backref="created_alerts")

    iocs = db.relationship(
        "Ioc",
        backref="alerta",
        cascade="all, delete-orphan",
        lazy=True
    )

    def __repr__(self):
        return f"<Alerta {self.ticket}>"


class Ioc(VtInfoMixin, db.Model):
    __tablename__ = "ioc"

    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50), index=True)
    valor = db.Column(db.String(255), index=True)

    alerta_id = db.Column(
        db.Integer,
        db.ForeignKey("alerta.id"),
        nullable=False,
        index=True
    )

    def __repr__(self):
        return f"<IOC {self.tipo}:{self.valor}>"