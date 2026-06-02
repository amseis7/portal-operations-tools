from datetime import datetime
from app.extensions import db
from app.models.mixins import VtInfoMixin


class VtTicket(db.Model):
    __tablename__ = "vt_ticket"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    descripcion = db.Column(db.Text)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    usuario_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    creador = db.relationship("User", backref="vt_tickets")

    iocs = db.relationship(
        "VtIoc",
        backref="ticket",
        cascade="all, delete-orphan"
    )


class VtIoc(VtInfoMixin, db.Model):
    __tablename__ = "vt_ioc"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("vt_ticket.id"), index=True)

    tipo = db.Column(db.String(50), index=True)
    valor = db.Column(db.String(255), index=True)


class ExportTemplate(db.Model):
    __tablename__ = "export_template"

    id = db.Column(db.Integer, primary_key=True)
    nombre_plataforma = db.Column(db.String(100), nullable=False, index=True)
    vt_engine_name = db.Column(db.String(100), nullable=False, index=True)

    supported_hashes = db.Column(db.String(100), default="md5,sha1,sha256")

    file_extension = db.Column(db.String(10), default="csv")

    header_content = db.Column(db.Text, default="")
    row_template = db.Column(db.Text, nullable=False)
    footer_content = db.Column(db.Text, default="")

    def __repr__(self):
        return f'<Template {self.nombre_plataforma}>'