from datetime import datetime
from app.extensions import db
import json

class VtTicket(db.Model):
    __tablename__ = "vt_ticket"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    descripcion = db.Column(db.Text)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)

    usuario_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    creador = db.relationship("User", backref="vt_tickets")

    iocs = db.relationship(
        "VtIoc",
        backref="ticket",
        cascade="all, delete-orphan"
    )

class VtIoc(db.Model):
    __tablename__ = "vt_ioc"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("vt_ticket.id"))

    tipo = db.Column(db.String(50), index=True)
    valor = db.Column(db.String(255), index=True)

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