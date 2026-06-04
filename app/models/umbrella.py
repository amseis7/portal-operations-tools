import re
from datetime import datetime
from flask import current_app
from cryptography.fernet import Fernet
from app.extensions import db


TIPOS_HERRAMIENTA = {
    'app_discovery': {
        'label': 'App Discovery',
        'icon': 'bi-grid-3x3-gap',
        'color': 'warning',
        'descripcion': 'Asignación de etiquetas a aplicaciones descubiertas en Cisco Umbrella',
    },
}


class UmbrellaCliente(db.Model):
    __tablename__ = "umbrella_cliente"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    _client_id_enc = db.Column("client_id_enc", db.String(512))
    _client_secret_enc = db.Column("client_secret_enc", db.String(512))

    herramientas = db.relationship(
        "UmbrellaHerramienta", backref="cliente", cascade="all, delete-orphan"
    )
    creador = db.relationship("User", foreign_keys=[created_by], backref="umbrella_clientes")

    def _cipher(self):
        return Fernet(current_app.config["SECRET_KEY_DB"])

    def set_credentials(self, client_id: str, client_secret: str) -> None:
        cipher = self._cipher()
        self._client_id_enc = cipher.encrypt(client_id.encode()).decode() if client_id else None
        self._client_secret_enc = cipher.encrypt(client_secret.encode()).decode() if client_secret else None

    def get_client_id(self) -> str | None:
        if not self._client_id_enc:
            return None
        try:
            return self._cipher().decrypt(self._client_id_enc.encode()).decode()
        except Exception:
            return None

    def get_client_secret(self) -> str | None:
        if not self._client_secret_enc:
            return None
        try:
            return self._cipher().decrypt(self._client_secret_enc.encode()).decode()
        except Exception:
            return None

    def has_credentials(self) -> bool:
        return bool(self._client_id_enc and self._client_secret_enc)

    def __repr__(self):
        return f"<UmbrellaCliente {self.nombre}>"


def _make_slug(nombre: str) -> str:
    s = nombre.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_]+', '-', s)
    s = re.sub(r'-+', '-', s).strip('-')
    return s[:100]


class UmbrellaHerramienta(db.Model):
    __tablename__ = "umbrella_herramienta"

    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey("umbrella_cliente.id"), nullable=False, index=True)
    tipo = db.Column(db.String(50), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False, index=True)
    descripcion = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    jobs = db.relationship("UmbrellaJob", backref="herramienta", cascade="all, delete-orphan")

    def generate_slug(self):
        base = _make_slug(self.nombre)
        slug, n = base, 1
        while UmbrellaHerramienta.query.filter_by(slug=slug).filter(UmbrellaHerramienta.id != self.id).first():
            slug = f"{base}-{n}"
            n += 1
        self.slug = slug

    @property
    def tipo_info(self) -> dict:
        return TIPOS_HERRAMIENTA.get(
            self.tipo,
            {"label": self.tipo, "icon": "bi-gear", "color": "secondary", "descripcion": ""},
        )

    def __repr__(self):
        return f"<UmbrellaHerramienta {self.tipo} — {self.nombre}>"


class UmbrellaJob(db.Model):
    __tablename__ = "umbrella_job"

    id = db.Column(db.Integer, primary_key=True)
    herramienta_id = db.Column(db.Integer, db.ForeignKey("umbrella_herramienta.id"), nullable=False, index=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    input_filename = db.Column(db.String(255))
    column_name = db.Column(db.String(100), default="App")
    label_name = db.Column(db.String(50))
    dry_run = db.Column(db.Boolean, default=False)

    status = db.Column(db.String(20), default="pending", index=True)
    error_message = db.Column(db.Text)

    total = db.Column(db.Integer, default=0)
    labeled = db.Column(db.Integer, default=0)
    skipped = db.Column(db.Integer, default=0)
    failed = db.Column(db.Integer, default=0)

    ejecutor = db.relationship("User", foreign_keys=[usuario_id])
    resultados = db.relationship("UmbrellaAppResultado", backref="job", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<UmbrellaJob {self.id} {self.status}>"


class UmbrellaAppResultado(db.Model):
    __tablename__ = "umbrella_app_resultado"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("umbrella_job.id"), nullable=False, index=True)

    app_name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))
    status = db.Column(db.String(20), index=True)
    label = db.Column(db.String(50))
    http_code = db.Column(db.Integer)
    error_message = db.Column(db.Text)

    def __repr__(self):
        return f"<UmbrellaAppResultado {self.app_name} {self.status}>"
