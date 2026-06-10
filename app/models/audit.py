from datetime import datetime
from flask import request as flask_request
from flask_login import current_user
from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    module = db.Column(db.String(30), nullable=False, index=True)   # csirt | virustotal | umbrella
    action = db.Column(db.String(50), nullable=False)               # create | delete | analyze | …
    object_type = db.Column(db.String(50), nullable=True)           # ticket | caso | cliente | …
    object_id = db.Column(db.String(100), nullable=True)            # ID or ticket string
    object_name = db.Column(db.String(200), nullable=True)          # Human-readable label
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)                     # Extra free-text context

    user = db.relationship("User", backref=db.backref("module_audit_logs", lazy="dynamic"))

    def __repr__(self):
        return f"<AuditLog {self.module}:{self.action} user={self.user_id}>"


def log_audit(module, action, object_type=None, object_id=None, object_name=None, details=None):
    """Add an audit entry and stage it in the current session (caller commits)."""
    ip = flask_request.headers.get("X-Forwarded-For", flask_request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()

    entry = AuditLog(
        module=module,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        object_name=str(object_name)[:200] if object_name is not None else None,
        user_id=current_user.id if current_user.is_authenticated else None,
        ip_address=ip,
        details=details,
    )
    db.session.add(entry)
