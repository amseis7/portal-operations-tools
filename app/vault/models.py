from datetime import datetime
from app.extensions import db


class VaultEntry(db.Model):
    __tablename__ = "vault_entry"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # server | platform | api | other
    username = db.Column(db.String(120), nullable=False)
    password_enc = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(250), nullable=True)
    notes_enc = db.Column(db.Text, nullable=True)
    shared = db.Column(db.Boolean, default=False, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = db.relationship("User", backref=db.backref("vault_entries", lazy="dynamic"))
    audit_logs = db.relationship(
        "VaultAuditLog",
        back_populates="entry",
        lazy="dynamic",
    )

    def __repr__(self):
        return f"<VaultEntry {self.id}: {self.title}>"


class VaultAuditLog(db.Model):
    __tablename__ = "vault_audit_log"

    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey("vault_entry.id", ondelete="SET NULL"), nullable=True)
    entry_title = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(30), nullable=False)  # view | create | edit | delete
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    entry = db.relationship("VaultEntry", back_populates="audit_logs")
    user = db.relationship("User", backref=db.backref("vault_audit_logs", lazy="dynamic"))

    def __repr__(self):
        return f"<VaultAuditLog entry={self.entry_id} action={self.action}>"
