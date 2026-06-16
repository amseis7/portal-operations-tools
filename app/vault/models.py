from datetime import datetime
from uuid import uuid4
from app.extensions import db


class VaultGroup(db.Model):
    __tablename__ = "vault_group"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid4()))
    name = db.Column(db.String(120), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("vault_group.id"), nullable=True)
    icon_id = db.Column(db.Integer, default=48)  # 48 = folder en KeePass
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    parent = db.relationship("VaultGroup", remote_side=[id], backref="children")
    entries = db.relationship("VaultEntry", back_populates="group")

    def __repr__(self):
        return f"<VaultGroup {self.id}: {self.name}>"


class VaultEntry(db.Model):
    __tablename__ = "vault_entry"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid4()))
    title = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # server | platform | api | other
    username = db.Column(db.String(120), nullable=False)
    password_enc = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(250), nullable=True)
    notes_enc = db.Column(db.Text, nullable=True)
    shared = db.Column(db.Boolean, default=False, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("vault_group.id"), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    icon_id = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = db.relationship("User", backref=db.backref("vault_entries", lazy="dynamic"))
    group = db.relationship("VaultGroup", back_populates="entries")
    custom_fields = db.relationship(
        "VaultEntryField",
        back_populates="entry",
        cascade="all, delete-orphan",
        order_by="VaultEntryField.id",
    )
    audit_logs = db.relationship(
        "VaultAuditLog",
        back_populates="entry",
        lazy="dynamic",
    )

    def __repr__(self):
        return f"<VaultEntry {self.id}: {self.title}>"


class VaultEntryField(db.Model):
    __tablename__ = "vault_entry_field"

    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(
        db.Integer,
        db.ForeignKey("vault_entry.id", ondelete="CASCADE"),
        nullable=False,
    )
    field_key = db.Column(db.String(100), nullable=False)
    field_value_enc = db.Column(db.Text, nullable=False)
    is_protected = db.Column(db.Boolean, default=False)

    entry = db.relationship("VaultEntry", back_populates="custom_fields")

    def __repr__(self):
        return f"<VaultEntryField entry={self.entry_id} key={self.field_key}>"


class VaultAuditLog(db.Model):
    __tablename__ = "vault_audit_log"

    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey("vault_entry.id", ondelete="SET NULL"), nullable=True)
    entry_title = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(30), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    entry = db.relationship("VaultEntry", back_populates="audit_logs")
    user = db.relationship("User", backref=db.backref("vault_audit_logs", lazy="dynamic"))

    def __repr__(self):
        return f"<VaultAuditLog entry={self.entry_id} action={self.action}>"
