from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from cryptography.fernet import Fernet
from app.extensions import db, login_manager


class UserTool(db.Model):
    __tablename__ = "user_tool"

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    tool_name = db.Column(db.String(50), primary_key=True)

    def __repr__(self):
        return f"<UserTool {self.user_id}:{self.tool_name}>"


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=True)

    nombre_completo = db.Column(db.String(100))
    email = db.Column(db.String(120), index=True)

    _virustotal_api_key = db.Column("virustotal_api_key", db.String(255))

    authorized_tools = db.relationship(
        "UserTool",
        backref="user",
        lazy="dynamic",
        cascade="all, delete-orphan"
    )

    def has_tool(self, tool_name):
        if self.is_admin:
            return True
        return self.authorized_tools.filter_by(tool_name=tool_name).first() is not None

    def get_tool_names(self):
        return [ut.tool_name for ut in self.authorized_tools]

    # -------- PASSWORD --------
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # -------- VT API KEY --------
    def _get_cipher(self):
        key = current_app.config["SECRET_KEY_DB"]
        return Fernet(key)

    def set_vt_key(self, plain_key: str):
        if not plain_key:
            self._virustotal_api_key = None
            return
        cipher = self._get_cipher()
        self._virustotal_api_key = cipher.encrypt(
            plain_key.encode()
        ).decode()

    def get_vt_key(self):
        if not self._virustotal_api_key:
            return None
        try:
            cipher = self._get_cipher()
            return cipher.decrypt(
                self._virustotal_api_key.encode()
            ).decode()
        except Exception:
            return None

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))