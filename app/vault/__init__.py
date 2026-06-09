from flask import Blueprint

bp = Blueprint('vault', __name__)

from app.vault import routes  # noqa: E402, F401
