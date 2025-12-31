from flask import Blueprint

bp = Blueprint('checklist', __name__)

from app.checklist import routes