from flask import Blueprint

bp = Blueprint('virustotal', __name__, template_folder='templates')

from app.virustotal import routes