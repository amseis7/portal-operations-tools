from flask import Blueprint

bp = Blueprint('umbrella', __name__, template_folder='templates')

from app.umbrella import routes
