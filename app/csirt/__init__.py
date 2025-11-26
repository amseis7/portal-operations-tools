from flask import Blueprint

bp = Blueprint('csirt', __name__, template_folder='templates')

from app.csirt import routes