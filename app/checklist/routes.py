from flask import render_template
from flask_login import login_required
from app.utils import check_access
from app.checklist import bp

@bp.route('/')
@login_required
@check_access('checklist')

def index():
    """
    Ruta principal del modulo.
    Acceso: /checklist/
    """
    return render_template('checklist/index.html', titulo_navbar="CheckList Clientes")