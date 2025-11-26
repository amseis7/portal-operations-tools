from flask import render_template, redirect, request, url_for
from flask_login import login_required, current_user
from app.main import bp
from app.models import Notification, db

@bp.route('/')
@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('main/dashboard.html')

@bp.app_context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notificaciones = Notification.query.filter_by(is_read=False).order_by(Notification.timestamp.desc()).all()
        return dict(mis_notificaciones=notificaciones, cantidad_notif=len(notificaciones))
    return dict(mis_notificaciones=[], cantidad_notif=0)

@bp.route('/notificacion/leida/<int:notif_id>', methods=['POST'])
@login_required
def marcar_leida(notif_id):
    notif = Notification.query.get_or_404(notif_id)
    notif.is_read = True
    db.session.commit()
    return redirect(request.referrer or url_for('main.dashboard'))

@bp.route('/notificaciones/limpiar')
@login_required
def marcar_todas_leidas():
    # Marca todas como leídas
    notificaciones = Notification.query.filter_by(is_read=False).all()
    for n in notificaciones:
        n.is_read = True
    db.session.commit()
    return redirect(request.referrer or url_for('main.dashboard'))