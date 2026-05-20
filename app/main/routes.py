from flask import render_template, redirect, request, url_for, flash
from flask_login import login_required, current_user
from app.main import bp
from app.models import Notification, db
from sqlalchemy import or_

@bp.route('/')
@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('main/dashboard.html')

@bp.app_context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notificaciones = Notification.query.filter(
            or_(
                Notification.user_id == current_user.id,
                Notification.user_id == None
            ),
            Notification.is_read == False
        ).order_by(Notification.timestamp.desc()).all()
        return dict(mis_notificaciones=notificaciones, cantidad_notif=len(notificaciones))
    return dict(mis_notificaciones=[], cantidad_notif=0)

@bp.route('/notificacion/leida/<int:notif_id>', methods=['POST'])
@login_required
def marcar_leida(notif_id):
    notif = Notification.query.get_or_404(notif_id)
    if notif.user_id is not None and notif.user_id != current_user.id:
        flash('No autorizado.', 'danger')
        return redirect(url_for('main.dashboard'))
    notif.is_read = True
    db.session.commit()
    return redirect(request.referrer or url_for('main.dashboard'))

@bp.route('/notificaciones/limpiar', methods=['POST'])
@login_required
def marcar_todas_leidas():
    Notification.query.filter(
        or_(
            Notification.user_id == current_user.id,
            Notification.user_id == None
        ),
        Notification.is_read == False
    ).update({"is_read": True})
    db.session.commit()
    return redirect(request.referrer or url_for('main.dashboard'))