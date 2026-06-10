from flask import render_template, redirect, request, url_for, flash
from flask_login import login_required, current_user
from app.main import bp
from app.models import Notification, db
from app.models.audit import AuditLog
from app.utils import admin_required
from sqlalchemy import or_

@bp.route('/')
@bp.route('/dashboard')
@login_required
def dashboard():
    nombre = current_user.nombre_completo.split()[0]
    return render_template('main/dashboard.html', nombre=nombre)

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

@bp.route('/audit')
@login_required
@admin_required
def audit():
    module_filter = request.args.get('module', '')
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if module_filter:
        query = query.filter(AuditLog.module == module_filter)
    logs = query.limit(500).all()
    return render_template('main/audit.html', logs=logs, module_filter=module_filter)


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