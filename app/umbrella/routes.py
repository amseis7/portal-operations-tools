import csv
import logging
from io import StringIO

from flask import flash, jsonify, redirect, render_template, request, url_for, Response
from flask_login import current_user

from app.extensions import db
from sqlalchemy.orm import joinedload
from app.models.umbrella import (
    TIPOS_HERRAMIENTA, UmbrellaAppResultado, UmbrellaCliente,
    UmbrellaHerramienta, UmbrellaJob,
)
from app.umbrella import bp
from app.umbrella.background import lanzar_job_background
from app.umbrella.client import VALID_LABELS
from app.umbrella.reader import read_apps, get_excel_columns
from app.utils import admin_required, proteger_blueprint

logger = logging.getLogger(__name__)

proteger_blueprint(bp, 'umbrella')

_TEMPLATE_MAP = {
    'app_discovery': 'umbrella/herramienta_app_discovery.html',
}

_LABEL_OPTIONS = sorted(VALID_LABELS - {'unreviewed'})


# ─── INDEX ──────────────────────────────────────────────────────────────────

@bp.route('/')
def index():
    clientes = UmbrellaCliente.query.order_by(UmbrellaCliente.nombre).all()
    return render_template(
        'umbrella/index.html',
        clientes=clientes,
        tipos=TIPOS_HERRAMIENTA,
        titulo_navbar="Herramientas Umbrella",
    )


# ─── CLIENTES ───────────────────────────────────────────────────────────────

@bp.route('/cliente/crear', methods=['POST'])
@admin_required
def crear_cliente():
    nombre = request.form.get('nombre', '').strip()
    client_id = request.form.get('client_id', '').strip()
    client_secret = request.form.get('client_secret', '').strip()

    if not nombre:
        flash('El nombre del cliente es obligatorio.', 'danger')
        return redirect(url_for('umbrella.index'))
    if not client_id or not client_secret:
        flash('Client ID y Client Secret son obligatorios.', 'danger')
        return redirect(url_for('umbrella.index'))

    cliente = UmbrellaCliente(
        nombre=nombre,
        descripcion=request.form.get('descripcion', '').strip() or None,
        created_by=current_user.id,
    )
    cliente.set_credentials(client_id, client_secret)
    db.session.add(cliente)
    db.session.commit()
    flash(f'Cliente "{nombre}" creado correctamente.', 'success')
    return redirect(url_for('umbrella.index'))


@bp.route('/cliente/<int:cliente_id>/editar', methods=['GET', 'POST'])
@admin_required
def editar_cliente(cliente_id):
    cliente = UmbrellaCliente.query.get_or_404(cliente_id)
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        if not nombre:
            flash('El nombre es obligatorio.', 'danger')
            return redirect(url_for('umbrella.editar_cliente', cliente_id=cliente_id))

        cliente.nombre = nombre
        cliente.descripcion = request.form.get('descripcion', '').strip() or None

        new_id = request.form.get('client_id', '').strip()
        new_secret = request.form.get('client_secret', '').strip()
        if new_id and new_secret:
            cliente.set_credentials(new_id, new_secret)
        elif bool(new_id) != bool(new_secret):
            flash('Para actualizar credenciales debes ingresar ambos: Client ID y Client Secret.', 'warning')

        db.session.commit()
        flash(f'Cliente "{cliente.nombre}" actualizado.', 'success')
        return redirect(url_for('umbrella.index'))

    return render_template(
        'umbrella/editar_cliente.html',
        cliente=cliente,
        titulo_navbar="Editar Cliente Umbrella",
    )


@bp.route('/cliente/<int:cliente_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_cliente(cliente_id):
    cliente = UmbrellaCliente.query.get_or_404(cliente_id)
    nombre = cliente.nombre
    db.session.delete(cliente)
    db.session.commit()
    flash(f'Cliente "{nombre}" eliminado junto con todas sus herramientas.', 'success')
    return redirect(url_for('umbrella.index'))


# ─── HERRAMIENTAS ───────────────────────────────────────────────────────────

@bp.route('/herramienta/crear', methods=['POST'])
@admin_required
def crear_herramienta():
    cliente_id = request.form.get('cliente_id', type=int)
    tipo = request.form.get('tipo', '').strip()
    nombre = request.form.get('nombre', '').strip()

    if not cliente_id or tipo not in TIPOS_HERRAMIENTA:
        flash('Cliente y tipo de herramienta válido son obligatorios.', 'danger')
        return redirect(url_for('umbrella.index'))

    cliente = UmbrellaCliente.query.get_or_404(cliente_id)
    if not nombre:
        nombre = f"{TIPOS_HERRAMIENTA[tipo]['label']} — {cliente.nombre}"

    herramienta = UmbrellaHerramienta(
        cliente_id=cliente_id,
        tipo=tipo,
        nombre=nombre,
        descripcion=request.form.get('descripcion', '').strip() or None,
        slug='__tmp__',
    )
    db.session.add(herramienta)
    db.session.flush()
    herramienta.generate_slug()
    db.session.commit()
    flash(f'Herramienta "{nombre}" creada.', 'success')
    return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta.slug))


@bp.route('/herramienta/<herramienta_slug>/')
def ver_herramienta(herramienta_slug):
    herramienta = UmbrellaHerramienta.query.filter_by(slug=herramienta_slug).first_or_404()
    jobs = (
        UmbrellaJob.query
        .options(joinedload(UmbrellaJob.ejecutor))
        .filter_by(herramienta_id=herramienta.id)
        .order_by(UmbrellaJob.created_at.desc())
        .limit(50)
        .all()
    )
    template = _TEMPLATE_MAP.get(herramienta.tipo, 'umbrella/herramienta_desconocida.html')
    return render_template(
        template,
        herramienta=herramienta,
        jobs=jobs,
        label_options=_LABEL_OPTIONS,
        titulo_navbar="Herramientas Umbrella",
    )


@bp.route('/herramienta/<herramienta_slug>/eliminar', methods=['POST'])
@admin_required
def eliminar_herramienta(herramienta_slug):
    herramienta = UmbrellaHerramienta.query.filter_by(slug=herramienta_slug).first_or_404()
    nombre = herramienta.nombre
    db.session.delete(herramienta)
    db.session.commit()
    flash(f'Herramienta "{nombre}" eliminada.', 'success')
    return redirect(url_for('umbrella.index'))


# ─── APP DISCOVERY: PREVIEW (AJAX) ──────────────────────────────────────────

@bp.route('/herramienta/<herramienta_slug>/preview', methods=['POST'])
def preview_excel(herramienta_slug):
    UmbrellaHerramienta.query.filter_by(slug=herramienta_slug).first_or_404()
    archivo = request.files.get('excel_file')
    column = request.form.get('column_name', 'App').strip() or 'App'

    if not archivo or archivo.filename == '':
        return jsonify({'error': 'Archivo no recibido'}), 400

    try:
        columns = get_excel_columns(archivo.stream)
        archivo.stream.seek(0)
        apps = read_apps(archivo.stream, column)
        return jsonify({'apps': apps, 'total': len(apps), 'columns': columns})
    except (ValueError, RuntimeError) as exc:
        return jsonify({'error': str(exc)}), 422


# ─── APP DISCOVERY: EJECUTAR ─────────────────────────────────────────────────

@bp.route('/herramienta/<herramienta_slug>/ejecutar', methods=['POST'])
def ejecutar(herramienta_slug):
    herramienta = UmbrellaHerramienta.query.filter_by(slug=herramienta_slug).first_or_404()
    archivo = request.files.get('excel_file')
    label_name = request.form.get('label_name', '').strip()
    column_name = request.form.get('column_name', 'App').strip() or 'App'
    dry_run = request.form.get('dry_run') == '1'

    if not archivo or archivo.filename == '':
        flash('Debes seleccionar un archivo Excel.', 'warning')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))

    if label_name not in VALID_LABELS:
        flash(f'Etiqueta no válida: {label_name}', 'danger')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))

    # Decrypt credentials in request context (before background thread)
    cid = herramienta.cliente.get_client_id()
    csecret = herramienta.cliente.get_client_secret()
    if not cid or not csecret:
        flash('Credenciales Umbrella no configuradas para este cliente.', 'danger')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))

    # Parse Excel synchronously — this is fast (file is already in memory)
    try:
        app_names = read_apps(archivo.stream, column_name)
    except (ValueError, RuntimeError) as exc:
        flash(f'Error al leer el Excel: {exc}', 'danger')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))

    job = UmbrellaJob(
        herramienta_id=herramienta.id,
        usuario_id=current_user.id,
        input_filename=archivo.filename,
        label_name=label_name,
        column_name=column_name,
        dry_run=dry_run,
        status='running',
        total=len(app_names),
    )
    db.session.add(job)
    db.session.commit()

    lanzar_job_background(app_names, job.id, cid, csecret, label_name, dry_run)

    flash(f'Proceso iniciado para {len(app_names)} apps. Los resultados se actualizan automáticamente.', 'info')
    return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))


# ─── ESTADO (AJAX POLLING) ───────────────────────────────────────────────────

@bp.route('/herramienta/<herramienta_slug>/estado')
def estado_herramienta(herramienta_slug):
    """Returns current status of the 50 most recent jobs for polling."""
    herramienta = UmbrellaHerramienta.query.filter_by(slug=herramienta_slug).first_or_404()
    jobs = (
        UmbrellaJob.query
        .filter_by(herramienta_id=herramienta.id)
        .order_by(UmbrellaJob.created_at.desc())
        .limit(50)
        .all()
    )
    return jsonify([{
        'id': j.id,
        'status': j.status,
        'total': j.total,
        'labeled': j.labeled,
        'skipped': j.skipped,
        'failed': j.failed,
        'error_message': j.error_message or '',
    } for j in jobs])


# ─── JOB DETAIL ─────────────────────────────────────────────────────────────

@bp.route('/herramienta/<herramienta_slug>/job/<int:job_id>')
def ver_job(herramienta_slug, job_id):
    herramienta = UmbrellaHerramienta.query.filter_by(slug=herramienta_slug).first_or_404()
    job = UmbrellaJob.query.get_or_404(job_id)
    if job.herramienta_id != herramienta.id:
        flash('Recurso no encontrado.', 'danger')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))
    if not current_user.is_admin and job.usuario_id != current_user.id:
        flash('No tienes permiso para ver este resultado.', 'danger')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))
    return render_template(
        'umbrella/resultado.html',
        herramienta=herramienta,
        job=job,
        titulo_navbar="Herramientas Umbrella",
    )


# ─── DESCARGA CSV ────────────────────────────────────────────────────────────

@bp.route('/herramienta/<herramienta_slug>/job/<int:job_id>/descargar')
def descargar_resultado(herramienta_slug, job_id):
    herramienta = UmbrellaHerramienta.query.filter_by(slug=herramienta_slug).first_or_404()
    job = UmbrellaJob.query.get_or_404(job_id)

    if job.herramienta_id != herramienta.id:
        flash('Recurso no encontrado.', 'danger')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))
    if not current_user.is_admin and job.usuario_id != current_user.id:
        flash('No tienes permiso para descargar este resultado.', 'danger')
        return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['#', 'Aplicacion', 'Categoria', 'Estado', 'Etiqueta', 'HTTP', 'Mensaje'])
    for i, r in enumerate(job.resultados, 1):
        writer.writerow([
            i,
            r.app_name,
            r.category or '',
            r.status,
            r.label or '',
            r.http_code or '',
            r.error_message or '',
        ])

    timestamp = job.created_at.strftime('%Y%m%d_%H%M%S')
    filename = f"umbrella_app_discovery_{job.id}_{timestamp}.csv"
    return Response(
        si.getvalue().encode('utf-8-sig'),  # utf-8-sig for Excel compatibility
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


# ─── ELIMINAR JOB ────────────────────────────────────────────────────────────

@bp.route('/job/<int:job_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_job(job_id):
    job = UmbrellaJob.query.get_or_404(job_id)
    herramienta = UmbrellaHerramienta.query.get_or_404(job.herramienta_id)
    herramienta_slug = herramienta.slug
    db.session.delete(job)
    db.session.commit()
    flash('Ejecución eliminada.', 'success')
    return redirect(url_for('umbrella.ver_herramienta', herramienta_slug=herramienta_slug))
