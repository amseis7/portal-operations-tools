from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Alerta, Ioc
from app.virustotal import bp
from app.virustotal.logic import consultar_virustotal_ioc # Importamos tu lógica

@bp.route('/analizar_ticket/<ticket_id>', methods=['POST'])
@login_required
def analizar_ticket(ticket_id):
    # 1. Validación de API Key
    if not current_user.virustotal_api_key:
        flash('Error: No tienes una API Key de VirusTotal configurada. Ve a "Mi Cuenta" para agregarla.', 'danger')
        return redirect(url_for('csirt.ver_iocs', ticket_id=ticket_id))

    # 2. Buscar IoCs del ticket (con filtro opcional)
    query = db.session.query(Ioc).join(Alerta).filter(Alerta.ticket == ticket_id)
    
    tipo_filtro = request.args.get('tipo')
    if tipo_filtro:
        if tipo_filtro == 'hash':
            query = query.filter(Ioc.tipo.in_(['hash', 'md5', 'sha1', 'sha256']))
        else:
            query = query.filter(Ioc.tipo == tipo_filtro)
            
    iocs = query.all()
    
    if not iocs:
        flash(f'No se encontraron IoCs del tipo seleccionado para el ticket {ticket_id}.', 'warning')
        return redirect(url_for('csirt.ver_iocs', ticket_id=ticket_id))

    flash(f'Iniciando análisis de {len(iocs)} IoCs en VirusTotal...', 'info')
    
    # 3. Bucle de análisis
    cont_exito = 0
    for ioc in iocs:
        if consultar_virustotal_ioc(ioc):
            cont_exito += 1
            
    flash(f'Análisis completado. {cont_exito}/{len(iocs)} IoCs actualizados.', 'success')
    # 4. REDIRECCIÓN FINAL
    return redirect(url_for('csirt.ver_iocs', ticket_id=ticket_id))

@bp.route('/analizar_alerta/<int:alerta_id>', methods=['POST'])
@login_required
def analizar_alerta(alerta_id):
    """
    Analiza SOLO los IoCs de una alerta específica.
    Opcional: Recibe ?tipo=ip para filtrar.
    """
    # Validación de API Key
    if not current_user.virustotal_api_key:
        flash('Error: Configura tu API Key en "Mi Cuenta".', 'danger')
        # Buscamos la alerta para saber a dónde volver
        alerta = Alerta.query.get(alerta_id)
        if alerta:
             return redirect(url_for('csirt.ver_iocs_alerta', alerta_id=alerta_id))
        return redirect(url_for('main.dashboard'))

    alerta = Alerta.query.get_or_404(alerta_id)
    iocs = alerta.iocs
    
    # --- FILTRO OPCIONAL POR TIPO ---
    tipo_filtro = request.args.get('tipo') # ej: 'ip', 'hash', 'url'
    
    if tipo_filtro:
        # Filtramos la lista en memoria
        if tipo_filtro == 'hash':
            iocs = [i for i in iocs if i.tipo in ['hash', 'md5', 'sha1', 'sha256']]
        else:
            iocs = [i for i in iocs if i.tipo == tipo_filtro]
            
    if not iocs:
        flash(f'No hay IoCs de tipo "{tipo_filtro or "todos"}" en esta alerta.', 'warning')
        return redirect(url_for('csirt.ver_iocs_alerta', alerta_id=alerta_id))

    flash(f'Analizando {len(iocs)} IoCs de {alerta.nombre_alerta}...', 'info')
    
    cont = 0
    for ioc in iocs:
        if consultar_virustotal_ioc(ioc):
            cont += 1
            
    flash(f'Análisis finalizado. {cont}/{len(iocs)} IoCs actualizados.', 'success')
    return redirect(url_for('csirt.ver_iocs_alerta', alerta_id=alerta_id))