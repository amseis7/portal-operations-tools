from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Alerta, Ioc, VtTicket, VtIoc
from app.virustotal import bp
from app.virustotal.logic import consultar_virustotal_ioc # Importamos tu lógica

@bp.route('/')
@login_required
def index():
    tickets = VtTicket.query.order_by(VtTicket.fecha_creacion.desc()).all()
    return render_template('virustotal/index.html', tickets=tickets)

# 2. CREAR NUEVO CASO
@bp.route('/crear_caso', methods=['POST'])
@login_required
def crear_caso():
    nombre = request.form.get('nombre')
    descripcion = request.form.get('descripcion')
    
    nuevo_ticket = VtTicket(
        nombre=nombre,
        descripcion=descripcion,
        usuario_id=current_user.id
    )
    db.session.add(nuevo_ticket)
    db.session.commit()
    
    flash('Caso de investigación creado.', 'success')
    return redirect(url_for('virustotal.ver_caso', caso_id=nuevo_ticket.id))

# 3. VER CASO (Detalle y Agregar IoCs)
@bp.route('/caso/<int:caso_id>', methods=['GET', 'POST'])
@login_required
def ver_caso(caso_id):
    caso = VtTicket.query.get_or_404(caso_id)
    
    # Agregar IoCs masivamente
    if request.method == 'POST':
        raw_text = request.form.get('hashes_input')
        tipo_seleccionado = request.form.get('tipo_ioc')
        
        if raw_text:
            items = [line.strip() for line in raw_text.splitlines() if line.strip()]
            count = 0
            for item in items:
                # Limpieza básica (igual que antes)
                valor_limpio = item
                if tipo_seleccionado == 'dominio':
                     valor_limpio = item.replace("https://", "").replace("http://", "").split("/")[0]
                
                nuevo_ioc = VtIoc(
                    ticket_id=caso.id,
                    tipo=tipo_seleccionado,
                    valor=valor_limpio
                )
                db.session.add(nuevo_ioc)
                count += 1
            db.session.commit()
            flash(f'{count} IoCs agregados al caso.', 'success')
            return redirect(url_for('virustotal.ver_caso', caso_id=caso.id))

    return render_template('virustotal/detalle_caso.html', caso=caso)

# 4. ANALIZAR CASO COMPLETO
@bp.route('/analizar_caso/<int:caso_id>', methods=['POST'])
@login_required
def analizar_caso(caso_id):
    if not current_user.virustotal_api_key:
        flash('Configura tu API Key primero.', 'danger')
        return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))

    caso = VtTicket.query.get_or_404(caso_id)
    iocs = caso.iocs
    
    flash(f'Analizando {len(iocs)} IoCs...', 'info')
    
    cont = 0
    for ioc in iocs:
        # Reutilizamos la lógica maestra
        if consultar_virustotal_ioc(ioc):
            cont += 1
            
    flash(f'Análisis finalizado. {cont} actualizados.', 'success')
    return redirect(url_for('virustotal.ver_caso', caso_id=caso_id))