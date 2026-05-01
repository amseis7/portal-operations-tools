from flask import render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.credentials import bp
from sqlalchemy import or_
from app.models.credentials import Credential, CredentialGroup
from app.utils import proteger_blueprint

proteger_blueprint(bp, 'credentials')

@bp.route('/')
def index():
    # Obtener todos los grupos para la barra lateral
    groups = CredentialGroup.query.order_by(CredentialGroup.name).all()
    
    # Recibir parámetros de la URL (lo que envía el buscador)
    active_group_id = request.args.get('group_id', type=int)
    search_query = request.args.get('q', '').strip() # <--- Aquí recibe lo que escribiste
    
    # Empezamos la consulta base
    query = Credential.query.join(CredentialGroup)

    active_group = None

    # LÓGICA DE BÚSQUEDA
    if search_query:
        # Busca si el texto está en el Título O Usuario O Notas O Url O Nombre del Grupo
        search_filter = (
            Credential.title.ilike(f'%{search_query}%') |
            Credential.username.ilike(f'%{search_query}%') |
            Credential.notes.ilike(f'%{search_query}%') |
            Credential.url.ilike(f'%{search_query}%') |
            CredentialGroup.name.ilike(f'%{search_query}%')
        )
        query = query.filter(search_filter)
        
    # LÓGICA DE FILTRO POR GRUPO (Solo si no estás buscando)
    elif active_group_id:
        query = query.filter(Credential.group_id == active_group_id)
        active_group = CredentialGroup.query.get(active_group_id)

    # Ejecutar la consulta final
    credentials = query.all()

    return render_template('credentials/index.html', 
                           groups=groups, 
                           credentials=credentials, 
                           active_group=active_group,
                           search_query=search_query)

                           
@bp.route('/create', methods=['GET', 'POST'])
def create():
    groups = CredentialGroup.query.order_by(CredentialGroup.name).all()
    
    if request.method == 'POST':
        title = request.form.get('title')
        username = request.form.get('username')
        password = request.form.get('password') # Texto plano
        url = request.form.get('url')
        notes = request.form.get('notes')
        group_id = request.form.get('group_id')
        new_group_name = request.form.get('new_group_name')

        # Lógica rápida para crear grupo al vuelo
        if new_group_name:
            group = CredentialGroup(name=new_group_name)
            db.session.add(group)
            db.session.commit()
            group_id = group.id
        
        if not group_id:
            flash('Debes seleccionar o crear un grupo.', 'danger')
            return redirect(url_for('credentials.create'))

        # Crear credencial
        cred = Credential(title=title, username=username, url=url, notes=notes, group_id=group_id)
        # AQUÍ OCURRE LA MAGIA: Se encripta antes de guardar
        cred.set_password(password) 
        
        db.session.add(cred)
        db.session.commit()
        flash('Credencial guardada y encriptada exitosamente.', 'success')
        return redirect(url_for('credentials.index', group_id=group_id))

    return render_template('credentials/form.html', groups=groups, credential=None)

@bp.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    cred = Credential.query.get_or_404(id)
    groups = CredentialGroup.query.order_by(CredentialGroup.name).all()

    if request.method == 'POST':
        cred.title = request.form.get('title')
        cred.username = request.form.get('username')
        cred.url = request.form.get('url')
        cred.notes = request.form.get('notes')
        cred.group_id = request.form.get('group_id')
        
        # Solo actualizamos la contraseña si el usuario escribió algo nuevo
        new_pass = request.form.get('password')
        if new_pass:
            cred.set_password(new_pass)

        db.session.commit()
        flash('Credencial actualizada.', 'success')
        return redirect(url_for('credentials.index', group_id=cred.group_id))

    return render_template('credentials/form.html', groups=groups, credential=cred)

@bp.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    cred = Credential.query.get_or_404(id)
    group_id = cred.group_id
    db.session.delete(cred)
    db.session.commit()
    flash('Credencial eliminada.', 'info')
    return redirect(url_for('credentials.index', group_id=group_id))

@bp.route('/group/create', methods=['POST'])
def create_group():
    group_name = request.form.get('name')
    
    if not group_name:
        flash('El nombre del grupo es obligatorio.', 'warning')
        return redirect(url_for('credentials.index'))
    
    # Validar que no exista ya
    existing = CredentialGroup.query.filter_by(name=group_name).first()
    if existing:
        flash('Ese grupo ya existe.', 'warning')
        return redirect(url_for('credentials.index'))

    new_group = CredentialGroup(name=group_name)
    db.session.add(new_group)
    db.session.commit()
    
    flash(f'Grupo "{group_name}" creado.', 'success')
    return redirect(url_for('credentials.index'))

@bp.route('/group/edit/<int:id>', methods=['POST'])
def edit_group(id):
    group = CredentialGroup.query.get_or_404(id)
    new_name = request.form.get('name')
    
    if not new_name:
        flash('El nombre no puede estar vacío.', 'warning')
        return redirect(url_for('credentials.index', group_id=group.id))
        
    # Validar duplicados (excluyendo el propio grupo)
    existing = CredentialGroup.query.filter(CredentialGroup.name == new_name, CredentialGroup.id != id).first()
    if existing:
        flash('Ya existe un grupo con ese nombre.', 'warning')
        return redirect(url_for('credentials.index', group_id=group.id))

    group.name = new_name
    db.session.commit()
    flash('Grupo renombrado exitosamente.', 'success')
    return redirect(url_for('credentials.index', group_id=group.id))

@bp.route('/group/delete/<int:id>', methods=['POST'])
def delete_group(id):
    group = CredentialGroup.query.get_or_404(id)
    
    # Opción: Borrar todas las credenciales asociadas primero
    # (Si prefieres que no deje borrar si tiene cosas, avísame para cambiar esto)
    for cred in group.credentials:
        db.session.delete(cred)
        
    db.session.delete(group)
    db.session.commit()
    
    flash(f'Grupo "{group.name}" y sus credenciales han sido eliminados.', 'info')
    return redirect(url_for('credentials.index'))

# --- ENDPOINT DE SEGURIDAD ---
@bp.route('/reveal/<int:id>', methods=['POST'])
def reveal(id):
    """
    Este endpoint recibe una petición AJAX y devuelve la contraseña desencriptada.
    Solo debe llamarse cuando el usuario hace clic en 'Ver'.
    """
    cred = Credential.query.get_or_404(id)
    try:
        plaintext = cred.get_password()
        return jsonify({'password': plaintext})
    except Exception as e:
        return jsonify({'error': 'No se pudo desencriptar'}), 500