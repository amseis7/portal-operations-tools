from app import create_app, db
from app.models import User

app = create_app()

# Esto permite usar el comando 'flask shell' con contexto cargado (opcional pero útil)
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

if __name__ == '__main__':
    app.run(debug=True)