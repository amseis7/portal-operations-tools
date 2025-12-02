from app import create_app, db
from app.models import VtTicket, VtIoc

app = create_app()
with app.app_context():
    # Esto revisa qué tablas faltan y las crea
    db.create_all()
    print("¡Tablas de VirusTotal creadas!")