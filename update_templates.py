from app import create_app, db
from app.models import ExportTemplate
import sqlite3

app = create_app()
with app.app_context():
    db.create_all()
    print("Tabla ExportTemplate creada.")
    
    # Crear unos templates por defecto para probar
    if not ExportTemplate.query.first():
        # 1. TrendMicro (CSV simple)
        t1 = ExportTemplate(
            nombre_plataforma="TrendMicro",
            vt_engine_name="TrendMicro",
            file_extension="csv",
            header_content="Object,Type,Description",
            row_template="{valor},{tipo},Bloqueado por CSIRT (VT:{positives})"
        )
        # 2. Generico (TXT)
        t2 = ExportTemplate(
            nombre_plataforma="Firewall Generico",
            vt_engine_name="Symantec",
            file_extension="txt",
            header_content="# Lista Negra",
            row_template="deny {valor};"
        )
        db.session.add_all([t1, t2])
        db.session.commit()
        print("Templates de ejemplo creados.")