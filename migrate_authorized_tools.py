"""
Script de migración de datos: authorized_tools CSV -> user_tool table

EJECUTAR UNA SOLA VEZ DESPUÉS de flask db upgrade.

Uso:
    python migrate_authorized_tools.py

Este script:
1. Lee el campo authorized_tools (CSV) de cada User
2. Crea registros UserTool por cada herramienta
3. NO elimina la columna authorized_tools (se debe hacer manualmente o con migración)
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models.user import User, UserTool
from app.tools_config import TOOLS

app = create_app()

with app.app_context():
    print("[MIGRACIÓN] Iniciando migración de authorized_tools...")
    
    users = User.query.all()
    count = 0
    
    for user in users:
        raw = getattr(user, 'authorized_tools', None)
        if raw is None:
            continue

        if isinstance(raw, str) and raw.strip() == '':
            continue

        if isinstance(raw, str) and raw.strip() == 'all':
            for tool_name in TOOLS.keys():
                exists = UserTool.query.filter_by(user_id=user.id, tool_name=tool_name).first()
                if not exists:
                    db.session.add(UserTool(user_id=user.id, tool_name=tool_name))
                    count += 1
        elif isinstance(raw, str):
            for tool_name in raw.split(','):
                tool_name = tool_name.strip()
                if tool_name:
                    exists = UserTool.query.filter_by(user_id=user.id, tool_name=tool_name).first()
                    if not exists:
                        db.session.add(UserTool(user_id=user.id, tool_name=tool_name))
                        count += 1

    db.session.commit()
    print(f"[MIGRACIÓN] Completada. {count} registros UserTool creados.")