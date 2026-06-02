# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A Flask-based CSIRT (Computer Security Incident Response Team) portal for Chilean government security operations. Core features: scraping the csirt.gob.cl RSS feed, IoC (Indicator of Compromise) extraction, VirusTotal API integration for threat analysis, and role-based user management.

## Running the app

**Development:**
```
python run.py
```
Starts Flask dev server at http://localhost:5000 with debug mode.

**Production:**
```
python server.py
```
Starts Cheroot WSGI with SSL (HTTPS on port 8443, or HTTP on 8080 if no certs). Auto-initializes DB and runs migrations on startup.

The app also supports Docker (`docker-compose up`) and PyInstaller EXE packaging.

## Environment setup

Copy or create `.env` with:
```
SECRET_KEY=<flask session secret>
SECRET_KEY_DB=<fernet base64 key for encrypting VT API keys>
CREDENTIAL_MANAGER_KEY=<reserved>
```

`SECRET_KEY_DB` must be a valid Fernet key (32-byte base64-encoded). `config.py` validates these on startup and raises `ValueError` if missing or malformed.

## Database

SQLite at `instance/app.db`. Flask-Migrate (Alembic) manages schema. Migrations live in `migrations/versions/`. The production server auto-runs `flask db upgrade` on startup. For development:

```
flask db migrate -m "description"
flask db upgrade
```

## No test suite currently exists

There are no pytest/unittest files. When adding tests, use pytest.

## Architecture

**App factory** in `app/__init__.py` registers four blueprints and sets up APScheduler:

| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `auth` | `/auth` | Login, setup, user/tool management |
| `main` | `/` | Dashboard, notifications |
| `csirt` | `/csirt` | Alert scraping, IoC extraction, CSV import/export |
| `virustotal` | `/virustotal` | VT API analysis cases, export templates |

**Models** (`app/models/`): `User`/`UserTool`, `Alerta`/`Ioc`, `VtTicket`/`VtIoc`/`ExportTemplate`, `Notification`. `VtInfoMixin` in `mixins.py` is shared by `Ioc` and `VtIoc` to store VirusTotal scan result fields.

**Tool-based access control**: Users are granted access to specific tools (e.g., `csirt`, `virustotal`) via the `user_tool` junction table. The `proteger_blueprint(bp, 'tool_name')` decorator in `utils.py` secures all routes in a blueprint by checking `UserTool`. Admin users bypass all tool restrictions.

**Scheduled scraping**: An APScheduler job (`vigilar_nuevas_alertas()`) runs hourly, pulling from the csirt.gob.cl RSS feed, extracting IoCs via regex, and storing results. Defined in `app/csirt/scheduler.py`.

**VirusTotal background worker**: Long-running VT API scans spawn a `threading.Thread` (`_worker_analisis` in `app/virustotal/routes.py`). The worker enforces a 0.5 s sleep between API calls and aborts on quota exhaustion. IoC results are cached for 14 days; cross-module lookups reuse results within 7 days.

**Encrypted API keys**: Each user's VT API key is encrypted at rest using Fernet (AES) with `SECRET_KEY_DB` as the encryption key. Use `User.set_vt_key()` / `User.get_vt_key()` — never access the raw `_vt_api_key` column directly.

**Multi-format export**: `ExportTemplate` model lets admins define custom export formats for AV/EDR platforms with template variables (`{valor}`, `{tipo}`, `{md5}`, etc.). Outputs CSV, TXT, XML, or JSON.

**Hybrid deployment detection**: `config.py` and `server.py` check `getattr(sys, 'frozen', False)` to detect PyInstaller EXE mode vs. normal Python, adjusting base paths accordingly.

## Key files

- `config.py` — Flask configuration, path resolution for all three deployment modes, secret key validation
- `app/extensions.py` — Shared extension instances (db, login_manager, csrf, limiter)
- `app/tools_config.py` — Registry of available tools (add new modules here)
- `app/utils.py` — `admin_required`, `proteger_blueprint` decorators; Excel export helper
- `server.py` — Production entry point with SSL negotiation and startup DB migration
