# AGENTS.md - Guía Rápida para OpenCode

Este documento destaca información crítica para agentes que trabajan en el repositorio `servidor-csirt`.

## ⚙️ Arquitectura y Componentes Clave

*   **Aplicación Flask:** Modularizada con Blueprints (`auth`, `main`, `csirt`, `virustotal`, `checklist`, `credentials`).
*   **Base de Datos:** SQLite (`instance/app.db`) persistida vía volumen Docker. Utiliza Flask-SQLAlchemy.
*   **Autenticación:** Flask-Login con gestión de contraseñas (política de complejidad).
*   **Gestión de Secretos:** Claves sensibles cargadas desde `.env` y credenciales encriptadas con Fernet.
*   **Tareas en Segundo Plano:** `APScheduler` para `Web Scraping` de CSIRT (alertas) y `Barrido Checklist` (monitoreo de servicios).
*   **Servidor:** `run.py` para desarrollo (`debug=True`), `server.py` para producción (Cheroot, SSL).

## 🚀 Comandos Esenciales

*   **Instalar dependencias:** `pip install -r requirements.txt`
*   **Iniciar desarrollo:** `python run.py` (Puerto 5000, con `debug=True`)
*   **Iniciar producción (Docker):**
    1.  Construir imagen: `docker build -t servidor-csirt .`
    2.  Lanzar servicios: `docker-compose up -d`
*   **Parche manual de DB:** `run.py` contiene una función `parchear_base_datos()` para añadir `virustotal_api_key` a la tabla `user` si falta. **Esto no es Flask-Migrate.**

## ⚠️ Peculiaridades y Puntos de Atención

*   **Logging:** Uso extensivo de `print()`. Priorizar la migración al módulo `logging` de Python para telemetría estructurada.
*   **Secrets en `.env`:** `SECRET_KEY_DB` y `CREDENTIAL_MANAGER_KEY` se cargan desde `.env`. En producción, usar variables de entorno directamente o bóvedas de secretos.
*   **Certificados SSL:** `cert.pem`, `key.pem`, `cert.crt` se copian directamente en la raíz. Considerar terminación SSL externa o inyección segura de secretos.
*   **Docker por Defecto:** La aplicación en Docker se ejecuta como `root`. Configurar un usuario no-root es crucial para el hardening.
*   **Desactivación CSRF:** La línea `@csrf.exempt` en `app/checklist/routes.py` está comentada. Si se descomenta, se debe evaluar el riesgo de seguridad.
*   **Validación de entradas:** La validación es ad-hoc y dispersa. Buscar patrones de `re.match` o `replace` para entradas de usuario.

## ✅ Convenciones

*   **Estilo:** Sigue las convenciones de Flask y Python.
*   **UI:** Bootstrap 5.
