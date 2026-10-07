# Auditoría técnica — Portal de Operaciones

**Fecha:** 2026-07-28
**Rama auditada:** `refactor/vault` (con cambios sin commitear)
**Alcance:** repositorio completo (136 archivos versionados, ~10.100 líneas entre Python y plantillas)
**Método:** lectura de código, ejecución de comprobaciones locales seguras (compilación, introspección del `url_map` y de `app.config`, inspección de `instance/`). No se ejecutó ninguna operación contra VirusTotal, Cisco Umbrella, csirt.gob.cl, ni contra la base de datos de producción.

---

## 1. Resumen ejecutivo

El proyecto es una aplicación Flask monolítica bien organizada por blueprints, con decisiones acertadas para su contexto: cifrado en reposo de credenciales, auditoría transversal, CSRF activo en todas las plantillas, control de acceso por herramienta y migraciones Alembic con cadena lineal íntegra. La base es sólida y **no requiere reescritura**.

Sin embargo, la auditoría encontró **cinco problemas críticos**, todos verificados con evidencia directa en el repositorio:

1. La API REST de APScheduler está publicada sin autenticación en `/scheduler/*` (13 endpoints, verificado en el `url_map`). `POST /scheduler/jobs` acepta una referencia textual `modulo:funcion`, lo que constituye ejecución remota de código sin credenciales.
2. El módulo `vault` —el más sensible del sistema, que almacena contraseñas— es el único blueprint al que **nunca se le aplicó `proteger_blueprint`**. Cualquier usuario autenticado accede al baúl aunque no tenga la herramienta asignada.
3. Dentro de `vault`, las rutas `edit` y `delete` no verifican propiedad: cualquier usuario autenticado puede modificar o borrar cualquier credencial por ID.
4. El asistente de importación KeePass escribe las contraseñas **en texto plano** en `instance/*.json` y no las borra si el flujo se abandona. **Se encontraron 4 archivos huérfanos con 30 credenciales reales en claro**, el más antiguo con 42 días de antigüedad.
5. La pantalla de configuración de sincronización devuelve la **contraseña maestra del `.kdbx` descifrada** dentro del HTML.

Adicionalmente, `requirements.txt` está incompleto (faltan `cheroot`, `Flask-Migrate`, `Flask-WTF`, `WTForms`): una instalación limpia o un `docker build` produce una aplicación que no arranca.

El sistema **no tiene ninguna prueba automatizada**. Dado que las herramientas escriben en plataformas externas (Cisco Umbrella) y manipulan credenciales, esto es el principal obstáculo para mantenerlo con seguridad durante varios años.

**Recomendación:** aplicar los cinco críticos y `A-01` de inmediato (todos son cambios pequeños y aislados), añadir después una red de pruebas mínima sobre control de acceso, y solo entonces abordar la deuda estructural.

---

## 2. Arquitectura actual observada

### Stack

| Capa | Tecnología |
|------|-----------|
| Lenguaje | Python 3.11 |
| Framework | Flask 3.1.2 (app factory + blueprints) |
| ORM / migraciones | SQLAlchemy 2.0.44 / Flask-SQLAlchemy 3.1.1 / Flask-Migrate (Alembic) |
| Base de datos | SQLite (`instance/app.db`, ~38 MB) |
| Sesiones / auth | Flask-Login + Werkzeug password hashing |
| Formularios | Flask-WTF / WTForms (solo en `vault`; el resto usa `request.form` crudo) |
| Frontend | Jinja2 + Bootstrap 5 vendorizado + JS vanilla inline |
| Tareas | APScheduler (scraping horario) + `threading.Thread` ad-hoc (VT, Umbrella, sync vault) |
| Cifrado | `cryptography` (Fernet) con tres claves distintas |
| Servidor prod | Cheroot WSGI + `BuiltinSSLAdapter` (8443 HTTPS / 8080 HTTP) |
| Empaquetado | PyInstaller (`.spec`), Docker (`Dockerfile` + `docker-compose.yml`) |
| Integraciones | csirt.gob.cl (RSS + scraping HTML), VirusTotal API v3, Cisco Umbrella API v2, archivos KeePass `.kdbx` (pykeepass) |

### Puntos de entrada

- `run.py` — desarrollo: `app.run(debug=True, host='0.0.0.0')` tras `flask db upgrade`.
- `server.py` — producción: inicializa/migra la DB, negocia SSL, levanta Cheroot con 10 hilos.
- `migrate_authorized_tools.py` — script de migración de datos **puntual y hoy inoperante** (ver `B-02`).

### Estructura

```
app/
├── __init__.py          app factory: extensiones, cabeceras, scheduler, 6 blueprints
├── extensions.py        instancias compartidas (db, login_manager, csrf, migrate, limiter)
├── tools_config.py      registro de herramientas (dirige el dashboard y los permisos)
├── utils.py             admin_required, proteger_blueprint, generador de Excel
├── models/              user, csirt, virustotal, umbrella, notification, audit, mixins
├── auth/                login, setup inicial, perfil, ABM de usuarios
├── main/                dashboard, notificaciones, visor de auditoría
├── csirt/               routes.py + logic.py (scraping, extracción de IoC, import/export)
├── virustotal/          routes.py + logic.py + background.py (worker de análisis)
├── umbrella/            routes.py + logic.py + client.py + reader.py + background.py
├── vault/               routes.py + models.py + forms.py + crypto.py + sync.py
├── templates/           26 plantillas Jinja
└── static/              Bootstrap y iconos vendorizados
```

### Responsabilidad de cada módulo

| Módulo | Responsabilidad | Estado |
|--------|-----------------|--------|
| `auth` | Autenticación, bootstrap del primer admin, gestión de usuarios y asignación de herramientas | Funcional; sin capa de formularios, validación dispersa |
| `main` | Dashboard, notificaciones vía context processor, visor de `AuditLog` | Correcto y simple |
| `csirt` | Scraping RSS+HTML de csirt.gob.cl, extracción de IoC, import/export CSV, reporte Excel | Funcional; lógica y presentación mezcladas |
| `virustotal` | Casos de investigación, consulta a VT API con caché de 14/7 días, exportación multi-formato por plantillas | El más complejo; `logic.py` con funciones muy largas |
| `umbrella` | Lectura de Excel y asignación masiva de etiquetas en Cisco Umbrella | **El mejor estructurado** (cliente/lógica/IO separados) y a la vez **el de mayor impacto externo** |
| `vault` | Baúl de credenciales cifradas, jerarquía tipo KeePass, importación y sincronización `.kdbx` | El más reciente; concentra los hallazgos críticos |

### Flujo de datos

```
Navegador ──HTTPS──> Cheroot (10 hilos) ──> Flask
                                             ├── before_request: setup + cambio de contraseña
                                             ├── blueprint before_request: has_tool()  [falta en vault]
                                             ├── ruta ──> logic.py ──> SQLAlchemy ──> SQLite
                                             └── logic ──> threading.Thread ──> API externa
                                                             (VT / Umbrella / .kdbx en red)
APScheduler (60 min) ──> vigilar_nuevas_alertas ──> RSS csirt.gob.cl ──> Notification
```

### Autenticación, autorización y sesiones

- Sesión: cookie firmada por Flask con `SECRET_KEY`. `HTTPONLY=True` (por defecto), **`SECURE=False`**, **`SAMESITE=None`**.
- Autenticación: Flask-Login. Rate limit de 5/min en login y 3/min en setup.
- Autorización en tres niveles: `@login_required` → `proteger_blueprint(bp, 'herramienta')` → `@admin_required`. Los admin saltan toda restricción de herramienta (`User.has_tool`).
- Contraseña inicial forzada mediante `before_app_request` con lista blanca de endpoints.

### Configuración por entorno

`config.py` es una única clase `Config` sin variantes dev/prod. Exige cuatro variables (`SECRET_KEY`, `SECRET_KEY_DB`, `CREDENTIAL_MANAGER_KEY`, `VAULT_KEY`) y aborta el arranque si falta alguna. `.env` está correctamente excluido de git y **no aparece en el historial** (verificado con `git log --all -- .env`). Detecta tres modos de despliegue (PyInstaller / Docker / local) para resolver rutas.

### Scripts de construcción, pruebas y despliegue

| Necesidad | Comando disponible | Estado |
|-----------|--------------------|--------|
| Instalar dependencias | `pip install -r requirements.txt` | **Roto** (ver `A-01`) |
| Ejecutar (dev) | `python run.py` | OK |
| Ejecutar (prod) | `python server.py` | OK |
| Migrar | `flask db migrate` / `flask db upgrade` | OK, cadena lineal íntegra |
| Linter | — | **No existe** |
| Comprobación de tipos | — | **No existe** |
| Pruebas | — | **No existe** |
| Construir | `pyinstaller Portal-Operations-Tools.spec` / `docker build` | El `.spec` está en `.gitignore` |

Comprobaciones seguras ejecutadas en esta auditoría:

```bash
python -m compileall -q app config.py run.py server.py    # exit 0, sin errores de sintaxis
python probe.py    # introspección de url_map y app.config con instance_path aislado
```

---

## 3. Aspectos correctamente implementados que conviene conservar

| # | Acierto | Dónde |
|---|---------|-------|
| 1 | **Registro de herramientas declarativo.** Añadir un módulo es: crear blueprint, registrarlo, añadir una entrada en `TOOLS`. El dashboard y los permisos se derivan solos. | `app/tools_config.py` |
| 2 | **`proteger_blueprint` como patrón.** Una línea asegura un blueprint entero; imposible olvidar un decorador ruta por ruta (aunque se olvidó el blueprint entero en `vault` — ver `C-02`). | `app/utils.py:19` |
| 3 | **Cifrado en reposo con claves separadas** por dominio (`SECRET_KEY_DB` para API keys y credenciales Umbrella, `VAULT_KEY` para el baúl). El acceso siempre pasa por métodos (`set_vt_key`/`get_vt_key`, `set_credentials`), nunca por la columna cruda. | `models/user.py:56-78`, `models/umbrella.py:35-57` |
| 4 | **Auditoría transversal.** `log_audit()` es sencillo, se estagea en la sesión y lo commitea el llamador — coherente transaccionalmente con la operación auditada. | `models/audit.py:27` |
| 5 | **CSRF en el 100% de los formularios.** Verificado en las 26 plantillas, incluidos los POST vía `fetch`. | Todas las plantillas |
| 6 | **Sin `|safe` en ninguna plantilla.** El autoescape de Jinja está intacto en contexto HTML. | Todas las plantillas |
| 7 | **`app/umbrella/` como modelo arquitectónico a seguir:** `client.py` (transporte + reintentos con backoff exponencial), `logic.py` (dominio puro con dataclasses, testeable sin Flask), `reader.py` (IO), `routes.py` (HTTP). Es la separación que debería adoptar el resto. | `app/umbrella/` |
| 8 | **Arranque que falla ruidosamente.** `config.py` aborta si falta un secreto y `server.py` hace `sys.exit(1)` si la migración falla: nunca arranca con la DB inconsistente. | `config.py:9-26`, `server.py:76-86` |
| 9 | **Cadena de migraciones lineal y coherente** (12 revisiones, un solo *head*: `1b639e84d474`), con el detalle correcto de `batch_alter_table` para SQLite. | `migrations/versions/` |
| 10 | **Cabeceras de seguridad** aplicadas globalmente (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`). | `app/__init__.py:31-38` |
| 11 | **Índices explícitos y compuestos** donde importan (`ix_alerta_ticket_tipo`, `ix_notification_read`) — poco frecuente en proyectos de este tamaño. | `models/csirt.py:8`, `models/notification.py:7` |
| 12 | **Modo de simulación (`dry_run`) en las dos herramientas destructivas** (scraping CSIRT y etiquetado Umbrella). | `csirt/logic.py:219`, `umbrella/logic.py:54` |

---

## 4. Problemas críticos

### C-01 — API de APScheduler expuesta sin autenticación (ejecución remota de código)

| | |
|---|---|
| **Prioridad** | Crítica |
| **Categoría** | Seguridad / control de acceso |
| **Archivo** | `config.py:49`, `app/__init__.py:50-52` |
| **Complejidad** | Baja |
| **Riesgo del cambio** | Muy bajo |

**Evidencia.** `config.py:49` fija `SCHEDULER_API_ENABLED = True` y `app/__init__.py:50-52` inicializa Flask-APScheduler. La introspección del `url_map` de la aplicación real confirma 13 rutas registradas y **ninguna** protegida por `login_required` ni por `before_request`:

```
/scheduler                       GET     scheduler.get_scheduler_info
/scheduler/jobs                  POST    scheduler.add_job
/scheduler/jobs                  GET     scheduler.get_jobs
/scheduler/jobs/<job_id>         DELETE  scheduler.delete_job
/scheduler/jobs/<job_id>/run     POST    scheduler.run_job
/scheduler/shutdown              POST    scheduler.shutdown_scheduler
...
```

Los `before_request` registrados son `{None: 4, 'csirt': 1, 'virustotal': 1, 'umbrella': 1}`; los cuatro globales son el chequeo de setup y el de cambio de contraseña, que no exigen autenticación.

**Consecuencia.** `POST /scheduler/jobs` acepta un job cuyo campo `func` es una referencia textual `modulo:funcion`, que APScheduler resuelve importando el módulo. Un atacante con acceso de red al puerto 8443, **sin ninguna credencial**, puede registrar y ejecutar código arbitrario con los privilegios del proceso — que tiene en memoria `VAULT_KEY` y `SECRET_KEY_DB`, es decir, todo el baúl de contraseñas. También puede detener el scheduler (`/scheduler/shutdown`) y enumerar los jobs.

**Recomendación.** Poner `SCHEDULER_API_ENABLED = False` en `config.py`. La API no se usa en ninguna parte del código ni de las plantillas (`grep` de `/scheduler` en `app/` no devuelve resultados). Si en el futuro se quisiera, exponerla detrás de `@admin_required`.

**Verificación.** Tras el cambio, la introspección del `url_map` no debe contener ninguna regla que empiece por `/scheduler`. El job `vigilante_csirt` debe seguir apareciendo en los logs de arranque y ejecutándose cada 60 minutos (deshabilitar la API REST no afecta al scheduler en sí).

---

### C-02 — El módulo `vault` carece por completo de control de acceso por herramienta

| | |
|---|---|
| **Prioridad** | Crítica |
| **Categoría** | Seguridad / control de acceso |
| **Archivo** | `app/vault/routes.py` (falta la llamada), `app/tools_config.py:23-29` |
| **Complejidad** | Baja |
| **Riesgo del cambio** | Medio (puede dejar sin acceso a usuarios que hoy lo usan de facto) |

**Evidencia.** `grep -rn proteger_blueprint` devuelve exactamente tres invocaciones:

```
app/csirt/routes.py:23        proteger_blueprint(bp, 'csirt')
app/umbrella/routes.py:23     proteger_blueprint(bp, 'umbrella')
app/virustotal/routes.py:19   proteger_blueprint(bp, 'virustotal')
```

`app/vault/routes.py` **no la llama**, pese a que `vault` está declarada como herramienta en `tools_config.py:23`. Confirmado empíricamente: `app.before_request_funcs` es `{None: 4, 'csirt': 1, 'virustotal': 1, 'umbrella': 1}` — sin clave `'vault'`.

**Consecuencia.** La casilla «Baúl de Contraseñas» de la pantalla de administración de usuarios no tiene ningún efecto. Todo usuario autenticado —incluido uno creado solo para consultar alertas CSIRT— puede entrar a `/vault/`, listar todas las entradas compartidas y **revelar sus contraseñas en claro** vía `POST /vault/<id>/reveal`. El permiso existe en la interfaz pero no se aplica en el servidor.

**Recomendación.** Añadir `proteger_blueprint(bp, 'vault')` tras los imports en `app/vault/routes.py`. **Antes de aplicarlo**, revisar qué usuarios usan hoy el baúl y concederles explícitamente la herramienta, porque el cambio les cortará el acceso (es el comportamiento correcto, pero es un cambio visible que debe anunciarse).

**Verificación.** Con un usuario no-admin y sin la herramienta `vault`: `GET /vault/` debe redirigir al dashboard con el aviso «No tienes acceso al módulo de vault». Con la herramienta concedida, acceso normal. Comprobar que `before_request_funcs` incluya la clave `'vault'`.

---

### C-03 — IDOR: cualquier usuario puede editar y borrar credenciales ajenas

| | |
|---|---|
| **Prioridad** | Crítica |
| **Categoría** | Seguridad / control de acceso |
| **Archivo** | `app/vault/routes.py:220-276` (`edit`, `delete`), y `283-311` (`group_new`, `group_delete`) |
| **Complejidad** | Baja |
| **Riesgo del cambio** | Bajo |

**Evidencia.** El módulo define el helper `_can_access(entry)` en la línea 34 y lo usa correctamente en `detail` (línea 195) y en `reveal` (línea 212). **No lo usa en `edit` ni en `delete`**:

```python
@bp.route("/<int:entry_id>/edit", methods=["GET", "POST"])
@login_required
def edit(entry_id):
    entry = _get_entry_or_404(entry_id)     # ← sin _can_access

    form = VaultEntryForm(obj=entry)
```

```python
@bp.route("/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete(entry_id):
    entry = _get_entry_or_404(entry_id)     # ← sin _can_access
    title, eid = entry.title, entry.id
```

Además `group_new` y `group_delete` solo llevan `@login_required`, sin `@admin_required` ni verificación alguna.

**Consecuencia.** Un usuario puede modificar la contraseña de una credencial privada de otro (`POST /vault/7/edit`) o eliminarla (`POST /vault/7/delete`) conocido solo el ID entero, que es enumerable. Combinado con `C-02`, cualquier usuario del portal puede hacerlo. `group_delete` además desasocia en masa las entradas del grupo (`update({"group_id": None})`), corrompiendo la jerarquía para todos.

**Recomendación.** Añadir `if not _can_access(entry): abort(403)` en `edit` y `delete`. Para escritura, considerar un predicado más estricto que el de lectura: `shared` debería habilitar ver, no necesariamente borrar. Restringir la gestión de grupos a `@admin_required`, que es coherente con el resto del flujo de importación.

**Verificación.** Con el usuario A dueño de la entrada N (no compartida) y el usuario B: `POST /vault/N/edit` y `POST /vault/N/delete` desde B deben devolver 403. Desde A y desde un admin, deben seguir funcionando. Una entrada con `shared=True` debe seguir siendo visible para todos.

---

### C-04 — Contraseñas en texto plano escritas y abandonadas en disco por el importador KeePass

| | |
|---|---|
| **Prioridad** | Crítica |
| **Categoría** | Seguridad / exposición de datos sensibles |
| **Archivo** | `app/vault/routes.py:398-404` (escritura), `447-459` (borrado condicional) |
| **Complejidad** | Media |
| **Riesgo del cambio** | Medio (cambia el mecanismo del asistente de 3 pasos) |

**Evidencia.** El importador vuelca todas las entradas del `.kdbx` —con `"password": kp_entry.password` **sin cifrar** (línea 373)— a un JSON en `instance/`:

```python
token = uuid_mod.uuid4().hex
tmp_json = os.path.join(current_app.instance_path, f"vault_import_{token}.json")
with open(tmp_json, "w", encoding="utf-8") as f:
    json_mod.dump({"new": new_entries, "conflicts": conflicts}, f)
```

El archivo solo se borra en `import_confirm` (línea 459). Si el administrador cierra la pestaña en la pantalla de previsualización, **queda para siempre**. No hay proceso de limpieza en ninguna parte del código.

**Esto ya ocurrió.** Inspección de `instance/` en este repositorio:

```
vault_import_5546a375a40740fabc439be822befaa1.json  4140 B  10 entradas con contraseña en claro  2026-06-18
vault_import_c17461a29a5b4fbabbaccaa205b675eb.json  4140 B  10 entradas con contraseña en claro  2026-06-16
vault_import_f831915071b44288b76f19024bfc1f6e.json  4140 B  10 entradas con contraseña en claro  2026-06-16
vault_import_266059e555174591978a7ee7da0abba4.json  5416 B  10 conflictos                        2026-06-16
```

**30 credenciales reales, legibles con un editor de texto, llevan 42 días en el directorio de la aplicación.** Anula por completo el cifrado Fernet del baúl: el atacante no necesita `VAULT_KEY`.

**Consecuencia.** Cualquiera con acceso al sistema de archivos del servidor (respaldo, copia de la carpeta, snapshot de la VM, usuario del equipo donde corre el EXE) lee las credenciales. El directorio `instance/` está en `.gitignore`, pero también contiene `app.db` y `app.db.old` — un respaldo por copia de carpeta los arrastra todos.

**Recomendación.** Tres acciones, en este orden:

1. **Inmediato y manual:** borrar los cuatro archivos y **rotar las 30 credenciales expuestas**. Esta es una decisión operativa que corresponde al responsable del baúl, no al código.
2. Cifrar el payload intermedio con `app.vault.crypto.encrypt` antes de escribirlo, o —mejor— eliminar el archivo intermedio: guardar en `session` solo el token y volver a parsear el `.kdbx`… lo que exige conservar el `.kdbx`. La alternativa más simple y sin dependencias nuevas es cifrar el JSON con la clave del vault, que ya está disponible.
3. Añadir limpieza por antigüedad: borrar todo `vault_import_*.json` con más de 30 minutos, al inicio de `import_kdbx`. Son tres líneas con `os.path.getmtime`.

**Verificación.** Iniciar una importación y abandonarla en la previsualización; iniciar otra 31 minutos después: el archivo huérfano debe haber desaparecido. Abrir con un editor un archivo intermedio recién creado: no debe contener ninguna contraseña legible. El flujo completo (subir → previsualizar → confirmar) debe seguir creando las mismas entradas.

---

### C-05 — La contraseña maestra del `.kdbx` se devuelve descifrada en el HTML

| | |
|---|---|
| **Prioridad** | Crítica |
| **Categoría** | Seguridad / exposición de datos sensibles |
| **Archivo** | `app/vault/routes.py:520-527`, `app/templates/vault/sync_settings.html:42-44` |
| **Complejidad** | Baja |
| **Riesgo del cambio** | Bajo (pequeño cambio de comportamiento visible) |

**Evidencia.** La ruta descifra la contraseña y la pasa a la plantilla:

```python
current_password = ""
if cfg and cfg.kdbx_password_enc:
    try:
        current_password = decrypt(cfg.kdbx_password_enc)
    except Exception:
        current_password = ""

return render_template("vault/sync_settings.html", cfg=cfg, current_password=current_password)
```

Y la plantilla la escribe en el atributo `value`:

```html
<input type="password" class="form-control" name="kdbx_password"
       value="{{ current_password }}"
       placeholder="Dejar en blanco para no cambiarla">
```

`type="password"` solo la oculta visualmente. Está en el DOM, en «ver código fuente», accesible desde cualquier extensión del navegador y potencialmente en la caché del navegador y en el historial del gestor de contraseñas.

Nótese la incoherencia interna: la tarjeta inferior de la misma plantilla (línea 84) sí hace lo correcto, mostrando solo la palabra «configurada».

**Consecuencia.** La contraseña maestra del archivo `.kdbx` que se publica en la red compartida —es decir, la llave de **todas** las credenciales exportadas— queda expuesta a cualquiera que abra esa pantalla o inspeccione el HTML. Además, el `placeholder` promete un comportamiento («dejar en blanco para no cambiarla») que el código no implementa: `routes.py:512` sobrescribe con `None` si el campo llega vacío, borrando la contraseña configurada.

**Recomendación.** No pasar `current_password` a la plantilla; dejar el campo vacío. Implementar de verdad el comportamiento prometido: si `kdbx_password` llega vacío **y** ya existe una contraseña guardada, conservar la existente en lugar de anularla. Eliminar la variable `current_password` de la ruta.

**Verificación.** Ver el código fuente de `/vault/configuracion`: el atributo `value` del campo de contraseña debe estar vacío. Guardar el formulario dejando la contraseña en blanco y comprobar que `cfg.kdbx_password_enc` conserva su valor anterior y que la sincronización sigue funcionando.

---

## 5. Problemas de prioridad alta

### A-01 — `requirements.txt` incompleto: la instalación limpia y el `docker build` producen una app que no arranca

**Categoría:** dependencias · **Archivo:** `requirements.txt` · **Complejidad:** baja · **Riesgo:** muy bajo

**Evidencia.** Cuatro paquetes que el código importa no están declarados:

| Paquete | Importado en | ¿En requirements? |
|---------|--------------|-------------------|
| `cheroot` | `server.py:6-7` | **No** |
| `Flask-Migrate` | `app/extensions.py:4`, `run.py:8`, `server.py:8` | **No** |
| `Flask-WTF` | `app/extensions.py:3`, `app/vault/forms.py:1` | **No** |
| `WTForms` | `app/vault/forms.py:2` | **No** |

Instalados en el entorno actual (`cheroot==11.1.2`, `Flask-Migrate==4.1.0`, `Flask-WTF==1.3.0`, `WTForms==3.2.2`), pero por arrastre histórico, no por declaración. En sentido contrario, `waitress==3.0.2` está declarado y **no se importa en ninguna parte** (el comentario del `Dockerfile` sigue diciendo «incluyendo waitress», aunque el `CMD` ejecuta `server.py`, que usa Cheroot).

**Consecuencia.** `pip install -r requirements.txt && python server.py` falla con `ModuleNotFoundError: No module named 'cheroot'`. El `Dockerfile` hace exactamente eso: **la imagen Docker está rota**. Cualquier reinstalación, máquina nueva o pipeline de CI futuro falla en el primer arranque.

**Recomendación.** Añadir las cuatro dependencias con las versiones actualmente instaladas y eliminar `waitress`. Revisar también `bcrypt`, `flask-csrf` y `pycryptodomex`, presentes en el entorno pero sin uso en el código (`pycryptodomex` es probablemente una dependencia transitiva de `pykeepass`).

**Verificación.** En un virtualenv limpio: `pip install -r requirements.txt` seguido de `python -c "from app import create_app"` debe completarse sin error. Después, `docker build .` debe terminar y el contenedor arrancar.

---

### A-02 — Inyección de format string en las plantillas de exportación (fuga de `SECRET_KEY`)

**Categoría:** seguridad · **Archivo:** `app/virustotal/logic.py:444`, validación en `app/virustotal/routes.py:27-55` · **Complejidad:** media · **Riesgo:** bajo

**Evidencia.** La plantilla de fila, editable por administradores, se ejecuta con `str.format`:

```python
linea = template.row_template.format(**variables)
```

La validación previa solo reconoce marcadores simples:

```python
usadas = set(re.findall(r'\{(\w+)\}', row))
invalidas = usadas - VARIABLES_PERMITIDAS
```

Ese patrón **no captura** expresiones con acceso a atributos: `{valor.__class__}` no coincide con `\{(\w+)\}`, luego `invalidas` queda vacío y la plantilla se acepta. En tiempo de ejecución, `.format()` sí resuelve el acceso a atributos, permitiendo alcanzar `__class__.__init__.__globals__` a partir de una cadena.

**Consecuencia.** Un administrador (o alguien que consiga una sesión de administrador) puede exfiltrar la configuración del proceso —incluidas `SECRET_KEY`, `SECRET_KEY_DB` y `VAULT_KEY`— dentro de un archivo de exportación aparentemente inocuo. Con `SECRET_KEY_DB` y `VAULT_KEY` se descifra todo el baúl y todas las API keys, sin volver a tocar la aplicación. Es una escalada de administrador a compromiso total y persistente.

**Recomendación.** Sustituir `str.format` por sustitución literal sobre el conjunto cerrado de variables permitidas:

```python
linea = template.row_template
for k in VARIABLES_PERMITIDAS:
    linea = linea.replace("{" + k + "}", str(variables.get(k, "")))
```

Es equivalente para todas las plantillas legítimas y elimina la clase entera de vulnerabilidad. Endurecer además `validar_plantilla` para rechazar cualquier `{` que no pertenezca a la lista blanca.

**Verificación.** Exportar con las plantillas existentes y comparar los ZIP resultantes byte a byte contra la salida actual: deben ser idénticos. Crear una plantilla con `{valor.__class__}` y confirmar que se rechaza en validación y que, de existir ya en la DB, produce el literal en lugar de evaluarse.

---

### A-03 — XSS almacenado a través de los diálogos `confirm()` en atributos `onsubmit`

**Categoría:** seguridad · **Archivo:** `app/templates/vault/index.html:93`, `app/templates/auth/admin_usuarios.html:45`, `app/templates/virustotal/admin_templates.html:107`, `app/templates/csirt/index.html:99` · **Complejidad:** baja · **Riesgo:** bajo

**Evidencia.** Datos controlados por el usuario se interpolan dentro de un literal de cadena JavaScript, a su vez dentro de un atributo HTML:

```html
onsubmit="return confirm('¿Eliminar grupo «{{ g.name }}»? Las entradas quedarán sin grupo.');"
```

El autoescape de Jinja convierte `'` en `&#39;`, lo que es correcto para contexto HTML pero **no** para contexto JavaScript: el analizador HTML decodifica la entidad *antes* de que el motor JS analice el atributo, de modo que la comilla llega intacta al código.

Los nombres de grupo los crea **cualquier usuario autenticado** (`vault.group_new` no tiene `@admin_required`, ver `C-03`), y el diálogo lo dispara un administrador.

**Consecuencia.** Un usuario con acceso al baúl crea un grupo llamado `');<carga>//`, y el JavaScript se ejecuta en la sesión del administrador cuando este intenta borrarlo. Con `SESSION_COOKIE_HTTPONLY=True` la cookie no es directamente robable, pero el atacante puede actuar en nombre del administrador vía peticiones autenticadas (crear un usuario admin, leer el baúl completo).

**Recomendación.** Sustituir el `confirm()` inline por un `data-*` atributo (que Jinja escapa correctamente para contexto de atributo) leído desde un manejador delegado:

```html
<form ... data-confirm="¿Eliminar grupo «{{ g.name }}»?">
```

```js
document.addEventListener('submit', e => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});
```

Un único manejador en `base.html` cubre las cuatro plantillas y elimina el patrón del proyecto.

**Verificación.** Crear un grupo llamado `Test'); alert(1); //`, pulsar «eliminar» y comprobar que el diálogo muestra el nombre literal sin ejecutar nada. Confirmar que el resto de diálogos de confirmación sigue funcionando.

---

### A-04 — Cookie de sesión sin `Secure` ni `SameSite`

**Categoría:** seguridad / configuración · **Archivo:** `config.py` (ausencia) · **Complejidad:** baja · **Riesgo:** bajo

**Evidencia.** Introspección de la configuración real: `SESSION_COOKIE_SECURE = False`, `SESSION_COOKIE_SAMESITE = None`, `PERMANENT_SESSION_LIFETIME = 31 días`. `config.py` no define ninguna de estas claves.

**Consecuencia.** Con `Secure=False`, si el servidor arranca sin certificados cae a HTTP en el puerto 8080 (`server.py:134-135`) y la cookie de sesión viaja en claro por la red corporativa. Con `SameSite` sin fijar, la protección contra CSRF depende exclusivamente de Flask-WTF; endurecerla es defensa en profundidad barata.

**Recomendación.** Añadir a `Config`: `SESSION_COOKIE_SECURE = True` (condicionado a que exista certificado, para no romper el modo HTTP de desarrollo), `SESSION_COOKIE_SAMESITE = 'Lax'`, `SESSION_COOKIE_HTTPONLY = True` (explícito).

**Verificación.** En HTTPS, inspeccionar la cookie en las herramientas del navegador: debe llevar `Secure`, `HttpOnly` y `SameSite=Lax`. Login, navegación entre módulos y logout deben seguir funcionando.

---

### A-05 — Sin límite de tamaño de subida (`MAX_CONTENT_LENGTH = None`)

**Categoría:** seguridad / disponibilidad · **Archivo:** `config.py` (ausencia); afecta a `vault/routes.py:341`, `umbrella/routes.py:190,210` · **Complejidad:** baja · **Riesgo:** bajo

**Evidencia.** `MAX_CONTENT_LENGTH = None` confirmado en la configuración cargada. Solo el importador CSV de CSIRT valida el tamaño, y lo hace a mano (`csirt/routes.py:186-191`, límite de 5 MB). Los tres puntos de subida restantes no validan nada:

- `vault.import_kdbx` → `file.save(tmp_kdbx)` escribe directamente en `instance/`.
- `umbrella.preview_excel` y `umbrella.ejecutar` → `pd.read_excel()` carga el archivo entero en memoria.

Con solo 10 hilos en Cheroot (`server.py:16`), esto ya causó incidentes de producción documentados (errores SSL EOF en subidas grandes, mitigados subiendo el `socket_timeout` a 60 s en `server.py:152`).

**Consecuencia.** Un único usuario autenticado puede llenar el disco del servidor (`vault.import_kdbx` escribe sin límite en `instance/`) o agotar la memoria con un `.xlsx` comprimido de forma maliciosa. Con 10 hilos, unas pocas peticiones concurrentes dejan el portal fuera de servicio.

**Recomendación.** Fijar `MAX_CONTENT_LENGTH = 25 * 1024 * 1024` en `Config` y añadir un manejador de `413` que devuelva un mensaje claro en lugar del error genérico de Werkzeug. Una vez hecho, el chequeo manual de `csirt/routes.py:186-191` puede simplificarse o mantenerse como límite más estricto para CSV.

**Verificación.** Subir un archivo de 30 MB a `/vault/import`: debe rechazarse con un mensaje legible. Los archivos de tamaño normal deben seguir importándose. Comprobar que no queda ningún `import_*.kdbx` residual en `instance/`.

---

### A-06 — `NameError` al gestionar el límite de cuota de VirusTotal

**Categoría:** corrección · **Archivo:** `app/virustotal/logic.py:184-199` · **Complejidad:** baja · **Riesgo:** muy bajo

**Evidencia.** Error de indentación: las variables se definen dentro del `if` pero se usan fuera.

```python
if response.status_code == 429:
    cuota = obtener_uso_api(api_key)

    if cuota:
        usado = cuota.get('diario_usado', 0)
        limite = cuota.get('diario_limite', 0)

    if isinstance(limite, int) and usado >= limite:      # ← fuera del if cuota
```

Si `obtener_uso_api` devuelve `None` —cosa que hace ante cualquier fallo de red o código HTTP distinto de 200 (`logic.py:493-498`)—, `limite` y `usado` no existen y la línea lanza `NameError`.

**Consecuencia.** Justo cuando VirusTotal responde 429 y la red falla, el worker de análisis captura el `NameError` en el `except` genérico de `background.py:66-73`, marca el IoC como «Excepción interna» y **continúa consumiendo cuota** para el resto del lote en lugar de abortar. El mecanismo de protección de cuota falla precisamente en su escenario de activación. Además, el mensaje de excepción bruto se guarda en `vt_motores_json` y se muestra en la interfaz.

**Recomendación.** Inicializar `usado = 0` y `limite = None` antes del `if cuota:`, o mover el chequeo dentro del bloque. Ante `cuota is None`, lo prudente es tratar el 429 como límite de velocidad (esperar 60 s y reintentar), que es el comportamiento actualmente previsto por defecto.

**Verificación.** Prueba unitaria con `obtener_uso_api` simulado devolviendo `None` y una respuesta 429: la función no debe lanzar `NameError` y debe entrar en la pausa de 60 s. Con cuota agotada simulada, debe elevar `VT_QUOTA_EXCEEDED` y abortar el lote.

---

### A-07 — La sincronización con KeePass es destructiva y no atómica

**Categoría:** integridad de datos · **Archivo:** `app/vault/sync.py:63-124` · **Complejidad:** media · **Riesgo:** medio

**Evidencia.** El export sobrescribe directamente el archivo de destino:

```python
if os.path.exists(path):
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)

kp = create_database(path, password=password, keyfile=keyfile)
...
kp.save()
```

`create_database` crea la base en `path`, destruyendo lo que hubiera. Si el proceso falla entre esa llamada y `kp.save()` —caída de red al recurso compartido, excepción, reinicio del servidor, corte de energía— el `.kdbx` queda vacío o corrupto. No hay copia previa ni escritura sobre archivo temporal con renombrado atómico.

Agravante: `trigger_async` se dispara en **cada** creación, edición, borrado de entrada, creación y borrado de grupo (`routes.py:183, 252, 273, 294, 309`). Un lote de importación genera una ráfaga de reescrituras completas del archivo sobre la red.

**Consecuencia.** Pérdida del archivo `.kdbx` compartido con el equipo. La base SQLite sigue siendo la fuente de verdad, así que se puede regenerar, pero durante ese intervalo el equipo se queda sin acceso al baúl vía KeePass y podría intentar restaurar desde un `.kdbx` corrupto.

**Recomendación.** Escribir a `path + ".tmp"`, y solo tras un `kp.save()` correcto hacer `os.replace(tmp, path)`, que es atómico en el mismo volumen. Conservar además la versión anterior como `.bak`. Complementariamente, agrupar los disparos: un solo `trigger_async` al final de la importación en lugar de uno por entrada.

**Verificación.** Simular un fallo (permisos denegados sobre el destino, o excepción inyectada antes de `kp.save()`) y comprobar que el `.kdbx` original permanece íntegro y abrible en KeePass. Tras una sincronización correcta, el archivo debe seguir quedando en solo lectura con el mismo número de entradas.

---

### A-08 — La cadena de auditoría confía ciegamente en `X-Forwarded-For`

**Categoría:** seguridad / observabilidad · **Archivo:** `app/models/audit.py:29-31` · **Complejidad:** baja · **Riesgo:** muy bajo

**Evidencia.**

```python
ip = flask_request.headers.get("X-Forwarded-For", flask_request.remote_addr)
```

Cheroot atiende directamente a los clientes (`server.py:151`); no hay proxy inverso delante que sanee esa cabecera.

**Consecuencia.** Cualquier cliente puede fijar `X-Forwarded-For: 10.0.0.1` y toda su actividad quedará registrada con una IP falsa: intentos de login fallidos, revelado de contraseñas del baúl, borrados. La auditoría, que es una de las mejores piezas del sistema, deja de ser confiable como evidencia justo en el escenario en que se necesita.

**Recomendación.** Usar `flask_request.remote_addr` directamente mientras no haya proxy. Si en el futuro se pone uno delante, usar `werkzeug.middleware.proxy_fix.ProxyFix` con el número de saltos de confianza, en lugar de leer la cabecera a mano.

**Verificación.** Enviar una petición autenticada con `X-Forwarded-For` falsificado y comprobar en `/audit` que la IP registrada es la real de la conexión.

---

### A-09 — `obtener_mapa_recurrencia` se asigna sin invocar

**Categoría:** corrección · **Archivo:** `app/csirt/routes.py:66` · **Complejidad:** baja · **Riesgo:** muy bajo

**Evidencia.**

```python
mapa_recurrencia = obtener_mapa_recurrencia      # ← el objeto función, no su resultado

if valores_en_pantalla:
    stats = db.session.query(...)
    mapa_recurrencia = {item[0]: item[1] for item in stats}
```

Se compara con la ruta hermana `ver_iocs_alerta` (línea 311), que sí llama a la función: `mapa_recurrencia = obtener_mapa_recurrencia(iocs)`.

**Consecuencia.** Cuando un ticket no tiene IoCs, la plantilla `detalle_iocs.html` recibe un objeto función en lugar de un diccionario. Está latente porque la plantilla itera sobre `iocs` (vacío) y nunca consulta el mapa; cualquier cambio futuro que use `mapa_recurrencia` fuera del bucle romperá la página. Además la lógica está duplicada: las líneas 68-73 reimplementan `obtener_mapa_recurrencia`.

**Recomendación.** Reemplazar las líneas 64-73 por `mapa_recurrencia = obtener_mapa_recurrencia(iocs)`, eliminando la duplicación y el error de una vez.

**Verificación.** Abrir `/csirt/iocs/<ticket>` para un ticket con IoCs y para uno sin ellos: la página debe renderizar en ambos casos y los contadores de recurrencia deben coincidir con los actuales.

---

### A-10 — Escrituras en Cisco Umbrella sin restricción de administrador ni idempotencia

**Categoría:** control de acceso / integridad externa · **Archivo:** `app/umbrella/routes.py:207-256` · **Complejidad:** media · **Riesgo:** medio

**Evidencia.** `ejecutar` solo está protegida por `proteger_blueprint(bp, 'umbrella')`, sin `@admin_required` (a diferencia de `crear_cliente`, `editar_cliente`, `eliminar_job`, todas sí restringidas). Lanza un `PATCH` real contra el tenant del cliente:

```python
lanzar_job_background(app_names, job.id, cid, csecret, label_name, dry_run)
```

No hay control de reenvío: cada `POST` crea un `UmbrellaJob` nuevo e hilos independientes. Un doble clic o un F5 sobre el POST lanza dos lotes concurrentes contra la misma API.

**Consecuencia.** Es la única herramienta que **modifica el estado de una plataforma externa de un cliente**. Cualquier usuario con la herramienta asignada puede reetiquetar cientos de aplicaciones en el Umbrella del cliente sin poder revertirlo desde el portal. El envío duplicado consume cuota de API y puede provocar 429 sobre el tenant real.

**Recomendación.** Decidir explícitamente el modelo de permisos (ver §16, requiere decisión humana). Como mínimo: deshabilitar el botón en el envío desde el cliente y rechazar en el servidor un nuevo job si ya existe uno con `status='running'` para la misma herramienta. Considerar `dry_run` como valor por defecto.

**Verificación.** Enviar el formulario dos veces seguidas: solo debe crearse un `UmbrellaJob`; el segundo debe rechazarse con un aviso. Un `dry_run` debe seguir sin generar ninguna llamada `PATCH` (verificable en el log de `umbrella.client`).

---

### A-11 — Ausencia total de pruebas automatizadas

**Categoría:** pruebas / mantenibilidad · **Archivo:** todo el repositorio · **Complejidad:** alta · **Riesgo:** nulo (solo añade)

**Evidencia.** No existe ningún archivo `test_*.py`, ni `pytest.ini`, `tox.ini` o configuración de CI. `CLAUDE.md` lo reconoce: «No test suite currently exists».

**Consecuencia.** Es la causa raíz de que problemas como `C-02` (un blueprint sin guardia) o `A-09` (una función sin invocar) hayan podido llegar y permanecer en producción. Ninguna de las refactorizaciones propuestas en este informe puede ejecutarse con confianza sin antes fijar el comportamiento actual con pruebas.

**Recomendación.** No perseguir cobertura amplia. Empezar por una red mínima de alto valor (ver §14, etapa 5): matriz de control de acceso por ruta, ida y vuelta del cifrado del vault, `validar_complejidad_password`, `detectar_tipo_hash`, `_make_slug`, `read_apps`, y `run_batch` con un cliente Umbrella simulado — este último es puro y ya está desacoplado de Flask.

**Verificación.** `pytest` en verde en un entorno limpio; incorporarlo a la rutina previa a cada despliegue.

---

## 6. Problemas de prioridad media

| ID | Problema | Archivo | Evidencia y consecuencia | Recomendación | Compl. |
|----|----------|---------|---------------------------|---------------|--------|
| **M-01** | Plantilla renderizada sin una variable que usa | `auth/routes.py:293` | Ante una contraseña inválida hace `render_template('auth/admin_usuarios.html', usuarios=...)` **sin** `tools_por_usuario`; la plantilla llama a `tools_por_usuario.get(u.id, [])` (línea 104) sobre un `Undefined` → error 500. Ruta de error nunca probada. | Redirigir con `flash` como en las demás validaciones de esa misma función. | Baja |
| **M-02** | Condición muerta y regresión funcional en el borrado de casos VT | `virustotal/routes.py:261-268` | Tras `@admin_required`, `if caso.usuario_id != current_user.id and not current_user.is_admin` es siempre falsa (código muerto). Efecto real: el dueño no-admin de un caso **no puede borrarlo**, pese a que el código pretende permitirlo. | Decidir la política y aplicarla en un solo sitio: o `@admin_required` y borrar la condición, o quitar el decorador y dejar la comprobación. | Baja |
| **M-03** | API key de VirusTotal en la ruta de la URL | `virustotal/logic.py:473` | `url = f".../users/{api_key}"`. Aunque el cuerpo va cifrado por TLS, la URL aparece en logs de acceso, cachés y trazas de proxy. | Usarla solo en la cabecera `x-apikey` con el endpoint `/users/current`, si la API lo permite; si no, documentar el riesgo aceptado. | Baja |
| **M-04** | Inyección en la cabecera `Content-Disposition` | `virustotal/routes.py:292`, `csirt/routes.py:286` | `filename=Pack_{caso_nombre}_{fecha}.zip` con `caso_nombre` tomado del *path* de la URL, sin comillas ni saneado. Permite manipular el nombre del archivo descargado. Werkzeug bloquea los saltos de línea, así que no hay división de respuesta. | Sanear el nombre (como ya se hace en `logic.py:461`) y entrecomillar el valor. Además, `caso_nombre` es redundante: el caso ya se busca por `caso_id`. | Baja |
| **M-05** | Inyección de fórmulas en los CSV exportados | `csirt/routes.py:150,279`, `umbrella/routes.py:324` | Los valores de IoC provienen del scraping de un sitio externo y se escriben crudos. Un valor que empiece por `=`, `+`, `-` o `@` se ejecuta como fórmula al abrir en Excel. Los CSV se comparten con equipos de AV/EDR. | Anteponer `'` a los valores que empiecen por esos caracteres antes de escribir. Cuatro líneas en un helper compartido. | Baja |
| **M-06** | `IndexError` silenciado durante la extracción de IoC | `csirt/logic.py:264` | `descripcion = clean[2].lower()` tras validar solo `len(clean) < 2`. Una tabla de dos columnas lanza `IndexError`, capturado por el `except` genérico de la línea 303, que registra y devuelve el conteo parcial. **Se pierden IoCs sin aviso alguno al usuario.** | Usar `descripcion = clean[2].lower() if len(clean) > 2 else ''`. Reducir el alcance del `try` para no enmascarar errores por fila. | Baja |
| **M-07** | Escapado de `LIKE` incorrecto en el buscador | `csirt/routes.py:403` | `query_str.replace('%', r'\%')` y luego `Ioc.valor.contains(query_escaped)`. SQLAlchemy genera `LIKE` **sin cláusula `ESCAPE`**, así que la barra invertida se busca literalmente: buscar `50%` no encuentra nada. No es un riesgo de inyección (los parámetros van ligados), es un fallo funcional. | Usar `.contains(query_str, autoescape=True)`, que SQLAlchemy soporta de forma nativa. | Baja |
| **M-08** | Análisis VT concurrentes sobre el mismo caso | `virustotal/background.py:85-88` | Cada `POST /analizar_caso/<id>` crea un `threading.Thread` sin verificar si ya hay uno en marcha, y sin `daemon=True` (a diferencia de los otros dos workers del proyecto). Dos lotes concurrentes duplican el consumo de cuota y compiten escribiendo las mismas filas. | Registrar los casos en ejecución en un `set` con lock y rechazar el segundo lanzamiento; marcar el hilo como `daemon`. | Media |
| **M-09** | Jobs Umbrella que quedan «running» para siempre | `umbrella/routes.py:244`, `umbrella/background.py` | El job se crea con `status='running'` antes de lanzar el hilo. Si el proceso se reinicia mientras corre, la fila queda en `running` indefinidamente: la UI muestra un spinner eterno y `A-10` (si se implementa el bloqueo por job activo) quedaría bloqueado. | Al arrancar, marcar como `failed` los jobs en `running` con más de N horas. | Baja |
| **M-10** | Rate limiter en memoria | `app/extensions.py:13` | Flask-Limiter advierte explícitamente al arrancar: «Using the in-memory storage… not recommended for production use». Los contadores se pierden en cada reinicio. | Aceptable para un despliegue mono-proceso; documentarlo como decisión consciente y no ampliar el uso del limitador a más rutas sin un backend persistente. | Baja |
| **M-11** | Escritura arbitraria de archivos vía `kdbx_path` | `vault/routes.py:496,511`, `vault/sync.py:65-68` | Un administrador introduce cualquier ruta del servidor; la sincronización hace `os.chmod` y `create_database` sobre ella, sobrescribiendo el archivo existente. | Restringir a un directorio base configurado, o al menos exigir extensión `.kdbx` y rechazar `..`. | Baja |
| **M-12** | Cuerpos de respuesta de Umbrella propagados a la interfaz | `umbrella/client.py:88,110`, `background.py:47` | `RuntimeError(f"...: {resp.text}")` acaba en `job.error_message`, que se muestra en pantalla y se exporta al CSV. La respuesta de un fallo de autenticación puede contener detalles del tenant. | Registrar `resp.text` completo en el log y mostrar al usuario solo el código HTTP y un mensaje genérico. | Baja |
| **M-13** | Sin configuración de logging | Todo el proyecto | 7 módulos hacen `logging.getLogger(__name__)`, pero **nadie llama a `logging.basicConfig`** ni configura handlers. Con Cheroot no hay logger raíz configurado: los `logger.info/error` no llegan a ningún destino persistente. El único archivo es `startup.log`, escrito con `open()` manual. Diagnosticar un fallo en producción es prácticamente imposible. | Configurar en `create_app` un `RotatingFileHandler` sobre `instance/logs/app.log`, nivel INFO, con formato que incluya módulo y timestamp. | Baja |
| **M-14** | `commit()` dentro de bucles y consultas N+1 | `csirt/logic.py:223`, `virustotal/logic.py:105,124,252`, `routes.py:107-117` | Un commit por alerta y por IoC; consulta de duplicados por cada elemento del lote. Con lotes de cientos de IoC son cientos de transacciones y consultas contra SQLite, que serializa las escrituras. | Precargar los valores existentes en un `set` antes del bucle y hacer un solo commit al final. Impacto real medible en importaciones grandes. | Media |
| **M-15** | Modelo `VaultAuditLog` muerto | `vault/models.py:93-108` | La tabla existe con relaciones y su migración, pero `grep` confirma que **nada escribe en ella**: el vault usa `log_audit` sobre `AuditLog`. Infraestructura duplicada y engañosa. | Confirmar que la tabla está vacía en producción y eliminar el modelo con una migración; o poblarlo si se quiere auditoría específica del vault. Decisión humana. | Baja |
| **M-16** | `CREDENTIAL_MANAGER_KEY` obligatoria pero sin uso | `config.py:19-21` | Es la única aparición en todo el código (`grep` en `*.py`). Un despliegue nuevo **no arranca** si no se define una variable que no sirve para nada. Reliquia del módulo de credenciales eliminado en la migración `3cf82448f25f`. | Eliminarla de `config.py` y de `docker-compose.yml`. | Baja |
| **M-17** | `<form>` anidado dentro de `<a>` | `templates/base.html:82-103` | HTML inválido: los navegadores reestructuran el DOM al parsearlo. El botón «marcar leída» puede activar el enlace de la notificación en lugar del formulario. | Sacar el formulario fuera del enlace y posicionarlo con CSS. | Baja |
| **M-18** | Sin Content-Security-Policy | `app/__init__.py:31-38` | Se aplican cuatro cabeceras de seguridad pero no CSP, que es la que habría limitado el impacto de `A-03`. | Añadir una CSP. Requiere trabajo previo: hay JS inline en casi todas las plantillas, luego harían falta nonces o extraer los scripts a archivos. | Media |
| **M-19** | `locale.setlocale` global en un servidor multihilo | `csirt/logic.py:16-22` | El locale es estado global del proceso, modificado en tiempo de importación y no seguro entre hilos. Con 10 hilos de Cheroot, el parseo de fechas puede comportarse de forma no determinista. | Parsear los meses en español con un diccionario explícito, eliminando la dependencia del locale del sistema (que además puede no existir en la imagen Docker). | Media |
| **M-20** | El modo simulación podría persistir datos | `csirt/logic.py:289-297` | En modo simulación se construye `Ioc(..., alerta=alerta_obj)`. Asignar la relación puede insertar el objeto en la sesión por cascada; el `commit()` está protegido, pero un autoflush posterior en la misma petición podría escribirlo. **Incertidumbre, no defecto confirmado:** no se reprodujo. | Verificar con una prueba en DB desechable. Si se confirma, no construir el objeto en modo simulación. | Baja |

---

## 7. Mejoras menores

| ID | Mejora | Archivo |
|----|--------|---------|
| B-01 | `bash.exe.stackdump` (volcado de fallo de MSYS) está **versionado en git** y aparece como modificado en el árbol de trabajo. | raíz |
| B-02 | `migrate_authorized_tools.py` es un script de un solo uso ya ejecutado, y hoy **está roto**: `getattr(user, 'authorized_tools')` ya no devuelve una cadena CSV sino una `AppenderQuery` (la relación de `models/user.py:33`), por lo que todos los `isinstance(raw, str)` son falsos y el script no hace nada en silencio. | raíz |
| B-03 | `legacy/` contiene cuatro archivos sin referencia alguna, incluido `verify_logic.py` (un experimento de scraping contra `r.jina.ai`). Está en `.gitignore` pero sigue en el disco. | `legacy/` |
| B-04 | `waitress==3.0.2` declarado y nunca importado; el comentario del `Dockerfile` menciona waitress mientras el `CMD` usa Cheroot. | `requirements.txt`, `Dockerfile` |
| B-05 | `CLAUDE.md` desactualizado: dice «four blueprints» (son seis, faltan `umbrella` y `vault`), afirma que `config.py` lanza `ValueError` (lanza `RuntimeError`) y no menciona `VAULT_KEY` en la sección de entorno. | `CLAUDE.md` |
| B-06 | **No existe `README.md`.** Un desarrollador nuevo no tiene punto de entrada. | raíz |
| B-07 | `base.html:9-11` carga tipografías desde Google Fonts, mientras todo Bootstrap está vendorizado. Incoherente para una herramienta interna que debería funcionar sin salida a internet. | `templates/base.html` |
| B-08 | `CERT_FILE = 'certificado\cert.pem'` sin prefijo `r`. Funciona por casualidad (`\c` no es una secuencia de escape reconocida), pero es frágil: un `\n` o `\t` en la ruta rompería silenciosamente. | `server.py:18-19` |
| B-09 | `print()` en lugar de `logger` en el worker de VT (10 ocurrencias) y en `server.py:126-127` (dos `print(os.path.exists(...))` de depuración olvidados). | `virustotal/background.py`, `server.py` |
| B-10 | Accesibilidad mínima: 6 de 26 plantillas no tienen ningún atributo `aria-*`; las acciones destructivas se apoyan solo en `confirm()`; los formularios largos no marcan `aria-invalid` en los campos con error. | `templates/` |
| B-11 | Código comentado sin borrar: `virustotal/routes.py:168-170`, `logic.py:329-341`, `csirt/routes.py:171-175` (chequeo de seguridad comentado, ya sustituido por `@admin_required`), `utils.py:13`. | varios |
| B-12 | Erratas en mensajes de usuario: «contreaseña» (`auth/routes.py:23`), «al menos un alerta mayúscula» (`:36`), «Ignoraldo email» (`virustotal/logic.py:159`), «buscar_resultado_freco_en_db» (nombre de función). | varios |
| B-13 | `.gitignore` excluye `build/Portal-Operations-Tools` en lugar de `build/` completo (82 MB en disco). | `.gitignore` |
| B-14 | `THREADS = 10` en Cheroot, sin comentario que justifique el valor ni relación documentada con el `socket_timeout` de 60 s. | `server.py:16` |
| B-15 | `crear_caso` (`virustotal/routes.py:64-74`) no valida que `nombre` no sea vacío pese a que la columna es `nullable=False`. | `virustotal/routes.py` |
| B-16 | El endpoint `/virustotal/api/estado_caso/<id>` no comprueba propiedad; cualquier usuario del módulo consulta el progreso de casos ajenos (fuga informativa menor). | `virustotal/routes.py:356` |

---

## 8. Riesgos de seguridad (resumen consolidado)

| ID | Riesgo | Vector | Severidad | Explotable por |
|----|--------|--------|-----------|----------------|
| C-01 | RCE vía API de APScheduler | `POST /scheduler/jobs` con `func` textual | **Crítica** | Cualquiera con acceso de red, **sin autenticación** |
| C-02 | Acceso no autorizado al baúl de contraseñas | Falta `proteger_blueprint` | **Crítica** | Cualquier usuario autenticado |
| C-03 | IDOR de escritura y borrado en el baúl | Falta `_can_access` en `edit`/`delete` | **Crítica** | Cualquier usuario autenticado |
| C-04 | 30 credenciales en claro en disco | `instance/vault_import_*.json` | **Crítica** | Acceso al sistema de archivos o a un respaldo |
| C-05 | Contraseña maestra del `.kdbx` en el HTML | `sync_settings.html:43` | **Crítica** | Cualquier administrador o quien vea la pantalla |
| A-02 | Fuga de `SECRET_KEY`/`VAULT_KEY` | Inyección de format string en plantillas de export | **Alta** | Administrador |
| A-03 | XSS almacenado | Nombre de grupo del vault → `confirm()` inline | **Alta** | Usuario autenticado → víctima admin |
| A-04 | Robo de sesión en red | Cookie sin `Secure` en modo HTTP | **Alta** | Atacante en la red local |
| A-05 | Denegación de servicio / disco lleno | Subidas sin límite de tamaño | **Alta** | Usuario autenticado |
| A-08 | Auditoría falsificable | `X-Forwarded-For` confiado | **Alta** | Cualquier cliente |
| A-10 | Modificación no autorizada de plataforma de cliente | `umbrella.ejecutar` sin gate de admin | **Alta** | Usuario con la herramienta |
| M-03 | Exposición de API key en URLs | `/users/{api_key}` | Media | Quien acceda a logs o cachés |
| M-04 | Manipulación del nombre de archivo descargado | `Content-Disposition` sin sanear | Media | Usuario autenticado |
| M-05 | Inyección de fórmulas en CSV | Valores de IoC scrapeados sin escapar | Media | Sitio externo → analista que abre el CSV |
| M-11 | Escritura arbitraria de archivos | `kdbx_path` sin restringir | Media | Administrador |
| M-12 | Fuga de detalles de la API externa | `resp.text` en `error_message` | Media | Usuario con la herramienta |
| M-18 | Sin CSP | Ausencia de cabecera | Media | Amplifica cualquier XSS |

**Vectores evaluados y NO encontrados** (verificado, no supuesto):

- **Inyección SQL:** ninguna. Todo pasa por el ORM con parámetros ligados; no hay `text()` ni f-strings en consultas.
- **XSS reflejado en contexto HTML:** ninguno. Autoescape de Jinja intacto, sin `|safe` en las 26 plantillas.
- **CSRF:** cubierto. `CSRFProtect` global y token presente en el 100% de los formularios, incluidos los POST por `fetch`.
- **SSRF:** no explotable. Todas las URL salientes tienen host fijo (`csirt.gob.cl`, `virustotal.com`, `api.umbrella.com`); no se construye ninguna con entrada del usuario.
- **Path traversal en subidas:** no explotable. Los nombres de archivo subidos se descartan y se sustituyen por UUID generados en el servidor.
- **Secretos en el repositorio:** ninguno. `.env` está ignorado y **no aparece en el historial de git**. `docker-compose.yml` usa correctamente `${VARIABLE}`. No hay claves incrustadas en el código.
- **`eval` / `exec` / `os.system` / `subprocess`:** ninguna ocurrencia.
- **Redirección abierta:** cubierta. `auth.login` valida el parámetro `next` (`routes.py:170-176`).

---

## 9. Deuda técnica

**Deuda estructural**

1. **Sin capa de servicio.** Las rutas mezclan HTTP, reglas de negocio y acceso a datos. `vault/routes.py` (600 líneas) contiene el flujo de importación completo; `csirt/routes.py` construye CSV a mano dentro del handler. `umbrella/` demuestra que el equipo sabe hacerlo mejor.
2. **Dos estilos de manejo de formularios.** `vault` usa Flask-WTF; los otros cinco módulos leen `request.form` con validación manual dispersa e inconsistente (`auth/routes.py` tiene tres validadores propios).
3. **Tres mecanismos de concurrencia distintos** para el mismo problema: APScheduler, `threading.Thread` no-daemon (VT), `threading.Thread` daemon (Umbrella, sync vault). Ninguno sobrevive a un reinicio ni reporta fallos a la interfaz de forma uniforme.
4. **Dos sistemas de auditoría.** `AuditLog` (usado) y `VaultAuditLog` (muerto, `M-15`).
5. **Configuración monolítica.** Una sola clase `Config` sin variantes por entorno; las diferencias dev/prod están repartidas entre `run.py` y `server.py`.
6. **`server.py` y `run.py` duplican** la lógica de inicialización de la base de datos con implementaciones ligeramente distintas (`server.py` maneja el caso «instalación nueva» con `db.create_all()`, `run.py` no).

**Deuda de proceso**

7. Sin pruebas (`A-11`), sin linter, sin comprobación de tipos, sin CI.
8. Sin logging configurado (`M-13`): no se puede diagnosticar producción.
9. `requirements.txt` mantenido a mano y desincronizado (`A-01`).
10. Sin `README` ni documentación de despliegue (`B-06`).

**Deuda de datos**

11. SQLite con escrituras concurrentes desde varios hilos de fondo. Funciona hoy por volumen bajo, pero SQLite serializa las escrituras y no hay `busy_timeout` configurado.
12. Sin estrategia de respaldo documentada. `instance/app.db.old` sugiere copias manuales.
13. `Ioc.valor` y `VtIoc.valor` limitados a 255 caracteres, sin truncado explícito: una URL larga scrapeada podría fallar al insertar.

---

## 10. Código aparentemente obsoleto o duplicado

**Obsoleto (verificado sin referencias):**

| Elemento | Evidencia | Acción propuesta |
|----------|-----------|------------------|
| `migrate_authorized_tools.py` | Script de un solo uso ya ejecutado; hoy inoperante porque el atributo que lee cambió de tipo (`B-02`) | Eliminar tras confirmar que la migración de datos se completó |
| `legacy/` (4 archivos) | Sin referencias; ya en `.gitignore` | Eliminar del disco |
| `bash.exe.stackdump` | Volcado de fallo, versionado | Eliminar del repositorio y añadir al `.gitignore` |
| `VaultAuditLog` | Tabla y modelo sin ninguna escritura (`M-15`) | Verificar que está vacía y eliminar |
| `CREDENTIAL_MANAGER_KEY` | Única aparición es su propia validación (`M-16`) | Eliminar |
| `waitress` | Declarado, nunca importado (`B-04`) | Eliminar de `requirements.txt` |
| Bloques comentados | `virustotal/routes.py:168-170`, `logic.py:329-341`, `csirt/routes.py:171-175`, `utils.py:13` | Eliminar (git conserva el historial) |
| `startup.log` | Generado en tiempo de ejecución, en el directorio raíz | Mover a `instance/logs/` |

**Duplicado:**

| Duplicación | Ubicaciones | Propuesta |
|-------------|-------------|-----------|
| Filtrado de IoC por tipo (`hash`→`[hash,md5,sha1,sha256]`, `url`→`[url,dominio]`) | `csirt/routes.py:55-60, 302-307`; `virustotal/routes.py:152-155, 195-200, 237-242` | **5 copias.** Extraer `filtrar_por_tipo(query, modelo, tipo)` a `app/utils.py` |
| Cálculo del mapa de recurrencia | `csirt/routes.py:68-73` reimplementa `csirt/logic.py:491-502` | Eliminar la copia (ver `A-09`) |
| Copia de los 8 campos VT entre objetos | `virustotal/logic.py:94-103` y `110-118` (idénticas), más `244-250` | Método `copiar_desde(otro)` en `VtInfoMixin` |
| Bloque de cifrado Fernet | `models/user.py:56-78` y `models/umbrella.py:35-57` | Extraer un `EncryptedFieldMixin` compartido |
| Inicialización de la base de datos | `run.py:16-46` y `server.py:53-86` | Función compartida con un parámetro para el caso «instalación nueva» |
| Detección de tipo de hash por longitud | `virustotal/logic.py:18-26` y `logic.py:401-405` (reimplementada en línea) | Usar `detectar_tipo_hash` en ambos sitios |
| Guardas de propiedad de job | `umbrella/routes.py:292-294` y `313-315` (idénticas) | Extraer a un helper o decorador |

---

## 11. Pruebas faltantes

Ordenadas por relación valor/coste. Todas ejecutables sin credenciales ni acceso externo.

**Nivel 1 — imprescindibles antes de refactorizar**

| # | Prueba | Qué protege |
|---|--------|-------------|
| 1 | Matriz de control de acceso: para cada blueprint × (anónimo, usuario sin herramienta, usuario con herramienta, admin), afirmar el código de estado esperado | `C-01`, `C-02`, `A-10`. Habría detectado ambos críticos |
| 2 | IDOR del vault: el usuario B no puede `GET/POST` `detail`, `reveal`, `edit`, `delete` de una entrada privada de A | `C-03` |
| 3 | Ida y vuelta del cifrado: `encrypt`/`decrypt` con Unicode, vacío y `None`; `set_vt_key`/`get_vt_key`; `set_credentials`/`get_client_*` | Corrupción silenciosa de credenciales |
| 4 | Higiene del importador: tras abandonar la previsualización, no queda ningún `vault_import_*.json`; y si queda, no contiene texto plano | `C-04` |
| 5 | `validar_complejidad_password`: los 4 requisitos, en el límite y por debajo | Puerta de entrada de autenticación |

**Nivel 2 — lógica de dominio (pura, rápida, sin Flask)**

| # | Prueba | Módulo |
|---|--------|--------|
| 6 | `detectar_tipo_hash` con md5/sha1/sha256 válidos, mayúsculas, no hexadecimales, longitudes límite | `virustotal/logic.py` |
| 7 | `run_batch` con un `UmbrellaClient` simulado: app no encontrada, ambigua, ya etiquetada, `dry_run`, troceado en lotes de >50, HTTP 207 parcial | `umbrella/logic.py` |
| 8 | `read_apps`: columna ausente, columna vacía, duplicados sin distinción de mayúsculas, corrección de mojibake | `umbrella/reader.py` |
| 9 | `_make_slug` + `generate_slug`: colisiones, acentos, cadena vacía, truncado a 100 | `models/umbrella.py` |
| 10 | `generar_exportacion_multiformato`: cada extensión, plantilla con variable inexistente, IoC malicioso excluido, deduplicación por hash | `virustotal/logic.py` |
| 11 | Manejo del 429 de VT con `obtener_uso_api` devolviendo `None` | `A-06` |
| 12 | Extracción de IoC sobre HTML de ejemplo guardado, incluida una tabla de 2 columnas | `M-06` |

**Nivel 3 — integración**

| # | Prueba |
|---|--------|
| 13 | Flujo completo de importación kdbx contra un `.kdbx` de prueba generado en el propio test: subir → previsualizar → confirmar → verificar entradas y jerarquía de grupos |
| 14 | Sincronización del vault: export a un `.kdbx` temporal, reapertura con `pykeepass`, verificación de entradas y grupos; y comportamiento ante fallo (`A-07`) |
| 15 | `flask db upgrade` desde base vacía hasta el head actual sobre una SQLite temporal — protege la cadena de migraciones |
| 16 | Setup inicial: sin admin redirige a `/auth/setup`; tras el setup, `/auth/setup` redirige a login |
| 17 | Validación de plantilla de export rechazando `{valor.__class__}` (`A-02`) |

**Cómo validar lo que requiere acceso externo, sin evadir la restricción:**

- **VirusTotal:** grabar una respuesta real de cada endpoint (`files`, `ip_addresses`, `domains`, `urls`) en `tests/fixtures/` y simular `requests.get`. Cubre el 100% del parseo sin consumir cuota. La conectividad real se valida a mano con el botón «ver cuota» del perfil.
- **Cisco Umbrella:** el mismo enfoque; `run_batch` ya recibe el cliente por parámetro, así que no requiere ningún cambio de diseño. **Nunca** ejecutar pruebas con `dry_run=False` contra un tenant real; la validación de extremo a extremo se hace en modo simulación contra un cliente de pruebas designado por el responsable.
- **csirt.gob.cl:** guardar un `alertas.rss` y una página de alerta reales como fixtures y probar los parseadores sobre ellos.
- **Sincronización `.kdbx`:** no requiere red. Generar el `.kdbx` en `tmp_path` de pytest y reabrirlo con `pykeepass`.

---

## 12. Mejoras de documentación

| Documento | Estado | Contenido necesario |
|-----------|--------|---------------------|
| `README.md` | **No existe** | Qué es, capturas o descripción de las 4 herramientas, requisitos, instalación, `.env` de ejemplo, ejecución local, ejecución en producción, cómo correr las pruebas, cómo construir el EXE y la imagen Docker |
| `.env.example` | **No existe** | Las cuatro (o tres, tras `M-16`) variables con instrucciones para generar las claves Fernet: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `docs/AGREGAR_HERRAMIENTA.md` | **No existe** | Receta paso a paso: crear `app/<modulo>/`, definir el blueprint, **llamar a `proteger_blueprint`** (el paso que se olvidó en `vault`), registrar en `create_app`, añadir a `TOOLS`, crear plantillas, generar migración, escribir la prueba de control de acceso |
| `docs/OPERACION.md` | **No existe** | Dónde vive la base, cómo respaldarla, cómo restaurarla, qué hacer si falla `flask db upgrade`, cómo rotar las claves de cifrado (hoy imposible sin un script de recifrado), qué significan los errores SSL de subida, cómo interpretar el visor de auditoría |
| `CLAUDE.md` | Desactualizado | Corregir el número de blueprints, el tipo de excepción de `config.py`, documentar `VAULT_KEY` y la sincronización kdbx (`B-05`) |
| Comentarios en código | Aceptables | Retirar los bloques de código comentado (`B-11`) y las notas del tipo «(Mantén tu código de eliminación aquí)» (`virustotal/routes.py:264`) |
| `SPECKIT_vault_csirt.md` | Sin ubicación clara | Está en la raíz y en `.gitignore`; si es documentación viva, moverla a `docs/` y versionarla |

---

## 13. Arquitectura objetivo recomendada

**No** se propone reescribir, cambiar de framework ni introducir microservicios. Se propone consolidar lo que el propio proyecto ya demostró que sabe hacer bien en `app/umbrella/`.

### Principio rector

> Cada módulo de herramienta se organiza como `app/umbrella/`: `routes.py` fino (HTTP y permisos), `logic.py` puro (dominio, testeable sin Flask), `client.py` (transporte externo), `models.py` (datos).

### Estructura objetivo

```
app/
├── __init__.py            factory: extensiones, cabeceras, logging, blueprints
├── extensions.py          sin cambios
├── config/                base.py, dev.py, prod.py  ← reemplaza config.py
├── security.py            proteger_blueprint, admin_required, requiere_propiedad  ← extraído de utils.py
├── excel.py               generación de reportes  ← extraído de utils.py
├── tools_config.py        sin cambios (es un acierto)
├── models/                + EncryptedFieldMixin compartido, − VaultAuditLog
└── <herramienta>/
    ├── __init__.py        blueprint + proteger_blueprint(bp, '<nombre>')   ← obligatorio
    ├── routes.py          solo HTTP: validar, delegar, renderizar
    ├── logic.py           dominio puro, sin imports de Flask
    ├── client.py          transporte externo (si aplica)
    ├── forms.py           Flask-WTF (unificar en todos los módulos)
    └── models.py
tests/
├── conftest.py            fixtures: app, cliente, usuarios por rol, DB temporal
├── test_acceso.py         matriz de control de acceso — la red de seguridad principal
├── fixtures/              respuestas grabadas de VT, Umbrella, RSS CSIRT
└── test_<modulo>.py
```

### Cambios concretos frente a hoy

| Aspecto | Hoy | Objetivo | Por qué |
|---------|-----|----------|---------|
| Guardia de blueprint | Llamada manual en `routes.py`, olvidada en `vault` | En `__init__.py` de cada módulo, junto al blueprint | Hace imposible registrar un blueprint sin decidir su permiso |
| Formularios | Flask-WTF en `vault`, `request.form` en el resto | Flask-WTF en todos | Validación declarativa, sin ramas manuales, CSRF integrado |
| Configuración | Una clase | `base`/`dev`/`prod` | Permite `SESSION_COOKIE_SECURE=True` en prod sin romper el desarrollo |
| Tareas de fondo | 3 mecanismos distintos | Un helper único: hilo daemon + registro de estado en DB + protección contra duplicados | Estado observable y uniforme para el usuario |
| Logging | Sin configurar | `RotatingFileHandler` en `instance/logs/` | Diagnóstico en producción |
| `utils.py` | Seguridad + Excel mezclados | `security.py` + `excel.py` | Cohesión; el reporte Excel es específico de CSIRT |
| Pruebas | Ninguna | `tests/` con matriz de acceso obligatoria por módulo | Impide que se repita `C-02` |

### Lo que NO se propone cambiar

- Flask, SQLAlchemy, Bootstrap, Jinja: adecuados y el equipo los domina.
- SQLite: correcto para el volumen actual. Migrar a PostgreSQL sería complejidad no justificada.
- Los tres modos de despliegue: funcionan y responden a necesidades reales.
- `tools_config.py`: es el mejor acierto de diseño del proyecto.
- El esquema de base de datos: sano, indexado y con migraciones íntegras.
- No introducir Celery/Redis: los hilos bastan para este volumen.

---

## 14. Plan de refactorización incremental

Diez etapas ordenadas por el criterio solicitado. Cada una es un commit independiente y revisable. **Ninguna etapa mezcla refactorización estructural con cambio funcional.**

---

### Etapa 1 — Vulnerabilidades críticas de control de acceso

**Objetivo.** Cerrar `C-01`, `C-02` y `C-03`.
**Archivos.** `config.py`, `app/vault/routes.py`.
**Cambios.**
1. `SCHEDULER_API_ENABLED = False`.
2. `proteger_blueprint(bp, 'vault')` en `app/vault/routes.py`.
3. `if not _can_access(entry): abort(403)` en `edit` y `delete`.
4. `@admin_required` en `group_new` y `group_delete`.

**Dependencias.** Ninguna. **Debe ir primero.**
**Pruebas.** Manual antes de tener suite: (a) `GET /scheduler/jobs` → 404; (b) usuario sin la herramienta `vault` → redirigido; (c) usuario B intenta `POST /vault/N/delete` sobre una entrada privada de A → 403; (d) el job `vigilante_csirt` sigue programado.
**Aceptación.** Ningún `/scheduler/*` en el `url_map`; `before_request_funcs` incluye `'vault'`; los cuatro escenarios anteriores se comportan como se describe; ningún flujo legítimo se rompe.
**Reversión.** `git revert` de un solo commit. Sin cambios de esquema ni de datos.
**Aviso.** El punto 2 es un **cambio de comportamiento visible**: los usuarios que hoy usan el baúl sin tener la herramienta asignada la perderán. Hay que concedérsela antes de desplegar.

---

### Etapa 2 — Fugas de credenciales

**Objetivo.** Cerrar `C-04` y `C-05`.
**Archivos.** `app/vault/routes.py`, `app/templates/vault/sync_settings.html`.
**Cambios.**
1. **Operativo, previo y manual:** borrar los cuatro `instance/vault_import_*.json` y **rotar las 30 credenciales expuestas**.
2. Cifrar el JSON intermedio con `crypto.encrypt` antes de escribirlo; descifrar al leerlo.
3. Al entrar en `import_kdbx`, borrar los `vault_import_*.json` de más de 30 minutos.
4. No pasar `current_password` a la plantilla; dejar el campo vacío.
5. Implementar de verdad «dejar en blanco para no cambiarla»: conservar la contraseña existente si el campo llega vacío.

**Dependencias.** Etapa 1 (el flujo de importación debe estar ya protegido).
**Pruebas.** Importación completa (subir → previsualizar → confirmar) crea las mismas entradas; importación abandonada no deja rastro legible; el HTML de `/vault/configuracion` no contiene la contraseña; guardar con el campo vacío conserva la contraseña y la sincronización sigue funcionando.
**Aceptación.** `grep` de cualquier contraseña conocida en `instance/` no devuelve nada; el flujo de importación es funcionalmente idéntico.
**Reversión.** `git revert`. El paso 1 no es reversible ni debe serlo.

---

### Etapa 3 — Reproducibilidad del despliegue

**Objetivo.** Cerrar `A-01`. Sin esto no se puede montar entorno de pruebas ni CI.
**Archivos.** `requirements.txt`, `Dockerfile` (comentario).
**Cambios.** Añadir `cheroot==11.1.2`, `Flask-Migrate==4.1.0`, `Flask-WTF==1.3.0`, `WTForms==3.2.2`. Eliminar `waitress`. **No** actualizar ninguna versión mayor.
**Dependencias.** Ninguna (puede ir en paralelo a la 1 y la 2).
**Pruebas.** Virtualenv limpio: `pip install -r requirements.txt` → `python -c "from app import create_app; create_app()"` sin error. `docker build .` completa.
**Aceptación.** Instalación limpia arranca; el entorno de desarrollo actual no se ve afectado (las versiones declaradas son las ya instaladas).
**Reversión.** `git revert`.

---

### Etapa 4 — Riesgos de pérdida y corrupción de datos

**Objetivo.** Cerrar `A-07` (sync destructiva) y `M-09` (jobs zombis).
**Archivos.** `app/vault/sync.py`, `app/vault/routes.py`, `app/__init__.py`.
**Cambios.**
1. Escritura atómica: `.tmp` + `os.replace`, con `.bak` de la versión anterior.
2. Un solo `trigger_async` al final de la importación en lugar de uno por entrada.
3. Al arrancar, marcar como `failed` los `UmbrellaJob` en `running` de más de 6 horas.

**Dependencias.** Etapas 1-2.
**Pruebas.** Fallo inyectado en el export → el `.kdbx` original permanece íntegro y abrible; export correcto → archivo en solo lectura con el número correcto de entradas; una importación de 50 entradas dispara una sola sincronización.
**Aceptación.** Ninguna secuencia de fallos deja el `.kdbx` corrupto; KeePass sigue abriéndolo en solo lectura.
**Reversión.** `git revert`. Los `.bak` generados pueden borrarse a mano.

---

### Etapa 5 — Errores funcionales

**Objetivo.** Cerrar `A-06`, `A-09`, `M-01`, `M-02`, `M-06`, `M-07`, `B-15`.
**Archivos.** `app/virustotal/logic.py`, `app/virustotal/routes.py`, `app/csirt/routes.py`, `app/csirt/logic.py`, `app/auth/routes.py`.
**Cambios.** Los siete arreglos puntuales descritos en §5 y §6. Cada uno es de una a tres líneas.
**Dependencias.** Ninguna, pero conviene después de la 3 para poder probar en un entorno limpio.
**Pruebas.** Por hallazgo, según la sección «Verificación» correspondiente.
**Aceptación.** `/csirt/iocs/<ticket>` renderiza con y sin IoCs; crear un usuario con contraseña inválida muestra un aviso en lugar de un 500; una tabla de IoC de 2 columnas no pierde filas; buscar `50%` devuelve resultados.
**Reversión.** Commits separados por hallazgo; se puede revertir cualquiera individualmente.
**Decisión humana requerida.** `M-02`: ¿debe un usuario no-admin poder borrar sus propios casos VT?

---

### Etapa 6 — Red de pruebas mínima (antes de refactorizar)

**Objetivo.** Fijar el comportamiento actual antes de tocar la estructura. Cubre `A-11` parcialmente.
**Archivos.** `tests/` (nuevo), `requirements-dev.txt` (nuevo), `pytest.ini`.
**Cambios.** `conftest.py` con fixtures de app, cliente y usuarios por rol sobre SQLite en memoria. Las pruebas 1-5 del Nivel 1 y 6-9 del Nivel 2 de §11. Fixtures grabadas de VT/Umbrella/RSS.
**Dependencias.** Etapa 3 (dependencias instalables); etapas 1-5 (para que fijen el comportamiento *correcto*, no el defectuoso).
**Pruebas.** `pytest` en verde. La matriz de acceso debe fallar si se elimina temporalmente `proteger_blueprint(bp, 'vault')` — así se valida que la prueba realmente protege.
**Aceptación.** Suite en verde en entorno limpio, ejecución en menos de 30 segundos, sin ninguna llamada de red.
**Reversión.** Solo añade archivos; borrarlos.

---

### Etapa 7 — Refactorizaciones internas (sin cambio de comportamiento)

**Objetivo.** `M-15`, `M-16`, deduplicación de §10, división de `utils.py`, `logging` (`M-13`), configuración por entorno.
**Archivos.** `app/utils.py` → `security.py` + `excel.py`; `config.py` → `app/config/`; `app/models/`; los seis `routes.py`.
**Cambios.** Una sub-etapa por ítem, en commits independientes:
7a. `logging` configurado en `create_app`.
7b. Configuración dividida en base/dev/prod, con `SESSION_COOKIE_SECURE` y `MAX_CONTENT_LENGTH` (cierra `A-04` y `A-05`).
7c. `utils.py` dividido.
7d. Filtro de tipo de IoC extraído (elimina 5 duplicados).
7e. `EncryptedFieldMixin` compartido.
7f. `VaultAuditLog` y `CREDENTIAL_MANAGER_KEY` eliminados.
7g. Limpieza de archivos obsoletos (§10).

**Dependencias.** Etapa 6 **obligatoria**: sin pruebas, estas refactorizaciones no son seguras.
**Pruebas.** `pytest` en verde tras cada sub-etapa. Recorrido manual de las cuatro herramientas.
**Aceptación.** Cero cambios de comportamiento observable. La suite pasa idéntica antes y después.
**Reversión.** Cada sub-etapa se revierte de forma independiente.
**Decisión humana.** 7f requiere confirmar que `vault_audit_log` está vacía en producción.

---

### Etapa 8 — Endurecimiento de seguridad restante

**Objetivo.** `A-02`, `A-03`, `A-08`, `A-10`, `M-03`, `M-04`, `M-05`, `M-08`, `M-11`, `M-12`.
**Archivos.** `app/virustotal/logic.py` y `routes.py`, `app/templates/base.html` y las 4 plantillas con `confirm()`, `app/models/audit.py`, `app/umbrella/routes.py` y `client.py`, `app/vault/routes.py`.
**Cambios.** Los descritos en §5 y §6.
**Dependencias.** Etapas 6 y 7.
**Pruebas.** Prueba de regresión de `A-02` (plantilla con `{valor.__class__}`); grupo con nombre `');alert(1)//`; comparación byte a byte de los ZIP exportados antes/después; doble envío del formulario de Umbrella.
**Aceptación.** Los exports existentes son idénticos byte a byte; ningún diálogo de confirmación ejecuta código; el segundo envío de Umbrella se rechaza.
**Reversión.** Commits separados por hallazgo.
**Decisión humana.** `A-10`: ¿debe `umbrella.ejecutar` exigir administrador? Afecta a quién puede trabajar hoy.

---

### Etapa 9 — Experiencia de uso y rendimiento

**Objetivo.** `M-14`, `M-17`, `M-19`, `B-07`, `B-10`, feedback en operaciones largas.
**Archivos.** `app/csirt/logic.py`, `app/virustotal/logic.py`, `app/templates/`.
**Cambios.** Precargar existentes en un `set` y hacer un solo commit por lote; corregir el formulario anidado en el enlace; parseo de meses sin `locale`; vendorizar la tipografía; añadir `aria-*` y estados de carga a los botones que lanzan procesos largos.
**Dependencias.** Etapas 6-8.
**Pruebas.** Importar un CSV de 500 alertas y comparar el tiempo antes/después; verificar que el número de filas creadas es idéntico. Recorrido con teclado por los formularios principales.
**Aceptación.** Mismos resultados, menor tiempo; la interfaz no cambia visualmente salvo los estados de carga añadidos.
**Reversión.** `git revert`.

---

### Etapa 10 — Documentación y mejoras opcionales

**Objetivo.** §12 completa, más `M-18` (CSP) si se decide abordarla.
**Archivos.** `README.md`, `.env.example`, `docs/`, `CLAUDE.md`.
**Cambios.** Los cuatro documentos de §12; actualizar `CLAUDE.md`. Opcionalmente, extraer el JS inline a archivos estáticos para habilitar una CSP estricta.
**Dependencias.** Todas las anteriores (la documentación debe describir el estado final).
**Pruebas.** Un desarrollador que no conozca el proyecto debe poder levantarlo siguiendo solo el `README`.
**Aceptación.** Instalación desde cero siguiendo la documentación, sin ayuda externa.
**Reversión.** Trivial.

---

## 15. Riesgos de la refactorización

| Riesgo | Etapa | Probabilidad | Impacto | Mitigación |
|--------|-------|--------------|---------|------------|
| `proteger_blueprint(bp,'vault')` deja sin acceso a usuarios que hoy trabajan | 1 | **Alta** | Alto | Auditar quién usa el baúl **antes** de desplegar y concederles la herramienta; anunciar el cambio |
| Restringir grupos del vault a admin bloquea un flujo cotidiano | 1 | Media | Medio | Verificar en `AuditLog` quién crea grupos; si son analistas, mantener `@login_required` y resolver solo el borrado |
| Cifrar el JSON de importación rompe una importación en curso | 2 | Baja | Bajo | Desplegar sin importaciones activas; el flujo se reinicia desde el principio |
| La escritura atómica del `.kdbx` falla en rutas de red SMB (`os.replace` entre volúmenes) | 4 | Media | Alto | Probar contra la ruta de red real antes de desplegar; el `.tmp` debe crearse en el mismo directorio destino |
| Reemplazar `str.format` cambia sutilmente alguna plantilla de export | 8 | Media | Alto | Comparar los ZIP byte a byte con todas las plantillas de producción antes y después |
| La configuración dividida en dev/prod cambia comportamiento inadvertidamente | 7b | Media | Medio | Volcar `app.config` antes y después y comparar; solo deben diferir las claves añadidas a propósito |
| `SESSION_COOKIE_SECURE=True` deja el portal inutilizable si arranca en modo HTTP | 7b | Media | Alto | Condicionar el valor a la existencia de certificados, con la misma lógica que ya usa `server.py:130` |
| Agrupar commits altera el comportamiento ante errores parciales | 9 | Media | Medio | Prueba explícita: lote con una fila inválida en medio; documentar si el comportamiento cambia (hoy: todo lo anterior queda guardado; después: nada) |
| Eliminar `VaultAuditLog` destruye datos si no estaba vacía | 7f | Baja | Alto | `SELECT COUNT(*)` antes; migración con `downgrade` funcional; respaldo previo |
| Las pruebas se acoplan a detalles internos y se vuelven frágiles | 6 | Media | Medio | Probar contra rutas HTTP y funciones de dominio públicas, nunca contra helpers privados; sin mocks de SQLAlchemy |
| Reintroducir un fallo ya corregido durante las refactorizaciones | 7-9 | Media | Alto | La etapa 6 es requisito bloqueante; la matriz de acceso debe correr en cada commit |
| Refactorizar `csirt/logic.py` rompe el scraping ante un cambio del sitio externo | 7-9 | Baja | Medio | Fixtures grabadas del RSS y del HTML; **no** tocar los parseadores en la misma etapa que la reestructuración |

**Riesgo transversal:** el proyecto no tiene entorno de staging identificado. Todo lo anterior asume que existe una copia de `instance/app.db` sobre la que probar. **Si no existe, crearla es el paso cero.**

---

## 16. Archivos que probablemente deberán modificarse

Ordenados por número de etapas que los tocan.

| Archivo | Etapas | Naturaleza del cambio |
|---------|--------|------------------------|
| `app/vault/routes.py` | 1, 2, 4, 8 | Guardias de acceso, cifrado del intermedio, limpieza, contraseña en la plantilla, `kdbx_path` |
| `config.py` → `app/config/` | 1, 3, 7b | Desactivar API del scheduler; división por entorno; cookies; `MAX_CONTENT_LENGTH`; quitar `CREDENTIAL_MANAGER_KEY` |
| `app/virustotal/logic.py` | 5, 7, 8, 9 | `NameError` del 429; `str.format`; API key en URL; deduplicación; lotes |
| `app/virustotal/routes.py` | 5, 7, 8 | Condición muerta; validación; `Content-Disposition`; filtro de tipo compartido |
| `app/csirt/routes.py` | 5, 7, 9 | `obtener_mapa_recurrencia`; escapado LIKE; `Content-Disposition`; filtro compartido |
| `app/csirt/logic.py` | 5, 9 | `IndexError`; `locale`; agrupación de commits |
| `app/__init__.py` | 4, 7a, 7b | Recuperación de jobs; logging; carga de configuración |
| `app/utils.py` | 7c, 7d | División en `security.py` + `excel.py`; helper de filtro de IoC |
| `app/umbrella/routes.py` | 8 | Permisos de `ejecutar`; protección contra reenvío |
| `app/vault/sync.py` | 4 | Escritura atómica con `.tmp` y `.bak` |
| `app/templates/base.html` | 8, 9 | Manejador `data-confirm`; formulario anidado; tipografía local |
| `app/models/audit.py` | 8 | `X-Forwarded-For` |
| `app/models/user.py`, `models/umbrella.py` | 7e | `EncryptedFieldMixin` compartido |
| `app/vault/models.py` | 7f | Eliminar `VaultAuditLog` |
| `requirements.txt` | 3 | Cuatro dependencias añadidas, `waitress` eliminada |
| `app/templates/vault/sync_settings.html` | 2 | Quitar la contraseña del `value` |
| `app/templates/vault/index.html`, `auth/admin_usuarios.html`, `virustotal/admin_templates.html`, `csirt/index.html` | 8 | `confirm()` inline → `data-confirm` |
| `app/auth/routes.py` | 5 | Redirección en lugar de render sin variable |
| `app/virustotal/background.py` | 8, B-09 | Protección contra duplicados; `logger` en vez de `print` |
| `app/umbrella/client.py` | 8 | No propagar `resp.text` al usuario |
| `server.py`, `run.py` | 7 | Inicialización de DB compartida; rutas raw; quitar `print` de depuración |
| `.gitignore` | 7g | `build/`, `bash.exe.stackdump` |

**Archivos nuevos:** `tests/` (conftest, fixtures, ~8 módulos), `requirements-dev.txt`, `pytest.ini`, `README.md`, `.env.example`, `docs/AGREGAR_HERRAMIENTA.md`, `docs/OPERACION.md`, `app/security.py`, `app/excel.py`, `app/config/`.

**Archivos a eliminar:** `migrate_authorized_tools.py`, `legacy/`, `bash.exe.stackdump`, `instance/vault_import_*.json` (los cuatro, previa rotación de credenciales).

**Archivos que NO deben tocarse en este plan:** `migrations/versions/*` (histórico inmutable), `app/static/*` (dependencias vendorizadas), `app/tools_config.py` (correcto tal como está), `app/models/mixins.py`, `app/models/csirt.py`, `app/models/notification.py`.

---

## Anexo — Decisiones que requieren criterio humano

Ninguna de estas puede resolverse desde el código; todas afectan a cómo trabaja el equipo hoy.

1. **Rotación de las 30 credenciales expuestas (`C-04`).** Qué sistemas son, quién las rota, en qué orden. Es la acción más urgente del informe y no es técnica.
2. **Quién debe tener acceso al baúl (`C-02`).** Al aplicar `proteger_blueprint`, los usuarios sin la herramienta perderán el acceso que hoy tienen de facto. Hay que decidir y conceder antes de desplegar.
3. **Quién puede crear y borrar grupos del vault (`C-03`).** ¿Solo administradores, o cualquier analista?
4. **Quién puede escribir en Cisco Umbrella (`A-10`).** Es la única herramienta que modifica la plataforma de un cliente. ¿Debe exigir administrador? ¿Debe `dry_run` ser el valor por defecto?
5. **Borrado de casos VT por su dueño no-admin (`M-02`).** El código actual es contradictorio; hay que elegir la política.
6. **Destino de `VaultAuditLog` (`M-15`).** ¿Se elimina o se empieza a poblar? Requiere confirmar que la tabla está vacía en producción.
7. **Existencia de un entorno de pruebas.** El plan asume una copia de la base sobre la que validar. Si no existe, crearla es el paso previo a todo.
8. **Política de respaldo de `instance/app.db`.** Hoy no está documentada; `app.db.old` sugiere copias manuales.
9. **Alcance de la CSP (`M-18`).** Implementarla obliga a extraer el JS inline de casi todas las plantillas: es trabajo real que hay que priorizar conscientemente.
10. **`SPECKIT_vault_csirt.md` y `docs/superpowers/`.** ¿Documentación viva que versionar, o notas de trabajo que archivar?

---

*Fin del informe. No se ha modificado ningún archivo del proyecto salvo la creación de este documento.*
