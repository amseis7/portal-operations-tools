# Diseño: Auditoría del módulo `auth`

**Fecha:** 2026-06-10
**Estado:** Aprobado por el usuario

## Problema

El sistema de audit log (`AuditLog` / `log_audit()` en `app/models/audit.py`) cubre los
módulos `csirt`, `virustotal`, `umbrella` y `vault`, pero el módulo `auth` no registra
nada: inicios de sesión, cierres de sesión, creación/edición/eliminación de usuarios y
cambios de perfil/contraseña no aparecen en la Auditoría Global.

## Alcance

Solo `app/auth/routes.py` y `app/templates/main/audit.html`. Sin cambios de modelo ni
migraciones — la tabla `audit_log` ya soporta los campos necesarios.

## Eventos a registrar (módulo `auth`)

| Ruta | Acción | Detalle |
|------|--------|---------|
| `login` (éxito) | `login` | usuario + IP (la IP la captura `log_audit`) |
| `login` (fallo) | `login_failed` | username intentado en `object_name`, `user_id` nulo. Nunca se registra la contraseña. |
| `logout` | `logout` | se registra **antes** de `logout_user()` para conservar `current_user` |
| `setup` | `setup` | creación del administrador inicial |
| `crear_usuario` | `create` | usuario creado, flag admin, herramientas asignadas |
| `editar_usuarios` | `edit` | herramientas, flag admin, si la contraseña fue actualizada |
| `eliminar_usuario` | `delete` | username capturado **antes** del delete, misma transacción |
| `perfil` | `edit_profile` | indica si la API key de VT fue actualizada (solo el hecho, no el valor) |
| `perfil` (cambio de pass) | `change_password` | cambio de contraseña desde perfil |
| `cambiar_password_inicial` | `change_password` | cambio de contraseña inicial obligatorio |

## Decisiones (confirmadas con el usuario)

1. **Se registran logins fallidos** (`login_failed`): valor de seguridad para detectar
   fuerza bruta. El endpoint ya tiene rate limit de 5/min, así que el volumen es acotado.
2. **Se registran acciones de auto-gestión** (perfil, contraseña propia), no solo
   acciones de administradores.

## Patrón de implementación

Idéntico al de los otros cuatro módulos: `log_audit('auth', ...)` agrega la entrada a la
sesión de SQLAlchemy y la ruta hace el `db.session.commit()`. En `login`, `login_failed`
y `logout` se agrega un commit explícito porque esas rutas no escribían en BD.

## Cambios de plantilla (`audit.html`)

- Botón de filtro «Usuarios» (`module=auth`).
- Badge de módulo para `auth`.
- Badges de acción: `login` (verde), `login_failed` (rojo), `logout` (gris),
  `change_password` / `edit_profile` (amarillo), `setup` (azul).
- Subtítulo actualizado para incluir gestión de usuarios.

## Pruebas

No existe suite de tests en el proyecto. Verificación manual: arranque del servidor y
revisión de la vista `/audit` tras login/logout y operaciones de usuarios.
