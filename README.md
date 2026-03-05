# Flask Login con bloqueo tras intentos fallidos

Aplicación web en Python/Flask con autenticación por usuario/contraseña, persistencia en SQLite y bloqueo permanente después de 5 intentos fallidos.

## Estructura

- `app.py`
- `templates/login.html`
- `templates/dashboard.html`
- `requirements.txt`
- `users.db` (se crea automáticamente)
- `auth.log` (se crea automáticamente)

## Requisitos

- Python 3.10+

## Instalación y ejecución

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Abrir en navegador: `http://127.0.0.1:5000/login`

## Usuario precargado

Al iniciar la app, si no existe, se crea:

- Usuario: `admin`
- Contraseña: `SecurePass123`

## Comportamiento de seguridad

- Contraseñas almacenadas con hash `bcrypt`.
- Si usuario no existe o contraseña es incorrecta: mensaje genérico `Usuario o contraseña incorrectos.`
- Si la cuenta está bloqueada: `Cuenta bloqueada.`
- A los 5 fallos de contraseña para un usuario existente: `is_locked = 1` (bloqueo permanente hasta cambio manual en DB).
- Login exitoso resetea `failed_attempts` a `0`.

## Logs (`auth.log`)

Se registran eventos de autenticación con `RotatingFileHandler`:

- timestamp
- ip (`request.remote_addr`)
- username ingresado
- outcome: `SUCCESS | FAIL_BAD_CREDENTIALS | FAIL_LOCKED | FAIL_UNKNOWN_USER`
- attempts (cuando aplica)
- user agent recortado
- `pw_fingerprint` opcional (HMAC-SHA256) para detectar repetición de passwords sin almacenar password en claro

## Variables de entorno opcionales

- `SECRET_KEY`: clave de sesión Flask.
- `PW_FINGERPRINT_KEY`: clave HMAC para fingerprint de password (si no se define, usa `SECRET_KEY`).

## Nota

Para desbloquear un usuario manualmente:

```sql
UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE username = 'admin';
```
