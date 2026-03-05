# Flask Login vulnerable (laboratorio)

Aplicación web en Python/Flask con autenticación por usuario/contraseña y persistencia en SQLite, configurada intencionalmente para pruebas de inyección SQL en entorno controlado.

## Estructura

- `app.py`
- `schema.sql`
- `create_user.py`
- `templates/login.html`
- `templates/dashboard.html`
- `requirements.txt`
- `users.db` (se crea automáticamente)
- `auth.log` (se crea automáticamente)

## Requisitos

- Python 3.10+

## Instalación y ejecución

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 create_user.py admin SecurePass123
python3 app.py
```

Abrir en navegador: `http://127.0.0.1:5000/login`

## Usuario para login

Puedes crear usuarios en la base SQL local con:

```bash
python3 create_user.py <usuario> <password>
```

Ejemplo:

- Usuario: `admin`
- Contraseña: `SecurePass123`

## Comportamiento del laboratorio

- Contraseñas almacenadas en texto plano en `users.password_hash`.
- Validación de login con consulta SQL concatenada (vulnerable a SQL Injection).
- Si usuario o contraseña no coinciden: `Usuario o contraseña incorrectos.`
- Si la cuenta está bloqueada en DB (`is_locked = 1`): `Cuenta bloqueada.`

## Logs (`auth.log`)

Se registran eventos de autenticación con `RotatingFileHandler`:

- timestamp
- ip (`request.remote_addr`)
- username ingresado
- outcome: `SUCCESS | FAIL_BAD_CREDENTIALS | FAIL_LOCKED`
- attempts (cuando aplica)
- user agent recortado
- `pw_fingerprint` opcional (HMAC-SHA256) para detectar repetición de passwords sin almacenar password en claro

## Variables de entorno opcionales

- `SECRET_KEY`: clave de sesión Flask.
- `PW_FINGERPRINT_KEY`: clave HMAC para fingerprint de password (si no se define, usa `SECRET_KEY`).

## Advertencia

No usar este proyecto en producción ni en redes expuestas a internet. Es solo para laboratorio.

Para desbloquear un usuario manualmente:

```sql
UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE username = 'admin';
```
