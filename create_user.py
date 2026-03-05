import sqlite3
import sys
from pathlib import Path

DB_PATH = "users.db"
SCHEMA_PATH = Path("schema.sql")


def ensure_schema(conn: sqlite3.Connection) -> None:
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"No se encontro el archivo de esquema: {SCHEMA_PATH}")

    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


def main() -> int:
    if len(sys.argv) != 3:
        print("Uso: python create_user.py <username> <password>")
        return 1

    username = sys.argv[1].strip()
    password = sys.argv[2]

    if not username or not password:
        print("Username y password son obligatorios")
        return 1

    try:
        with sqlite3.connect(DB_PATH) as conn:
            ensure_schema(conn)
            conn.execute(
                """
                INSERT INTO users (username, password_hash, failed_attempts, is_locked)
                VALUES (?, ?, 0, 0)
                """,
                (username, password),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        print(f"El usuario '{username}' ya existe")
        return 1
    except FileNotFoundError as exc:
        print(str(exc))
        return 1

    print(f"Usuario '{username}' creado correctamente en {DB_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
