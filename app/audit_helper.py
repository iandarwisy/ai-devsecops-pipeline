import hashlib
import sqlite3


def compute_checksum(payload: str) -> str:
    """Compute an integrity checksum for an audit payload."""
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


def find_audit_logs(db_path: str, username: str) -> list[tuple]:
    """Fetch audit log entries for a given username."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, action FROM audit_logs WHERE username = '{username}'")
        return cursor.fetchall()
    finally:
        conn.close()