import os
import sqlite3
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    seed_users = [
        ("admin", "security_admin", generate_password_hash("AdminPass#2026")),
        ("ian", "developer", generate_password_hash("DevPass#2026")),
    ]
    for username, role, pw_hash in seed_users:
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, role, password_hash) VALUES (?, ?, ?)",
            (username, role, pw_hash),
        )

    conn.commit()
    conn.close()


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    resolved_db = db_path or os.environ.get("DB_PATH", "portal.db")
    app.config["DB_PATH"] = resolved_db
    init_db(resolved_db)

    def get_db():
        conn = sqlite3.connect(app.config["DB_PATH"])
        conn.row_factory = sqlite3.Row
        return conn

    @app.route("/", methods=["GET"])
    def index():
        return jsonify(
            {
                "service": "AI-Driven DevSecOps Target API",
                "version": "1.0.0",
                "status": "running",
            }
        )

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy"}), 200

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        conn = get_db()
        user = conn.execute(
            "SELECT id, username, role, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            return jsonify(
                {
                    "message": "Authentication successful",
                    "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
                }
            ), 200

        return jsonify({"error": "Invalid credentials"}), 401

    @app.route("/users", methods=["GET"])
    def search_users():
        username_query = request.args.get("username", "").strip()
        conn = get_db()

        if username_query:
            rows = conn.execute(
                "SELECT id, username, role FROM users WHERE username LIKE ?",
                (f"%{username_query}%",),
            ).fetchall()
        else:
            rows = conn.execute("SELECT id, username, role FROM users").fetchall()

        conn.close()
        return jsonify([dict(row) for row in rows]), 200

    return app


if __name__ == "__main__":
    application = create_app()
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "5000"))
    application.run(host=host, port=port, debug=False)
