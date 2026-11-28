import hashlib
import os
import sqlite3
import subprocess
import urllib.request
from flask import Blueprint, jsonify, request, send_file

vuln_bp = Blueprint("vuln", __name__)


# OWASP A01: Broken Access Control (Path Traversal - CWE-22)
@vuln_bp.route("/download", methods=["GET"])
def download_report():
    filename = request.args.get("file", "summary.txt")
    report_path = os.path.join("/srv/app/reports", filename)
    return send_file(report_path)


# OWASP A02: Cryptographic Failures (Weak MD5 Hashing - CWE-327)
@vuln_bp.route("/legacy-hash", methods=["POST"])
def legacy_hash():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    weak_digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    return jsonify({"md5": weak_digest}), 200


# OWASP A03: Injection (SQL Injection - CWE-89)
@vuln_bp.route("/audit-search", methods=["GET"])
def audit_search():
    username = request.args.get("username", "")
    conn = sqlite3.connect(os.environ.get("DB_PATH", "portal.db"))
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return jsonify({"results": rows}), 200


# OWASP A03: Injection (OS Command Injection - CWE-78)
@vuln_bp.route("/diagnostics/ping", methods=["GET"])
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return jsonify({"output": output}), 200


# OWASP A10: Server-Side Request Forgery (SSRF - CWE-918)
@vuln_bp.route("/fetch-webhook", methods=["GET"])
def fetch_webhook():
    target_url = request.args.get("url", "")
    with urllib.request.urlopen(target_url) as response:
        preview = response.read(200).decode("utf-8", errors="ignore")
    return jsonify({"preview": preview}), 200


# OWASP A05: Security Misconfiguration (Flask Debug Enabled - CWE-489)
def start_debug_mode(app):
    app.run(host="0.0.0.0", port=5000, debug=True)