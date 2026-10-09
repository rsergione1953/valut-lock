import os
import base64
import sqlite3
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_FILE = "passwords_vault.db"


class SecurityManager:
    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    @staticmethod
    def encrypt_data(plain_text: str, key: bytes) -> str:
        f = Fernet(key)
        return f.encrypt(plain_text.encode()).decode()

    @staticmethod
    def decrypt_data(cipher_text: str, key: bytes) -> str:
        f = Fernet(key)
        return f.decrypt(cipher_text.encode()).decode()


class DatabaseManager:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                servizio TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                note TEXT
            )
        """)
        conn.commit()
        conn.close()

    def get_or_create_salt(self) -> bytes:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM config WHERE key = 'salt'")
        row = cursor.fetchone()
        if row:
            salt = row[0]
        else:
            salt = os.urandom(16)
            cursor.execute(
                "INSERT INTO config (key, value) VALUES ('salt', ?)", (salt,)
            )
            conn.commit()
        conn.close()
        return salt

    def add_entry(self, servizio, username, password_encrypted, note):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO vault (servizio, username, password_encrypted, note) VALUES (?, ?, ?, ?)",
            (servizio, username, password_encrypted, note),
        )
        conn.commit()
        conn.close()

    def update_entry(self, entry_id, servizio, username, password_encrypted, note):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE vault SET servizio = ?, username = ?, password_encrypted = ?, note = ? WHERE id = ?",
            (servizio, username, password_encrypted, note, entry_id),
        )
        conn.commit()
        conn.close()

    def get_all_entries(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, servizio, username, password_encrypted, note FROM vault ORDER BY servizio ASC"
        )
        rows = cursor.fetchall()
        conn.close()
        return rows

    def delete_entry(self, entry_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
        conn.commit()
        conn.close()


db = DatabaseManager()


def get_key_from_session():
    if "key_b64" in session:
        return session["key_b64"].encode()
    return None


@app.route("/")
def index():
    if get_key_from_session():
        return render_template("dashboard.html")
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    master_pwd = data.get("master_password", "").strip()
    if not master_pwd:
        return jsonify(
            {"success": False, "message": "Inserisci la Master Password."}
        ), 400

    salt = db.get_or_create_salt()
    derived_key = SecurityManager.derive_key(master_pwd, salt)

    entries = db.get_all_entries()
    if entries:
        try:
            SecurityManager.decrypt_data(entries[0][3], derived_key)
        except Exception:
            return jsonify(
                {"success": False, "message": "Master Password errata!"}
            ), 401

    session["key_b64"] = derived_key.decode()
    return jsonify({"success": True})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/credentials", methods=["GET"])
def api_get_credentials():
    key = get_key_from_session()
    if not key:
        return jsonify({"error": "Non autorizzato"}), 401

    entries = db.get_all_entries()
    result = []
    for entry_id, servizio, username, pwd_enc, note in entries:
        try:
            pwd_dec = SecurityManager.decrypt_data(pwd_enc, key)
        except Exception:
            pwd_dec = "*** ERRORE DECIFRATURA ***"
        result.append(
            {
                "id": entry_id,
                "servizio": servizio,
                "username": username,
                "password": pwd_dec,
                "note": note or "",
            }
        )
    return jsonify(result)


@app.route("/api/credentials", methods=["POST"])
def api_add_credential():
    key = get_key_from_session()
    if not key:
        return jsonify({"error": "Non autorizzato"}), 401

    data = request.json or {}
    s = data.get("servizio", "").strip()
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    n = data.get("note", "").strip()

    if not s or not u or not p:
        return jsonify({"error": "Campi mancanti"}), 400

    pwd_enc = SecurityManager.encrypt_data(p, key)
    db.add_entry(s, u, pwd_enc, n)
    return jsonify({"success": True})


@app.route("/api/credentials/<int:entry_id>", methods=["PUT"])
def api_update_credential(entry_id):
    key = get_key_from_session()
    if not key:
        return jsonify({"error": "Non autorizzato"}), 401

    data = request.json or {}
    s = data.get("servizio", "").strip()
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    n = data.get("note", "").strip()

    if not s or not u or not p:
        return jsonify({"error": "Campi mancanti"}), 400

    pwd_enc = SecurityManager.encrypt_data(p, key)
    db.update_entry(entry_id, s, u, pwd_enc, n)
    return jsonify({"success": True})


@app.route("/api/credentials/<int:entry_id>", methods=["DELETE"])
def api_delete_credential(entry_id):
    key = get_key_from_session()
    if not key:
        return jsonify({"error": "Non autorizzato"}), 401

    db.delete_entry(entry_id)
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
