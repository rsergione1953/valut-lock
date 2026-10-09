import os
import base64
import sqlite3
import flet as ft
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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


def main(page: ft.Page):
    page.title = "SPsoft VaultLock"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#1A1614"
    page.padding = 20

    db = DatabaseManager()
    salt = db.get_or_create_salt()
    fernet_key = None

    def show_snack(msg):
        page.overlay.append(ft.SnackBar(ft.Text(msg), open=True))
        page.update()

    # SCHERMATA LOGIN
    def build_login():
        master_entry = ft.TextField(
            label="Master Password",
            password=True,
            can_reveal_password=True,
            border_color="#D97706",
            focused_border_color="#B45309",
            border_radius=12,
            width=300,
        )

        def unlock(e):
            nonlocal fernet_key
            pwd = master_entry.value
            if not pwd:
                show_snack("Inserisci la Master Password")
                return

            derived = SecurityManager.derive_key(pwd, salt)
            entries = db.get_all_entries()
            if entries:
                try:
                    SecurityManager.decrypt_data(entries[0][3], derived)
                except Exception:
                    show_snack("Master Password Errata!")
                    return

            fernet_key = derived
            page.controls.clear()
            build_dashboard()
            page.update()

        page.controls.append(
            ft.Column(
                [
                    ft.Text("🗄️", size=60),
                    ft.Text(
                        "SPsoft VaultLock",
                        size=24,
                        weight=ft.FontWeight.BOLD,
                        color="#D97706",
                    ),
                    ft.Text("Cassaforte Password Mobile", color="#9CA3AF", size=13),
                    ft.Container(height=20),
                    master_entry,
                    ft.Container(height=10),
                    ft.FilledButton(
                        "Sblocca Cassaforte 🔐",
                        on_click=unlock,
                        style=ft.ButtonStyle(
                            bgcolor="#D97706",
                            color="#FFFFFF",
                            shape=ft.RoundedRectangleBorder(radius=12),
                        ),
                        width=300,
                        height=45,
                    ),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                expand=True,
            )
        )

    # SCHERMATA DASHBOARD
    def build_dashboard():
        cards_list = ft.ListView(expand=True, spacing=10)

        def load_cards(query=""):
            cards_list.controls.clear()
            entries = db.get_all_entries()
            for entry_id, servizio, username, pwd_enc, note in entries:
                if (
                    query
                    and query.lower() not in servizio.lower()
                    and query.lower() not in username.lower()
                ):
                    continue
                try:
                    pwd_dec = SecurityManager.decrypt_data(pwd_enc, fernet_key)
                except Exception:
                    pwd_dec = "*** ERRORE ***"

                state = {"visible": False}
                pwd_text = ft.Text("Password: ••••••••••••", color="#9CA3AF", size=12)

                def toggle_show(e, p=pwd_dec, t_ref=pwd_text, st=state):
                    st["visible"] = not st["visible"]
                    t_ref.value = (
                        f"Password: {p}" if st["visible"] else "Password: ••••••••••••"
                    )
                    page.update()

                # Gestione corretta e asincrona degli appunti con Flet Service
                async def copy_p(e, p=pwd_dec, s=servizio):
                    await ft.Clipboard().set(p)
                    show_snack(f"Password '{s}' copiata negli appunti!")

                def delete_p(e_id=entry_id):
                    db.delete_entry(e_id)
                    load_cards(search_field.value)

                def open_edit_dialog(
                    e,
                    c_id=entry_id,
                    c_serv=servizio,
                    c_user=username,
                    c_pass=pwd_dec,
                    c_note=note,
                ):
                    s_in = ft.TextField(label="Servizio", value=c_serv)
                    u_in = ft.TextField(label="Username", value=c_user)
                    p_in = ft.TextField(
                        label="Password",
                        value=c_pass,
                        password=True,
                        can_reveal_password=True,
                    )
                    n_in = ft.TextField(label="Note", value=c_note or "")

                    def save_edit(e):
                        if s_in.value and u_in.value and p_in.value:
                            enc = SecurityManager.encrypt_data(p_in.value, fernet_key)
                            db.update_entry(
                                c_id, s_in.value, u_in.value, enc, n_in.value
                            )
                            dialog.open = False
                            page.update()
                            load_cards(search_field.value)

                    dialog = ft.AlertDialog(
                        title=ft.Text("Modifica Credenziale"),
                        content=ft.Column(
                            [s_in, u_in, p_in, n_in], height=260, tight=True
                        ),
                        actions=[
                            ft.TextButton(
                                "Annulla",
                                on_click=lambda e: (
                                    setattr(dialog, "open", False) or page.update()
                                ),
                            ),
                            ft.TextButton("Salva", on_click=save_edit),
                        ],
                    )
                    page.overlay.append(dialog)
                    dialog.open = True
                    page.update()

                note_content = (
                    ft.Text(f"Note: {note}", color="#D1D5DB", size=11, italic=True)
                    if note
                    else ft.Container()
                )

                cards_list.controls.append(
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Text(
                                    servizio,
                                    weight=ft.FontWeight.BOLD,
                                    color="#D97706",
                                    size=16,
                                ),
                                ft.Text(
                                    f"Utente: {username}", color="#F3F4F6", size=13
                                ),
                                pwd_text,
                                note_content,
                                ft.Row(
                                    [
                                        ft.IconButton(
                                            ft.Icons.VISIBILITY,
                                            icon_color="#9CA3AF",
                                            tooltip="Mostra/Nascondi",
                                            on_click=toggle_show,
                                        ),
                                        ft.IconButton(
                                            ft.Icons.COPY,
                                            icon_color="#9CA3AF",
                                            tooltip="Copia Password",
                                            on_click=copy_p,
                                        ),
                                        ft.IconButton(
                                            ft.Icons.EDIT,
                                            icon_color="#D97706",
                                            tooltip="Modifica",
                                            on_click=open_edit_dialog,
                                        ),
                                        ft.IconButton(
                                            ft.Icons.DELETE,
                                            icon_color="#EF4444",
                                            tooltip="Elimina",
                                            on_click=lambda e: delete_p(),
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.END,
                                ),
                            ]
                        ),
                        bgcolor="#2D2420",
                        padding=15,
                        border_radius=14,
                        border=ft.Border.all(1, "#3D312A"),
                    )
                )
            page.update()

        search_field = ft.TextField(
            hint_text="🔍 Cerca...",
            border_radius=10,
            bgcolor="#2D2420",
            on_change=lambda e: load_cards(e.control.value),
        )

        def open_add_dialog(e):
            s_in = ft.TextField(label="Servizio")
            u_in = ft.TextField(label="Username")
            p_in = ft.TextField(
                label="Password", password=True, can_reveal_password=True
            )
            n_in = ft.TextField(label="Note (opzionale)")

            def save_new(e):
                if s_in.value and u_in.value and p_in.value:
                    enc = SecurityManager.encrypt_data(p_in.value, fernet_key)
                    db.add_entry(s_in.value, u_in.value, enc, n_in.value)
                    dialog.open = False
                    page.update()
                    load_cards(search_field.value)

            dialog = ft.AlertDialog(
                title=ft.Text("Nuova Credenziale"),
                content=ft.Column([s_in, u_in, p_in, n_in], height=260, tight=True),
                actions=[
                    ft.TextButton(
                        "Annulla",
                        on_click=lambda e: (
                            setattr(dialog, "open", False) or page.update()
                        ),
                    ),
                    ft.TextButton("Salva", on_click=save_new),
                ],
            )
            page.overlay.append(dialog)
            dialog.open = True
            page.update()

        page.controls.append(
            ft.Column(
                [
                    ft.Row(
                        [
                            ft.Text(
                                "🗄️ VaultLock Mobile",
                                weight=ft.FontWeight.BOLD,
                                color="#D97706",
                                size=18,
                            ),
                            ft.IconButton(
                                ft.Icons.LOCK, on_click=lambda e: page.window.reload()
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Row(
                        [
                            ft.Container(content=search_field, expand=True),
                            ft.FloatingActionButton(
                                icon=ft.Icons.ADD,
                                bgcolor="#D97706",
                                on_click=open_add_dialog,
                            ),
                        ]
                    ),
                    cards_list,
                ],
                expand=True,
            )
        )
        load_cards()

    build_login()


ft.run(main)
