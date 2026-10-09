import os
import json
import base64
import sqlite3
import customtkinter as ctk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configurazione Tema CustomTkinter
ctk.set_appearance_mode("Dark")

# Palette Colori Caldi
COLOR_BG_DARK = "#1A1614"  # Cioccolato Scuro Sfondo
COLOR_CARD = "#2D2420"  # Marrone Caldo per Card/Pannelli
COLOR_CARD_HOVER = "#3B302B"  # Hover Card
COLOR_AMBER = "#D97706"  # Ambra Principale
COLOR_AMBER_HOVER = "#B45309"  # Ambra Scuro Hover
COLOR_TEXT = "#F3F4F6"  # Testo Chiaro
COLOR_TEXT_MUTED = "#9CA3AF"  # Testo Secondario
COLOR_DANGER = "#EF4444"  # Rosso per Elimina

DB_FILE = "passwords_vault.db"


class SecurityManager:
    """Gestisce la derivazione della chiave di cifratura (PBKDF2) e la cifratura AES-256."""

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
    """Gestisce il database SQLite locale."""

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


class PasswordVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Password Vault - SPsoft")
        self.configure(fg_color=COLOR_BG_DARK)

        # Posizionamento al centro dello schermo
        self.center_window(850, 600)

        # Impostazione Icona Finestra (.ico se presente)
        if os.path.exists("cassaforte.ico"):
            self.iconbitmap("cassaforte.ico")

        self.db = DatabaseManager()
        self.salt = self.db.get_or_create_salt()
        self.fernet_key = None

        self.show_login_screen()

    def center_window(self, width: int, height: int):
        """Calcola la posizione per centrare la finestra sullo schermo."""
        self.update_idletasks()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)

        self.geometry(f"{width}x{height}+{x}+{y}")

    # -------------------------------------------------------------
    # SCHERMATA DI LOGIN / SBLOCCO
    # -------------------------------------------------------------
    def show_login_screen(self):
        self.clear_window()

        frame = ctk.CTkFrame(
            self,
            fg_color=COLOR_CARD,
            corner_radius=20,
            border_width=1,
            border_color=COLOR_AMBER,
        )
        frame.pack(expand=True, padx=40, pady=40, fill="both")

        lbl_icon = ctk.CTkLabel(frame, text="🗄️", font=("Helvetica", 48))
        lbl_icon.pack(pady=(30, 0))

        lbl_logo = ctk.CTkLabel(
            frame,
            text="VaultLock",
            font=("Helvetica", 28, "bold"),
            text_color=COLOR_AMBER,
        )
        lbl_logo.pack(pady=(5, 10))

        lbl_subtitle = ctk.CTkLabel(
            frame,
            text="Inserisci la Master Password per decifrare la cassaforte",
            font=("Helvetica", 13),
            text_color=COLOR_TEXT_MUTED,
        )
        lbl_subtitle.pack(pady=(0, 20))

        self.entry_master = ctk.CTkEntry(
            frame,
            show="•",
            width=320,
            height=45,
            corner_radius=12,
            fg_color="#1E1916",
            border_color=COLOR_AMBER,
            text_color=COLOR_TEXT,
            font=("Helvetica", 14),
        )
        self.entry_master.pack(pady=10)
        self.entry_master.focus()
        self.entry_master.bind("<Return>", lambda e: self.unlock_vault())

        btn_unlock = ctk.CTkButton(
            frame,
            text="Sblocca Cassaforte 🔐",
            command=self.unlock_vault,
            fg_color=COLOR_AMBER,
            hover_color=COLOR_AMBER_HOVER,
            text_color="#FFFFFF",
            font=("Helvetica", 14, "bold"),
            height=45,
            width=320,
            corner_radius=12,
        )
        btn_unlock.pack(pady=20)

    def unlock_vault(self):
        master_pwd = self.entry_master.get().strip()
        if not master_pwd:
            messagebox.showwarning("Attenzione", "Inserisci la Master Password.")
            return

        self.fernet_key = SecurityManager.derive_key(master_pwd, self.salt)

        entries = self.db.get_all_entries()
        if entries:
            try:
                SecurityManager.decrypt_data(entries[0][3], self.fernet_key)
            except Exception:
                messagebox.showerror(
                    "Errore", "Master Password errata! Impossibile decifrare i dati."
                )
                return

        self.show_dashboard()

    # -------------------------------------------------------------
    # DASHBOARD PRINCIPALE
    # -------------------------------------------------------------
    def show_dashboard(self):
        self.clear_window()

        header_frame = ctk.CTkFrame(
            self, fg_color=COLOR_CARD, corner_radius=0, height=60
        )
        header_frame.pack(fill="x", side="top")

        lbl_title = ctk.CTkLabel(
            header_frame,
            text="🗄️ SPsoft Password Vault",
            font=("Helvetica", 18, "bold"),
            text_color=COLOR_AMBER,
        )
        lbl_title.pack(side="left", padx=20, pady=15)

        btn_logout = ctk.CTkButton(
            header_frame,
            text="Blocca 🔒",
            command=self.show_login_screen,
            fg_color="#374151",
            hover_color="#4B5563",
            width=90,
            height=32,
            corner_radius=8,
        )
        btn_logout.pack(side="right", padx=20, pady=15)

        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        top_bar = ctk.CTkFrame(main_frame, fg_color="transparent")
        top_bar.pack(fill="x", pady=(0, 15))

        self.entry_search = ctk.CTkEntry(
            top_bar,
            placeholder_text="🔍 Cerca servizio...",
            height=40,
            corner_radius=10,
            fg_color=COLOR_CARD,
            border_color="#443730",
            text_color=COLOR_TEXT,
        )
        self.entry_search.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entry_search.bind("<KeyRelease>", lambda e: self.load_cards())

        btn_add = ctk.CTkButton(
            top_bar,
            text="+ Nuova Credenziale",
            command=self.open_add_dialog,
            fg_color=COLOR_AMBER,
            hover_color=COLOR_AMBER_HOVER,
            height=40,
            corner_radius=10,
            font=("Helvetica", 13, "bold"),
        )
        btn_add.pack(side="right")

        self.scroll_frame = ctk.CTkScrollableFrame(
            main_frame, fg_color="transparent", label_text_color=COLOR_TEXT
        )
        self.scroll_frame.pack(fill="both", expand=True)

        self.load_cards()

    def load_cards(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        search_query = self.entry_search.get().lower()
        entries = self.db.get_all_entries()

        count = 0
        for entry_id, servizio, username, pwd_enc, note in entries:
            if (
                search_query
                and search_query not in servizio.lower()
                and search_query not in username.lower()
            ):
                continue

            try:
                pwd_dec = SecurityManager.decrypt_data(pwd_enc, self.fernet_key)
            except Exception:
                pwd_dec = "*** ERRORE DECIFRATURA ***"

            self.create_card(entry_id, servizio, username, pwd_dec, note)
            count += 1

        if count == 0:
            lbl_empty = ctk.CTkLabel(
                self.scroll_frame,
                text="Nessuna credenziale trovata.",
                text_color=COLOR_TEXT_MUTED,
                font=("Helvetica", 14),
            )
            lbl_empty.pack(pady=40)

    def create_card(self, entry_id, servizio, username, password, note):
        card = ctk.CTkFrame(
            self.scroll_frame,
            fg_color=COLOR_CARD,
            corner_radius=14,
            border_width=1,
            border_color="#3D312A",
        )
        card.pack(fill="x", pady=6, padx=5)

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", padx=15, pady=12, fill="both", expand=True)

        lbl_servizio = ctk.CTkLabel(
            info_frame,
            text=servizio,
            font=("Helvetica", 15, "bold"),
            text_color=COLOR_AMBER,
            anchor="w",
        )
        lbl_servizio.pack(fill="x")

        lbl_user = ctk.CTkLabel(
            info_frame,
            text=f"Utente: {username}",
            font=("Helvetica", 12),
            text_color=COLOR_TEXT,
            anchor="w",
        )
        lbl_user.pack(fill="x")

        show_var = ctk.BooleanVar(value=False)

        def toggle_pwd():
            if show_var.get():
                lbl_pwd.configure(text=f"Password: {password}")
            else:
                lbl_pwd.configure(text="Password: ••••••••••••")

        lbl_pwd = ctk.CTkLabel(
            info_frame,
            text="Password: ••••••••••••",
            font=("Helvetica", 12),
            text_color=COLOR_TEXT_MUTED,
            anchor="w",
        )
        lbl_pwd.pack(fill="x")

        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(side="right", padx=15, pady=12)

        def copy_pwd():
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo(
                "Copiato", f"Password per '{servizio}' copiata negli appunti!"
            )

        btn_show = ctk.CTkCheckBox(
            btn_frame,
            text="Mostra",
            variable=show_var,
            command=toggle_pwd,
            onvalue=True,
            offvalue=False,
            text_color=COLOR_TEXT_MUTED,
            width=60,
        )
        btn_show.pack(side="left", padx=5)

        btn_copy = ctk.CTkButton(
            btn_frame,
            text="📋 Copia",
            command=copy_pwd,
            width=70,
            height=32,
            fg_color="#374151",
            hover_color="#4B5563",
            corner_radius=8,
        )
        btn_copy.pack(side="left", padx=5)

        # Pulsante Modifica
        btn_edit = ctk.CTkButton(
            btn_frame,
            text="✏️",
            command=lambda: self.open_edit_dialog(
                entry_id, servizio, username, password, note
            ),
            width=40,
            height=32,
            fg_color="#D97706",
            hover_color="#B45309",
            corner_radius=8,
        )
        btn_edit.pack(side="left", padx=5)

        btn_del = ctk.CTkButton(
            btn_frame,
            text="🗑️",
            command=lambda: self.delete_card(entry_id, servizio),
            width=40,
            height=32,
            fg_color=COLOR_DANGER,
            hover_color="#991B1B",
            corner_radius=8,
        )
        btn_del.pack(side="left", padx=5)

    def delete_card(self, entry_id, servizio):
        if messagebox.askyesno(
            "Conferma",
            f"Sei sicuro di voler eliminare la credenziale per '{servizio}'?",
        ):
            self.db.delete_entry(entry_id)
            self.load_cards()

    # -------------------------------------------------------------
    # DIALOGO AGGIUNTA NUOVA CREDENZIALE
    # -------------------------------------------------------------
    def open_add_dialog(self):
        self._open_form_dialog(
            title_text="Nuova Credenziale",
            button_text="Salva Credenziale",
            is_edit=False,
        )

    # -------------------------------------------------------------
    # DIALOGO MODIFICA CREDENZIALE
    # -------------------------------------------------------------
    def open_edit_dialog(self, entry_id, servizio, username, password, note):
        self._open_form_dialog(
            title_text="Modifica Credenziale",
            button_text="Aggiorna Credenziale",
            is_edit=True,
            entry_id=entry_id,
            init_servizio=servizio,
            init_username=username,
            init_password=password,
            init_note=note,
        )

    def _open_form_dialog(
        self,
        title_text,
        button_text,
        is_edit=False,
        entry_id=None,
        init_servizio="",
        init_username="",
        init_password="",
        init_note="",
    ):
        dialog = ctk.CTkToplevel(self)
        dialog.title(title_text)
        dialog.geometry("400x480")
        dialog.configure(fg_color=COLOR_BG_DARK)
        dialog.transient(self)
        dialog.grab_set()

        d_x = self.winfo_x() + (self.winfo_width() // 2) - 200
        d_y = self.winfo_y() + (self.winfo_height() // 2) - 240
        dialog.geometry(f"400x480+{d_x}+{d_y}")

        lbl_title = ctk.CTkLabel(
            dialog,
            text=title_text,
            font=("Helvetica", 18, "bold"),
            text_color=COLOR_AMBER,
        )
        lbl_title.pack(pady=15)

        entry_servizio = ctk.CTkEntry(
            dialog,
            placeholder_text="Nome Servizio (es. Amazon, Email)",
            width=320,
            height=40,
            corner_radius=10,
            fg_color=COLOR_CARD,
        )
        entry_servizio.pack(pady=8)
        entry_servizio.insert(0, init_servizio)

        entry_username = ctk.CTkEntry(
            dialog,
            placeholder_text="Username / Email",
            width=320,
            height=40,
            corner_radius=10,
            fg_color=COLOR_CARD,
        )
        entry_username.pack(pady=8)
        entry_username.insert(0, init_username)

        entry_pwd = ctk.CTkEntry(
            dialog,
            placeholder_text="Password",
            width=320,
            height=40,
            corner_radius=10,
            fg_color=COLOR_CARD,
        )
        entry_pwd.pack(pady=8)
        entry_pwd.insert(0, init_password)

        entry_note = ctk.CTkEntry(
            dialog,
            placeholder_text="Note aggiuntive (opzionale)",
            width=320,
            height=40,
            corner_radius=10,
            fg_color=COLOR_CARD,
        )
        entry_note.pack(pady=8)
        if init_note:
            entry_note.insert(0, init_note)

        def save_action():
            s = entry_servizio.get().strip()
            u = entry_username.get().strip()
            p = entry_pwd.get().strip()
            n = entry_note.get().strip()

            if not s or not u or not p:
                messagebox.showwarning(
                    "Campi Mancanti",
                    "Servizio, Username e Password sono obbligatori.",
                    parent=dialog,
                )
                return

            enc_p = SecurityManager.encrypt_data(p, self.fernet_key)
            if is_edit:
                self.db.update_entry(entry_id, s, u, enc_p, n)
            else:
                self.db.add_entry(s, u, enc_p, n)

            dialog.destroy()
            self.load_cards()

        btn_save = ctk.CTkButton(
            dialog,
            text=button_text,
            command=save_action,
            fg_color=COLOR_AMBER,
            hover_color=COLOR_AMBER_HOVER,
            width=320,
            height=42,
            corner_radius=10,
            font=("Helvetica", 14, "bold"),
        )
        btn_save.pack(pady=20)

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    app = PasswordVaultApp()
    app.mainloop()
