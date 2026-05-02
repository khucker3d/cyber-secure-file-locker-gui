"""
Secure File Locker GUI
Cross-platform Python/Tkinter file encryption tool for Windows and macOS.

Features:
- Select a file to lock or unlock
- Encrypt files with password-based AES encryption
- Unlock encrypted .locked files as a safe copy
- Remove lock by restoring the original file and deleting the .locked file
- Set and display a password hint after the first failed unlock attempt
- Track failed attempts inside protected encrypted file metadata
- Lock file access after 10 failed attempts
- Change password for an encrypted file
- Password strength indicator
- Optional delete original file after encryption
- Optional remove lock after successful unlock

Install dependency:
    pip install cryptography

Run:
    python secure_file_locker_gui.py

Notes:
- This tool does not store the password.
- If the password is forgotten, the encrypted file cannot be recovered.
- The failed attempt counter is stored in authenticated metadata. Editing the file manually will break validation.
"""

"""
Secure File Locker GUI
Cross-platform Python/Tkinter file encryption tool for Windows and macOS.
"""

import base64
import json
import os
import secrets
import string
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DRAG_AND_DROP_AVAILABLE = True
except ImportError:
    DND_FILES = None
    TkinterDnD = None
    DRAG_AND_DROP_AVAILABLE = False


APP_NAME = "Secure File Locker"
LOCKED_EXTENSION = ".locked"
FILE_MAGIC = "SECURE_FILE_LOCKER_V1"
MAX_FAILED_ATTEMPTS = 10
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
CHUNK_WARNING_SIZE_MB = 100


def b64encode(raw_bytes: bytes) -> str:
    return base64.b64encode(raw_bytes).decode("utf-8")


def b64decode(encoded_text: str) -> bytes:
    return base64.b64decode(encoded_text.encode("utf-8"))


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def make_metadata_aad(metadata: dict) -> bytes:
    protected_metadata = {
        "magic": metadata["magic"],
        "version": metadata["version"],
        "original_name": metadata["original_name"],
        "hint": metadata["hint"],
        "salt": metadata["salt"],
        "nonce": metadata["nonce"],
    }
    return json.dumps(protected_metadata, sort_keys=True).encode("utf-8")


def create_file_hmac(key: bytes, metadata: dict, ciphertext_b64: str) -> str:
    h = hmac.HMAC(key, hashes.SHA256())
    signed_data = json.dumps(
        {
            "metadata": {
                "magic": metadata["magic"],
                "version": metadata["version"],
                "original_name": metadata["original_name"],
                "hint": metadata["hint"],
                "salt": metadata["salt"],
                "nonce": metadata["nonce"],
            },
            "ciphertext": ciphertext_b64,
        },
        sort_keys=True,
    ).encode("utf-8")
    h.update(signed_data)
    return b64encode(h.finalize())


def verify_file_hmac(key: bytes, metadata: dict, ciphertext_b64: str, expected_hmac_b64: str) -> None:
    h = hmac.HMAC(key, hashes.SHA256())
    signed_data = json.dumps(
        {
            "metadata": {
                "magic": metadata["magic"],
                "version": metadata["version"],
                "original_name": metadata["original_name"],
                "hint": metadata["hint"],
                "salt": metadata["salt"],
                "nonce": metadata["nonce"],
            },
            "ciphertext": ciphertext_b64,
        },
        sort_keys=True,
    ).encode("utf-8")
    h.update(signed_data)
    h.verify(b64decode(expected_hmac_b64))


def read_locked_file(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError("This file is not a valid locked file.") from exc

    if data.get("magic") != FILE_MAGIC:
        raise ValueError("This file was not created by this file locker.")

    required_keys = [
        "magic", "version", "original_name", "hint", "salt",
        "nonce", "attempts", "locked", "ciphertext", "hmac",
    ]

    for key in required_keys:
        if key not in data:
            raise ValueError(f"Locked file is missing required field: {key}")

    return data


def write_locked_file(path: Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def prevent_overwrite(path: Path) -> Path:
    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    counter = 1

    while True:
        candidate = parent / f"{stem}_copy_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def get_default_locked_path(source_path: Path) -> Path:
    return source_path.with_name(source_path.name + LOCKED_EXTENSION)


def get_default_unlocked_path(locked_path: Path, original_name: str) -> Path:
    return locked_path.with_name(original_name)


def password_strength(password: str) -> tuple[str, int]:
    score = 0

    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if any(char.islower() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char in string.punctuation for char in password):
        score += 1

    if score <= 2:
        return "Weak", score
    if score <= 4:
        return "Moderate", score
    if score == 5:
        return "Strong", score

    return "Very Strong", score


def encrypt_file(source_path: Path, password: str, hint: str, delete_original: bool) -> Path:
    if not source_path.exists() or not source_path.is_file():
        raise ValueError("Please select a valid file to lock.")

    if source_path.suffix == LOCKED_EXTENSION:
        raise ValueError("This file already appears to be locked.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    plaintext = source_path.read_bytes()

    metadata = {
        "magic": FILE_MAGIC,
        "version": 1,
        "original_name": source_path.name,
        "hint": hint.strip(),
        "salt": b64encode(salt),
        "nonce": b64encode(nonce),
        "attempts": 0,
        "locked": False,
    }

    aesgcm = AESGCM(key)
    aad = make_metadata_aad(metadata)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext_b64 = b64encode(ciphertext)

    metadata["ciphertext"] = ciphertext_b64
    metadata["hmac"] = create_file_hmac(key, metadata, ciphertext_b64)

    output_path = prevent_overwrite(get_default_locked_path(source_path))
    write_locked_file(output_path, metadata)

    if delete_original:
        source_path.unlink()

    return output_path


def update_attempt_state(path: Path, data: dict, attempts: int, locked: bool) -> None:
    data["attempts"] = attempts
    data["locked"] = locked
    write_locked_file(path, data)


def decrypt_file(
    locked_path: Path,
    password: str,
    remove_lock: bool = False,
    overwrite_existing: bool = False,
) -> Path:
    data = read_locked_file(locked_path)

    attempts = int(data.get("attempts", 0))
    file_is_locked = bool(data.get("locked", False))

    if file_is_locked or attempts >= MAX_FAILED_ATTEMPTS:
        raise PermissionError("This file is locked after too many failed attempts.")

    salt = b64decode(data["salt"])
    nonce = b64decode(data["nonce"])
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        verify_file_hmac(key, data, data["ciphertext"], data["hmac"])
        aad = make_metadata_aad(data)
        plaintext = aesgcm.decrypt(nonce, b64decode(data["ciphertext"]), aad)
    except Exception as exc:
        attempts += 1
        locked = attempts >= MAX_FAILED_ATTEMPTS
        update_attempt_state(locked_path, data, attempts, locked)

        if locked:
            raise PermissionError("Too many failed attempts. This file is now locked.") from exc

        raise InvalidTag("Incorrect password or file has been altered.") from exc

    output_path = get_default_unlocked_path(locked_path, data["original_name"])

    if remove_lock:
        if output_path.exists() and not overwrite_existing:
            raise FileExistsError("The original filename already exists. Enable overwrite to remove the lock.")
    else:
        output_path = prevent_overwrite(output_path)

    output_path.write_bytes(plaintext)

    if remove_lock:
        locked_path.unlink()
    else:
        data["attempts"] = 0
        data["locked"] = False
        data["hmac"] = create_file_hmac(key, data, data["ciphertext"])
        write_locked_file(locked_path, data)

    return output_path


def change_file_password(locked_path: Path, current_password: str, new_password: str, new_hint: str) -> Path:
    data = read_locked_file(locked_path)

    if bool(data.get("locked", False)) or int(data.get("attempts", 0)) >= MAX_FAILED_ATTEMPTS:
        raise PermissionError("This file is locked after too many failed attempts.")

    old_salt = b64decode(data["salt"])
    old_nonce = b64decode(data["nonce"])
    old_key = derive_key(current_password, old_salt)
    aesgcm_old = AESGCM(old_key)

    try:
        verify_file_hmac(old_key, data, data["ciphertext"], data["hmac"])
        old_aad = make_metadata_aad(data)
        plaintext = aesgcm_old.decrypt(old_nonce, b64decode(data["ciphertext"]), old_aad)
    except Exception as exc:
        attempts = int(data.get("attempts", 0)) + 1
        locked = attempts >= MAX_FAILED_ATTEMPTS
        update_attempt_state(locked_path, data, attempts, locked)
        raise InvalidTag("Current password is incorrect or file has been altered.") from exc

    new_salt = secrets.token_bytes(SALT_SIZE)
    new_nonce = secrets.token_bytes(NONCE_SIZE)
    new_key = derive_key(new_password, new_salt)

    new_data = {
        "magic": FILE_MAGIC,
        "version": 1,
        "original_name": data["original_name"],
        "hint": new_hint.strip(),
        "salt": b64encode(new_salt),
        "nonce": b64encode(new_nonce),
        "attempts": 0,
        "locked": False,
    }

    aesgcm_new = AESGCM(new_key)
    new_aad = make_metadata_aad(new_data)
    ciphertext = aesgcm_new.encrypt(new_nonce, plaintext, new_aad)
    ciphertext_b64 = b64encode(ciphertext)

    new_data["ciphertext"] = ciphertext_b64
    new_data["hmac"] = create_file_hmac(new_key, new_data, ciphertext_b64)

    write_locked_file(locked_path, new_data)
    return locked_path


class SecureFileLockerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("820x720")
        self.root.minsize(760, 560)

        self.selected_file = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.hint = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.delete_original = tk.BooleanVar(value=False)
        self.remove_lock_after_unlock = tk.BooleanVar(value=False)
        self.overwrite_existing_on_remove = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Select a file to begin.")
        self.strength = tk.StringVar(value="Password strength: Not checked")

        self.current_password = tk.StringVar()
        self.new_password = tk.StringVar()
        self.confirm_new_password = tk.StringVar()
        self.new_hint = tk.StringVar()

        self.build_ui()
        self.bind_events()

    def build_ui(self) -> None:
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        main = ttk.Frame(canvas, padding=18)
        canvas_window = canvas.create_window((0, 0), window=main, anchor="nw")

        def update_scroll_region(_event=None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_canvas_window(event) -> None:
            canvas.itemconfig(canvas_window, width=event.width)

        def on_mousewheel(event) -> None:
            if sys.platform.startswith("darwin"):
                canvas.yview_scroll(-1 * int(event.delta), "units")
            else:
                canvas.yview_scroll(-1 * int(event.delta / 120), "units")

        main.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_canvas_window)
        canvas.bind_all("<MouseWheel>", on_mousewheel)

        title = ttk.Label(main, text=APP_NAME, font=("Arial", 20, "bold"))
        title.pack(anchor="w")

        subtitle = ttk.Label(
            main,
            text="Encrypt and decrypt files locally using a password. Your password is never stored.",
            wraplength=680,
        )
        subtitle.pack(anchor="w", pady=(4, 16))

        self.build_file_section(main)
        self.build_password_section(main)
        self.build_action_section(main)
        self.build_change_password_section(main)
        self.build_log_section(main)
        self.build_status_section(main)

    def build_file_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="File Selection", padding=12)
        frame.pack(fill="x", pady=(0, 12))

        file_entry = ttk.Entry(frame, textvariable=self.selected_file)
        file_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        browse_button = ttk.Button(frame, text="Browse", command=self.browse_file)
        browse_button.pack(side="left")

        drop_text = "Drag and drop a file here"
        if not DRAG_AND_DROP_AVAILABLE:
            drop_text = "Drag and drop unavailable. Install with: pip install tkinterdnd2"

        self.drop_label = ttk.Label(
            frame,
            text=drop_text,
            anchor="center",
            relief="groove",
            padding=12,
        )
        self.drop_label.pack(fill="x", pady=(10, 0))

        if DRAG_AND_DROP_AVAILABLE:
            self.drop_label.drop_target_register(DND_FILES)
            self.drop_label.dnd_bind("<<Drop>>", self.handle_file_drop)

    def build_password_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Lock / Unlock Password", padding=12)
        frame.pack(fill="x", pady=(0, 12))

        ttk.Label(frame, text="Password").grid(row=0, column=0, sticky="w", pady=4)
        self.password_entry = ttk.Entry(frame, textvariable=self.password, show="*")
        self.password_entry.grid(row=0, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(frame, text="Confirm Password").grid(row=1, column=0, sticky="w", pady=4)
        self.confirm_entry = ttk.Entry(frame, textvariable=self.confirm_password, show="*")
        self.confirm_entry.grid(row=1, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(frame, text="Password Hint").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.hint).grid(row=2, column=1, sticky="ew", pady=4, padx=(8, 0))

        show_box = ttk.Checkbutton(
            frame,
            text="Show password",
            variable=self.show_password,
            command=self.toggle_password_visibility,
        )
        show_box.grid(row=3, column=1, sticky="w", pady=(6, 2), padx=(8, 0))

        ttk.Label(frame, textvariable=self.strength).grid(row=4, column=1, sticky="w", pady=(2, 0), padx=(8, 0))

        ttk.Checkbutton(
            frame,
            text="Delete original file after locking",
            variable=self.delete_original,
        ).grid(row=5, column=1, sticky="w", pady=(6, 0), padx=(8, 0))

        ttk.Checkbutton(
            frame,
            text="Remove lock after successful unlock",
            variable=self.remove_lock_after_unlock,
        ).grid(row=6, column=1, sticky="w", pady=(6, 0), padx=(8, 0))

        ttk.Checkbutton(
            frame,
            text="Overwrite existing original file when removing lock",
            variable=self.overwrite_existing_on_remove,
        ).grid(row=7, column=1, sticky="w", pady=(6, 0), padx=(8, 0))

        frame.columnconfigure(1, weight=1)

    def build_action_section(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=(0, 12))

        ttk.Button(frame, text="Lock File", command=self.lock_file).pack(side="left", padx=(0, 8))
        ttk.Button(frame, text="Unlock File", command=self.unlock_file).pack(side="left", padx=(0, 8))
        ttk.Button(frame, text="Open File Folder", command=self.open_selected_folder).pack(side="left", padx=(0, 8))
        ttk.Button(frame, text="Clear", command=self.clear_fields).pack(side="left")

    def build_change_password_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Change Password for Locked File", padding=12)
        frame.pack(fill="x", pady=(0, 12))

        ttk.Label(frame, text="Current Password").grid(row=0, column=0, sticky="w", pady=4)
        self.current_password_entry = ttk.Entry(frame, textvariable=self.current_password, show="*")
        self.current_password_entry.grid(row=0, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(frame, text="New Password").grid(row=1, column=0, sticky="w", pady=4)
        self.new_password_entry = ttk.Entry(frame, textvariable=self.new_password, show="*")
        self.new_password_entry.grid(row=1, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(frame, text="Confirm New Password").grid(row=2, column=0, sticky="w", pady=4)
        self.confirm_new_password_entry = ttk.Entry(frame, textvariable=self.confirm_new_password, show="*")
        self.confirm_new_password_entry.grid(row=2, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(frame, text="New Hint").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.new_hint).grid(row=3, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Button(frame, text="Change Password", command=self.change_password).grid(
            row=4,
            column=1,
            sticky="w",
            pady=(8, 0),
            padx=(8, 0),
        )

        frame.columnconfigure(1, weight=1)

    def build_log_section(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Activity Log", padding=12)
        frame.pack(fill="both", expand=True, pady=(0, 12))

        self.log_box = tk.Text(frame, height=8, wrap="word")
        self.log_box.pack(fill="both", expand=True)
        self.log("Ready.")

    def build_status_section(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, textvariable=self.status, wraplength=700).pack(anchor="w")

    def bind_events(self) -> None:
        self.password.trace_add("write", lambda *_: self.update_strength())
        self.new_password.trace_add("write", lambda *_: self.update_new_password_strength())

    def browse_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file")
        if path:
            self.set_selected_file(path)

    def set_selected_file(self, path: str) -> None:
        clean_path = path.strip()
        self.selected_file.set(clean_path)
        self.status.set(f"Selected: {clean_path}")
        self.log(f"Selected file: {clean_path}")

    def handle_file_drop(self, event) -> None:
        try:
            dropped_items = self.root.tk.splitlist(event.data)
            if not dropped_items:
                return

            path = Path(dropped_items[0])

            if not path.exists() or not path.is_file():
                messagebox.showwarning("Invalid Drop", "Please drop a single valid file.")
                return

            self.set_selected_file(str(path))

        except Exception as exc:
            self.status.set(str(exc))
            self.log(f"Drag and drop failed: {exc}")
            messagebox.showerror("Drag and Drop Failed", str(exc))

    def toggle_password_visibility(self) -> None:
        show_char = "" if self.show_password.get() else "*"
        self.password_entry.config(show=show_char)
        self.confirm_entry.config(show=show_char)
        self.current_password_entry.config(show=show_char)
        self.new_password_entry.config(show=show_char)
        self.confirm_new_password_entry.config(show=show_char)

    def update_strength(self) -> None:
        password = self.password.get()
        if not password:
            self.strength.set("Password strength: Not checked")
            return

        label, _score = password_strength(password)
        self.strength.set(f"Password strength: {label}")

    def update_new_password_strength(self) -> None:
        password = self.new_password.get()
        if len(password) >= 8:
            label, _score = password_strength(password)
            self.status.set(f"New password strength: {label}")

    def log(self, message: str) -> None:
        self.log_box.insert("end", f"{message}\n")
        self.log_box.see("end")

    def get_selected_path(self) -> Path:
        selected = self.selected_file.get().strip()
        if not selected:
            raise ValueError("Please select a file first.")
        return Path(selected)

    def validate_password_for_lock(self) -> str:
        password = self.password.get()
        confirm = self.confirm_password.get()

        if not password:
            raise ValueError("Please enter a password.")
        if password != confirm:
            raise ValueError("Password and confirmation do not match.")
        if len(password) < 12:
            raise ValueError("Use a password with at least 12 characters.")

        return password

    def validate_password_for_unlock(self) -> str:
        password = self.password.get()
        if not password:
            raise ValueError("Please enter the unlock password.")
        return password

    def check_large_file_warning(self, path: Path) -> bool:
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb >= CHUNK_WARNING_SIZE_MB:
            return messagebox.askyesno(
                "Large File Warning",
                f"This file is about {size_mb:.1f} MB. Version 1 loads files into memory. Continue?",
            )
        return True

    def lock_file(self) -> None:
        try:
            path = self.get_selected_path()
            password = self.validate_password_for_lock()
            hint = self.hint.get()

            if not self.check_large_file_warning(path):
                return

            if self.delete_original.get():
                confirmed = messagebox.askyesno(
                    "Confirm Delete Original",
                    "The original file will be deleted after encryption. Make sure your password is saved. Continue?",
                )
                if not confirmed:
                    return

            output_path = encrypt_file(path, password, hint, self.delete_original.get())
            self.status.set(f"File locked successfully: {output_path}")
            self.log(f"Locked file created: {output_path}")
            messagebox.showinfo("Success", f"File locked successfully:\n{output_path}")

        except Exception as exc:
            self.status.set(str(exc))
            self.log(f"Lock failed: {exc}")
            messagebox.showerror("Lock Failed", str(exc))

    def unlock_file(self) -> None:
        try:
            path = self.get_selected_path()
            password = self.validate_password_for_unlock()

            data = read_locked_file(path)
            attempts = int(data.get("attempts", 0))

            if attempts >= 1 and data.get("hint"):
                messagebox.showinfo("Password Hint", f"Hint: {data.get('hint')}")

            remove_lock = self.remove_lock_after_unlock.get()
            overwrite_existing = self.overwrite_existing_on_remove.get()

            if remove_lock:
                warning = (
                    "This will decrypt the file back to its original filename "
                    "and delete the .locked file.\n\n"
                    "Make sure you want this file unlocked permanently. Continue?"
                )
                if not messagebox.askyesno("Remove Lock", warning):
                    return

            if remove_lock and overwrite_existing:
                overwrite_warning = (
                    "Overwrite is enabled. If a file with the original name already exists, "
                    "it will be replaced.\n\n"
                    "Continue?"
                )
                if not messagebox.askyesno("Confirm Overwrite", overwrite_warning):
                    return

            output_path = decrypt_file(path, password, remove_lock, overwrite_existing)

            if remove_lock:
                success_message = f"Lock removed successfully:\n{output_path}"
                self.status.set(f"Lock removed successfully: {output_path}")
                self.log(f"Lock removed and file restored: {output_path}")
                messagebox.showinfo("Success", success_message)
            else:
                success_message = f"Unlocked copy created:\n{output_path}"
                self.status.set(f"File unlocked successfully: {output_path}")
                self.log(f"Unlocked file copy created: {output_path}")
                messagebox.showinfo("Success", success_message)

        except PermissionError as exc:
            self.status.set(str(exc))
            self.log(f"Unlock blocked: {exc}")
            messagebox.showwarning("File Locked", str(exc))

        except InvalidTag:
            try:
                data = read_locked_file(self.get_selected_path())
                attempts = int(data.get("attempts", 0))
                remaining = max(0, MAX_FAILED_ATTEMPTS - attempts)
                hint_text = data.get("hint", "")

                warning = f"Incorrect password or file has been altered. Attempts remaining: {remaining}"
                if attempts >= 1 and hint_text:
                    warning += f"\n\nHint: {hint_text}"

                self.status.set(warning)
                self.log(warning)
                messagebox.showwarning("Unlock Failed", warning)

            except Exception as nested_exc:
                self.status.set(str(nested_exc))
                self.log(f"Unlock failed: {nested_exc}")
                messagebox.showerror("Unlock Failed", str(nested_exc))

        except Exception as exc:
            self.status.set(str(exc))
            self.log(f"Unlock failed: {exc}")
            messagebox.showerror("Unlock Failed", str(exc))

    def change_password(self) -> None:
        try:
            path = self.get_selected_path()
            current = self.current_password.get()
            new = self.new_password.get()
            confirm = self.confirm_new_password.get()
            hint = self.new_hint.get()

            if not current:
                raise ValueError("Enter the current password.")
            if not new:
                raise ValueError("Enter the new password.")
            if new != confirm:
                raise ValueError("New password and confirmation do not match.")
            if len(new) < 12:
                raise ValueError("Use a new password with at least 12 characters.")

            output_path = change_file_password(path, current, new, hint)
            self.status.set(f"Password changed successfully: {output_path}")
            self.log(f"Password changed for: {output_path}")
            messagebox.showinfo("Success", "Password changed successfully.")

        except InvalidTag as exc:
            self.status.set(str(exc))
            self.log(f"Password change failed: {exc}")
            messagebox.showerror("Password Change Failed", str(exc))

        except Exception as exc:
            self.status.set(str(exc))
            self.log(f"Password change failed: {exc}")
            messagebox.showerror("Password Change Failed", str(exc))

    def open_selected_folder(self) -> None:
        try:
            path = self.get_selected_path()
            folder = path.parent

            if sys.platform.startswith("darwin"):
                subprocess.run(["open", str(folder)], check=False)
            elif os.name == "nt":
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                subprocess.run(["xdg-open", str(folder)], check=False)

            self.log(f"Opened folder: {folder}")

        except Exception as exc:
            self.status.set(str(exc))
            self.log(f"Open folder failed: {exc}")
            messagebox.showerror("Open Folder Failed", str(exc))

    def clear_fields(self) -> None:
        self.selected_file.set("")
        self.password.set("")
        self.confirm_password.set("")
        self.hint.set("")
        self.current_password.set("")
        self.new_password.set("")
        self.confirm_new_password.set("")
        self.new_hint.set("")
        self.delete_original.set(False)
        self.remove_lock_after_unlock.set(False)
        self.overwrite_existing_on_remove.set(False)
        self.status.set("Cleared fields.")
        self.log("Cleared fields.")


def main() -> None:
    if DRAG_AND_DROP_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    SecureFileLockerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
