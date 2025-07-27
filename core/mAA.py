import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel, scrolledtext
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
import string
import os
import time
import sys
import csv

# ====== CONSTANTS ======
KEY_FILE = "secret.key.encrypted"
SALT_FILE = "salt.salt"
PASSWORDS_FILE = "passwords.dat"
DEFAULT_PASSWORD_LENGTH = 16  # Fixed length for custom passwords when chunking is used
AUTO_LOCK_INTERVAL_MS = 5 * 60 * 1000  # 5 minutes in milliseconds
CLIPBOARD_CLEAR_DELAY_MS = 30 * 1000  # 30 seconds in milliseconds

def center_window(win, parent=None):
    """Center a given window on the screen."""
    win.update_idletasks()
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    win_width = win.winfo_width()
    win_height = win.winfo_height()
    x = (screen_width - win_width) // 2
    y = (screen_height - win_height) // 2
    win.geometry(f'+{x}+{y}')

def is_password_like(text):
    """
    Checks if a given text string appears to be a password.
    Requires at least 8 characters and a mix of A-Z, a-z, 0-9, or common symbols.
    """
    return bool(re.search(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", text))

def clipboard_monitor(root_app_instance):
    """
    Monitors the clipboard for password-like content and schedules it for clearing.
    This runs in a separate thread.
    """
    try:
        import pyperclip
    except ImportError:
        # Clipboard monitoring disabled if pyperclip not installed
        return

    last_clip = ""
    def monitor():
        nonlocal last_clip
        try:
            current = pyperclip.paste()
            # Only act if content has changed and it looks like a password
            if current != last_clip and is_password_like(current):
                last_clip = current
                # Schedule clearing on the main Tkinter thread
                root_app_instance.after(
                    CLIPBOARD_CLEAR_DELAY_MS,
                    lambda: root_app_instance._perform_external_clipboard_clear(current)
                )
                root_app_instance._update_status(
                    f"Password-like content detected on clipboard. Will clear in {CLIPBOARD_CLEAR_DELAY_MS // 1000} seconds."
                )
            elif current == last_clip and current == "":
                last_clip = ""
        except Exception:
            # Suppress errors (clipboard access issues)
            pass
        if root_app_instance.clipboard_monitor_running:
            root_app_instance.after(3000, monitor)
    monitor()

class LoginWindow(Toplevel):
    """
    A separate Toplevel window for handling user login with a master password.
    """
    def __init__(self, master_app):
        super().__init__(master_app)
        self.master_app = master_app
        self.title("Login to Password Manager")
        self.geometry("350x200")
        self.resizable(False, False)
        self.transient(master_app)
        self.grab_set()
        self.master_app.active_toplevels.append(self)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        self._create_widgets()
        center_window(self, master_app)
        self.entry_master_password.focus_set()

        if not os.path.exists(KEY_FILE):
            messagebox.showinfo(
                "First Time Setup",
                "Welcome! This appears to be your first time running the password manager.\n"
                "Please create a **strong** master password. This password cannot be recovered!",
                parent=self
            )
            self.title("Set Master Password")

    def destroy(self):
        if self in self.master_app.active_toplevels:
            self.master_app.active_toplevels.remove(self)
        super().destroy()

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=(20, 20))
        main_frame.pack(expand=True)
        ttk.Label(main_frame, text="Master Password:", font=("Arial", 12)).pack(pady=10)
        self.entry_master_password = ttk.Entry(main_frame, show='*', width=30, font=("Arial", 12))
        self.entry_master_password.pack(pady=5)
        self.entry_master_password.bind("<Return>", lambda event: self._attempt_login())
        ttk.Button(main_frame, text="Login", command=self._attempt_login, width=15).pack(pady=10)

    def _attempt_login(self):
        master_password = self.entry_master_password.get()
        if not master_password:
            messagebox.showwarning("Input Error", "Master password cannot be empty.", parent=self)
            return
        if not self.master_app._process_login(master_password, self):
            self.entry_master_password.delete(0, tk.END)

    def _on_closing(self):
        if messagebox.askokcancel("Quit", "Are you sure you want to quit the application?", parent=self):
            self.master_app.quit()

class PasswordManagerApp(tk.Tk):
    """
    The main application window, holding core logic and managing login/main interfaces.
    """
    def __init__(self):
        super().__init__()
        self.title("Mustee's Secure Password Manager")
        self.geometry("450x300")
        self.fernet = None
        self.salt = self._load_or_create_salt()
        self.lock_timer_id = None
        self.clipboard_clear_id = None
        self.clipboard_monitor_thread = None
        self.clipboard_monitor_running = False
        self.active_toplevels = []
        self._create_main_widgets()
        self._bind_activity_events()
        self._show_login_window()
        self.protocol("WM_DELETE_WINDOW", self._on_main_closing)

    def _on_main_closing(self):
        if messagebox.askokcancel("Quit", "Are you sure you want to quit the application?", parent=self):
            self.quit()

    def quit(self):
        # Stop clipboard monitor
        self.clipboard_monitor_running = False
        if self.lock_timer_id:
            self.after_cancel(self.lock_timer_id)
        if self.clipboard_clear_id:
            self.after_cancel(self.clipboard_clear_id)
        super().quit()

    def _load_or_create_salt(self):
        try:
            if not os.path.exists(SALT_FILE):
                salt = os.urandom(16)
                with open(SALT_FILE, "wb") as f:
                    f.write(salt)
            else:
                with open(SALT_FILE, "rb") as f:
                    salt = f.read()
            return salt
        except IOError as e:
            messagebox.showerror("File Error", f"Failed to access salt file: {e}\nApplication will exit.", parent=self)
            sys.exit(1)

    def _derive_key(self, master_password):
        """
        Derive a secure encryption key from the master password using PBKDF2HMAC.
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=200000
            )
            key = kdf.derive(master_password.encode('utf-8'))
            return base64.urlsafe_b64encode(key)
        except Exception as e:
            messagebox.showerror("Key Derivation Error", f"Failed to derive key: {e}", parent=self)
            return None

    def _check_password_strength(self, password):
        length_score = 0
        if len(password) >= 12:
            length_score = 3
        elif len(password) >= 8:
            length_score = 2
        else:
            length_score = 1
        char_type_score = 0
        if any(c.islower() for c in password): char_type_score += 1
        if any(c.isupper() for c in password): char_type_score += 1
        if any(c.isdigit() for c in password): char_type_score += 1
        if any(c in string.punctuation for c in password): char_type_score += 1
        total_score = length_score + char_type_score
        if total_score >= 7:
            return "Very Strong 💪"
        elif total_score >= 5:
            return "Strong 👍"
        elif total_score >= 3:
            return "Good 👌"
        else:
            return "Weak 😞"

    def _show_login_window(self):
        LoginWindow(self)

    def _process_login(self, master_password_attempt, login_window_instance):
        is_first_time_setup = not os.path.exists(KEY_FILE)
        if is_first_time_setup:
            strength = self._check_password_strength(master_password_attempt)
            confirm_password = simpledialog.askstring(
                "Confirm Master Password",
                f"Master Password Strength: {strength}\nEnter again to confirm:",
                show='*',
                parent=login_window_instance
            )
            if not confirm_password or master_password_attempt != confirm_password:
                messagebox.showerror("Error", "Passwords do not match. Please try again.", parent=login_window_instance)
                return False
        self.fernet_key = self._derive_key(master_password_attempt)
        if self.fernet_key is None:
            return False
        try:
            self.fernet = Fernet(self.fernet_key)
            self._load_and_verify_fernet_key()
            login_window_instance.destroy()
            self.deiconify()
            self._update_status("Master password accepted. Ready.")
            self._reset_lock_timer()
            self._start_clipboard_monitor()
            return True
        except InvalidToken:
            messagebox.showerror("Error", "Invalid master password. Please try again.", parent=login_window_instance)
            self.fernet = None
            return False
        except IOError as e:
            messagebox.showerror("File Error", f"Error accessing key file: {e}\nPlease check file permissions.", parent=login_window_instance)
            self.fernet = None
            return False
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred during login: {e}\nPlease try again.", parent=login_window_instance)
            self.fernet = None
            return False

    def _load_and_verify_fernet_key(self):
        if not os.path.exists(KEY_FILE):
            try:
                dummy_encrypted_data = self.fernet.encrypt(b"master_password_check_data")
                with open(KEY_FILE, "wb") as f:
                    f.write(dummy_encrypted_data)
                self._update_status("Initial setup: Master password file created.")
            except Exception as e:
                raise IOError(f"Failed to initialize key file: {e}")
        else:
            try:
                with open(KEY_FILE, "rb") as f:
                    stored_encrypted_data = f.read()
                self.fernet.decrypt(stored_encrypted_data)
            except InvalidToken:
                raise InvalidToken("Incorrect Master Password for verification.")
            except Exception as e:
                raise IOError(f"Error reading or decrypting key file: {e}")

    def _create_main_widgets(self):
        self.main_content_frame = ttk.Frame(self)
        self.main_content_frame.pack(fill="both", expand=True)
        ttk.Label(self.main_content_frame, text="🔐 Mustee's Password Manager", font=("Arial", 16, "bold")).pack(pady=20)
        ttk.Button(self.main_content_frame, text="✨ Generate Password",
                   command=self._open_generation_chooser_from_main, width=35).pack(pady=5)
        ttk.Button(self.main_content_frame, text="📂 View Saved Passwords",
                   command=self._open_saved_passwords_window, width=35).pack(pady=5)
        ttk.Button(self.main_content_frame, text="❌ Exit",
                   command=self._on_main_closing, width=35).pack(pady=5)
        # Using a standard Tkinter Label for the status bar to maintain sunken relief style
        self.status_bar = tk.Label(self, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _update_status(self, message):
        self.status_bar.config(text=message)

    def _bind_activity_events(self):
        self.bind_all("<Button-1>", self._reset_lock_timer)
        self.bind_all("<Key>", self._reset_lock_timer)

    def _reset_lock_timer(self, event=None):
        if self.lock_timer_id:
            self.after_cancel(self.lock_timer_id)
        if self.fernet:
            self.lock_timer_id = self.after(AUTO_LOCK_INTERVAL_MS, self._lock_application)

    def _lock_application(self):
        if self.fernet is None:
            return
        messagebox.showinfo("Auto-Locked", "Application locked due to inactivity.", parent=self)
        self.fernet = None
        self.clipboard_monitor_running = False
        for window in list(self.active_toplevels):
            try:
                window.destroy()
            except tk.TclError:
                pass
        self.active_toplevels.clear()
        self.after(100, self._show_login_window)
        self._update_status("Application locked.")

    def _start_clipboard_monitor(self):
        if not self.clipboard_monitor_running:
            try:
                import pyperclip
                self.clipboard_monitor_running = True
                if self.clipboard_monitor_thread is None or not self.clipboard_monitor_thread.is_alive():
                    self.clipboard_monitor_thread = threading.Thread(target=clipboard_monitor, args=(self,), daemon=True)
                    self.clipboard_monitor_thread.start()
                    self._update_status("Clipboard monitor started.")
            except ImportError:
                messagebox.showwarning(
                    "Clipboard Warning",
                    "pyperclip module not found. Automatic clipboard monitoring will be disabled. "
                    "Please install it using 'pip install pyperclip'.",
                    parent=self
                )
            except Exception as e:
                self._update_status(f"Error starting clipboard monitor: {e}")

    def _schedule_clipboard_clear(self):
        if self.clipboard_clear_id:
            self.after_cancel(self.clipboard_clear_id)
        self.clipboard_clear_id = self.after(CLIPBOARD_CLEAR_DELAY_MS, self._perform_clipboard_clear)
        self._update_status(f"Password copied to clipboard. Will clear in {CLIPBOARD_CLEAR_DELAY_MS // 1000} seconds.")

    def _perform_clipboard_clear(self):
        try:
            self.clipboard_clear()
            self._update_status("Clipboard cleared.")
        except tk.TclError as e:
            self._update_status(f"Failed to clear clipboard: {e}. You may need to manually clear it.")
        except Exception as e:
            self._update_status(f"An unexpected error occurred while clearing clipboard: {e}")
        finally:
            self.clipboard_clear_id = None

    def _perform_external_clipboard_clear(self, content_to_clear):
        try:
            import pyperclip
            if pyperclip.paste() == content_to_clear:
                pyperclip.copy("")
                self._update_status("Password-like content cleared from clipboard.")
            else:
                self._update_status("Clipboard content changed, not cleared.")
        except Exception as e:
            self._update_status(f"Error during external clipboard clear: {e}")

    def _open_generation_chooser_from_main(self, source_window=None, from_new_entry=False):
        if self.fernet:
            PasswordGenerationChooserWindow(
                self,
                source_window=source_window,
                return_to_main_app=(source_window is None),
                from_new_entry=from_new_entry
            )
        else:
            messagebox.showwarning("Access Denied", "Please log in first.", parent=self)

    def _open_random_generator_window(self, parent_window=None, return_to_chooser_callback=None):
        RandomPasswordGeneratorWindow(self, parent_window, return_to_chooser_callback)

    def _open_custom_generator_window(self, parent_window=None, return_to_chooser_callback=None):
        CustomPasswordGeneratorWindow(self, parent_window, return_to_chooser_callback)

    def _open_saved_passwords_window(self):
        if self.fernet:
            SavedPasswordsManagerWindow(self)
        else:
            messagebox.showwarning("Access Denied", "Please log in first.", parent=self)

    # ====== SHARED PASSWORD LOGIC ======
    def _generate_random_password(self, length=DEFAULT_PASSWORD_LENGTH):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for _ in range(length))

    def _generate_custom_password(self, phrase, option):
        min_len, max_len = 5, 10
        phrase_len = len(phrase)
        if not (min_len <= phrase_len <= max_len):
            return None

        if option == "intact":
            total_additional_chars = 6
            filler_pool = string.punctuation + string.digits + string.ascii_uppercase + string.ascii_lowercase
            guaranteed_chars = [
                secrets.choice(string.ascii_lowercase),
                secrets.choice(string.ascii_uppercase),
                secrets.choice(string.digits),
                secrets.choice(string.punctuation)
            ]
            remaining_chars_needed = total_additional_chars - len(guaranteed_chars)
            random_fillers = [secrets.choice(filler_pool) for _ in range(remaining_chars_needed)]
            all_fillers = guaranteed_chars + random_fillers
            secrets.SystemRandom().shuffle(all_fillers)
            first_index = secrets.randbelow(len(all_fillers))
            first_char = all_fillers.pop(first_index)
            remaining_chars = "".join(all_fillers)
            return f"{first_char}{phrase}{remaining_chars}"

        # Chunking logic
        chunk_size = option
        all_chunks = [phrase[i:i+chunk_size] for i in range(0, phrase_len, chunk_size)]
        target_length = DEFAULT_PASSWORD_LENGTH
        num_fillers = target_length - phrase_len
        filler_pool = string.punctuation + string.digits + string.ascii_uppercase + string.ascii_lowercase

        if num_fillers >= 4:
            guaranteed = [
                secrets.choice(string.ascii_lowercase),
                secrets.choice(string.ascii_uppercase),
                secrets.choice(string.digits),
                secrets.choice(string.punctuation)
            ]
            remaining_needed = num_fillers - 4
            random_fillers = [secrets.choice(filler_pool) for _ in range(remaining_needed)]
            all_fillers = guaranteed + random_fillers
        else:
            all_fillers = [secrets.choice(filler_pool) for _ in range(num_fillers)]

        secrets.SystemRandom().shuffle(all_fillers)
        bins = [[] for _ in range(len(all_chunks) + 1)]
        for char in all_fillers:
            secrets.choice(bins).append(char)

        final_list = []
        for i, chunk in enumerate(all_chunks):
            final_list.extend(bins[i])
            final_list.append(chunk)
        final_list.extend(bins[-1])
        password = "".join(final_list)
        return password[:target_length]

    def save_password_entry_to_file(self, website, username, password, original_website=None):
        try:
            data_to_encrypt = f"{website} | {username} | {password}".encode('utf-8')
            encrypted_data = self.fernet.encrypt(data_to_encrypt).decode('utf-8')
            entries = []
            current_websites = set()
            if os.path.exists(PASSWORDS_FILE):
                with open(PASSWORDS_FILE, "r") as file:
                    for line in file:
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue
                        try:
                            decrypted_line = self.fernet.decrypt(line_stripped.encode('utf-8')).decode('utf-8')
                            parts = decrypted_line.split(" | ")
                            if len(parts) == 3:
                                if original_website and parts[0] == original_website:
                                    continue
                                current_websites.add(parts[0])
                            entries.append(line_stripped)
                        except InvalidToken:
                            continue
                        except Exception:
                            continue
            if not original_website and website in current_websites:
                messagebox.showwarning(
                    "Duplicate Website",
                    f"An entry for '{website}' already exists. Please use 'Edit' or a different name.",
                    parent=self
                )
                return False
            entries.append(encrypted_data)
            with open(PASSWORDS_FILE, "w") as file:
                for entry in entries:
                    file.write(f"{entry}\n")
            if original_website:
                self._update_status(f"Password for '{original_website}' updated to '{website}'.")
            else:
                self._update_status(f"Password for '{website}' saved.")
            return True
        except IOError as e:
            messagebox.showerror("File Write Error", f"Failed to save password due to file system error: {e}", parent=self)
            self._update_status("Failed to save password.")
            return False
        except Exception as e:
            messagebox.showerror("Save Error", f"An unexpected error occurred while saving password: {e}", parent=self)
            self._update_status("Failed to save password.")
            return False

    def load_all_passwords_from_file(self):
        passwords_data = []
        if not os.path.exists(PASSWORDS_FILE):
            return passwords_data
        try:
            with open(PASSWORDS_FILE, "r") as file:
                for line in file:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    try:
                        decrypted_line = self.fernet.decrypt(line_stripped.encode('utf-8')).decode('utf-8')
                        parts = decrypted_line.split(" | ")
                        if len(parts) == 3:
                            passwords_data.append({"website": parts[0], "username": parts[1], "password": parts[2]})
                    except InvalidToken:
                        continue
                    except Exception:
                        continue
        except IOError as e:
            messagebox.showerror("File Read Error", f"Could not load passwords file due to file system error: {e}", parent=self)
            self._update_status("Failed to load passwords.")
        except Exception as e:
            messagebox.showerror("Load Error", f"An unexpected error occurred while loading passwords: {e}", parent=self)
            self._update_status("Failed to load passwords.")
        return passwords_data

    def delete_password_entry_from_file(self, website_to_delete):
        try:
            updated_entries = []
            if os.path.exists(PASSWORDS_FILE):
                with open(PASSWORDS_FILE, "r") as file:
                    for line in file:
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue
                        try:
                            decrypted_line = self.fernet.decrypt(line_stripped.encode('utf-8')).decode('utf-8')
                            parts = decrypted_line.split(" | ")
                            if len(parts) == 3 and parts[0] == website_to_delete:
                                self._update_status(f"Found and marked for deletion: '{website_to_delete}'.")
                                continue
                            updated_entries.append(line_stripped)
                        except InvalidToken:
                            updated_entries.append(line_stripped)
                        except Exception:
                            updated_entries.append(line_stripped)
            with open(PASSWORDS_FILE, "w") as file:
                for entry in updated_entries:
                    file.write(f"{entry}\n")
            self._update_status(f"Password for '{website_to_delete}' deleted.")
            return True
        except IOError as e:
            messagebox.showerror("File Delete Error", f"Failed to delete password due to file system error: {e}", parent=self)
            self._update_status("Failed to delete password.")
            return False
        except Exception as e:
            messagebox.showerror("Delete Error", f"An unexpected error occurred while deleting password: {e}", parent=self)
            self._update_status("Failed to delete password.")
            return False

    def export_passwords_to_csv(self):
        passwords = self.load_all_passwords_from_file()
        if not passwords:
            messagebox.showinfo("Export Info", "No passwords to export.", parent=self)
            self._update_status("No passwords to export.")
            return
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"passwords_export_{timestamp}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Website', 'Username', 'Password']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entry in passwords:
                    writer.writerow({
                        'Website': entry['website'],
                        'Username': entry['username'],
                        'Password': entry['password']
                    })
            messagebox.showinfo("Export Success", f"Passwords exported successfully to '{filename}'", parent=self)
            self._update_status(f"Passwords exported to '{filename}'.")
        except IOError as e:
            messagebox.showerror("Export Error", f"Failed to export passwords to CSV: {e}\nCheck file permissions or disk space.", parent=self)
            self._update_status("Failed to export passwords.")
        except Exception as e:
            messagebox.showerror("Export Error", f"An unexpected error occurred during CSV export: {e}", parent=self)
            self._update_status("Failed to export passwords.")

class BaseGeneratorWindow(Toplevel):
    """Base class for password generation windows."""
    def __init__(self, master_app, title_text, parent_window=None, return_to_chooser_callback=None):
        super().__init__(master_app)
        self.master_app = master_app
        self.title(title_text)
        self.geometry("500x350")
        self.transient(parent_window if parent_window else master_app)
        self.grab_set()
        self.return_to_chooser_callback = return_to_chooser_callback
        self.master_app.active_toplevels.append(self)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._create_common_widgets()
        center_window(self, parent_window if parent_window else master_app)

    def destroy(self):
        if self in self.master_app.active_toplevels:
            self.master_app.active_toplevels.remove(self)
        super().destroy()

    def _create_common_widgets(self):
        self.form_frame = ttk.Frame(self, padding=(10, 10))
        self.form_frame.pack(pady=10)

        ttk.Label(self.form_frame, text="Website:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.website_entry = ttk.Entry(self.form_frame, width=40)
        self.website_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.form_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = ttk.Entry(self.form_frame, width=40)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.form_frame, text="Generated Password:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.password_entry = ttk.Entry(self.form_frame, width=40, show='*', state='readonly')
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        button_frame = ttk.Frame(self)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="👁️ Toggle Pass", command=self._toggle_password_visibility, width=15).grid(row=0, column=0, padx=5, pady=3)
        ttk.Button(button_frame, text="📋 Copy Pass", command=self._copy_password, width=15).grid(row=0, column=1, padx=5, pady=3)
        self.save_button = ttk.Button(button_frame, text="💾 Save Password", command=self._save_password_and_close, width=15)
        self.save_button.grid(row=0, column=2, padx=5, pady=3)

        ttk.Button(button_frame, text="Main Menu", command=self._go_to_main_menu, width=15).grid(row=1, column=0, padx=5, pady=3)
        if self.return_to_chooser_callback:
            ttk.Button(button_frame, text="🔙 Back", command=self._go_back_to_chooser, width=15).grid(row=1, column=1, padx=5, pady=3)
        else:
            ttk.Button(button_frame, text="❌ Close", command=self.destroy, width=15).grid(row=1, column=1, padx=5, pady=3)

    def _toggle_password_visibility(self):
        current_show_char = self.password_entry.cget('show')
        if current_show_char == '*':
            self.password_entry.config(show='')
            self.master_app._update_status("Generated password visibility ON.")
        else:
            self.password_entry.config(show='*')
            self.master_app._update_status("Generated password visibility OFF.")

    def _copy_password(self):
        password = self.password_entry.get()
        if password:
            try:
                self.clipboard_clear()
                self.clipboard_append(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!", parent=self)
                self.master_app._schedule_clipboard_clear()
            except tk.TclError as e:
                messagebox.showerror("Clipboard Error", f"Failed to copy to clipboard: {e}", parent=self)
                self.master_app._update_status(f"Failed to copy password: {e}")
        else:
            messagebox.showwarning("Empty", "No password to copy.", parent=self)
            self.master_app._update_status("No password to copy.")

    def _save_password_and_close(self):
        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not (website and username and password):
            messagebox.showwarning("Missing Info", "Please fill all fields and generate a password.", parent=self)
            return
        if self.master_app.save_password_entry_to_file(website, username, password):
            self.destroy()

    def _go_back_to_chooser(self):
        self.destroy()
        if self.return_to_chooser_callback:
            self.return_to_chooser_callback()

    def _go_to_main_menu(self):
        self.destroy()
        self.master_app.deiconify()

class RandomPasswordGeneratorWindow(BaseGeneratorWindow):
    """Window for generating random passwords."""
    def __init__(self, master_app, parent_window=None, return_to_chooser_callback=None):
        super().__init__(master_app, "Random Password Generator", parent_window, return_to_chooser_callback)
        self._add_specific_widgets()

    def _add_specific_widgets(self):
        generate_button_frame = ttk.Frame(self)
        generate_button_frame.pack(pady=5)
        ttk.Button(
            generate_button_frame,
            text=f"Generate Random Password ({DEFAULT_PASSWORD_LENGTH} Chars)",
            command=self._generate_password,
            width=35
        ).pack()

    def _generate_password(self):
        new_pass = self.master_app._generate_random_password()
        self.password_entry.config(state='normal')
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, new_pass)
        self.password_entry.config(state='readonly', show='*')
        self.master_app._update_status("Random password generated.")

class CustomPasswordGeneratorWindow(BaseGeneratorWindow):
    """Window for generating custom passwords."""
    def __init__(self, master_app, parent_window=None, return_to_chooser_callback=None):
        super().__init__(master_app, "Custom Password Generator", parent_window, return_to_chooser_callback)
        self._add_specific_widgets()

    def _add_specific_widgets(self):
        self.phrase_frame = ttk.Frame(self, padding=(10, 5))
        self.phrase_frame.pack(before=self.form_frame)
        ttk.Label(self.phrase_frame, text="Base Phrase/Name:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.phrase_entry = ttk.Entry(self.phrase_frame, width=40)
        self.phrase_entry.grid(row=0, column=1, padx=5, pady=2)

        generate_button_frame = ttk.Frame(self)
        generate_button_frame.pack(before=self.form_frame, pady=5)
        ttk.Button(
            generate_button_frame,
            text="Select Customization Option",
            command=self._initiate_custom_generation,
            width=30
        ).pack()

    def _initiate_custom_generation(self):
        phrase = self.phrase_entry.get().strip()
        if not phrase:
            messagebox.showwarning("Missing Phrase", "Please enter a phrase or name.", parent=self)
            return
        min_len, max_len = 5, 10
        phrase_len = len(phrase)
        if not (min_len <= phrase_len <= max_len):
            messagebox.showwarning(
                "Custom Password",
                f"Base phrase must be between {min_len} and {max_len} characters long.\n"
                f"Your phrase '{phrase}' is {phrase_len} characters.",
                parent=self
            )
            return

        valid_chunk_sizes = []
        for size in [2, 3, 4]:
            if phrase_len % size == 0:
                valid_chunk_sizes.append(size)
        ChunkSelectionDialog(self, self.master_app, phrase, valid_chunk_sizes, self._handle_option_selection)

    def _handle_option_selection(self, selected_option):
        if selected_option is None:
            self.master_app._update_status("Custom password generation cancelled.")
            return
        phrase = self.phrase_entry.get().strip()
        new_pass = self.master_app._generate_custom_password(phrase, selected_option)
        if new_pass:
            self.password_entry.config(state='normal')
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, new_pass)
            self.password_entry.config(state='readonly', show='*')
            self.master_app._update_status(f"Custom password generated with option: '{selected_option}'.")

class ChunkSelectionDialog(Toplevel):
    """
    A dialog for the user to select how the custom password should be generated:
    either keeping the phrase intact or dividing it into chunks.
    """
    def __init__(self, master_window, master_app_ref, phrase, valid_chunk_sizes, callback_func):
        super().__init__(master_window)
        self.title("Select Custom Password Option")
        self.transient(master_window)
        self.grab_set()
        self.phrase = phrase
        self.valid_chunk_sizes = valid_chunk_sizes
        self.callback_func = callback_func
        self.master_app_ref = master_app_ref
        self.master_app_ref.active_toplevels.append(self)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self._create_widgets()
        center_window(self, master_window)

    def destroy(self):
        if self in self.master_app_ref.active_toplevels:
            self.master_app_ref.active_toplevels.remove(self)
        super().destroy()

    def _create_widgets(self):
        ttk.Label(self, text=f"Base Phrase: '{self.phrase}' (Length: {len(self.phrase)})", font=("Arial", 10, "bold")).pack(pady=10)
        ttk.Label(self, text="How would you like to use your phrase?").pack(pady=5)
        ttk.Button(self, text="Help", command=self._show_help, width=6).pack(pady=2)

        ttk.Button(
            self,
            text="Phrase Mode",
            command=lambda: self._on_select("intact"),
            width=20
        ).pack(pady=5)
        if self.valid_chunk_sizes:
            ttk.Label(self, text=f"Or divide into chunks (total length {DEFAULT_PASSWORD_LENGTH}):").pack(pady=5)
            for size in self.valid_chunk_sizes:
                ttk.Button(
                    self,
                    text=f"Chunks ({size})",
                    command=lambda s=size: self._on_select(s),
                    width=20
                ).pack(pady=5)
        else:
            ttk.Label(self, text="(Phrase not evenly divisible by 2, 3, or 4.)").pack(pady=5)
        ttk.Button(self, text="Cancel", command=self._on_cancel, width=20).pack(pady=10)

    def _show_help(self):
        help_text = (
            "Phrase Mode: Keeps your base phrase intact. A random character is added at the start, and 5 random characters are added at the end.\n"
            "Chunks (N): Splits your phrase into N-character chunks. Random characters (including at least one lowercase, uppercase, digit, and symbol) are then inserted between and around chunks to reach the total password length of 16."
        )
        messagebox.showinfo("Password Generation Help", help_text, parent=self)

    def _on_select(self, option):
        self.callback_func(option)
        self.destroy()

    def _on_cancel(self):
        self.callback_func(None)
        self.destroy()

class PasswordGenerationChooserWindow(Toplevel):
    """
    A dialog that lets the user choose between generating a random or custom password.
    """
    def __init__(self, master_app, source_window=None, return_to_main_app=False, from_new_entry=False):
        super().__init__(master_app)
        self.master_app = master_app
        self.source_window = source_window
        self.return_to_main_app = return_to_main_app
        self.from_new_entry = from_new_entry
        self.title("Choose Password Type")
        self.geometry("300x250")
        self.resizable(False, False)
        self.transient(source_window if source_window else master_app)
        self.grab_set()
        self.master_app.active_toplevels.append(self)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._create_widgets()
        center_window(self, source_window if source_window else master_app)

    def destroy(self):
        if self in self.master_app.active_toplevels:
            self.master_app.active_toplevels.remove(self)
        super().destroy()

    def _create_widgets(self):
        ttk.Label(self, text="Select Password Generation Type:", font=("Arial", 10, "bold")).pack(pady=15)
        ttk.Button(self, text="Random",
                   command=self._open_random_generator, width=30).pack(pady=5)
        ttk.Button(self, text="Custom",
                   command=self._open_custom_generator, width=30).pack(pady=5)
        ttk.Button(self, text="Main Menu", command=self._go_to_main_menu,
                   width=30).pack(pady=5)
        if self.from_new_entry:
            ttk.Button(self, text="🔙 Back", command=self._go_back, width=30).pack(pady=5)

    def _open_random_generator(self):
        self.destroy()
        self.master_app._open_random_generator_window(
            parent_window=self.source_window,
            return_to_chooser_callback=self._reopen_chooser
        )

    def _open_custom_generator(self):
        self.destroy()
        self.master_app._open_custom_generator_window(
            parent_window=self.source_window,
            return_to_chooser_callback=self._reopen_chooser
        )

    def _reopen_chooser(self):
        PasswordGenerationChooserWindow(self.master_app, self.source_window, self.return_to_main_app, self.from_new_entry)

    def _go_back(self):
        self.destroy()

    def _go_to_main_menu(self):
        if self.source_window:
            try:
                self.source_window.destroy()
            except:
                pass
        self.destroy()
        self.master_app.deiconify()

class SavedPasswordsManagerWindow(Toplevel):
    """Window for viewing and managing saved passwords."""
    def __init__(self, master_app):
        super().__init__(master_app)
        self.master_app = master_app
        self.title("View and Manage Saved Passwords")
        self.geometry("650x550")
        self.transient(master_app)
        self.grab_set()
        self.sorted_passwords = []
        self.editing_website = None
        self.master_app.active_toplevels.append(self)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._create_widgets()
        center_window(self, master_app)
        self._update_password_list()

    def destroy(self):
        if self in self.master_app.active_toplevels:
            self.master_app.active_toplevels.remove(self)
        super().destroy()

    def _create_widgets(self):
        ttk.Label(self, text="Your Saved Websites:", font=("Arial", 14, "bold")).pack(pady=10)

        search_frame = ttk.Frame(self)
        search_frame.pack(pady=5, padx=20, fill=tk.X)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame, width=50)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind('<KeyRelease>', self._filter_list)

        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        self.password_list = tk.Listbox(list_frame, height=10, font=("Courier", 10))
        self.password_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.password_list.bind('<<ListboxSelect>>', self._on_list_select)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.password_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.password_list.config(yscrollcommand=scrollbar.set)

        details_frame = ttk.LabelFrame(self, text="Selected Entry Details", padding=(10, 10))
        details_frame.pack(fill=tk.X, padx=20, pady=10)
        ttk.Label(details_frame, text="Website:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.display_website = ttk.Entry(details_frame, width=50, state='readonly')
        self.display_website.grid(row=0, column=1, padx=5, pady=2)
        ttk.Label(details_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.display_username = ttk.Entry(details_frame, width=50, state='readonly')
        self.display_username.grid(row=1, column=1, padx=5, pady=2)
        ttk.Label(details_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.display_password = ttk.Entry(details_frame, width=50, show='*', state='readonly')
        self.display_password.grid(row=2, column=1, padx=5, pady=2)

        details_buttons_frame = ttk.Frame(details_frame)
        details_buttons_frame.grid(row=3, column=0, columnspan=2, pady=5)
        ttk.Button(details_buttons_frame, text="👁️ Toggle Pass",
                   command=self._toggle_display_password_visibility, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(details_buttons_frame, text="📋 Copy Pass",
                   command=self._copy_display_password, width=15).pack(side=tk.LEFT, padx=5)
        self.edit_button = ttk.Button(details_buttons_frame, text="✏️ Edit Selected",
                                      command=self._edit_selected_password, width=15)
        self.edit_button.pack(side=tk.LEFT, padx=5)
        self.save_changes_button = ttk.Button(details_buttons_frame, text="💾 Save Changes",
                                             command=self._save_edited_password, width=15, state='disabled')
        self.save_changes_button.pack(side=tk.LEFT, padx=5)
        self.cancel_edit_button = ttk.Button(details_buttons_frame, text="↩️ Cancel Edit",
                                            command=self._cancel_edit, width=15, state='disabled')
        self.cancel_edit_button.pack(side=tk.LEFT, padx=5)

        action_buttons_frame = ttk.Frame(self)
        action_buttons_frame.pack(pady=5)
        ttk.Button(action_buttons_frame, text="➕ New Entry",
                   command=self._open_generation_chooser_for_new_entry, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_buttons_frame, text="🗑️ Delete Selected",
                   command=self._delete_selected_password, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_buttons_frame, text="🔄 Refresh List",
                   command=self._update_password_list, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_buttons_frame, text="📤 Export to CSV",
                   command=self.master_app.export_passwords_to_csv, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_buttons_frame, text="Main Menu",
                   command=self._go_to_main_menu, width=20).pack(side=tk.LEFT, padx=5)

    def _highlight_listbox_matches(self, query):
        query = query.lower()
        for i in range(self.password_list.size()):
            item_text = self.password_list.get(i).lower()
            if query in item_text:
                self.password_list.itemconfig(i, {'bg': '#d1e7dd'})
            else:
                self.password_list.itemconfig(i, {'bg': 'white'})

    def _filter_list(self, event=None):
        filter_text = self.search_entry.get().lower()
        self.password_list.delete(0, tk.END)
        for entry in self.sorted_passwords:
            self.password_list.insert(tk.END, entry["website"])
        if filter_text:
            self._highlight_listbox_matches(filter_text)
        else:
            for i in range(self.password_list.size()):
                self.password_list.itemconfig(i, {'bg': 'white'})
        self._clear_display_fields()

    def _update_password_list(self):
        self.password_list.delete(0, tk.END)
        all_passwords = self.master_app.load_all_passwords_from_file()
        self.sorted_passwords = sorted(all_passwords, key=lambda x: x['website'].lower())
        for entry in self.sorted_passwords:
            self.password_list.insert(tk.END, entry["website"])
        self.master_app._update_status(f"Loaded {len(self.sorted_passwords)} passwords in manager window.")
        self.search_entry.delete(0, tk.END)
        self._clear_display_fields()

    def _on_list_select(self, event):
        selected_indices = self.password_list.curselection()
        if not selected_indices:
            self._clear_display_fields()
            return
        index = selected_indices[0]
        selected_website_name = self.password_list.get(index)
        selected_entry = next((entry for entry in self.sorted_passwords if entry["website"] == selected_website_name), None)
        if selected_entry:
            self._set_display_fields(selected_entry["website"], selected_entry["username"], selected_entry["password"], readonly=True)
            self.master_app._update_status(f"Displaying entry for '{selected_entry['website']}'.")
            self.edit_button.config(state='normal')
            self.save_changes_button.config(state='disabled')
            self.cancel_edit_button.config(state='disabled')
            self.editing_website = None

    def _set_display_fields(self, website, username, password, readonly=True):
        state = 'readonly' if readonly else 'normal'
        show_char = '*' if readonly else ''
        self.display_website.config(state='normal')
        self.display_username.config(state='normal')
        self.display_password.config(state='normal')
        self.display_website.delete(0, tk.END)
        self.display_website.insert(0, website)
        self.display_username.delete(0, tk.END)
        self.display_username.insert(0, username)
        self.display_password.delete(0, tk.END)
        self.display_password.insert(0, password)
        self.display_website.config(state=state)
        self.display_username.config(state=state)
        self.display_password.config(state=state, show=show_char)

    def _clear_display_fields(self):
        self._set_display_fields("", "", "", readonly=True)
        self.edit_button.config(state='disabled')
        self.save_changes_button.config(state='disabled')
        self.cancel_edit_button.config(state='disabled')
        self.editing_website = None

    def _toggle_display_password_visibility(self):
        if self.display_password.cget('show') == '*':
            self.display_password.config(show='')
            self.master_app._update_status("Display password visibility ON.")
        else:
            self.display_password.config(show='*')
            self.master_app._update_status("Display password visibility OFF.")

    def _copy_display_password(self):
        password = self.display_password.get()
        if password:
            try:
                self.clipboard_clear()
                self.clipboard_append(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!", parent=self)
                self.master_app._schedule_clipboard_clear()
            except tk.TclError as e:
                messagebox.showerror("Clipboard Error", f"Failed to copy to clipboard: {e}", parent=self)
                self.master_app._update_status(f"Failed to copy password: {e}")
        else:
            messagebox.showwarning("Empty", "No password selected to copy.", parent=self)
            self.master_app._update_status("No password to copy from display.")

    def _edit_selected_password(self):
        selected_indices = self.password_list.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select a website to edit.", parent=self)
            return
        index = selected_indices[0]
        selected_website_name = self.password_list.get(index)
        selected_entry = next((entry for entry in self.sorted_passwords if entry["website"] == selected_website_name), None)
        if selected_entry:
            self._set_display_fields(selected_entry["website"], selected_entry["username"], selected_entry["password"], readonly=False)
            self.editing_website = selected_entry["website"]
            self.save_changes_button.config(state='normal')
            self.cancel_edit_button.config(state='normal')
            self.edit_button.config(state='disabled')
            self.master_app._update_status(f"Editing entry for '{selected_website_name}'.")

    def _save_edited_password(self):
        if self.editing_website is None:
            messagebox.showwarning("No Edit in Progress", "No entry is currently being edited.", parent=self)
            return
        new_website = self.display_website.get().strip()
        new_username = self.display_username.get().strip()
        new_password = self.display_password.get().strip()
        if not (new_website and new_username and new_password):
            messagebox.showwarning("Missing Info", "Please fill all fields.", parent=self)
            return
        if new_website != self.editing_website:
            for entry in self.sorted_passwords:
                if entry["website"] == new_website and entry["website"] != self.editing_website:
                    messagebox.showwarning(
                        "Duplicate Website",
                        f"An entry for '{new_website}' already exists. Please choose a different website name.",
                        parent=self
                    )
                    return
        if self.master_app.save_password_entry_to_file(new_website, new_username, new_password, original_website=self.editing_website):
            self._update_password_list()
            self._clear_display_fields()

    def _cancel_edit(self):
        if messagebox.askyesno("Confirm Cancel", "Are you sure you want to cancel editing? Changes will be lost.", parent=self):
            messagebox.showinfo("Edit Cancelled", "Changes were not saved.", parent=self)
            self._update_password_list()
            self._clear_display_fields()

    def _delete_selected_password(self):
        selected_indices = self.password_list.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select a website to delete.", parent=self)
            return
        index_to_delete = selected_indices[0]
        website_to_delete = self.password_list.get(index_to_delete)
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{website_to_delete}'?", parent=self):
            return
        if self.master_app.delete_password_entry_from_file(website_to_delete):
            self._update_password_list()
            self._clear_display_fields()

    def _open_generation_chooser_for_new_entry(self):
        self.master_app._open_generation_chooser_from_main(source_window=self, from_new_entry=True)

    def _go_to_main_menu(self):
        self.destroy()
        self.master_app.deiconify()

def main():
    """Run the password manager application."""
    app = PasswordManagerApp()
    app.mainloop()

if __name__ == "__main__":
    main()