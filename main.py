import json
from tkinter import *
from tkinter import messagebox
from encryption import Encryptor
import os

STORAGE_FILE = "storage.json"

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.master_password = "test"
        self.encryptor = None
        self.setup_ui()

    def setup_ui(self):
        Label(self.root, text="Master Password:").pack(pady=5)
        self.master_password_entry = Entry(self.root, show="*", width=30)
        self.master_password_entry.pack(pady=5)
        Button(self.root, text="Unlock", command=self.unlock).pack(pady=5)

    def unlock(self):
        master_password = self.master_password_entry.get()
        if not master_password:
            messagebox.showerror("Error", "Master password cannot be empty.")
            return

        self.encryptor = Encryptor(master_password)
        self.master_password = master_password

        if not os.path.exists(STORAGE_FILE):
            with open(STORAGE_FILE, "w") as f:
                json.dump({}, f)

        self.root.destroy()
        self.main_window()

    def main_window(self):
        main_window = Tk()
        main_window.title("Password Manager")

        Label(main_window, text="Account Name:").pack(pady=5)
        self.account_entry = Entry(main_window, width=30)
        self.account_entry.pack(pady=5)

        Label(main_window, text="Password:").pack(pady=5)
        self.password_entry = Entry(main_window, width=30)
        self.password_entry.pack(pady=5)

        Button(main_window, text="Save", command=self.save_password).pack(pady=5)
        Button(main_window, text="View Saved Passwords", command=self.view_passwords).pack(pady=5)

    def save_password(self):
        account = self.account_entry.get()
        password = self.password_entry.get()

        if not account or not password:
            messagebox.showerror("Error", "Account or password cannot be empty.")
            return

        encrypted_password = self.encryptor.encrypt(password)

        with open(STORAGE_FILE, "r+") as f:
            data = json.load(f)
            data[account] = encrypted_password
            f.seek(0)
            json.dump(data, f)

        self.account_entry.delete(0, END)
        self.password_entry.delete(0, END)
        messagebox.showinfo("Success", "Password saved successfully!")

    def view_passwords(self):
        with open(STORAGE_FILE, "r") as f:
            data = json.load(f)

        view_window = Toplevel()
        view_window.title("Saved Passwords")

        for account, encrypted_password in data.items():
            try:
                decrypted_password = self.encryptor.decrypt(encrypted_password)
                Label(view_window, text=f"{account}: {decrypted_password}").pack()
            except Exception:
                Label(view_window, text=f"{account}: [Decryption Failed]").pack()


if __name__ == "__main__":
    root = Tk()
    app = PasswordManager(root)
    root.mainloop()
