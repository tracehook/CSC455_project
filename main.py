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
        self.root.geometry("400x200")  # Set initial size of the main window
        self.master_password = "test"
        self.encryptor = None
        self.setup_ui()

    def setup_ui(self):
        Label(self.root, text="Master Password:").pack(pady=10)
        self.master_password_entry = Entry(self.root, show="*", width=30)
        self.master_password_entry.pack(pady=10)
        Button(self.root, text="Unlock", command=self.unlock).pack(pady=10)

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
        main_window.geometry("500x400")  # Set the window size

        # Labels and Entry Fields
        Label(main_window, text="Application:", font=("Arial", 12)).pack(pady=10)
        self.application_entry = Entry(main_window, width=40)
        self.application_entry.pack(pady=10)

        Label(main_window, text="Account Name:", font=("Arial", 12)).pack(pady=10)
        self.account_entry = Entry(main_window, width=40)
        self.account_entry.pack(pady=10)

        Label(main_window, text="Password:", font=("Arial", 12)).pack(pady=10)
        self.password_entry = Entry(main_window, width=40)
        self.password_entry.pack(pady=10)

        # Save Button
        Button(main_window, text="Save", command=self.save_password, width=20).pack(pady=10)

        # View Passwords Button
        Button(main_window, text="View Saved Passwords", command=self.view_passwords, width=20).pack(pady=10)


    def save_password(self):
        application = self.application_entry.get()
        account = self.account_entry.get()
        password = self.password_entry.get()

        if not application or not account or not password:
            messagebox.showerror("Error", "Application, account, or password cannot be empty.")
            return

        encrypted_password = self.encryptor.encrypt(password)

        # Load existing data or create a new structure
        with open(STORAGE_FILE, "r+") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}

            if application not in data:
                data[application] = []

            # Append the account-password pair as a dictionary
            data[application].append({
                "account": account,
                "password": encrypted_password
            })

            f.seek(0)
            json.dump(data, f)
            f.truncate()

        # Clear the input fields
        self.application_entry.delete(0, END)
        self.account_entry.delete(0, END)
        self.password_entry.delete(0, END)
        messagebox.showinfo("Success", "Password saved successfully!")

    def view_passwords(self):
        with open(STORAGE_FILE, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                messagebox.showerror("Error", "No saved passwords found.")
                return

        view_window = Toplevel()
        view_window.title("Saved Passwords")
        view_window.geometry("500x400")

        for application, entries in data.items():
            Label(view_window, text=f"Application: {application}", font=("Arial", 12, "bold")).pack(pady=10)
            for entry in entries:
                if isinstance(entry, dict):  # Ensure entry is a dictionary
                    try:
                        decrypted_password = self.encryptor.decrypt(entry["password"])
                        account = entry["account"]
                        Label(view_window, text=f"  Account: {account}, Password: {decrypted_password}", font=("Arial", 10)).pack(anchor="w", padx=20)
                    except Exception:
                        Label(view_window, text=f"  Account: {entry.get('account', 'Unknown')}, Password: [Decryption Failed]", font=("Arial", 10)).pack(anchor="w", padx=20)


if __name__ == "__main__":
    root = Tk()
    app = PasswordManager(root)
    root.mainloop()
