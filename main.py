import json
from tkinter import *
from tkinter import messagebox
from encryption import Encryptor
import os

STORAGE_FILE = "storage.json"

class PasswordManager:
    def __init__(self, root):
        """
        Initialize the Password Manager application.
        Sets up the main window for entering the master password.
        """
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("400x200")  # Set initial size of the main window
        self.master_password = "test"  # Default master password for demonstration
        self.encryptor = None  # Will hold the Encryptor instance after unlocking
        self.setup_ui()

    def setup_ui(self):
        """
        Set up the user interface for the master password entry screen.
        Includes a label, an entry field for the master password, and an unlock button.
        """
        Label(self.root, text="Master Password:").pack(pady=10)
        self.master_password_entry = Entry(self.root, show="*", width=30)
        self.master_password_entry.pack(pady=10)
        Button(self.root, text="Unlock", command=self.unlock).pack(pady=10)

    def unlock(self):
        """
        Handle the unlocking of the application by verifying the master password.
        If valid, it initializes the Encryptor and switches to the main window.
        """
        master_password = self.master_password_entry.get()
        if not master_password:
            messagebox.showerror("Error", "Master password cannot be empty.")
            return

        # Create an Encryptor instance with the master password
        self.encryptor = Encryptor(master_password)
        self.master_password = master_password

        # Create storage file if it doesn't exist
        if not os.path.exists(STORAGE_FILE):
            with open(STORAGE_FILE, "w") as f:
                json.dump({}, f)

        self.root.destroy()  # Close the master password window
        self.main_window()  # Open the main application window

    def main_window(self):
        """
        Set up the main window where users can save and view passwords.
        Includes input fields for application, account, and password, and buttons to save or view data.
        """
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
        """
        Save the entered password data for an application.
        Encrypts the password before saving it to the storage file.
        """
        application = self.application_entry.get()
        account = self.account_entry.get()
        password = self.password_entry.get()

        # Ensure all fields are filled
        if not application or not account or not password:
            messagebox.showerror("Error", "Application, account, or password cannot be empty.")
            return

        # Encrypt the password
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

        # Clear the input fields after saving
        self.application_entry.delete(0, END)
        self.account_entry.delete(0, END)
        self.password_entry.delete(0, END)
        messagebox.showinfo("Success", "Password saved successfully!")

    def view_passwords(self):
        """
        Display all saved passwords in a new window.
        Decrypts each password before displaying it, and handles decryption errors gracefully.
        """
        with open(STORAGE_FILE, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                messagebox.showerror("Error", "No saved passwords found.")
                return

        # Create a new window for displaying saved passwords
        view_window = Toplevel()
        view_window.title("Saved Passwords")
        view_window.geometry("500x400")

        for application, entries in data.items():
            # Display the application name
            Label(view_window, text=f"Application: {application}", font=("Arial", 12, "bold")).pack(pady=10)
            for entry in entries:
                if isinstance(entry, dict):  # Ensure entry is a dictionary
                    try:
                        # Decrypt the password and display it with the account
                        decrypted_password = self.encryptor.decrypt(entry["password"])
                        account = entry["account"]
                        Label(view_window, text=f"  Account: {account}, Password: {decrypted_password}", font=("Arial", 10)).pack(anchor="w", padx=20)
                    except Exception:
                        # Handle decryption errors
                        Label(view_window, text=f"  Account: {entry.get('account', 'Unknown')}, Password: [Decryption Failed]", font=("Arial", 10)).pack(anchor="w", padx=20)

# Main entry point
if __name__ == "__main__":
    root = Tk()  # Create the root window
    app = PasswordManager(root)  # Initialize the Password Manager application
    root.mainloop()  # Start the Tkinter event loop
