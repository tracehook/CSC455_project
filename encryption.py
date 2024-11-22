from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import base64

class Encryptor:
    """
    Handles encryption and decryption of data using AES encryption.
    The encryption key is derived from a master password.
    """

    def __init__(self, master_password):
        """
        Initializes the Encryptor with a key derived from the master password.

        Args:
            master_password (str): The master password provided by the user.
        """
        # Use SHA-256 to derive a 32-byte key from the master password
        self.key = sha256(master_password.encode()).digest()

    def encrypt(self, plaintext):
        """
        Encrypts a plaintext string using AES encryption in CBC mode.

        Args:
            plaintext (str): The data to be encrypted.

        Returns:
            str: Base64-encoded encrypted data (IV + ciphertext).
        """
        # Create a new AES cipher object in CBC mode with a random IV
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv  # Initialization vector
        # Pad the plaintext to ensure it is a multiple of AES block size
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        # Combine the IV and ciphertext, then encode it as Base64
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, encrypted_text):
        """
        Decrypts an encrypted string back to plaintext.

        Args:
            encrypted_text (str): Base64-encoded encrypted data (IV + ciphertext).

        Returns:
            str: The decrypted plaintext string.
        """
        # Decode the Base64-encoded data
        encrypted_data = base64.b64decode(encrypted_text)
        # Extract the IV (first 16 bytes) and the ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        # Create a new AES cipher object in CBC mode with the extracted IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # Decrypt the ciphertext and remove padding
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
