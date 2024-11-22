from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import base64

class Encryptor:
    def __init__(self, master_password):
        self.key = sha256(master_password.encode()).digest()

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, encrypted_text):
        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
