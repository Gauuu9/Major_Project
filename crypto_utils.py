# crypto_utils.py

import base64
import hashlib
import time
import uuid
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from tkinter import messagebox

def generate_key(voice_features=""):
    current_time = int(time.time()) + int(time.strftime('%Y%m%d'))
    system_entropy = int(hashlib.sha256(str(uuid.getnode()).encode()).hexdigest(), 16)
    jitter = secrets.randbits(32)
    salt = secrets.token_bytes(16)

    seed = current_time ^ system_entropy ^ jitter

    if voice_features:
        seed ^= int(hashlib.blake2b(voice_features.encode()).hexdigest(), 16)

    key = hashlib.pbkdf2_hmac('sha512', str(seed).encode(), salt, 100000, dklen=32)
    return key, salt

def encrypt_and_store_key(key):
    # Store the AES key as hex in file_key.txt
    with open("file_key.txt", "w") as file:
        file.write(key.hex())
    if hasattr(encrypt_and_store_key, 'last_ciphertext'):
        messagebox.showinfo("Ciphertext", f"Ciphertext:\n{encrypt_and_store_key.last_ciphertext}")
    else:
        messagebox.showinfo("Key Saved", "File key saved in 'file_key.txt'")

def encrypt_text(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    return encrypted


# --- Decryption Utilities ---
def load_key_from_filekey(file_key_value):
    """Load the AES key from user input (file_key_value as hex string)."""
    try:
        return bytes.fromhex(file_key_value)
    except Exception:
        return None

def decrypt_text(encrypted, key):
    """Decrypt a base64-encoded AES-GCM encrypted message."""
    raw = base64.b64decode(encrypted)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
