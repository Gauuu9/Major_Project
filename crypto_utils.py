# crypto_utils.py

import base64
import hashlib
import time
import uuid
import secrets
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from tkinter import messagebox

def get_quantum_random_number():
    try:
        response = requests.get("https://qrng.physik.hu-berlin.de/json/uint16", timeout=5)
        response.raise_for_status()
        data = response.json()
        if "data" in data and isinstance(data["data"], list):
            return data["data"][0]
        else:
            print("QRBGS API responded, but no valid data. Falling back to pseudo-random.")
            return secrets.randbits(32)
    except Exception as e:
        print(f"QRBGS failed, falling back to pseudo-random. Reason: {e}")
        return secrets.randbits(32)
  # Fallback to local randomness

def generate_key(voice_features=""):
    current_time = int(time.time()) + int(time.strftime('%Y%m%d'))
    system_entropy = int(hashlib.sha256(str(uuid.getnode()).encode()).hexdigest(), 16)
    quantum_entropy = get_quantum_random_number()
    salt = secrets.token_bytes(16)

    seed = current_time ^ system_entropy ^ quantum_entropy

    if voice_features:
        seed ^= int(hashlib.blake2b(voice_features.encode()).hexdigest(), 16)

    key = hashlib.pbkdf2_hmac('sha512', str(seed).encode(), salt, 100000, dklen=32)
    return key, salt

def encrypt_and_store_key(key):
    file_key = Fernet.generate_key()
    cipher = Fernet(file_key)

    encrypted_key = cipher.encrypt(key.hex().encode())

    with open("encryption_key.enc", "wb") as key_file:
        key_file.write(encrypted_key)

    with open("file_key.txt", "wb") as file:
        file.write(file_key)

    messagebox.showinfo("Key Saved", "Key saved in 'encryption_key.enc'\nFile key saved in 'file_key.txt'")

def encrypt_text(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    return encrypted

# --- Decryption Utilities ---
def load_key():
    """Load the Fernet key and decrypt the AES key from files."""
    with open("file_key.txt", "rb") as f:
        file_key = f.read()
    cipher = Fernet(file_key)
    with open("encryption_key.enc", "rb") as f:
        encrypted_key = f.read()
    key_hex = cipher.decrypt(encrypted_key)
    key = bytes.fromhex(key_hex.decode())
    return key

def decrypt_text(encrypted, key):
    """Decrypt a base64-encoded AES-GCM encrypted message."""
    raw = base64.b64decode(encrypted)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
