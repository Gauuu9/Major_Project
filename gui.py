# gui.py

import tkinter as tk
from tkinter import ttk, messagebox
from audio_utils import get_voice_features
from crypto_utils import generate_key, encrypt_and_store_key, encrypt_text, load_key, decrypt_text

class CryptographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Cryptography App")
        self.root.geometry("850x550")
        self.root.configure(bg="#f8f9fa")

        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure("TButton",
                        background="#0d6efd",
                        foreground="white",
                        font=("Segoe UI", 10),
                        padding=8)
        style.map("TButton",
                  background=[('active', '#5fa5ff')])

    def create_widgets(self):
        header = tk.Label(self.root, text="Text Encryption Tool",
                          bg="#f8f9fa", fg="#212529", font=("Segoe UI", 20, "bold"))
        header.pack(pady=20)

        self.text_box = tk.Text(self.root, width=80, height=12,
                                font=("Segoe UI", 12), bg="#ffffff", fg="#212529", insertbackground="black", bd=1, relief=tk.SOLID)
        self.text_box.pack(pady=10, padx=20)

        frame = ttk.Frame(self.root)
        frame.pack(pady=20)

        encrypt_button = ttk.Button(frame, text="🔐 Encrypt", command=self.handle_encrypt)
        encrypt_button.grid(row=0, column=0, padx=15)

        decrypt_button = ttk.Button(frame, text="🔓 Decrypt", command=self.handle_decrypt)
        decrypt_button.grid(row=0, column=1, padx=15)

        clear_button = ttk.Button(frame, text="🧹 Clear", command=self.clear_text)
        clear_button.grid(row=0, column=2, padx=15)

    def clear_text(self):
        self.text_box.delete(1.0, tk.END)

    def handle_encrypt(self):
        secret = self.text_box.get(1.0, tk.END).strip()
        if not secret:
            messagebox.showwarning("Warning", "No text to encrypt!")
            return

        voice_features = get_voice_features()
        key, _ = generate_key(voice_features)
        encrypted_text = encrypt_text(secret, key)

        self.text_box.delete(1.0, tk.END)
        self.text_box.insert(tk.END, encrypted_text)

        encrypt_and_store_key(key)
        messagebox.showinfo("Success", "Encryption Complete!")

    def handle_decrypt(self):
        encrypted = self.text_box.get(1.0, tk.END).strip()
        if not encrypted:
            messagebox.showwarning("Warning", "No text to decrypt!")
            return
        try:
            key = load_key()
            decrypted = decrypt_text(encrypted, key)
            self.text_box.delete(1.0, tk.END)
            self.text_box.insert(tk.END, decrypted)
            messagebox.showinfo("Success", "Decryption Complete!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
