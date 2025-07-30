
# Cryptography App

A simple GUI-based text encryption and decryption tool using voice features for key generation.

## Features
- **AES-GCM Encryption**: Securely encrypts your text using AES-GCM.
- **Voice-based Key Generation**: Uses your voice features to help generate a unique encryption key.
- **Key Storage**: Encryption key is securely stored using Fernet symmetric encryption.
- **Easy-to-use GUI**: Encrypt and decrypt text with a single click.

## How It Works
1. **Encrypting Text**:
    - Enter your text in the text box.
    - Click the **Encrypt** button.
    - The app will prompt you to record your voice (for key generation).
    - The text is encrypted and displayed in the text box.
    - The encryption key is securely stored in `encryption_key.enc` and the Fernet key in `file_key.txt`.

2. **Decrypting Text**:
    - Paste the encrypted text in the text box.
    - Click the **Decrypt** button.
    - The app retrieves the stored keys and decrypts the text.

## File Structure
- `main.py`: Main entry point
- `gui.py`: Main GUI application
- `audio_utils.py`: Handles audio recording and feature extraction
- `crypto_utils.py`: Handles key generation, encryption, decryption, and key storage
- `encryption_key.enc`: Encrypted AES key (auto-generated)
- `file_key.txt`: Fernet key for decrypting the AES key (auto-generated)
- `requirements.txt`: Python dependencies

## Requirements
- Python 3.8+
- See `requirements.txt` for dependencies (PyCryptodome, cryptography, numpy, soundfile, pyaudio, etc.)

## Installation
1. Clone the repository:
   ```sh
   git clone <your-repo-url>
   cd <repo-folder>
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Run the app:
   ```sh
   python gui.py
   ```

## Security Notes
- The encryption key is protected using Fernet and stored locally. Do not share `encryption_key.enc` or `file_key.txt`.
- Voice features are used to enhance key uniqueness, but the system entropy and time are also included.

## License
MIT License

---

**Enjoy secure text encryption with your voice!**
