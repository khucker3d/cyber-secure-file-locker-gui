# Secure File Locker GUI

A cross-platform Python desktop application for securely encrypting and decrypting files using password-based encryption.

---

## Features

* AES-256 encryption (AES-GCM)
* Password-based key derivation (PBKDF2)
* File integrity protection (HMAC)
* Drag and drop file support
* Password hint system
* Failed attempt tracking with lockout
* Safe unlock (copy) and permanent unlock (remove lock)
* Change password for encrypted files
* Cross-platform (Windows and macOS)

---

## Screenshots

*Add screenshots here*

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/secure-file-locker-gui.git
cd secure-file-locker-gui
```

### 2. Create virtual environment

```bash
python -m venv venv
```

Activate:

Mac:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Run the App

```bash
python secure_file_locker_gui.py
```

---

## How It Works

1. Select a file
2. Enter a password
3. Encrypt or decrypt locally
4. No data ever leaves your machine

---

## Security Notes

* Passwords are never stored
* Encryption uses AES-GCM (authenticated encryption)
* PBKDF2 with 600,000 iterations protects against brute-force attacks
* File integrity is verified before decryption

---

## Limitations

* No password recovery
* Large files are loaded into memory
* Lockout mechanism is local and not tamper-proof

---

## Documentation

See the `/docs` folder for:

* Detailed usage guide
* Code breakdown
* Technical design

---

## License

MIT License
