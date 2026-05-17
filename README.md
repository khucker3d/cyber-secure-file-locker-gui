# My Secure File Locker GUI
Author: Kellie Hucker

## About
Secure File Locker is a cross-platform desktop application built with Python and Tkinter that allows users to encrypt and decrypt files locally using password-based encryption. The tool uses strong cryptographic standards, including AES encryption and PBKDF2 key derivation, to protect file contents. It is designed as a lightweight, user-friendly utility for securely locking files without relying on external services or cloud storage.

<img width="830" height="1005" alt="Screenshot 2026-05-14 at 11 48 38" src="https://github.com/user-attachments/assets/d0cdf1b5-9cd7-47bb-bbf1-19a7c2d05d06" />

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

## Key Capabilities
This tool is best suited for personal use, local protection, and portfolio demonstration.
* File encryption and decryption
* Password-protected access
* Password hint system
* Failed attempt tracking with lockout protection
* Password change functionality
* Safe unlock (copy) and permanent unlock (remove lock)
* Runs on both Windows and macOS

## [How To Use:](https://github.com/khucker3d/secure-file-locker-gui/blob/main/docs/Secure%20File%20Locker%20GUI.md)

### Limitations
* This tool is designed for local security and usability, but it has important limitations:
* Password recovery is not possible. If the password is lost, the file cannot be decrypted.
* Failed attempt tracking is stored locally and can be bypassed if the file is copied or restored.
* Large files are fully loaded into memory, which may impact performance for very large files.
* No hardware-backed security such as TPM or secure enclaves.
* No multi-user or access control system.
* No cloud sync or backup functionality.
* Not resistant to advanced forensic or state-level attacks.

## License
MIT License
