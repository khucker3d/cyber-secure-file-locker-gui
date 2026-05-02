# Secure File Locker GUI

## About
Secure File Locker is a cross-platform desktop application built with Python and Tkinter that allows users to encrypt and decrypt files locally using password-based encryption.

The tool uses strong cryptographic standards, including AES encryption and PBKDF2 key derivation, to protect file contents. It is designed as a lightweight, user-friendly utility for securely locking files without relying on external services or cloud storage.

### Key Capabilities

- File encryption and decryption
- Password-protected access
- Password hint system
- Failed attempt tracking with lockout protection
- Password change functionality
- Safe unlock (copy) and permanent unlock (remove lock)

The application runs on both Windows and macOS.

---

## Limitations
This tool is designed for local security and usability, but it has important limitations:
- Password recovery is not possible. If the password is lost, the file cannot be decrypted.
- Failed attempt tracking is stored locally and can be bypassed if the file is copied or restored.
- Large files are fully loaded into memory, which may impact performance for very large files.
- No hardware-backed security such as TPM or secure enclaves.
- No multi-user or access control system.
- No cloud sync or backup functionality.
- Not resistant to advanced forensic or state-level attacks.

This tool is best suited for personal use, local protection, and portfolio demonstration.

---

## Install Dependencies:
  - Encryption library:```pip install cryptography```
  - Drag and drop support:```pip install tkinterdnd2```

## Run the Python script:
- Run the Application: ```python secure_file_locker_gui.py```

## How to Use
### Lock a File:
  - Select a file using the Browse button *(or use the drag and drop feature)*
  - Enter a password
  - Confirm the password
  - Optional: enter a password hint
  - Optional: enable delete original file
  - Click Lock File

Result: A ```.locked``` file is created
*Note: It's safe to delete the original file*

### Unlock a File (Safe Copy):
1. Select a .locked file
2. Enter the password
3. Click Unlock File
Result: A decrypted copy is created and the ```.locked``` file remains unchanged

### Remove Lock (Permanent Unlock)
1. Select a .locked file
2. Enter the password
3. Enable Remove lock after successful unlock
4. Optionally enable overwrite existing file
5. Click Unlock File
Result: Original file is restored & .locked file is deleted

### Change Password
1. Select a .locked file
2. Enter current password
3. Enter new password
4. Confirm new password
5. Optionally update hint
6. Click Change Password

### Failed Attempts
- After the first failed attempt, the password hint is shown
- After 10 failed attempts, the file is locked from further attempts


## Best Practices
Security: 
- Use strong passwords with at least 12 to 16 characters
- Include uppercase, lowercase, numbers, and symbols
- Store passwords in a password manager
- Do not rely on password hints for sensitive information

File Handling:
- Keep backups of important files before locking
- Test unlocking before deleting originals
- Avoid overwriting files unless necessary

Usage:
- Use safe unlock (copy) for testing
- Use remove lock only when confident
- Be cautious when enabling delete original file

Development:
- Use virtual environments for dependency management
- Avoid modifying encrypted files manually
- Validate inputs before encryption and decryption
- Keep dependencies updated
