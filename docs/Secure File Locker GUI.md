# How To Use: Secure File Locker
<img width="830" height="1005" alt="Screenshot 2026-05-14 at 11 48 38" src="https://github.com/user-attachments/assets/bf1e2007-5b1e-4279-b432-acc25cbe75c5" />

## Setup
1. Install Dependencies:
  * Encryption library:```pip install cryptography```
  * Drag and drop support:```pip install tkinterdnd2```
2. Run the Python script:```python secure_file_locker_gui.py```

     *Note: I used IDLE to create and run the script*

## How to Lock a File
1. Select a file using the Browse button *or use the drag and drop option*
3. Enter your file's lock password
4. Confirm the password
6. (Optional) Enter a password hint
7. (Optional) Enable Delete original file after locking
9. Click Lock File
Result: A ```.locked``` file is created

## How to Unlock a File (Temp Unlock)
1. Select ```.locked``` file
2. Enter the password
3. Click Unlock File
Result: A decrypted copy is created, and the ```.locked``` file remains unchanged

### Remove Lock (Permanent Unlock)
1. Select ```.locked``` file
2. Enter the password
3. Enable the " Remove lock after successful unlock option
4. Enable overwrite existing file
5. Click Unlock File
Result: Original file is restored & ```.locked``` file is deleted

### Change Password
1. Select ```.locked```  file
2. Enter current password
3. Enter new password
4. Confirm new password
5. Optionally update hint
6. Click Change Password

### Failed Attempts
* After the first failed attempt, the password hint is shown
* After 10 failed attempts, the file is locked from further attempts

## Best Practices
### Security: 
* Use strong passwords with at least 12 to 16 characters
* Include uppercase, lowercase, numbers, and symbols
* Store passwords in a password manager
* Do not rely on password hints for sensitive information

### File Handling:
* Keep backups of important files before locking
* Test unlocking before deleting originals
* Avoid overwriting files unless necessary

### Usage:
* Use safe unlock (copy) for testing
* Use the remove lock only when confident
* Be cautious when enabling the deletion of the original file
