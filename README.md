# CyberLock

CyberLock is a pure frontend secure password manager built with **HTML, CSS, and JavaScript**.

## Features

- Create, save, edit, and delete password entries
- Each entry includes website, username, and password
- Password generator with customizable options:
  - length
  - uppercase
  - numbers
  - symbols
- Password strength meter (weak/medium/strong with color indicators)
- Search/filter across saved entries
- Copy-to-clipboard for saved passwords
- Show/hide toggles for password fields
- Master password login/unlock screen
- Encrypted local storage (no plaintext passwords)

## Run

No backend is required.

1. Open `/home/runner/work/CyberLock/CyberLock/index.html` in a modern browser.
2. Create a master password on first launch.
3. Unlock with the same master password on later launches.

## File Structure

- `/home/runner/work/CyberLock/CyberLock/index.html`
- `/home/runner/work/CyberLock/CyberLock/styles.css`
- `/home/runner/work/CyberLock/CyberLock/script.js`

## Encryption (brief)

CyberLock hashes the master password with **SHA-256**, then uses the hash as input to **PBKDF2** (with salt + high iterations) to derive an **AES-GCM** encryption key via the Web Crypto API. Vault data is encrypted before being written to `localStorage`, so even if storage is accessed directly, saved passwords remain encrypted ciphertext and cannot be read without the correct master password.
