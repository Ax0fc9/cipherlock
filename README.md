🔐 CipherLock

AES-256 File & Folder Encryption. Local. Zero Cloud. Zero Trust.

 ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ██╗      ██████╗  ██████╗██╗  ██╗
██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝
██║     ██║██████╔╝███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╔╝ 
██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ 
╚██████╗██║██║     ██║  ██║███████╗██║  ██║███████╗╚██████╔╝╚██████╗██║  ██╗
 ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
CipherLock is a professional-grade command-line encryption tool that lets you lock any file or entire folder behind military-grade AES-256 encryption — derived from your password, stored nowhere, known only to you.

✨ Features
FeatureDetailsAES-256-CBC EncryptionIndustry-standard symmetric encryptionPBKDF2-SHA256 Key Derivation480,000 iterations (OWASP 2024 standard)Random 256-bit SaltUnique per encryption — rainbow tables are uselessHMAC-SHA256 IntegrityDetects tampering or corruption before decryptionFolder EncryptionEntire directories are compressed then sealed into one .vault fileMasked Password InputYour password is never echoed to the terminalZero Cloud100% local. No keys leave your machine. No servers.Streaming-safe DesignHandles large files efficiently in chunksClean Cyberpunk UIBeautiful ASCII banner and color-coded terminal outputComprehensive Error HandlingWrong password, corrupted vaults, and missing files handled gracefully

🛡️ Security Specifications
Encryption

Algorithm: AES-256-CBC (256-bit key, 128-bit IV)
Key Derivation: PBKDF2-HMAC-SHA256
Iterations: 480,000 (aligns with OWASP 2024 minimum for SHA-256)
Salt: 256-bit (32 bytes), cryptographically random, unique per vault
IV: 128-bit (16 bytes), cryptographically random, unique per vault
Padding: PKCS#7

Integrity

MAC Algorithm: HMAC-SHA256
MAC Scope: Covers VERSION + IS_DIR_FLAG + SALT + IV + CIPHERTEXT (Encrypt-then-MAC)
Comparison: Constant-time (hmac.compare_digest) to prevent timing attacks

Vault File Format
┌─────────────────────────────────────────────────┐
│  MAGIC       4 bytes   "CLCK"                   │
│  VERSION     1 byte    0x01                     │
│  IS_DIR      1 byte    0x00 = file, 0x01 = dir  │
│  SALT        32 bytes  random PBKDF2 salt        │
│  IV          16 bytes  random AES IV             │
│  HMAC        32 bytes  HMAC-SHA256 tag           │
│  CIPHERTEXT  N bytes   AES-256-CBC payload       │
└─────────────────────────────────────────────────┘
Cryptography Library
CipherLock uses the cryptography Python package (by the Python Cryptographic Authority), which wraps OpenSSL under the hood — the same battle-tested engine used by banks and governments worldwide.
What CipherLock Does NOT Do

Store your password anywhere
Send any data to any server
Use weak or deprecated algorithms (no MD5, no DES, no ECB mode)
Leak stack traces on failure


📦 Installation
Requirements

Python 3.8 or higher
pip

Steps
bash# 1. Clone or download CipherLock
git clone https://github.com/yourname/cipherlock
cd cipherlock

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Make globally accessible
chmod +x cipherlock.py
sudo ln -s $(pwd)/cipherlock.py /usr/local/bin/cipherlock

🚀 Usage
Encrypt a File
bashpython cipherlock.py encrypt -i secret.txt -o secret.vault
  ›  Source   : /home/user/secret.txt
  ›  Output   : secret.vault
  ›  Type     : File
  ›  Cipher   : AES-256-CBC  +  PBKDF2-SHA256 (480,000 iterations)

  🔑 Password:
  🔑 Confirm :

  ›  Deriving encryption key …
  ›  Encrypting …

  ✔  Vault created → secret.vault  (2.1 KB)
Encrypt a Folder
bashpython cipherlock.py encrypt -i ./my_project/ -o my_project.vault
CipherLock automatically compresses the entire folder structure (preserving all subfolders and files) into a .tar.gz archive, then encrypts it as a single .vault file.
Decrypt a File
bashpython cipherlock.py decrypt -i secret.vault -o secret_restored.txt
Decrypt a Folder
bashpython cipherlock.py decrypt -i my_project.vault -o ./restored/
The original directory structure is fully restored inside the destination path.

🧪 Example Workflow
bash# Lock a sensitive folder before uploading to an untrusted location
python cipherlock.py encrypt -i ./client_contracts/ -o contracts_2024.vault

# Move/send the .vault file anywhere safely
cp contracts_2024.vault /media/usb_drive/

# Restore on another machine (with CipherLock + correct password)
python cipherlock.py decrypt -i contracts_2024.vault -o ./contracts_restored/

⚠️ Error Handling
ScenarioCipherLock's ResponseWrong password✖ Integrity check FAILED — wrong password or corrupted vault.Missing input file✖ Input not found: /path/to/fileCorrupted vault✖ Not a valid CipherLock vault (bad magic bytes).Empty password✖ Password cannot be empty.Mismatched confirmation✖ Passwords do not match.Padding error (corruption)✖ Decryption padding error — vault may be corrupted.
No Python tracebacks are ever shown to the user.

📋 Requirements
cryptography>=42.0.0
All other dependencies (os, sys, getpass, tarfile, struct, tempfile, hmac) are Python standard library modules.

🗂️ File Structure
cipherlock/
├── cipherlock.py      # Main CLI tool
├── requirements.txt   # Python dependencies
└── README.md          # This file

🔒 Security Best Practices

Use a strong password — at least 16 characters with mixed case, numbers, and symbols
Never share your password through the same channel as the vault file
Back up your password — if lost, the vault is mathematically unrecoverable
Verify the vault after creation by decrypting to a temp location
Delete originals securely using shred (Linux) or Secure Empty Trash (macOS) after encryption


📜 License
MIT License — free for personal and commercial use.

👤 Author
Built with ❤️ and paranoia by a developer who actually reads RFCs.

"Encryption is not about hiding something wrong. It's about protecting something right."