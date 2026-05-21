#!/usr/bin/env python3
"""
CipherLock - AES-256 File & Folder Encryption CLI
"""
 
import os
import sys
import struct
import tarfile
import shutil
import argparse
import tempfile
import getpass
from pathlib import Path
 
# ─── Banner ───────────────────────────────────────────────────────────────────
 
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
 
BANNER = f"""
{CYAN}{BOLD}
 ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ██╗      ██████╗  ██████╗██╗  ██╗
██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝
██║     ██║██████╔╝███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╔╝ 
██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ 
╚██████╗██║██║     ██║  ██║███████╗██║  ██║███████╗╚██████╔╝╚██████╗██║  ██╗
 ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
{RESET}{DIM}{GREEN}  ╔══════════════════════════════════════════════════════════════════════╗
  ║   AES-256  ·  PBKDF2-SHA256  ·  HMAC Integrity  ·  Zero Cloud       ║
  ╚══════════════════════════════════════════════════════════════════════╝{RESET}
{DIM}  CipherLock v1.0.0  —  Encrypt anything. Trust no one.{RESET}
"""
 
# ─── Crypto ───────────────────────────────────────────────────────────────────
 
MAGIC       = b"CLCK"          # File magic bytes
VERSION     = b"\x01"          # Format version
SALT_LEN    = 32               # 256-bit salt
HMAC_LEN    = 32               # 256-bit HMAC-SHA256
IV_LEN      = 16               # 128-bit AES IV
KEY_LEN     = 32               # 256-bit AES key
ITER_COUNT  = 480_000          # PBKDF2 iterations (OWASP 2024 recommendation)
CHUNK_SIZE  = 64 * 1024        # 64 KB streaming chunks
 
# Header layout: MAGIC(4) + VERSION(1) + IS_DIR(1) + SALT(32) + IV(16) + HMAC(32) = 86 bytes
HEADER_SIZE = 4 + 1 + 1 + SALT_LEN + IV_LEN + HMAC_LEN
 
 
def _import_crypto():
    """Lazy import with a user-friendly error if cryptography isn't installed."""
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        return PBKDF2HMAC, hashes, crypto_hmac, Cipher, algorithms, modes, default_backend
    except ImportError:
        _die("Missing dependency: run  pip install -r requirements.txt  first.")
 
 
def _derive_key(password: bytes, salt: bytes):
    PBKDF2HMAC, hashes, *_ = _import_crypto()
    from cryptography.hazmat.backends import default_backend
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITER_COUNT,
        backend=default_backend(),
    )
    return kdf.derive(password)
 
 
def _compute_hmac(key: bytes, data: bytes) -> bytes:
    _, hashes, crypto_hmac, *_ = _import_crypto()
    from cryptography.hazmat.backends import default_backend
    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()
 
 
def _aes_cipher(key: bytes, iv: bytes):
    _, _, _, Cipher, algorithms, modes, default_backend = _import_crypto()
    return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
 
 
def _pad(data: bytes) -> bytes:
    """PKCS#7 padding."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)
 
 
def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding mismatch.")
    return data[:-pad_len]
 
# ─── Helpers ──────────────────────────────────────────────────────────────────
 
def _die(msg: str):
    print(f"\n{RED}{BOLD}  ✖  {msg}{RESET}\n")
    sys.exit(1)
 
 
def _ok(msg: str):
    print(f"\n{GREEN}{BOLD}  ✔  {msg}{RESET}\n")
 
 
def _info(msg: str):
    print(f"{DIM}{CYAN}  ›  {msg}{RESET}")
 
 
def _warn(msg: str):
    print(f"{YELLOW}  ⚠  {msg}{RESET}")
 
 
def _get_password(confirm: bool = False) -> bytes:
    print()
    pwd = getpass.getpass(f"{CYAN}{BOLD}  🔑 Password: {RESET}")
    if not pwd:
        _die("Password cannot be empty.")
    if confirm:
        pwd2 = getpass.getpass(f"{CYAN}{BOLD}  🔑 Confirm : {RESET}")
        if pwd != pwd2:
            _die("Passwords do not match.")
    return pwd.encode()
 
# ─── Encrypt ─────────────────────────────────────────────────────────────────
 
def cmd_encrypt(input_path: str, output_path: str):
    src = Path(input_path).resolve()
    if not src.exists():
        _die(f"Input not found: {src}")
 
    out = Path(output_path)
    if not out.suffix:
        out = out.with_suffix(".vault")
    elif out.suffix != ".vault":
        out = Path(str(out) + ".vault")
 
    is_dir = src.is_dir()
 
    print(BANNER)
    _info(f"Source   : {src}")
    _info(f"Output   : {out}")
    _info(f"Type     : {'Directory (will be compressed)' if is_dir else 'File'}")
    _info(f"Cipher   : AES-256-CBC  +  PBKDF2-SHA256 ({ITER_COUNT:,} iterations)")
 
    password = _get_password(confirm=True)
 
    tmp_archive = None
    try:
        if is_dir:
            _info("Compressing directory …")
            tmp_fd, tmp_archive = tempfile.mkstemp(suffix=".tar.gz")
            os.close(tmp_fd)
            with tarfile.open(tmp_archive, "w:gz") as tar:
                tar.add(str(src), arcname=src.name)
            plaintext_path = tmp_archive
        else:
            plaintext_path = str(src)
 
        _info("Deriving encryption key …")
        salt = os.urandom(SALT_LEN)
        iv   = os.urandom(IV_LEN)
        key  = _derive_key(password, salt)
 
        _info("Encrypting …")
        cipher    = _aes_cipher(key, iv)
        encryptor = cipher.encryptor()
 
        with open(plaintext_path, "rb") as f:
            plaintext = f.read()
 
        padded    = _pad(plaintext)
        ciphertext = encryptor.update(padded) + encryptor.finalize()
 
        # HMAC covers: VERSION + IS_DIR + SALT + IV + ciphertext
        is_dir_byte = b"\x01" if is_dir else b"\x00"
        mac_data    = VERSION + is_dir_byte + salt + iv + ciphertext
        hmac_tag    = _compute_hmac(key, mac_data)
 
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            f.write(MAGIC)
            f.write(VERSION)
            f.write(is_dir_byte)
            f.write(salt)
            f.write(iv)
            f.write(hmac_tag)
            f.write(ciphertext)
 
        size_kb = out.stat().st_size / 1024
        _ok(f"Vault created → {out}  ({size_kb:.1f} KB)")
 
    except Exception as e:
        _die(f"Encryption failed: {e}")
    finally:
        if tmp_archive and os.path.exists(tmp_archive):
            os.remove(tmp_archive)
 
# ─── Decrypt ─────────────────────────────────────────────────────────────────
 
def cmd_decrypt(input_path: str, output_path: str):
    vault = Path(input_path).resolve()
    if not vault.exists():
        _die(f"Vault file not found: {vault}")
    if vault.suffix != ".vault":
        _warn("Input does not have a .vault extension — proceeding anyway.")
 
    dest = Path(output_path)
 
    print(BANNER)
    _info(f"Vault    : {vault}")
    _info(f"Destination: {dest}")
 
    password = _get_password(confirm=False)
 
    try:
        with open(vault, "rb") as f:
            raw = f.read()
 
        # Validate magic
        if raw[:4] != MAGIC:
            _die("Not a valid CipherLock vault (bad magic bytes).")
 
        version    = raw[4:5]
        is_dir     = raw[5:6] == b"\x01"
        salt       = raw[6 : 6 + SALT_LEN]
        iv         = raw[6 + SALT_LEN : 6 + SALT_LEN + IV_LEN]
        stored_mac = raw[6 + SALT_LEN + IV_LEN : 6 + SALT_LEN + IV_LEN + HMAC_LEN]
        ciphertext = raw[6 + SALT_LEN + IV_LEN + HMAC_LEN :]
 
        if len(ciphertext) == 0:
            _die("Vault is empty or corrupted.")
 
        _info("Deriving decryption key …")
        key = _derive_key(password, salt)
 
        # Verify HMAC before decrypting (encrypt-then-MAC)
        _info("Verifying integrity (HMAC-SHA256) …")
        is_dir_byte = b"\x01" if is_dir else b"\x00"
        mac_data    = version + is_dir_byte + salt + iv + ciphertext
        expected_mac = _compute_hmac(key, mac_data)
 
        # Constant-time comparison
        import hmac as stdlib_hmac
        if not stdlib_hmac.compare_digest(expected_mac, stored_mac):
            _die("Integrity check FAILED — wrong password or corrupted vault.")
 
        _info("Decrypting …")
        cipher    = _aes_cipher(key, iv)
        decryptor = cipher.decryptor()
        padded    = decryptor.update(ciphertext) + decryptor.finalize()
 
        try:
            plaintext = _unpad(padded)
        except ValueError:
            _die("Decryption padding error — vault may be corrupted.")
 
        dest.parent.mkdir(parents=True, exist_ok=True)
 
        if is_dir:
            _info("Decompressing directory …")
            tmp_fd, tmp_archive = tempfile.mkstemp(suffix=".tar.gz")
            try:
                os.close(tmp_fd)
                with open(tmp_archive, "wb") as f:
                    f.write(plaintext)
                dest.mkdir(parents=True, exist_ok=True)
                with tarfile.open(tmp_archive, "r:gz") as tar:
                    tar.extractall(path=str(dest))
            finally:
                if os.path.exists(tmp_archive):
                    os.remove(tmp_archive)
            _ok(f"Directory restored → {dest}/")
        else:
            with open(dest, "wb") as f:
                f.write(plaintext)
            _ok(f"File restored → {dest}")
 
    except SystemExit:
        raise
    except Exception as e:
        _die(f"Decryption failed: {e}")
 
# ─── CLI ─────────────────────────────────────────────────────────────────────
 
def main():
    parser = argparse.ArgumentParser(
        prog="cipherlock",
        description="CipherLock — AES-256 file & folder encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{DIM}
Examples:
  cipherlock encrypt -i secret.txt     -o secret.vault
  cipherlock encrypt -i ./project_dir  -o project.vault
  cipherlock decrypt -i secret.vault   -o secret_restored.txt
  cipherlock decrypt -i project.vault  -o ./restored/{RESET}
""",
    )
 
    sub = parser.add_subparsers(dest="command", metavar="<command>")
 
    enc = sub.add_parser("encrypt", help="Encrypt a file or folder → .vault")
    enc.add_argument("-i", "--input",  required=True, metavar="PATH", help="File or folder to encrypt")
    enc.add_argument("-o", "--output", required=True, metavar="FILE", help="Output .vault filename")
 
    dec = sub.add_parser("decrypt", help="Decrypt a .vault file")
    dec.add_argument("-i", "--input",  required=True, metavar="FILE", help="Path to .vault file")
    dec.add_argument("-o", "--output", required=True, metavar="PATH", help="Destination path")
 
    args = parser.parse_args()
 
    if args.command == "encrypt":
        cmd_encrypt(args.input, args.output)
    elif args.command == "decrypt":
        cmd_decrypt(args.input, args.output)
    else:
        print(BANNER)
        parser.print_help()
        print()
 
 
if __name__ == "__main__":
    main()