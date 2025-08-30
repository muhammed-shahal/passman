import base64
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .db import get_meta, set_meta

DEFAULT_KDF_ITERS = 200_000
BACKEND = default_backend()

def derive_key(master_password: str, salt: bytes, kdf_iters: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=kdf_iters,
        backend=BACKEND
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

def get_fernet(conn, master_password: str) -> Fernet:
    salt = get_meta(conn, "salt")
    if not salt:
        raise RuntimeError("Vault not initialized. Run: passman init")
    iters_raw = get_meta(conn, "kdf_iters")
    kdf_iters = int((iters_raw or str(DEFAULT_KDF_ITERS).encode()).decode())
    key = derive_key(master_password, salt, kdf_iters)
    return Fernet(key)

def set_verifier(conn, f: Fernet):
    token = f.encrypt(b"verify")
    set_meta(conn, "verifier", token)

def check_verifier(conn, f: Fernet) -> bool:
    token = get_meta(conn, "verifier")
    if not token:
        return False
    try:
        return f.decrypt(token) == b"verify"
    except InvalidToken:
        return False

def require_master_and_fernet(conn, ask_new: bool = False) -> Fernet:
    if ask_new:
        while True:
            pw1 = getpass("Create master password: ")
            pw2 = getpass("Confirm master password: ")
            if pw1 != pw2:
                print("Passwords do not match. Try again.\n")
                continue
            if len(pw1) < 8:
                print("Use at least 8 characters.\n")
                continue
            break
        f = get_fernet(conn, pw1)
        set_verifier(conn, f)
        print("Master password set.")
        return f
    else:
        pw = getpass("Master password: ")
        f = get_fernet(conn, pw)
        if not check_verifier(conn, f):
            raise SystemExit("Incorrect master password.")
        return f
