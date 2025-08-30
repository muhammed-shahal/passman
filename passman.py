#!/usr/bin/env python3
"""
passman.py — A simple, secure CLI password manager using:
- Python 3.10+
- SQLite for storage
- cryptography (Fernet) for symmetric encryption with master password (PBKDF2)
- Argparse CLI with subcommands
Features:
    init, generate, strength-check, add, list, retrieve, update, delete
Usage examples:
    python passman.py init --db ./vault.db
    python passman.py generate --length 20 --digits --symbols
    python passman.py add --site gmail --username musthafa --gen --length 18 --digits --symbols
    python passman.py list
    python passman.py retrieve --site gmail --username musthafa
    python passman.py update --site gmail --username musthafa --gen
    python passman.py delete --site gmail --username musthafa
"""

import os
import sys
import sqlite3
import base64
import argparse
import re
import secrets
import string
from datetime import datetime
from getpass import getpass
from typing import Optional, Tuple

# --- Encryption (Fernet + PBKDF2) ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.fernet import Fernet, InvalidToken  # type: ignore

DEFAULT_DB = os.path.expanduser("~/.passman/vault.db")
DEFAULT_KDF_ITERS = 200_000  # reasonable default
BACKEND = default_backend()


def resolve_db_path(cli_path: Optional[str]) -> str:
    # Priority: CLI arg > env var > default
    if cli_path:
        return cli_path
    env = os.getenv("PASSMAN_DB")
    return env if env else DEFAULT_DB

def ensure_dir_for(path: str):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def connect(db_path: str) -> sqlite3.Connection:
    ensure_dir_for(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(conn: sqlite3.Connection, kdf_iters: int):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value BLOB
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL COLLATE NOCASE,
            username TEXT COLLATE NOCASE,
            password BLOB NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(site, username)
        );
    """)
    # If salt not set, set it; also store kdf_iters and a verifier
    cur.execute("SELECT value FROM meta WHERE key='salt';")
    row = cur.fetchone()
    if row is None:
        salt = os.urandom(16)
        cur.execute("INSERT INTO meta(key, value) VALUES('salt', ?);", (salt,))
        cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('kdf_iters', ?);", (str(kdf_iters).encode(),))
        # create empty verifier placeholder; will be set after master password provided
        cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('verifier', ?);", (b'',))
        conn.commit()

def get_meta(conn: sqlite3.Connection, key: str) -> Optional[bytes]:
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key=?;", (key,))
    r = cur.fetchone()
    return r[0] if r else None

def set_meta(conn: sqlite3.Connection, key: str, value: bytes):
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?);", (key, value))
    conn.commit()

def derive_key(master_password: str, salt: bytes, kdf_iters: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=kdf_iters,
        backend=BACKEND
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)  # Fernet expects base64-encoded bytes

def get_fernet(conn: sqlite3.Connection, master_password: str) -> Fernet:
    salt = get_meta(conn, "salt")
    if not salt:
        raise RuntimeError("Vault not initialized. Run: passman.py init")
    iters_raw = get_meta(conn, "kdf_iters")
    kdf_iters = int((iters_raw or str(DEFAULT_KDF_ITERS).encode()).decode())
    key = derive_key(master_password, salt, kdf_iters)
    return Fernet(key)

def set_verifier(conn: sqlite3.Connection, f: Fernet):
    token = f.encrypt(b"verify")
    set_meta(conn, "verifier", token)

def check_verifier(conn: sqlite3.Connection, f: Fernet) -> bool:
    token = get_meta(conn, "verifier")
    if not token:
        # If verifier missing (old vault), consider it invalid
        return False
    try:
        pt = f.decrypt(token)
        return pt == b"verify"
    except InvalidToken:
        return False


# --- Password generation & strength ---

def generate_password(length: int = 16, use_digits: bool = True, use_symbols: bool = True) -> str:
    if length < 8:
        raise ValueError("Password length should be at least 8.")
    alphabet = string.ascii_letters
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        # printable but excludes whitespace
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/\\|"
    # Ensure at least one char from each selected class
    parts = []
    if use_digits:
        parts.append(secrets.choice(string.digits))
    if use_symbols:
        parts.append(secrets.choice("!@#$%^&*()-_=+[]{};:,.?/\\|"))
    parts.append(secrets.choice(string.ascii_lowercase))
    parts.append(secrets.choice(string.ascii_uppercase))
    while len(parts) < length:
        parts.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(parts)
    return "".join(parts[:length])

def strength_label(pw: str) -> Tuple[int, str]:
    score = 0
    if len(pw) >= 12: score += 1
    if len(pw) >= 16: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"[a-z]", pw): score += 1
    if re.search(r"\d", pw): score += 1
    if re.search(r"[!@#$%^&*()\-\_=+\[\]{};:,.?/\\|]", pw): score += 1
    # Very naive repeats/sequence penalty
    if re.search(r"(.)\1{2,}", pw): score -= 1

    # Map to label
    if score <= 2:
        return score, "weak"
    elif score <= 4:
        return score, "medium"
    else:
        return score, "strong"

# --- CRUD operations ---

def add_credential(conn: sqlite3.Connection, f: Fernet, site: str, username: Optional[str],
                   password: str, notes: Optional[str] = None):
    enc = f.encrypt(password.encode("utf-8"))
    now = datetime.utcnow().isoformat()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO credentials(site, username, password, notes, created_at, updated_at)
            VALUES(?,?,?,?,?,?);
        """, (site, username, enc, notes, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        raise SystemExit("Entry already exists for this site/username. Use update instead.")

def update_credential(conn: sqlite3.Connection, f: Fernet, site: str, username: Optional[str],
                      new_password: str, notes: Optional[str] = None):
    enc = f.encrypt(new_password.encode("utf-8"))
    now = datetime.utcnow().isoformat()
    cur = conn.cursor()
    cur.execute("""
        UPDATE credentials
           SET password=?, notes=COALESCE(?, notes), updated_at=?
         WHERE site=? AND (username IS ? OR username = ?);
    """, (enc, notes, now, site, username, username))
    if cur.rowcount == 0:
        raise SystemExit("No matching entry to update.")
    conn.commit()

def list_credentials(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("SELECT site, username, created_at, updated_at FROM credentials ORDER BY site, username;")
    rows = cur.fetchall()
    if not rows:
        print("No credentials saved yet.")
        return
    w1 = max(4, max((len(r[0]) for r in rows), default=4))
    w2 = max(8, max((len(r[1] or "") for r in rows), default=8))
    print(f"{'SITE'.ljust(w1)}  {'USERNAME'.ljust(w2)}  CREATED AT (UTC)              UPDATED AT (UTC)")
    print("-"*(w1+w2+36+4))
    for site, username, created_at, updated_at in rows:
        print(f"{site.ljust(w1)}  {(username or '').ljust(w2)}  {created_at[:19]}            {updated_at[:19]}")

def retrieve_credential(conn: sqlite3.Connection, f: Fernet, site: str, username: Optional[str]) -> str:
    cur = conn.cursor()
    cur.execute("""
        SELECT password FROM credentials
         WHERE site=? AND (username IS ? OR username = ?)
         LIMIT 1;
    """, (site, username, username))
    row = cur.fetchone()
    if not row:
        raise SystemExit("No matching entry found.")
    enc = row[0]
    try:
        pw = f.decrypt(enc).decode("utf-8")
    except InvalidToken:
        raise SystemExit("Decryption failed. Wrong master password.")
    return pw

def delete_credential(conn: sqlite3.Connection, site: str, username: Optional[str]):
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM credentials
         WHERE site=? AND (username IS ? OR username = ?);
    """, (site, username, username))
    if cur.rowcount == 0:
        raise SystemExit("No matching entry to delete.")
    conn.commit()

# --- CLI ---

def require_master_and_fernet(conn: sqlite3.Connection, ask_new: bool = False) -> Fernet:
    """
    - ask_new=True: used on first init to SET the master password and store verifier.
    - ask_new=False: used to UNLOCK existing vault.
    """
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
        # store verifier using this key
        set_verifier(conn, f)
        print("Master password set.")
        return f
    else:
        pw = getpass("Master password: ")
        f = get_fernet(conn, pw)
        if not check_verifier(conn, f):
            raise SystemExit("Incorrect master password.")
        return f

def cmd_init(args):
    db = resolve_db_path(args.db)
    conn = connect(db)
    init_db(conn, args.kdf_iters or DEFAULT_KDF_ITERS)
    # If verifier is empty, we need to set master password now
    if not get_meta(conn, "verifier"):
        _ = require_master_and_fernet(conn, ask_new=True)
        print(f"Vault initialized at: {db}")
    else:
        print(f"Vault already initialized at: {db}")

def cmd_generate(args):
    pw = generate_password(length=args.length, use_digits=args.digits, use_symbols=args.symbols)
    score, label = strength_label(pw)
    print(pw)
    print(f"Strength: {label} (score {score})")

def cmd_add(args):
    db = resolve_db_path(args.db)
    conn = connect(db)
    if not get_meta(conn, "salt"):
        raise SystemExit("Vault not initialized. Run: passman.py init")
    f = require_master_and_fernet(conn, ask_new=False)

    if args.gen:
        pw = generate_password(length=args.length, use_digits=args.digits, use_symbols=args.symbols)
        score, label = strength_label(pw)
        print(f"Generated password strength: {label} (score {score})")
    else:
        pw = getpass("Password to save (input hidden): ")
        score, label = strength_label(pw)
        print(f"Entered password strength: {label} (score {score})")

    notes = args.notes
    add_credential(conn, f, args.site, args.username, pw, notes)
    print("Credential saved.")

def cmd_list(args):
    db = resolve_db_path(args.db)
    conn = connect(db)
    list_credentials(conn)

def cmd_retrieve(args):
    db = resolve_db_path(args.db)
    conn = connect(db)
    if not get_meta(conn, "salt"):
        raise SystemExit("Vault not initialized. Run: passman.py init")
    f = require_master_and_fernet(conn, ask_new=False)
    pw = retrieve_credential(conn, f, args.site, args.username)
    print(pw)

def cmd_update(args):
    db = resolve_db_path(args.db)
    conn = connect(db)
    if not get_meta(conn, "salt"):
        raise SystemExit("Vault not initialized. Run: passman.py init")
    f = require_master_and_fernet(conn, ask_new=False)

    if args.gen:
        new_pw = generate_password(length=args.length, use_digits=args.digits, use_symbols=args.symbols)
        score, label = strength_label(new_pw)
        print(f"New generated password strength: {label} (score {score})")
    else:
        new_pw = getpass("New password (input hidden): ")
        score, label = strength_label(new_pw)
        print(f"New password strength: {label} (score {score})")

    update_credential(conn, f, args.site, args.username, new_pw, args.notes)
    print("Credential updated.")

def cmd_delete(args):
    db = resolve_db_path(args.db)
    conn = connect(db)
    confirm = input(f"Delete entry for site='{args.site}', username='{args.username}'? (y/N): ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return
    delete_credential(conn, args.site, args.username)
    print("Credential deleted.")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CLI Password Manager (SQLite + Encryption)")
    p.add_argument("--db", help=f"Path to SQLite DB (or set PASSMAN_DB). Default: {DEFAULT_DB}")
    sub = p.add_subparsers(dest="command", required=True)

    # init
    s = sub.add_parser("init", help="Initialize vault (creates DB, sets master password)")
    s.add_argument("--kdf-iters", type=int, help=f"PBKDF2 iterations (default {DEFAULT_KDF_ITERS})")
    s.set_defaults(func=cmd_init)

    # generate
    s = sub.add_parser("generate", help="Generate a strong password and show strength")
    s.add_argument("--length", type=int, default=16)
    s.add_argument("--digits", action="store_true", help="Include digits")
    s.add_argument("--symbols", action="store_true", help="Include symbols")
    s.set_defaults(func=cmd_generate)

    # add
    s = sub.add_parser("add", help="Add a credential (encrypts and saves)")
    s.add_argument("--site", required=True)
    s.add_argument("--username")
    s.add_argument("--notes")
    s.add_argument("--gen", action="store_true", help="Auto-generate password")
    s.add_argument("--length", type=int, default=16)
    s.add_argument("--digits", action="store_true")
    s.add_argument("--symbols", action="store_true")
    s.set_defaults(func=cmd_add)

    # list
    s = sub.add_parser("list", help="List saved entries")
    s.set_defaults(func=cmd_list)

    # retrieve
    s = sub.add_parser("retrieve", help="Retrieve and decrypt a saved password")
    s.add_argument("--site", required=True)
    s.add_argument("--username")
    s.set_defaults(func=cmd_retrieve)

    # update
    s = sub.add_parser("update", help="Update a credential's password/notes")
    s.add_argument("--site", required=True)
    s.add_argument("--username")
    s.add_argument("--notes")
    s.add_argument("--gen", action="store_true", help="Auto-generate new password")
    s.add_argument("--length", type=int, default=16)
    s.add_argument("--digits", action="store_true")
    s.add_argument("--symbols", action="store_true")
    s.set_defaults(func=cmd_update)

    # delete
    s = sub.add_parser("delete", help="Delete a credential")
    s.add_argument("--site", required=True)
    s.add_argument("--username")
    s.set_defaults(func=cmd_delete)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)

if __name__ == "__main__":
    main()