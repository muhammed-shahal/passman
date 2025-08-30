from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
import sqlite3

def add_credential(conn, f: Fernet, site, username, password, notes=None):
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
        raise SystemExit("Entry already exists. Use update instead.")

def update_credential(conn, f, site, username, new_password, notes=None):
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

def list_credentials(conn):
    cur = conn.cursor()
    cur.execute("SELECT site, username, created_at, updated_at FROM credentials ORDER BY site, username;")
    rows = cur.fetchall()
    if not rows:
        print("No credentials saved yet."); return
    w1 = max(4, max((len(r[0]) for r in rows), default=4))
    w2 = max(8, max((len(r[1] or "") for r in rows), default=8))
    print(f"{'SITE'.ljust(w1)}  {'USERNAME'.ljust(w2)}  CREATED AT (UTC)              UPDATED AT (UTC)")
    print("-"*(w1+w2+36+4))
    for site, username, created_at, updated_at in rows:
        print(f"{site.ljust(w1)}  {(username or '').ljust(w2)}  {created_at[:19]}            {updated_at[:19]}")

def retrieve_credential(conn, f, site, username) -> str:
    cur = conn.cursor()
    cur.execute("""
        SELECT password FROM credentials
         WHERE site=? AND (username IS ? OR username = ?)
         LIMIT 1;
    """, (site, username, username))
    row = cur.fetchone()
    if not row: raise SystemExit("No matching entry found.")
    try:
        return f.decrypt(row[0]).decode("utf-8")
    except InvalidToken:
        raise SystemExit("Decryption failed. Wrong master password.")

def delete_credential(conn, site, username):
    cur = conn.cursor()
    cur.execute("DELETE FROM credentials WHERE site=? AND (username IS ? OR username = ?);", (site, username, username))
    if cur.rowcount == 0:
        raise SystemExit("No matching entry to delete.")
    conn.commit()
