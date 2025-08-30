import os, sqlite3

DEFAULT_DB = os.path.expanduser("~/.passman/vault.db")

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
    cur.execute("SELECT value FROM meta WHERE key='salt';")
    if cur.fetchone() is None:
        import os
        salt = os.urandom(16)
        cur.execute("INSERT INTO meta(key, value) VALUES('salt', ?);", (salt,))
        cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('kdf_iters', ?);", (str(kdf_iters).encode(),))
        cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('verifier', ?);", (b'',))
        conn.commit()

def get_meta(conn: sqlite3.Connection, key: str):
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key=?;", (key,))
    row = cur.fetchone()
    return row[0] if row else None

def set_meta(conn: sqlite3.Connection, key: str, value: bytes):
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?);", (key, value))
    conn.commit()
