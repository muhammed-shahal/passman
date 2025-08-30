import argparse
from getpass import getpass

from . import db
from . import utils
from . import crypto
from . import password as pw
from . import vault


def cmd_init(args):
    db_path = utils.resolve_db_path(args.db)
    conn = db.connect(db_path)
    db.init_db(conn, args.kdf_iters or crypto.DEFAULT_KDF_ITERS)
    if not db.get_meta(conn, "verifier"):
        _ = crypto.require_master_and_fernet(conn, ask_new=True)
        print(f"Vault initialized at: {db_path}")
    else:
        print(f"Vault already initialized at: {db_path}")


def cmd_generate(args):
    generated = pw.generate_password(length=args.length,
                                     use_digits=args.digits,
                                     use_symbols=args.symbols)
    score, label = pw.strength_label(generated)
    print(generated)
    print(f"Strength: {label} (score {score})")


def cmd_add(args):
    db_path = utils.resolve_db_path(args.db)
    conn = db.connect(db_path)
    if not db.get_meta(conn, "salt"):
        raise SystemExit("Vault not initialized. Run: passman init")

    f = crypto.require_master_and_fernet(conn, ask_new=False)

    if args.gen:
        secret = pw.generate_password(length=args.length,
                                      use_digits=args.digits,
                                      use_symbols=args.symbols)
        score, label = pw.strength_label(secret)
        print(f"Generated password strength: {label} (score {score})")
    else:
        secret = getpass("Password to save (input hidden): ")
        score, label = pw.strength_label(secret)
        print(f"Entered password strength: {label} (score {score})")

    vault.add_credential(conn, f, args.site, args.username, secret, args.notes)
    print("Credential saved.")


def cmd_list(args):
    db_path = utils.resolve_db_path(args.db)
    conn = db.connect(db_path)
    vault.list_credentials(conn)


def cmd_retrieve(args):
    db_path = utils.resolve_db_path(args.db)
    conn = db.connect(db_path)
    if not db.get_meta(conn, "salt"):
        raise SystemExit("Vault not initialized. Run: passman init")
    f = crypto.require_master_and_fernet(conn, ask_new=False)
    secret = vault.retrieve_credential(conn, f, args.site, args.username)
    print(secret)


def cmd_update(args):
    db_path = utils.resolve_db_path(args.db)
    conn = db.connect(db_path)
    if not db.get_meta(conn, "salt"):
        raise SystemExit("Vault not initialized. Run: passman init")
    f = crypto.require_master_and_fernet(conn, ask_new=False)

    if args.gen:
        new_secret = pw.generate_password(length=args.length,
                                          use_digits=args.digits,
                                          use_symbols=args.symbols)
        score, label = pw.strength_label(new_secret)
        print(f"New generated password strength: {label} (score {score})")
    else:
        new_secret = getpass("New password (input hidden): ")
        score, label = pw.strength_label(new_secret)
        print(f"New password strength: {label} (score {score})")

    vault.update_credential(conn, f, args.site, args.username, new_secret, args.notes)
    print("Credential updated.")


def cmd_delete(args):
    db_path = utils.resolve_db_path(args.db)
    conn = db.connect(db_path)
    confirm = input(f"Delete entry for site='{args.site}', username='{args.username}'? (y/N): ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return
    vault.delete_credential(conn, args.site, args.username)
    print("Credential deleted.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CLI Password Manager (SQLite + Encryption)")
    parser.add_argument("--db", help=f"Path to SQLite DB (or set PASSMAN_DB). Default: {db.DEFAULT_DB}")
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    s = sub.add_parser("init", help="Initialize vault (creates DB, sets master password)")
    s.add_argument("--kdf-iters", type=int, help=f"PBKDF2 iterations (default {crypto.DEFAULT_KDF_ITERS})")
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

    return parser
