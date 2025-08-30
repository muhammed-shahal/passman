import sys
from .cli import build_parser

"""
passman.py — A simple, secure CLI password manager using:
- Python 3.10+
- SQLite for storage
- cryptography (Fernet) for symmetric encryption with master password (PBKDF2)
- Argparse CLI with subcommands
Features:
    init, generate, strength-check, add, list, retrieve, update, delete
Usage examples:
    python -m passman init --db ./vault.db
    python -m passman generate --length 20 --digits --symbols
    python -m passman add --site gmail --username musthafa --gen --length 18 --digits --symbols
    python -m passman list
    python -m passman retrieve --site gmail --username musthafa
    python -m passman update --site gmail --username musthafa --gen
    python -m passman delete --site gmail --username musthafa
"""

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
