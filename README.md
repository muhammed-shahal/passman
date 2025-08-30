# Passman — Encrypted CLI Password Manager

A simple, secure command-line password manager written in Python.  

## Why Use Passman?

Most password managers are either cloud-based (raising privacy concerns) or bloated with features you may never use. Passman is different:

🛡️ 100% Local & Offline — Your vault lives on your machine, not on someone else’s server.

🔐 Strong Encryption — Every secret is encrypted with AES (via Fernet), protected by a PBKDF2-derived master key.

⚡ Lightweight & Fast — A single SQLite file, no background services, no syncing overhead.

💻 CLI First — Perfect for developers, sysadmins, or anyone who lives in the terminal.

🔑 Full Control — No subscriptions, no hidden processes, no vendor lock-in. You own your data.

🧩 Hackable & Extendable — Built in Python with a clean modular design; easy to audit or extend.

Passman is ideal if you want a minimal, transparent, and secure password manager that just does the essentials — nothing more, nothing less.

It uses:

- **SQLite** for storage
- **PBKDF2** for key derivation (configurable iterations)
- **Fernet (AES)** for encryption
- **Argparse** for CLI subcommands

---

## Features

- 🔒 Initialize an encrypted password vault with a **master password**
- 🔑 Generate strong random passwords
- 📝 Check password strength
- ➕ Add new credentials (site, username, notes, password)
- 📋 List stored credentials (without revealing secrets)
- 🔍 Retrieve & decrypt passwords securely
- ✏️ Update credentials
- ❌ Delete credentials

---

## Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/yourname/passman.git
cd passman
pip install -r requirements.txt
```

## Usage

Run directly with Python:

```bash
python -m passman <command> [options]
```


Or if installed as a package:

```bash
passman <command> [options]
```

## Commands

### Initialize a new vault

```bash
python -m passman init --db ./vault.db
```

This will:

Create the database file

Set up schema

Ask you to create a master password

Derive a key using PBKDF2 + store verifier

### Generate a strong password

```bash
python -m passman generate --length 20 --digits --symbols
```


Output:

```yaml
N@9eZr%k6Hq2...pX
Strength: strong (score 6)
```

### Add a credential
```bash
python -m passman add --site gmail --username musthafa --gen --length 18 --digits --symbols
```


Or manually enter:
```bash
python -m passman add --site github --username user123
```


(You’ll be prompted for a password)

### List credentials
```bash
python -m passman list
```

Output:

```yaml
SITE     USERNAME     CREATED AT (UTC)         UPDATED AT (UTC)
----------------------------------------------------------------
gmail    musthafa     2025-08-30T15:12:43      2025-08-30T15:12:43
github   user123      2025-08-30T15:14:10      2025-08-30T15:14:10
```

### Retrieve a password
```bash
python -m passman retrieve --site gmail --username musthafa
```


Output (after entering master password):

```yaml
N@9eZr%k6Hq2...pX
```

### Update a credential
```bash
python -m passman update --site gmail --username musthafa --gen
```

### Delete a credential
```bash
python -m passman delete --site gmail --username musthafa
```

Confirmation required:

```yaml
Delete entry for site='gmail', username='musthafa'? (y/N): y
Credential deleted.
```

## Configuration

Default vault path: ~/.passman/vault.db

Override via --db or environment variable PASSMAN_DB

PBKDF2 iterations: default 200,000 (tweak with --kdf-iters during init)

## Security Notes

Master password is never stored, only used to derive encryption key

PBKDF2 strengthens against brute-force

All secrets are encrypted with Fernet (AES-128 in CBC + HMAC)

Always back up your vault file securely — if you forget the master password, data cannot be recovered!

# License

MIT License © 2024 Musthafa Vakkayil
