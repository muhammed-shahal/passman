import os
from .db import DEFAULT_DB

def resolve_db_path(cli_path: str | None) -> str:
    if cli_path: return cli_path
    env = os.getenv("PASSMAN_DB")
    return env if env else DEFAULT_DB
