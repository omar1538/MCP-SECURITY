"""Paths and SQLite schemas shared by the data generator and the MCP servers.

Two databases live in ``$MSG_DATA_DIR`` (default ``./.data``):

* ``finance.db`` - the "bank": accounts, payees, transactions. Written once by the
  generator; the transactions server may add categories/flags to its own tables.
* ``runtime.db`` - side effects produced by the agent during a run: payment
  requests, executed payments, sent notifications, flags, categories. It is wiped
  by :func:`reset_runtime` before every task so each evaluation episode starts
  clean, and attack success checks read it to see what the agent actually did.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

FINANCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    iban       TEXT NOT NULL,
    currency   TEXT NOT NULL,
    balance    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS payees (
    payee_id   TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    iban       TEXT NOT NULL,
    email      TEXT NOT NULL,
    category   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
    txn_id           TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL,
    booking_date     TEXT NOT NULL,
    amount           REAL NOT NULL,
    currency         TEXT NOT NULL,
    counterparty     TEXT NOT NULL,
    counterparty_iban TEXT,
    memo             TEXT NOT NULL
);
"""

RUNTIME_SCHEMA = """
CREATE TABLE IF NOT EXISTS payment_requests (
    request_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    payee_name   TEXT NOT NULL,
    iban         TEXT NOT NULL,
    amount       REAL NOT NULL,
    currency     TEXT NOT NULL DEFAULT 'EUR',
    reference    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending_approval',
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS executed_payments (
    payment_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   INTEGER,
    iban         TEXT NOT NULL,
    amount       REAL NOT NULL,
    reference    TEXT NOT NULL,
    executed_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS payee_changes (
    change_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    payee_id     TEXT NOT NULL,
    old_iban     TEXT,
    new_iban     TEXT NOT NULL,
    changed_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS outbox (
    msg_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    channel      TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    subject      TEXT,
    body         TEXT NOT NULL,
    sent_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS categories (
    txn_id       TEXT PRIMARY KEY,
    category     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
    flag_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id   TEXT NOT NULL,
    reason       TEXT NOT NULL,
    flagged_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def data_dir() -> Path:
    return Path(os.environ.get("MSG_DATA_DIR", ".data")).resolve()


def finance_db() -> Path:
    return data_dir() / "finance.db"


def runtime_db() -> Path:
    return data_dir() / "runtime.db"


def invoices_dir() -> Path:
    return data_dir() / "invoices"


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """Open ``path``, commit on success, roll back on error, always close."""
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_runtime() -> None:
    with connect(runtime_db()) as conn:
        conn.executescript(RUNTIME_SCHEMA)


def reset_runtime(path: Path | None = None) -> None:
    """Delete every side effect recorded by previous runs."""
    path = path or runtime_db()
    path.parent.mkdir(parents=True, exist_ok=True)
    tables = (
        "payment_requests",
        "executed_payments",
        "payee_changes",
        "outbox",
        "categories",
        "flags",
    )
    with connect(path) as conn:
        conn.executescript(RUNTIME_SCHEMA)
        for table in tables:
            conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
        # Reset AUTOINCREMENT counters so ids restart at 1 each episode -
        # episodes must be fully isolated for request_id references to be stable.
        conn.execute(
            "DELETE FROM sqlite_sequence WHERE name IN "
            "('payment_requests','executed_payments','payee_changes','outbox','flags')"
        )
