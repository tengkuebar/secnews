"""SQLite schema and queries."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id           INTEGER PRIMARY KEY,
    source       TEXT NOT NULL,
    url          TEXT NOT NULL UNIQUE,
    title        TEXT NOT NULL,
    published_at TEXT,
    summary      TEXT,
    body         TEXT,
    content_hash TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'News report',
    scraped_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_articles_hash ON articles(content_hash);
CREATE INDEX IF NOT EXISTS idx_articles_pub ON articles(published_at);

CREATE TABLE IF NOT EXISTS cves (
    cve_id     TEXT NOT NULL,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    cvss       REAL,
    severity   TEXT,
    affected   TEXT,
    exploited  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cve_id, article_id)
);
CREATE INDEX IF NOT EXISTS idx_cves_id ON cves(cve_id);

CREATE TABLE IF NOT EXISTS alerts_sent (
    id             INTEGER PRIMARY KEY,
    rule           TEXT NOT NULL,
    cve_id         TEXT NOT NULL,
    article_id     INTEGER,
    sent_at        TEXT NOT NULL,
    last_cvss      REAL,
    last_exploited INTEGER NOT NULL DEFAULT 0,
    UNIQUE (rule, cve_id)
);

CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    source     TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'Scrape',
    fetched    INTEGER NOT NULL DEFAULT 0,
    new        INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL,
    error      TEXT,
    retries    INTEGER NOT NULL DEFAULT 0,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
"""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: str) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection):
    """All-or-nothing writes so an interrupted run cannot corrupt data."""
    try:
        conn.execute("BEGIN")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def log_run(conn, source, status, fetched=0, new=0, error=None, retries=0, kind="Scrape", detail=None):
    conn.execute(
        "INSERT INTO runs(started_at, source, kind, fetched, new, status, error, retries, detail)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (now(), source, kind, fetched, new, status, error, retries, detail),
    )
    conn.commit()
