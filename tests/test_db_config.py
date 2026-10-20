import sqlite3

import pytest

from secnews import db
from secnews.config import load_config


def test_schema_has_all_tables(conn):
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"articles", "cves", "alerts_sent", "runs"} <= names


def test_url_is_unique(conn):
    ins = ("INSERT INTO articles(source,url,title,content_hash,scraped_at)"
           " VALUES ('s','u','t','h','now')")
    conn.execute(ins)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(ins)


def test_alerts_unique_per_rule_and_cve(conn):
    q = "INSERT INTO alerts_sent(rule,cve_id,article_id,sent_at) VALUES ('r','CVE-2026-0001',1,'n')"
    conn.execute(q)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(q)


def test_transaction_rolls_back_on_error(conn):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            conn.execute("INSERT INTO articles(source,url,title,content_hash,scraped_at)"
                         " VALUES ('s','u1','t','h1','n')")
            raise RuntimeError("interrupted")
    assert conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0] == 0


def test_load_config_defaults_and_relative_db(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("sources: [{name: X, feed: http://x}]\n", encoding="utf-8")
    cfg = load_config(p)
    assert cfg["scheduler"]["interval_minutes"] == 60
    assert cfg["database"].startswith(str(tmp_path))
    assert cfg["sources"][0]["name"] == "X"
