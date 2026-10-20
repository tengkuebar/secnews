"""Store articles and their CVEs; run a full scrape across sources."""
from __future__ import annotations

import logging

from . import db
from .cve import classify_kind, extract_cves
from .fetch import Fetcher, FetchError, fetch_source

log = logging.getLogger("secnews.ingest")


def store_articles(conn, source: str, articles: list[dict], kind: str | None = None) -> list[int]:
    """Insert unseen articles (by URL or content hash). Returns new article ids.

    `kind` forces the label for every article from a source (e.g. CISA is always a
    vendor advisory); otherwise it is guessed from the headline.
    """
    new_ids = []
    with db.transaction(conn):
        for a in articles:
            dup = conn.execute(
                "SELECT 1 FROM articles WHERE url = ? OR content_hash = ?",
                (a["url"], a["content_hash"])).fetchone()
            if dup:
                continue
            label = kind or classify_kind(a["title"], a["body"])
            cur = conn.execute(
                "INSERT INTO articles(source,url,title,published_at,summary,body,content_hash,kind,scraped_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (source, a["url"], a["title"], a["published_at"], a["summary"],
                 a["body"], a["content_hash"], label, db.now()))
            aid = cur.lastrowid
            for rec in extract_cves(a["title"], a["body"]):
                conn.execute(
                    "INSERT OR IGNORE INTO cves(cve_id,article_id,cvss,severity,affected,exploited)"
                    " VALUES (?,?,?,?,?,?)",
                    (rec["cve_id"], aid, rec["cvss"], rec["severity"], rec["affected"], rec["exploited"]))
            new_ids.append(aid)
    return new_ids


def reindex_cves(conn) -> dict:
    """Re-run CVE extraction over every stored article.

    Use after the extraction rules improve. Articles, runs and alert history are
    untouched; only the `cves` rows are rebuilt (in one transaction).
    """
    before = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    with db.transaction(conn):
        conn.execute("DELETE FROM cves")
        for a in conn.execute("SELECT id, title, body FROM articles").fetchall():
            for rec in extract_cves(a["title"], a["body"]):
                conn.execute(
                    "INSERT OR IGNORE INTO cves(cve_id,article_id,cvss,severity,affected,exploited)"
                    " VALUES (?,?,?,?,?,?)",
                    (rec["cve_id"], a["id"], rec["cvss"], rec["severity"], rec["affected"], rec["exploited"]))
    after = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    return {"before": before, "after": after}


def scrape_all(conn, cfg: dict, fetcher: Fetcher | None = None, only: str | None = None) -> dict:
    """Scrape every enabled source. One failing source never stops the others."""
    fetcher = fetcher or Fetcher(cfg)
    result = {"new_article_ids": [], "sources": {}}
    for src in cfg["sources"]:
        if not src.get("enabled", True) or (only and src["name"] != only):
            continue
        name = src["name"]
        try:
            articles, retries = fetch_source(fetcher, src)
            ids = store_articles(conn, name, articles, kind=src.get("kind"))
            status = "OK" if articles else "Partial"
            db.log_run(conn, name, status, fetched=len(articles), new=len(ids), retries=retries,
                       error=None if articles else "feed returned no items")
            result["new_article_ids"] += ids
            result["sources"][name] = {"status": status, "fetched": len(articles), "new": len(ids)}
        except FetchError as e:
            log.warning("scrape failed for %s: %s", name, e)
            db.log_run(conn, name, "Failed", error=str(e), retries=e.retries)
            result["sources"][name] = {"status": "Failed", "error": str(e)}
        except Exception as e:  # keep the loop alive; the run log records it
            log.exception("unexpected error scraping %s", name)
            db.log_run(conn, name, "Failed", error=f"{type(e).__name__}: {e}")
            result["sources"][name] = {"status": "Failed", "error": str(e)}
    return result
