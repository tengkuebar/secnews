"""One full cycle: scrape every source, then evaluate alert rules."""
from __future__ import annotations

import logging
import threading

from . import db
from .alerts import process_alerts
from .ingest import scrape_all

log = logging.getLogger("secnews.pipeline")
_lock = threading.Lock()  # never run two cycles at once (scheduler + "scrape now")


def run_cycle(cfg: dict, fetcher=None, senders=None, only: str | None = None) -> dict:
    if not _lock.acquire(blocking=False):
        return {"skipped": "a run is already in progress"}
    conn = db.init_db(cfg["database"])
    try:
        scrape = scrape_all(conn, cfg, fetcher, only=only)
        alerts = process_alerts(conn, cfg, senders)
        log.info("cycle done: %s new articles, %s alerts",
                 len(scrape["new_article_ids"]), len(alerts))
        return {"scrape": scrape, "alerts": alerts}
    finally:
        conn.close()
        _lock.release()
