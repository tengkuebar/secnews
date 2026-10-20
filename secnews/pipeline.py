"""One full cycle: scrape every source, then evaluate alert rules."""
from __future__ import annotations

import logging
import threading

from . import db, nvd
from .alerts import process_alerts
from .ingest import scrape_all

log = logging.getLogger("secnews.pipeline")
_lock = threading.Lock()  # never run two cycles at once (scheduler + "scrape now")


def run_cycle(cfg: dict, fetcher=None, senders=None, only: str | None = None, nvd_session=None) -> dict:
    if not _lock.acquire(blocking=False):
        return {"skipped": "a run is already in progress"}
    conn = db.init_db(cfg["database"])
    try:
        scrape = scrape_all(conn, cfg, fetcher, only=only)
        official = {"skipped": "not run"}
        if not only:   # a single-source scrape should stay quick
            try:
                official = nvd.enrich(conn, cfg, session=nvd_session)
            except Exception:   # an NVD problem must never stop alerts from going out
                log.exception("nvd enrichment crashed")
                official = {"error": "crashed, see logs/secnews.log"}
        alerts = process_alerts(conn, cfg, senders)
        log.info("cycle done: %s new articles, %s alerts",
                 len(scrape["new_article_ids"]), len(alerts))
        return {"scrape": scrape, "nvd": official, "alerts": alerts}
    finally:
        conn.close()
        _lock.release()
