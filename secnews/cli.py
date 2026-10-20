"""Command line: python -m secnews <command>."""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import sys
import time
from pathlib import Path

from . import db, queries
from .alerts import SENDERS, send_test
from .config import load_config
from .pipeline import run_cycle


def setup_logging(cfg: dict) -> None:
    logdir = Path(cfg["_path"]).parent / "logs"
    logdir.mkdir(exist_ok=True)
    h = logging.handlers.RotatingFileHandler(logdir / "secnews.log", maxBytes=1_000_000,
                                             backupCount=3, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(isinstance(x, logging.handlers.RotatingFileHandler) for x in root.handlers):
        root.addHandler(h)


def _table(rows, cols):
    if not rows:
        print("(nothing)")
        return
    widths = [max(len(c), *(len(str(r.get(c, "") or "")) for r in rows)) for c in cols]
    print("  ".join(c.upper().ljust(w) for c, w in zip(cols, widths)))
    for r in rows:
        print("  ".join(str(r.get(c, "") or "").ljust(w)[:w] for c, w in zip(cols, widths)))


def cmd_init(cfg, a):
    db.init_db(cfg["database"]).close()
    print(f"Database ready at {cfg['database']}")


def cmd_reindex(cfg, a):
    from .ingest import reindex_cves
    r = reindex_cves(db.init_db(cfg["database"]))
    print(f"CVE rows rebuilt from stored articles: {r['before']} before, {r['after']} after")


def cmd_nvd(cfg, a):
    from . import nvd
    if not nvd.settings(cfg)["enabled"]:
        print("NVD scores are switched off. Set nvd: enabled: true in config.yaml.")
        return 1
    conn = db.init_db(cfg["database"])
    waiting = len(nvd.pending(conn))
    n = a.limit or (waiting if a.all else None)
    print(f"{waiting} CVEs waiting for an official score; asking about {n or nvd.settings(cfg)['max_per_run']}.")
    r = nvd.enrich(conn, cfg, limit=n)
    print(f"Asked NVD about {r['asked']}, {r['scored']} had a score." + (f" Stopped: {r['error']}" if r["error"] else ""))
    return 1 if r["error"] else 0


def cmd_scrape(cfg, a):
    res = run_cycle(cfg, only=a.source)
    if "skipped" in res:
        print(res["skipped"])
        return 1
    for name, s in res["scrape"]["sources"].items():
        print(f"{name}: {s['status']}" + (f" - {s['fetched']} fetched, {s['new']} new" if "fetched" in s
                                           else f" - {s.get('error')}"))
    for al in res["alerts"]:
        print(f"ALERT {al['rule']} -> {', '.join(al['channels'])}: {al['cve_id']}")
    return 0


def cmd_search(cfg, a):
    conn = db.init_db(cfg["database"])
    rows, total = queries.search_articles(conn, q=a.q, severity=a.severity, source=a.source, cve=a.cve,
                                          date_from=a.date_from, date_to=a.date_to, page=a.page,
                                          per_page=a.per_page)
    for r in rows:
        r["date"] = (r["published_at"] or r["scraped_at"] or "")[:10]
        r["cvss"] = r["cvss"] if r["cvss"] is not None else ""
        r["sev"] = r["severity"] or ""
    _table(rows, ["date", "sev", "cvss", "top_cve", "seen", "source", "title"])
    pages = max(1, -(-total // a.per_page))
    print(f"\n{total} articles, page {a.page} of {pages}")


def cmd_cve(cfg, a):
    conn = db.init_db(cfg["database"])
    d = queries.cve_detail(conn, a.cve_id)
    if not d:
        print("Not found")
        return 1
    print(f"{d['cve_id']}  {d['severity']}  CVSS {d['cvss']}  (from {d['score_source']})")
    if d["nvd"]:
        print(f"NVD: {d['nvd']['cvss']} (CVSS v{d['nvd']['version']}, {d['nvd']['status']}) {d['nvd']['vector'] or ''}")
    if d["conflict"]:
        print("Sources disagree on the score: " + " vs ".join(str(x) for x in d["conflict"]))
    print(f"First seen {d['first_seen']}; {d['article_count']} articles, {d['source_count']} sources; "
          f"exploitation reported: {'yes' if d['exploited'] else 'no'}")
    if d["affected"]:
        print(f"Affected: {d['affected']}")
    for x in d["articles"]:
        print(f"  [{x['kind']}] {x['source']}: {x['title']} (CVSS {x['cvss']}) {x['url']}")


def cmd_log(cfg, a):
    conn = db.init_db(cfg["database"])
    rows = queries.list_runs(conn, kind=a.kind, failures=a.failures, limit=a.limit)
    for r in rows:
        r["result"] = r["detail"] or r["error"] or f"{r['fetched']} fetched, {r['new']} new"
    _table(rows, ["started_at", "source", "kind", "status", "result"])


def cmd_alerts_test(cfg, a):
    ok, msg = send_test(cfg, a.channel)
    print(("OK: " if ok else "FAILED: ") + msg)
    return 0 if ok else 1


def cmd_schedule(cfg, a):
    from .scheduler import make_scheduler
    sched = make_scheduler(lambda: load_config(cfg["_path"]))
    print("Scheduler running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sched.shutdown()


def cmd_serve(cfg, a):
    from .web import create_app
    app = create_app(cfg["_path"], with_scheduler=not a.no_scheduler)
    app.run(host=a.host, port=a.port, debug=False, use_reloader=False)


def build_parser():
    p = argparse.ArgumentParser(prog="secnews", description="Security news and CVE tracker")
    p.add_argument("--config", default="config.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the database").set_defaults(fn=cmd_init)
    sub.add_parser("reindex", help="re-extract CVEs from stored articles after rule changes").set_defaults(fn=cmd_reindex)
    s = sub.add_parser("scrape", help="scrape sources now, then run alert rules")
    s.add_argument("--source")
    s.set_defaults(fn=cmd_scrape)
    s = sub.add_parser("nvd", help="fetch official NVD scores for recent CVEs now")
    s.add_argument("--limit", type=int, help="ask about at most this many CVEs")
    s.add_argument("--all", action="store_true", help="ask about every waiting CVE (slow without an API key)")
    s.set_defaults(fn=cmd_nvd)
    s = sub.add_parser("search", help="search stored articles")
    s.add_argument("--q")
    s.add_argument("--severity", choices=list(queries.SEV_SQL))
    s.add_argument("--source")
    s.add_argument("--cve")
    s.add_argument("--from", dest="date_from", help="YYYY-MM-DD")
    s.add_argument("--to", dest="date_to", help="YYYY-MM-DD")
    s.add_argument("--page", type=int, default=1)
    s.add_argument("--per-page", type=int, default=10)
    s.set_defaults(fn=cmd_search)
    s = sub.add_parser("cve", help="show one CVE")
    s.add_argument("cve_id")
    s.set_defaults(fn=cmd_cve)
    s = sub.add_parser("log", help="show the run log")
    s.add_argument("--failures", action="store_true")
    s.add_argument("--kind", choices=["Scrape", "Alert"])
    s.add_argument("--limit", type=int, default=30)
    s.set_defaults(fn=cmd_log)
    s = sub.add_parser("alerts-test", help="send a test message to a channel")
    s.add_argument("channel", choices=list(SENDERS))
    s.set_defaults(fn=cmd_alerts_test)
    sub.add_parser("schedule", help="run the scheduler without the web UI").set_defaults(fn=cmd_schedule)
    s = sub.add_parser("serve", help="start the dashboard (and scheduler)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--no-scheduler", action="store_true")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    cfg = load_config(a.config)
    setup_logging(cfg)
    return a.fn(cfg, a) or 0


if __name__ == "__main__":
    sys.exit(main())
