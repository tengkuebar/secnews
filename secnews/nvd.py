"""Official CVSS scores from the NIST National Vulnerability Database (NVD).

Only CVE IDs that secnews already found in the news are sent to NVD, one request per CVE, through its
public CVE API 2.0. Without an API key NVD allows 5 requests per 30 seconds, so a run is capped and the
rest waits for the next cycle. A free key (named in config, never stored) raises that to 50.
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import requests

from . import db

log = logging.getLogger("secnews.nvd")

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE_NAME = "NVD"
# Newest scoring system first. NVD fills these in after its analysts have looked at a CVE.
METRIC_ORDER = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")
RETRY_UNSCORED_AFTER = timedelta(hours=6)    # "awaiting analysis", or not in NVD yet
REFRESH_SCORED_AFTER = timedelta(days=7)     # analysts do revise scores, rarely
LOOKBACK_DAYS = 60
GAP_KEYLESS, GAP_KEYED = 6.5, 0.7            # seconds between requests (limits: 5/30s and 50/30s)
DEFAULT_MAX_PER_RUN = 20


def settings(cfg: dict) -> dict:
    n = cfg.get("nvd") or {}
    return {"enabled": bool(n.get("enabled", False)), "api_key_env": n.get("api_key_env") or "NVD_API_KEY",
            "max_per_run": max(1, int(n.get("max_per_run") or DEFAULT_MAX_PER_RUN))}


def parse(payload: dict) -> dict | None:
    """Pick the score out of an NVD response. None means NVD has no record of the CVE (yet)."""
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    out = {"cvss": None, "severity": None, "version": None, "vector": None, "status": cve.get("vulnStatus")}
    metrics = cve.get("metrics") or {}
    for key in METRIC_ORDER:
        entries = metrics.get(key) or []
        if not entries:
            continue
        m = next((e for e in entries if e.get("type") == "Primary"), entries[0])   # NVD's own, else a vendor's
        d = m.get("cvssData") or {}
        if d.get("baseScore") is None:
            continue
        out.update(cvss=float(d["baseScore"]), version=d.get("version"), vector=d.get("vectorString"),
                   severity=(d.get("baseSeverity") or m.get("baseSeverity") or "").title() or None)
        break
    return out


def _utc(s: str) -> datetime:
    return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def pending(conn, now: datetime | None = None) -> list[str]:
    """CVE IDs worth asking NVD about, most useful first: never asked, then unscored, then stale."""
    now = now or datetime.now(timezone.utc)
    cut = (now - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    known = {r["cve_id"]: r for r in conn.execute("SELECT cve_id, cvss, fetched_at FROM nvd_scores")}
    rows = conn.execute(
        "SELECT c.cve_id, MIN(COALESCE(a.published_at, a.scraped_at)) AS first, MAX(c.exploited) AS ex "
        "FROM cves c JOIN articles a ON a.id = c.article_id GROUP BY c.cve_id HAVING first >= ?", (cut,)).fetchall()
    ranked = []
    for r in rows:
        k = known.get(r["cve_id"])
        if k is None:
            tier = 0
        else:
            age = now - _utc(k["fetched_at"])
            if k["cvss"] is None and age >= RETRY_UNSCORED_AFTER:
                tier = 1
            elif k["cvss"] is not None and age >= REFRESH_SCORED_AFTER:
                tier = 2
            else:
                continue
        ranked.append((tier, -r["ex"], r["first"], r["cve_id"]))
    ranked.sort(key=lambda t: (t[0], t[1], _neg(t[2])))
    return [t[3] for t in ranked]


def _neg(iso: str) -> float:
    return -_utc(iso).timestamp()   # newest first within a tier


def _store(conn, cve_id: str, rec: dict | None, now: datetime) -> None:
    rec = rec or {"cvss": None, "severity": None, "version": None, "vector": None, "status": "Not in NVD yet"}
    conn.execute(
        "INSERT INTO nvd_scores(cve_id,cvss,severity,version,vector,status,fetched_at) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(cve_id) DO UPDATE SET cvss=excluded.cvss, severity=excluded.severity, "
        "version=excluded.version, vector=excluded.vector, status=excluded.status, fetched_at=excluded.fetched_at",
        (cve_id, rec["cvss"], rec["severity"], rec["version"], rec["vector"], rec["status"],
         now.strftime("%Y-%m-%dT%H:%M:%SZ")))


def enrich(conn, cfg: dict, session=None, sleep=time.sleep, limit: int | None = None,
           now: datetime | None = None) -> dict:
    """Ask NVD about pending CVEs, up to the cap. Stops at the first sign of trouble, so it never hammers NVD."""
    s = settings(cfg)
    result = {"asked": 0, "scored": 0, "error": None}
    if not s["enabled"]:
        return {**result, "skipped": "NVD scores are switched off"}
    todo = pending(conn, now)[: limit or s["max_per_run"]]
    if not todo:
        return result
    f = cfg.get("fetching", {})
    session = session or requests.Session()
    session.headers["User-Agent"] = f.get("user_agent", "secnews")
    key = os.environ.get(s["api_key_env"])
    if key:
        session.headers["apiKey"] = key
    gap, timeout = (GAP_KEYED if key else GAP_KEYLESS), float(f.get("timeout_seconds", 15))
    for i, cid in enumerate(todo):
        if i:
            sleep(gap)
        try:
            r = session.get(f"{API}?cveId={cid}", timeout=timeout)
        except requests.RequestException as e:
            result["error"] = f"{type(e).__name__}: {e}"
            break
        result["asked"] += 1
        stamp = now or datetime.now(timezone.utc)
        if r.status_code == 404:                       # NVD rejects an ID it has never heard of
            _store(conn, cid, None, stamp)
        elif r.status_code == 200:
            try:
                rec = parse(json.loads(r.text))
            except ValueError:
                result["error"] = "NVD returned something that is not JSON"
                break
            _store(conn, cid, rec, stamp)
            result["scored"] += 1 if rec and rec["cvss"] is not None else 0
        else:
            hint = " (rate limited: set an API key, or lower max_per_run)" if r.status_code in (403, 429) else ""
            result["error"] = f"HTTP {r.status_code}{hint}"
            result["asked"] -= 1
            break
        conn.commit()
    status = "Failed" if result["error"] else "OK"
    detail = f"{result['scored']} of {result['asked']} CVEs scored" + (f"; {len(todo) - result['asked']} left" if len(todo) > result["asked"] else "")
    db.log_run(conn, SOURCE_NAME, status, fetched=result["asked"], new=result["scored"],
               error=result["error"], detail=detail)
    log.info("nvd: %s%s", detail, f" ({result['error']})" if result["error"] else "")
    return result


def counts(conn) -> dict:
    """How many recent CVEs have an official score: for the Today page."""
    cut = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    total = conn.execute(
        "SELECT COUNT(*) FROM (SELECT c.cve_id, MIN(COALESCE(a.published_at, a.scraped_at)) AS first "
        "FROM cves c JOIN articles a ON a.id = c.article_id GROUP BY c.cve_id HAVING first >= ?)", (cut,)).fetchone()[0]
    scored = conn.execute("SELECT COUNT(*) FROM nvd_scores n WHERE n.cvss IS NOT NULL AND n.cve_id IN "
                          "(SELECT cve_id FROM cves)").fetchone()[0]
    return {"total": total, "scored": scored}
