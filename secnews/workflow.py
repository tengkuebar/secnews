"""Your decisions on CVEs (reviewed, snoozed, notes) and the pages built on them: Today and Threats.

A reviewed or snoozed CVE leaves Today, and comes back by itself if its score rises or exploitation is
first reported. That is the whole point: you are never asked to re-read something that has not changed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import queries

SNOOZES = {"1": ("1 day", 1), "3": ("3 days", 3), "7": ("1 week", 7),
           "change": ("until the score changes", None)}
ISO = "%Y-%m-%dT%H:%M:%SZ"
NOTE_MAX = 500
WORTH_MIN_SCORE = 9.0


def _iso(dt: datetime) -> str:
    return dt.strftime(ISO)


def load_reviews(conn) -> dict:
    return {r["cve_id"]: r for r in conn.execute("SELECT * FROM reviews")}


def state_of(row, cvss, exploited, now: datetime) -> dict:
    """open / snoozed / reviewed for one CVE, with a label and, if it came back, the reason."""
    open_ = {"state": "open", "label": "Needs attention"}
    if row is None:
        return {**open_, "why": None}
    if cvss is not None and (row["base_cvss"] is None or cvss > row["base_cvss"]):
        why = (f"Back in the queue: score published ({cvss})" if row["base_cvss"] is None
               else f"Back in the queue: score rose from {row['base_cvss']}")
        return {**open_, "why": why}
    if exploited and not row["base_exploited"]:
        return {**open_, "why": "Back in the queue: exploitation now reported"}
    if row["status"] == "reviewed":
        return {"state": "reviewed", "label": f"Reviewed {queries.ago(row['updated_at'], now)} ago", "why": None}
    if row["until"] is None:
        if cvss != row["base_cvss"]:
            return {**open_, "why": "Back in the queue: the score changed"}
        return {"state": "snoozed", "label": "Snoozed until the score changes", "why": None}
    if row["until"] <= _iso(now):
        return {**open_, "why": "Back in the queue: the snooze ended"}
    until = datetime.strptime(row["until"], ISO)
    return {"state": "snoozed", "label": f"Snoozed until {until.day} {until.strftime('%b')}", "why": None}


def log_event(conn, cve_id: str, text: str, now: datetime | None = None) -> None:
    conn.execute("INSERT INTO cve_events(cve_id, at, text) VALUES (?,?,?)",
                 (cve_id, _iso(now or datetime.now(timezone.utc)), text))


def decide(conn, cve_id: str, action: str, snooze: str | None = None, now: datetime | None = None):
    """Record a decision. Returns the confirmation sentence, or None if the CVE or choice is unknown."""
    now = now or datetime.now(timezone.utc)
    cve_id = cve_id.upper()
    d = queries.cve_detail(conn, cve_id)
    if not d:
        return None
    if action == "open":
        conn.execute("DELETE FROM reviews WHERE cve_id = ?", (cve_id,))
        log_event(conn, cve_id, "You reopened this.", now)
        msg = f"Reopened {cve_id}."
    elif action in ("reviewed", "snoozed"):
        until, text, msg = None, "You marked this reviewed.", f"Marked {cve_id} as reviewed."
        if action == "snoozed":
            if snooze not in SNOOZES:
                return None
            label, days = SNOOZES[snooze]
            until = _iso(now + timedelta(days=days)) if days else None
            lead = "for " if days else ""
            text, msg = f"You snoozed this {lead}{label}.", f"Snoozed {cve_id} {lead}{label}."
        conn.execute(
            "INSERT INTO reviews(cve_id,status,until,base_cvss,base_exploited,updated_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET status=excluded.status, until=excluded.until, "
            "base_cvss=excluded.base_cvss, base_exploited=excluded.base_exploited, updated_at=excluded.updated_at",
            (cve_id, action, until, d["cvss"], int(bool(d["exploited"])), _iso(now)))
        log_event(conn, cve_id, text, now)
    else:
        return None
    conn.commit()
    return msg


def add_note(conn, cve_id: str, text: str, now: datetime | None = None) -> bool:
    text = " ".join(text.split())[:NOTE_MAX] if text else ""
    if not text:
        return False
    now = now or datetime.now(timezone.utc)
    conn.execute("INSERT INTO cve_notes(cve_id, text, created_at) VALUES (?,?,?)", (cve_id.upper(), text, _iso(now)))
    log_event(conn, cve_id.upper(), "You added a note.", now)
    conn.commit()
    return True


def notes_for(conn, cve_id: str) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT text, created_at FROM cve_notes WHERE cve_id = ? ORDER BY id DESC", (cve_id.upper(),))]


def history(conn, d: dict) -> list[dict]:
    """What happened to one CVE, newest first: coverage, exploitation reports, alerts and your own actions."""
    events = []
    seen_sources: set[str] = set()
    exploited_noted = False
    for a in sorted(d["articles"], key=lambda a: a["when_"]):
        if a["source"] in seen_sources:
            continue
        verb = "First seen in" if not seen_sources else "Also covered by"
        seen_sources.add(a["source"])
        events.append({"at": a["when_"], "text": f"{verb} {a['source']} ({a['kind'].lower()})."})
        if a["exploited"] and not exploited_noted:
            exploited_noted = True
            events.append({"at": a["when_"], "text": f"{a['source']} reported exploitation."})
    for al in d["alerts"]:
        events.append({"at": al["sent_at"], "text": f"Alert sent by rule “{al['rule']}”."})
    for r in conn.execute("SELECT at, text FROM cve_events WHERE cve_id = ?", (d["cve_id"],)):
        events.append({"at": r["at"], "text": r["text"]})
    events.sort(key=lambda e: e["at"], reverse=True)
    return events


def _annotate(conn, items: list[dict], by_cve: dict, now: datetime) -> list[dict]:
    reviews = load_reviews(conn)
    out = []
    for i in items:
        st = state_of(reviews.get(i["cve_id"]), i["cvss"], i["exploited"], now)
        why = by_cve.get(i["cve_id"])
        reasons = []
        if st["why"]:
            reasons.append((st["why"], True))
        if i["exploited"]:
            reasons.append(("Exploitation reported", True))
        if i["conflict"]:
            reasons.append((f"News quotes {min(i['conflict'])} to {max(i['conflict'])}", False))
        if i["alert_tone"] != "ok" and (i["exploited"] or (i["cvss"] or 0) >= 9.0):
            reasons.append(("No alert sent", True))
        out.append({**i, **st, "product": ", ".join(why["products"]) if why else "",
                    "watched": bool(why), "reasons": reasons})
    return out


def load(conn, conf: dict, now: datetime | None = None):
    """(triage result, annotated items worst first, exposure result): shared by Today and Threats."""
    now = now or datetime.now(timezone.utc)
    t = queries.triage(conn, conf["alert_rules"], now=now, limit=10 ** 6)
    x = queries.exposure(conn, conf["watchlist"], conf["alert_rules"], conf["sources"], now=now, t=t)
    return t, _annotate(conn, t["queue"], x["by_cve"], now), x


def today(conn, conf: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    t, items, x = load(conn, conf, now)
    decisions = [i for i in items if i["watched"] and i["state"] == "open"]
    worth = [i for i in items if not i["watched"] and i["state"] == "open" and i["exploited"]
             and (i["cvss"] or 0) >= WORTH_MIN_SCORE][:5]
    day_start = _iso(now.replace(hour=0, minute=0, second=0, microsecond=0))
    reviewed_today = conn.execute("SELECT COUNT(*) FROM reviews WHERE status='reviewed' AND updated_at >= ?",
                                  (day_start,)).fetchone()[0]
    return {
        "decisions": decisions, "worth": worth,
        "need_n": len(decisions), "watching": len(conf["watchlist"]),
        "exploited_week": t["kpis"]["exploited"],
        "rules_on": sum(1 for r in conf["alert_rules"] if r.get("enabled", True)),
        "feeds_ok": x["feeds_ok"], "feeds_active": x["feeds_active"],
        "snoozed_n": sum(1 for i in items if i["state"] == "snoozed"),
        "reviewed_today": reviewed_today,
        "all_clear": not decisions and not worth,
    }


TABS = [("open", "Needs attention"), ("snoozed", "Snoozed"), ("reviewed", "Reviewed"), ("all", "All")]


def threats(conn, conf: dict, tab="open", sev="All", q="", watch_only=False, page=1, per_page=10,
            now: datetime | None = None) -> dict:
    _, items, _ = load(conn, conf, now)
    q = (q or "").strip().lower()
    base = [i for i in items
            if (sev == "All" or i["severity"] == sev)
            and (not watch_only or i["watched"])
            and (not q or q in " ".join([i["cve_id"], i["title"] or "", i["affected"] or "", i["product"]]).lower())]
    counts = {k: sum(1 for i in base if k == "all" or i["state"] == k) for k, _ in TABS}
    shown = [i for i in base if tab == "all" or i["state"] == tab]
    pages = max(1, -(-len(shown) // per_page))
    page = min(max(1, page), pages)
    return {"rows": shown[(page - 1) * per_page: page * per_page], "total": len(shown), "counts": counts,
            "page": page, "pages": pages, "first": (page - 1) * per_page + 1 if shown else 0,
            "last": min(page * per_page, len(shown))}
