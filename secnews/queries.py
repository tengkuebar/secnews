"""Read-side queries shared by the CLI and the web dashboard."""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone

SEV_SQL = {
    "Critical": "x.cvss >= 9.0",
    "High": "x.cvss >= 7.0 AND x.cvss < 9.0",
    "Medium": "x.cvss >= 4.0 AND x.cvss < 7.0",
    "Low": "x.cvss > 0 AND x.cvss < 4.0",
    "Unrated": "x.cvss IS NULL",
}

_RANK = ("CASE WHEN x.cvss >= 9 THEN 4 WHEN x.cvss >= 7 THEN 3 WHEN x.cvss >= 4 THEN 2 "
         "WHEN x.cvss > 0 THEN 1 ELSE 0 END")


def severity_label(cvss):
    from .cve import severity_for
    return severity_for(cvss)


def search_articles(conn, q=None, severity=None, source=None, cve=None,
                    date_from=None, date_to=None, page=1, per_page=10):
    """Return (rows, total). Ranked by severity, then sources covering the CVE, then date."""
    where, args = [], []
    if q:
        like = f"%{q.lower()}%"
        where.append("(LOWER(a.title) LIKE ? OR LOWER(COALESCE(a.summary,'')) LIKE ? "
                     "OR LOWER(COALESCE(x.cve_list,'')) LIKE ?)")
        args += [like, like, like]
    if severity and severity in SEV_SQL:
        where.append(SEV_SQL[severity])
    if source:
        where.append("a.source = ?")
        args.append(source)
    if cve:
        where.append("a.id IN (SELECT article_id FROM cves WHERE cve_id = ?)")
        args.append(cve.upper())
    if date_from:
        where.append("COALESCE(a.published_at, a.scraped_at) >= ?")
        args.append(date_from)
    if date_to:
        where.append("COALESCE(a.published_at, a.scraped_at) <= ?")
        args.append(date_to + "T23:59:59Z" if len(date_to) == 10 else date_to)
    wsql = ("WHERE " + " AND ".join(where)) if where else ""
    base = f"""
        FROM articles a
        LEFT JOIN (SELECT article_id, MAX(cvss) AS cvss, MIN(cve_id) AS top_cve,
                          GROUP_CONCAT(cve_id, ', ') AS cve_list
                   FROM cves GROUP BY article_id) x ON x.article_id = a.id
        {wsql}"""
    total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
    page = max(1, int(page))
    rows = conn.execute(f"""
        SELECT a.*, x.cvss, x.top_cve, x.cve_list,
               COALESCE((SELECT COUNT(DISTINCT ar.source) FROM cves c2
                         JOIN articles ar ON ar.id = c2.article_id
                         WHERE c2.cve_id = x.top_cve), 0) AS seen
        {base}
        ORDER BY {_RANK} DESC, seen DESC, COALESCE(a.published_at, a.scraped_at) DESC
        LIMIT ? OFFSET ?""", args + [per_page, (page - 1) * per_page]).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["severity"] = severity_label(d["cvss"]) if d["top_cve"] else None
        out.append(d)
    return out, total


def list_sources(conn):
    return [r[0] for r in conn.execute("SELECT DISTINCT source FROM articles ORDER BY source")]


def cve_detail(conn, cve_id):
    cve_id = cve_id.upper()
    arts = conn.execute("""
        SELECT a.id, a.title, a.url, a.source, a.kind, a.summary, a.body,
               COALESCE(a.published_at, a.scraped_at) AS when_, c.cvss, c.affected, c.exploited,
               (SELECT COUNT(*) FROM cves c2 WHERE c2.article_id = a.id) AS n_cves
        FROM cves c JOIN articles a ON a.id = c.article_id
        WHERE c.cve_id = ? ORDER BY when_ DESC""", (cve_id,)).fetchall()
    if not arts:
        return None
    arts = [dict(a) for a in arts]
    scores = [a["cvss"] for a in arts if a["cvss"] is not None]
    vendor = [a["cvss"] for a in arts if a["kind"] == "Vendor advisory" and a["cvss"] is not None]
    shown = vendor[0] if vendor else (max(scores) if scores else None)
    distinct = sorted(set(scores), reverse=True)
    alerts = conn.execute("SELECT rule, sent_at FROM alerts_sent WHERE cve_id = ? ORDER BY sent_at DESC",
                          (cve_id,)).fetchall()
    return {
        "cve_id": cve_id,
        "cvss": shown,
        "severity": severity_label(shown),
        "score_source": "the vendor advisory" if vendor else ("the highest reported score" if scores else None),
        "conflict": distinct if len(distinct) > 1 else None,
        "affected": next((a["affected"] for a in arts if a["affected"]), None),
        "first_seen": min(a["when_"] for a in arts),
        "article_count": len(arts),
        "source_count": len({a["source"] for a in arts}),
        "exploited": any(a["exploited"] for a in arts),
        "articles": arts,
        "alerts": [dict(a) for a in alerts],
    }


ROUNDUP_CVES = 3     # an article naming more CVEs than this is a roundup, not about one product
ROUNDUP_WINDOW = 200  # characters either side of the CVE ID that count as "about this CVE"


def _haystack(d):
    """Text a watchlist product is matched against, for one CVE.

    A focused article (few CVEs) contributes its headline and summary. A roundup
    contributes only the text around this CVE's ID, so a vendor named elsewhere
    in the same article is not blamed on every CVE it lists.
    """
    parts = [d["affected"] or ""]
    for a in d["articles"]:
        if (a["n_cves"] or 0) <= ROUNDUP_CVES:
            parts.append((a["title"] or "") + " " + (a["summary"] or ""))
        else:
            body = a["body"] or ""
            for m in re.finditer(re.escape(d["cve_id"]), body, flags=re.IGNORECASE):
                parts.append(body[max(0, m.start() - ROUNDUP_WINDOW): m.end() + ROUNDUP_WINDOW])
    return " ".join(parts)


def alert_status(detail, rules):
    """Plain-language alert state for one CVE: (label, tone) with tone ok/bad/wait/none."""
    if detail["alerts"]:
        names = ", ".join(sorted({a["rule"] for a in detail["alerts"]}))
        return f"Sent: {names}", "ok"
    enabled = [r for r in rules if r.get("enabled", True)]
    if not enabled:
        return "Not sent: no rule is on", "bad"
    if detail["cvss"] is None:
        return "Waiting for a score", "wait"
    from .alerts import rule_matches
    if any(rule_matches(r, detail) for r in enabled):
        return "Pending", "wait"
    return "Below your rules", "none"


def triage(conn, rules, now=None, kpi_days=7, queue_days=30, limit=25):
    """Everything the triage dashboard shows, one row per CVE.

    The queue covers CVEs first seen in the last `queue_days`. Ranking: score,
    then exploitation reported, then number of sources, then newest.
    """
    now = now or datetime.now(timezone.utc)
    iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    queue_cut, kpi_cut = iso(now - timedelta(days=queue_days)), iso(now - timedelta(days=kpi_days))
    ids = [r[0] for r in conn.execute("SELECT DISTINCT cve_id FROM cves")]
    items = []
    for cid in ids:
        d = cve_detail(conn, cid)
        if not d or d["first_seen"] < queue_cut:
            continue
        label, tone = alert_status(d, rules)
        spread = (max(d["conflict"]) - min(d["conflict"])) if d["conflict"] else 0.0
        items.append({
            "cve_id": cid, "title": d["articles"][0]["title"], "cvss": d["cvss"],
            "severity": d["severity"], "exploited": d["exploited"],
            "sources": d["source_count"], "articles": d["article_count"],
            "conflict": d["conflict"] if spread >= 1.0 else None,
            "first_seen": d["first_seen"], "affected": d["affected"],
            "alert": label, "alert_tone": tone,
            "recent": d["first_seen"] >= kpi_cut,
            "haystack": _haystack(d),
        })
    items.sort(key=lambda i: i["first_seen"], reverse=True)  # newest first within ties (sort is stable)
    items.sort(key=lambda i: (-(i["cvss"] if i["cvss"] is not None else -1), -int(bool(i["exploited"])),
                              -i["sources"]))
    recent = [i for i in items if i["recent"]]
    critical = [i for i in recent if i["cvss"] is not None and i["cvss"] >= 9.0]
    mix = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unrated": 0}
    for i in items:
        mix[i["severity"]] += 1
    return {
        "kpis": {
            "critical": len(critical),
            "exploited": sum(1 for i in recent if i["exploited"]),
            "disagree": sum(1 for i in recent if i["conflict"]),
            "critical_unalerted": sum(1 for i in critical if i["alert_tone"] != "ok"),
        },
        "queue": items[:limit], "total": len(items), "mix": mix,
        "disagreements": [i for i in items if i["conflict"]][:5],
        "kpi_days": kpi_days, "queue_days": queue_days,
    }


def ago(iso, now):
    """Short relative age: 12m, 5h, 3d. Empty string if there is no timestamp."""
    if not iso:
        return ""
    t = datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    secs = max(0, int((now - t).total_seconds()))
    if secs < 3600:
        return f"{max(1, secs // 60)}m"
    if secs < 48 * 3600:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"


def pipeline(conn, sources, now=None, first_days=30, alert_days=7):
    """Everything the pipeline-health dashboard shows.

    `sources` is the configured list ({name, enabled, ...}). Each source gets its
    last 24 scrape runs (oldest first) so a failure streak is visible at a glance.
    """
    now = now or datetime.now(timezone.utc)
    iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    day_ago, first_cut, alert_cut = iso(now - timedelta(hours=24)), iso(now - timedelta(days=first_days)), iso(now - timedelta(days=alert_days))

    rows = []
    for s in sources:
        name, enabled = s["name"], s.get("enabled", True)
        runs = conn.execute("SELECT status, fetched, new, started_at FROM runs WHERE source=? AND kind='Scrape' "
                            "ORDER BY id DESC LIMIT 24", (name,)).fetchall()
        runs = list(reversed(runs))
        newest = conn.execute("SELECT MAX(COALESCE(published_at, scraped_at)) FROM articles WHERE source=?", (name,)).fetchone()[0]
        last = runs[-1] if runs else None
        if not enabled:
            status, tone = "off", "none"
        elif not last:
            status, tone = "no runs yet", "wait"
        elif last["status"] == "Failed":
            status, tone = "failing", "bad"
        elif any(r["status"] == "Failed" for r in runs):
            status, tone = "recovered", "wait"
        elif last["status"] == "Partial":
            status, tone = "partial", "wait"
        else:
            status, tone = "ok", "ok"
        rows.append({
            "name": name, "enabled": enabled, "status": status, "tone": tone,
            "cells": [r["status"] for r in runs],
            "fetched": last["fetched"] if last else 0,
            "new_24h": sum(r["new"] for r in runs if r["started_at"] >= day_ago),
            "newest_age": ago(newest, now) if newest else "never",
            "error": None,
        })
        rows[-1]["off_reason"] = None
        if last and last["status"] == "Failed":
            e = conn.execute("SELECT error FROM runs WHERE source=? AND kind='Scrape' AND status='Failed' "
                             "ORDER BY id DESC LIMIT 1", (name,)).fetchone()
            text = e[0] if e else None
            if enabled:
                rows[-1]["error"] = text
            else:
                rows[-1]["off_reason"] = text  # switched off: keep the last error as context, not as an alarm

    active = [r for r in rows if r["enabled"]]
    newest_any = conn.execute("SELECT MAX(COALESCE(published_at, scraped_at)) FROM articles").fetchone()[0]

    # Who reports first: among CVEs covered by two or more sources, which source's article came first.
    firsts: dict[str, int] = {}
    for cid, in conn.execute("SELECT cve_id FROM cves GROUP BY cve_id HAVING COUNT(DISTINCT article_id) > 1").fetchall():
        arts = conn.execute("SELECT a.source, COALESCE(a.published_at, a.scraped_at) AS t FROM cves c "
                            "JOIN articles a ON a.id = c.article_id WHERE c.cve_id = ? ORDER BY t", (cid,)).fetchall()
        if len({a["source"] for a in arts}) < 2 or arts[0]["t"] < first_cut:
            continue
        firsts[arts[0]["source"]] = firsts.get(arts[0]["source"], 0) + 1
    first = sorted(firsts.items(), key=lambda kv: -kv[1])

    # Alert delivery per channel, read from the alert rows of the run log.
    chans: dict[str, dict] = {}
    for r in conn.execute("SELECT status, detail, error FROM runs WHERE kind='Alert' AND started_at >= ?", (alert_cut,)):
        if r["status"] == "OK" and r["detail"] and r["detail"].startswith("Sent to "):
            for ch in r["detail"][8:].split(" for ")[0].split(","):
                chans.setdefault(ch.strip(), {"sent": 0, "failed": 0})["sent"] += 1
        elif r["status"] == "Failed" and r["error"]:
            for part in r["error"].split("; "):
                ch = part.split(":")[0].strip()
                if ch:
                    chans.setdefault(ch, {"sent": 0, "failed": 0})["failed"] += 1

    failed_24h = conn.execute("SELECT COUNT(*) FROM runs WHERE kind='Scrape' AND status='Failed' AND started_at >= ?", (day_ago,)).fetchone()[0]
    return {
        "sources": rows,
        "kpis": {
            "healthy": sum(1 for r in active if r["tone"] == "ok"), "active": len(active),
            "failed_24h": failed_24h,
            "newest_age": ago(newest_any, now) if newest_any else "never",
            "undelivered": sum(c["failed"] for c in chans.values()),
        },
        "first": first, "first_max": first[0][1] if first else 0, "first_days": first_days,
        "channels": chans, "alert_days": alert_days,
    }


def watch_terms(item):
    """Terms a watchlist entry matches on: its name plus any extra terms. Lower-cased, 3+ characters."""
    terms = [item["name"]] + list(item.get("match", []))
    out = []
    for t in terms:
        t = " ".join(str(t).split()).lower()
        if len(t) >= 3 and t not in out:
            out.append(t)
    return out


def _term_regex(terms):
    # Whole-word match, so "ios" does not match "scenarios". Terms under 3 characters are never used.
    return re.compile("|".join(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])" for t in terms), re.IGNORECASE)


def watch_names(detail, watchlist):
    """Names of watchlist products that one CVE's text mentions (a hint, not proof)."""
    hay = _haystack(detail)
    return [w["name"] for w in watchlist if watch_terms(w) and _term_regex(watch_terms(w)).search(hay)]


def exposure(conn, watchlist, rules, sources, now=None, days=30, t=None):
    """Which watched products have matching CVEs, worst first. Matching is by name in text, so it is a hint.

    Pass `t` (a triage result covering at least `days`) to avoid computing it twice.
    """
    now = now or datetime.now(timezone.utc)
    t = t or triage(conn, rules, now=now, queue_days=days, limit=100000)
    products = []
    for w in watchlist:
        terms = watch_terms(w)
        rx = _term_regex(terms) if terms else None
        hits = []
        for i in t["queue"]:
            m = rx.search(i["haystack"]) if rx else None
            if m:
                hs = i["haystack"]
                snip = excerpt(" ".join(hs[max(0, m.start() - 70): m.end() + 70].split()), 160)
                hits.append({**i, "snippet": snip, "matched": m.group(0)})
        scores = [i["cvss"] for i in hits if i["cvss"] is not None]
        top = max(scores) if scores else None
        if not hits:
            level, tone = "Quiet", "ok"
        elif top is None:
            level, tone = "Unrated", "none"
        else:
            level = severity_label(top)
            tone = "bad" if top >= 7.0 else "wait"
        products.append({"name": w["name"], "terms": terms, "hits": hits, "top": top,
                         "level": level, "tone": tone, "exploited": any(i["exploited"] for i in hits)})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unrated": 4, "Quiet": 5}
    products.sort(key=lambda p: (order[p["level"]], p["name"].lower()))
    severe = [p for p in products if p["tone"] == "bad"]
    by_cve: dict[str, dict] = {}
    for p in products:
        for i in p["hits"]:
            m = by_cve.setdefault(i["cve_id"], {**i, "products": [], "why": []})
            m["products"].append(p["name"])
            m["why"].append({"product": p["name"], "matched": i["matched"], "snippet": i["snippet"]})
    matches = [{**m, "product": ", ".join(m["products"])} for m in by_cve.values()]
    matches.sort(key=lambda m: (-(m["cvss"] if m["cvss"] is not None else -1), -int(bool(m["exploited"]))))
    pipe = pipeline(conn, sources, now=now)["kpis"]
    return {
        "products": products, "severe": len(severe), "total": len(products),
        "quiet": sum(1 for p in products if p["level"] == "Quiet"),
        "matches": matches[:8], "match_total": len(matches), "by_cve": by_cve,
        "feeds_ok": pipe["healthy"], "feeds_active": pipe["active"], "days": days,
    }


def excerpt(text, limit=200):
    """Trim to `limit` characters at a word boundary and say so with an ellipsis."""
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:.-")
    return (cut or text[:limit]) + "…"


def _rolling_week_counts(conn, now, weeks=8):
    """Unique CVEs by the 7-day window in which each was first seen, oldest first."""
    firsts = conn.execute("SELECT MIN(COALESCE(a.published_at, a.scraped_at)) FROM cves c "
                          "JOIN articles a ON a.id = c.article_id GROUP BY c.cve_id").fetchall()
    counts = [0] * weeks
    for (t,) in firsts:
        when = datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        idx = int((now - when).total_seconds() // (7 * 86400))
        if 0 <= idx < weeks:
            counts[weeks - 1 - idx] += 1
    return counts


def briefing(conn, rules, sources, now=None):
    """The weekly briefing: rolling last 7 days against the 7 before, built only from stored data."""
    now = now or datetime.now(timezone.utc)
    iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    cut7, cut14 = iso(now - timedelta(days=7)), iso(now - timedelta(days=14))
    t = triage(conn, rules, now=now, queue_days=14, limit=100000)
    week = [i for i in t["queue"] if i["first_seen"] >= cut7]       # ranked by score, then exploitation, then sources
    # "The one to act on": a CVE that is being exploited and scores 7.0+ comes before a higher score with no
    # exploitation. The sort is stable, so the order inside each group is unchanged.
    week.sort(key=lambda i: not (i["exploited"] and (i["cvss"] or 0) >= 7.0))
    prev = [i for i in t["queue"] if i["first_seen"] < cut7]
    read = conn.execute("SELECT COUNT(*), COUNT(DISTINCT source) FROM articles WHERE scraped_at >= ?", (cut7,)).fetchone()

    lead = None
    if week:
        top = week[0]
        d = cve_detail(conn, top["cve_id"])
        reporting = {a["source"] for a in d["articles"] if a["exploited"]}
        basis = "vendor advisory score" if d["score_source"] == "the vendor advisory" else "highest score quoted"
        parts = [f"{top['cve_id']} scores {d['cvss']} ({basis})." if d["cvss"] is not None
                 else f"{top['cve_id']} has no published score yet."]
        if top["conflict"]:
            parts.append("Sources quote different scores: " + " vs ".join(str(x) for x in top["conflict"]) + ".")
        parts.append(f"{len(reporting)} of {d['source_count']} sources report exploitation." if reporting
                     else "No source reports exploitation.")
        parts.append("An alert has been sent." if top["alert_tone"] == "ok" else "No alert has been sent.")
        first_article = d["articles"][0]
        lead = {**top, "deck": " ".join(parts), "url": first_article["url"], "source": first_article["source"]}

    more = []
    for i in week[1:4]:
        d = cve_detail(conn, i["cve_id"])
        a = d["articles"][0]
        more.append({**i, "url": a["url"], "source": a["source"], "summary": excerpt(a["summary"] or "", 200)})

    alerts_week = conn.execute("SELECT COUNT(*) FROM alerts_sent WHERE sent_at >= ?", (cut7,)).fetchone()[0]
    changes = []
    for r in conn.execute("SELECT cve_id, rule, last_cvss, last_exploited FROM alerts_sent ORDER BY sent_at DESC LIMIT 200"):
        d = cve_detail(conn, r["cve_id"])
        if d and d["cvss"] is not None and r["last_cvss"] is not None and d["cvss"] > r["last_cvss"]:
            changes.append({"k": "Score raised:", "t": f"{r['cve_id']} was {r['last_cvss']} when '{r['rule']}' alerted, and is now {d['cvss']}."})
        elif d and d["exploited"] and not r["last_exploited"]:
            changes.append({"k": "Exploitation reported:", "t": f"{r['cve_id']} had no exploitation report when '{r['rule']}' alerted. It does now."})
    for s in pipeline(conn, sources, now=now)["sources"]:
        if s["tone"] == "bad":
            changes.append({"k": "Source failing:", "t": f"{s['name']} is failing ({s['error'] or 'no detail'})."})
        elif s["status"] == "off" and s["off_reason"]:
            changes.append({"k": "Source off:", "t": f"{s['name']} is switched off. Its last run failed: {s['off_reason']}."})

    new_n, prev_n = len(week), len(prev)
    delta = ("Up from " if new_n > prev_n else "Down from " if new_n < prev_n else "Same as ") + f"{prev_n} the week before."
    return {
        "start": (now - timedelta(days=7)).date(), "end": now.date(),
        "articles_read": read[0], "sources_n": read[1],
        "lead": lead, "more": more,
        "numbers": {
            "new": new_n, "new_note": delta,
            "exploited": sum(1 for i in week if i["exploited"]),
            "disagree": sum(1 for i in week if i["conflict"]),
            "alerts": alerts_week,
        },
        "weeks": _rolling_week_counts(conn, now), "changes": changes,
    }


def weekly_cve_counts(conn, weeks=8, today=None):
    """Unique CVEs by the week they were first seen, oldest first (Monday weeks)."""
    today = today or date.today()
    start_this = today - timedelta(days=today.weekday())
    starts = [start_this - timedelta(weeks=i) for i in range(weeks - 1, -1, -1)]
    first = conn.execute("""
        SELECT c.cve_id, MIN(COALESCE(a.published_at, a.scraped_at)) AS first_seen
        FROM cves c JOIN articles a ON a.id = c.article_id GROUP BY c.cve_id""").fetchall()
    counts = [0] * weeks
    for r in first:
        d = datetime.strptime(r["first_seen"][:10], "%Y-%m-%d").date()
        for i in range(weeks - 1, -1, -1):
            if d >= starts[i]:
                if d < starts[i] + timedelta(weeks=1):
                    counts[i] += 1
                break
    return counts


def stats(conn):
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    week = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    one = lambda sql, a=(): conn.execute(sql, a).fetchone()[0]
    return {
        "new_24h": one("SELECT COUNT(*) FROM articles WHERE scraped_at >= ?", (since,)),
        "unique_cves": one("SELECT COUNT(DISTINCT cve_id) FROM cves"),
        "high_or_worse": one("SELECT COUNT(DISTINCT cve_id) FROM cves WHERE cvss >= 7.0"),
        "alerts_week": one("SELECT COUNT(*) FROM alerts_sent WHERE sent_at >= ?", (week,)),
    }


def list_runs(conn, kind=None, failures=False, limit=200):
    where, args = [], []
    if kind:
        where.append("kind = ?")
        args.append(kind)
    if failures:
        where.append("status = 'Failed'")
    sql = "SELECT * FROM runs " + (("WHERE " + " AND ".join(where)) if where else "") + \
          " ORDER BY id DESC LIMIT ?"
    return [dict(r) for r in conn.execute(sql, args + [limit])]


def run_stats(conn):
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    one = lambda sql, a=(): conn.execute(sql, a).fetchone()[0]
    return {
        "scrapes_24h": one("SELECT COUNT(*) FROM runs WHERE kind='Scrape' AND started_at >= ?", (since,)),
        "failed_24h": one("SELECT COUNT(*) FROM runs WHERE status='Failed' AND started_at >= ?", (since,)),
        "alerts_24h": one("SELECT COUNT(*) FROM runs WHERE kind='Alert' AND status='OK' AND started_at >= ?", (since,)),
        "last_ok": one("SELECT MAX(started_at) FROM runs WHERE kind='Scrape' AND status IN ('OK','Partial')"),
    }


def source_health(conn, source_names):
    out = []
    for name in source_names:
        r = conn.execute("SELECT status, started_at, error FROM runs WHERE source=? AND kind='Scrape' "
                         "ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        out.append({"name": name, "status": r["status"] if r else "No runs yet",
                    "when": r["started_at"] if r else None, "error": r["error"] if r else None})
    return out
