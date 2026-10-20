"""Alert rules and senders (Slack, generic webhook, email).

Rules alert once per CVE. A later article about the same CVE adds nothing;
a higher CVSS or a first exploitation report triggers one update alert.
"""
from __future__ import annotations

import logging
import smtplib
from datetime import datetime, time as dtime, timedelta, timezone
from email.message import EmailMessage

import requests

from . import db
from .config import secret
from .queries import cve_detail

log = logging.getLogger("secnews.alerts")


# ---------- rule matching ----------

def rule_matches(rule: dict, detail: dict) -> bool:
    cvss = detail["cvss"]
    min_cvss = rule.get("min_cvss")
    if min_cvss is not None:
        if cvss is None:
            if rule.get("unrated", "skip") != "alert":
                return False
        elif cvss < float(min_cvss):
            return False
    sources = rule.get("sources")
    if sources and not any(a["source"] in sources for a in detail["articles"]):
        return False
    kws = [k.lower() for k in rule.get("keywords", []) if k]
    if kws:
        hay = " ".join([(a["title"] or "") + " " + (a["summary"] or "") for a in detail["articles"]]
                       + [detail["affected"] or ""]).lower()
        if not any(k in hay for k in kws):
            return False
    return True


def in_quiet_hours(cfg: dict, now: datetime | None = None) -> bool:
    q = cfg["scheduler"].get("quiet_hours") or {}
    if not q.get("start") or not q.get("end"):
        return False
    now = now or datetime.now()
    h1, m1 = map(int, q["start"].split(":"))
    h2, m2 = map(int, q["end"].split(":"))
    s, e, t = dtime(h1, m1), dtime(h2, m2), now.time()
    if s == e:
        return False
    return (s <= t < e) if s < e else (t >= s or t < e)


# ---------- message ----------

def build_message(rule: dict, detail: dict, update: str | None = None) -> dict:
    first = detail["articles"][0]
    score = f"CVSS {detail['cvss']}" if detail["cvss"] is not None else "unrated"
    lines = [f"[{rule['name']}] {detail['cve_id']}: {detail['severity']} ({score})"
             + (f" - UPDATE: {update}" if update else ""),
             first["title"]]
    if detail["affected"]:
        lines.append(f"Affected: {detail['affected']}")
    if detail["exploited"]:
        lines.append("Exploitation reported.")
    lines.append(f"Covered by {detail['source_count']} source(s). {first['url']}")
    return {"text": "\n".join(lines), "cve_id": detail["cve_id"], "severity": detail["severity"],
            "cvss": detail["cvss"], "exploited": detail["exploited"], "rule": rule["name"],
            "url": first["url"], "update": update}


# ---------- senders ----------

class SendError(Exception):
    pass


def send_slack(cfg, msg, post=requests.post):
    url = secret(cfg["channels"].get("slack", {}).get("webhook_env"))
    if not url:
        raise SendError("Slack webhook env var is not set")
    r = post(url, json={"text": msg["text"]}, timeout=10)
    if r.status_code >= 300:
        raise SendError(f"Slack returned HTTP {r.status_code}")


def send_webhook(cfg, msg, post=requests.post):
    url = secret(cfg["channels"].get("webhook", {}).get("url_env"))
    if not url:
        raise SendError("Webhook URL env var is not set")
    r = post(url, json=msg, timeout=10)
    if r.status_code >= 300:
        raise SendError(f"Webhook returned HTTP {r.status_code}")


def send_email(cfg, msg, smtp_cls=smtplib.SMTP):
    c = cfg["channels"].get("email", {})
    if not c.get("smtp_host") or not c.get("to"):
        raise SendError("Email is not configured")
    m = EmailMessage()
    m["Subject"] = msg["text"].splitlines()[0][:150]
    m["From"] = c.get("username") or c["to"]
    m["To"] = c["to"]
    m.set_content(msg["text"])
    try:
        with smtp_cls(c["smtp_host"], int(c.get("smtp_port", 587)), timeout=15) as s:
            s.starttls()
            pw = secret(c.get("password_env"))
            if c.get("username") and pw:
                s.login(c["username"], pw)
            s.send_message(m)
    except (OSError, smtplib.SMTPException) as e:
        raise SendError(f"Email failed: {e}")


SENDERS = {"slack": send_slack, "webhook": send_webhook, "email": send_email}


def send_test(cfg, channel, senders=None):
    """Send a clearly-labelled test message. Returns (ok, message)."""
    senders = senders or SENDERS
    msg = {"text": "[secnews] Test message. Your alert channel works.", "test": True,
           "cve_id": None, "rule": "test"}
    try:
        senders[channel](cfg, msg)
        return True, "Sent"
    except SendError as e:
        return False, str(e)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ---------- engine ----------

def process_alerts(conn, cfg, senders=None, now: datetime | None = None, lookback_days=7) -> list[dict]:
    """Evaluate rules for recently seen CVEs and send what is due. Returns sent records."""
    rules = [r for r in cfg.get("alert_rules", []) if r.get("enabled", True)]
    if not rules or in_quiet_hours(cfg, now):
        return []
    senders = senders or SENDERS
    since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cve_ids = [r[0] for r in conn.execute(
        "SELECT DISTINCT c.cve_id FROM cves c JOIN articles a ON a.id = c.article_id "
        "WHERE a.scraped_at >= ?", (since,))]
    sent = []
    dead: dict[str, str] = {}          # channel -> error, for this cycle only
    failures: dict[tuple, list] = {}   # (rule, channel) -> [error, count]
    for cid in cve_ids:
        detail = cve_detail(conn, cid)
        for rule in rules:
            if not rule_matches(rule, detail):
                continue
            prev = conn.execute("SELECT * FROM alerts_sent WHERE rule=? AND cve_id=?",
                                (rule["name"], cid)).fetchone()
            update = None
            if prev:
                if not rule.get("realert_on_change", True):
                    continue
                if detail["cvss"] is not None and (prev["last_cvss"] is None or detail["cvss"] > prev["last_cvss"]):
                    update = f"CVSS rose to {detail['cvss']}"
                elif detail["exploited"] and not prev["last_exploited"]:
                    update = "exploitation now reported"
                else:
                    continue
            msg = build_message(rule, detail, update)
            ok = []
            for ch in rule.get("channels", []):
                if ch in dead:  # already failed this cycle: do not retry or log per CVE
                    failures.setdefault((rule["name"], ch), [dead[ch], 0])[1] += 1
                    continue
                try:
                    senders[ch](cfg, msg)
                    ok.append(ch)
                except Exception as e:
                    dead[ch] = str(e)
                    failures.setdefault((rule["name"], ch), [str(e), 0])[1] += 1
            if ok:
                with db.transaction(conn):
                    conn.execute(
                        "INSERT INTO alerts_sent(rule,cve_id,article_id,sent_at,last_cvss,last_exploited)"
                        " VALUES (?,?,?,?,?,?) ON CONFLICT(rule,cve_id) DO UPDATE SET"
                        " sent_at=excluded.sent_at, last_cvss=excluded.last_cvss,"
                        " last_exploited=excluded.last_exploited, article_id=excluded.article_id",
                        (rule["name"], cid, detail["articles"][0]["id"], db.now(),
                         detail["cvss"], 1 if detail["exploited"] else 0))
                sent.append({"rule": rule["name"], "cve_id": cid, "channels": ok, "update": update})
            if ok:
                db.log_run(conn, rule["name"], "OK", kind="Alert",
                           detail=f"Sent to {', '.join(ok)} for {cid}" + (f" ({update})" if update else ""))
    for (rname, ch), (err, count) in failures.items():
        db.log_run(conn, rname, "Failed", kind="Alert", error=f"{ch}: {err}",
                   detail=f"{count} alert(s) not sent")
    return sent
