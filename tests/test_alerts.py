from datetime import datetime

from conftest import FakeSession
from secnews import db
from secnews.alerts import (SendError, in_quiet_hours, process_alerts, rule_matches, send_slack,
                            send_test, send_webhook)
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all


def scraped(conn, cfg, feeds):
    f = Fetcher(cfg, session=FakeSession({"https://a.example/feed": feeds["a"],
                                          "https://b.example/feed": feeds["b"]}), sleep=lambda s: None)
    scrape_all(conn, cfg, f)


class Recorder:
    def __init__(self, fail=False):
        self.msgs, self.fail = [], fail

    def __call__(self, cfg, msg):
        if self.fail:
            raise SendError("boom")
        self.msgs.append(msg)


NOON = datetime(2026, 10, 8, 12, 0)


def test_quiet_hours_wrap_midnight(cfg):
    assert in_quiet_hours(cfg, datetime(2026, 10, 8, 23, 0))
    assert in_quiet_hours(cfg, datetime(2026, 10, 8, 3, 0))
    assert not in_quiet_hours(cfg, NOON)


def test_rule_matches_conditions():
    d = {"cvss": 7.5, "articles": [{"source": "X", "title": "Acme flaw", "summary": ""}], "affected": None}
    assert rule_matches({"min_cvss": 7.0}, d)
    assert not rule_matches({"min_cvss": 9.0}, d)
    assert rule_matches({"keywords": ["acme"]}, d)
    assert not rule_matches({"keywords": ["fortinet"]}, d)
    assert not rule_matches({"sources": ["Y"]}, d)
    unrated = dict(d, cvss=None)
    assert not rule_matches({"min_cvss": 7.0}, unrated)
    assert rule_matches({"min_cvss": 7.0, "unrated": "alert"}, unrated)


def test_two_sources_one_alert_then_score_rise_realerts(conn, cfg, feeds):
    cfg["alert_rules"] = [{"name": "Crit", "min_cvss": 7.0, "channels": ["slack"]}]
    scraped(conn, cfg, feeds)  # CVE-2026-0001 appears in both sources (9.8 and 7.5)
    rec = Recorder()
    sent = process_alerts(conn, cfg, {"slack": rec}, NOON)
    assert [s["cve_id"] for s in sent] == ["CVE-2026-0001"]
    assert len(rec.msgs) == 1
    # Run again: nothing new, nothing sent.
    assert process_alerts(conn, cfg, {"slack": rec}, NOON) == []
    # A later article pushes the score above what we last alerted on.
    conn.execute("UPDATE alerts_sent SET last_cvss = 7.5")
    conn.commit()
    sent = process_alerts(conn, cfg, {"slack": rec}, NOON)
    assert len(sent) == 1 and "rose" in sent[0]["update"]
    assert len(rec.msgs) == 2


def test_exploitation_first_reported_realerts(conn, cfg, feeds):
    cfg["alert_rules"] = [{"name": "Crit", "min_cvss": 7.0, "channels": ["slack"]}]
    scraped(conn, cfg, feeds)
    rec = Recorder()
    process_alerts(conn, cfg, {"slack": rec}, NOON)
    conn.execute("UPDATE alerts_sent SET last_exploited = 0")
    conn.commit()
    sent = process_alerts(conn, cfg, {"slack": rec}, NOON)
    assert sent and "exploitation" in sent[0]["update"]


def test_realert_can_be_disabled(conn, cfg, feeds):
    cfg["alert_rules"] = [{"name": "Crit", "min_cvss": 7.0, "channels": ["slack"], "realert_on_change": False}]
    scraped(conn, cfg, feeds)
    rec = Recorder()
    process_alerts(conn, cfg, {"slack": rec}, NOON)
    conn.execute("UPDATE alerts_sent SET last_cvss = 1.0")
    conn.commit()
    assert process_alerts(conn, cfg, {"slack": rec}, NOON) == []


def test_quiet_hours_defer_then_send_later(conn, cfg, feeds):
    cfg["alert_rules"] = [{"name": "Crit", "min_cvss": 7.0, "channels": ["slack"]}]
    scraped(conn, cfg, feeds)
    rec = Recorder()
    assert process_alerts(conn, cfg, {"slack": rec}, datetime(2026, 10, 8, 23, 30)) == []
    assert rec.msgs == []
    assert len(process_alerts(conn, cfg, {"slack": rec}, NOON)) == 1


def test_failed_send_is_logged_and_retried(conn, cfg, feeds):
    cfg["alert_rules"] = [{"name": "Crit", "min_cvss": 7.0, "channels": ["slack"]}]
    scraped(conn, cfg, feeds)
    assert process_alerts(conn, cfg, {"slack": Recorder(fail=True)}, NOON) == []
    row = conn.execute("SELECT * FROM runs WHERE kind='Alert'").fetchone()
    assert row["status"] == "Failed" and "boom" in row["error"]
    assert len(process_alerts(conn, cfg, {"slack": Recorder()}, NOON)) == 1


def test_broken_channel_logs_one_failure_per_cycle_not_per_cve(conn, cfg, feeds):
    cfg["alert_rules"] = [{"name": "All", "min_cvss": 1.0, "channels": ["slack"]}]
    scraped(conn, cfg, feeds)  # several matching CVEs
    process_alerts(conn, cfg, {"slack": Recorder(fail=True)}, NOON)
    rows = conn.execute("SELECT * FROM runs WHERE kind='Alert'").fetchall()
    assert len(rows) == 1 and "not sent" in rows[0]["detail"]


def test_disabled_rule_is_ignored(conn, cfg, feeds):
    cfg["alert_rules"] = [{"name": "Off", "enabled": False, "min_cvss": 1, "channels": ["slack"]}]
    scraped(conn, cfg, feeds)
    assert process_alerts(conn, cfg, {"slack": Recorder()}, NOON) == []


def test_slack_and_webhook_post_to_stub(cfg, monkeypatch):
    class R:
        status_code = 200

    calls = []
    post = lambda url, json=None, timeout=None: calls.append((url, json)) or R()
    monkeypatch.setenv("S_HOOK", "http://localhost/slack")
    monkeypatch.setenv("W_URL", "http://localhost/hook")
    cfg["channels"] = {"slack": {"webhook_env": "S_HOOK"}, "webhook": {"url_env": "W_URL"}}
    send_slack(cfg, {"text": "hi"}, post=post)
    send_webhook(cfg, {"text": "hi", "cve_id": "X"}, post=post)
    assert calls[0] == ("http://localhost/slack", {"text": "hi"})
    assert calls[1][0] == "http://localhost/hook" and calls[1][1]["cve_id"] == "X"


def test_missing_secret_is_a_clear_error(cfg, monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    cfg["channels"] = {"slack": {"webhook_env": "NOPE"}}
    ok, msg = send_test(cfg, "slack")
    assert not ok and "not set" in msg
