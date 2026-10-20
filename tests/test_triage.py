from datetime import datetime, timezone

from conftest import FakeSession
from secnews import db, queries
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)  # fixtures were published 5-7 October 2026


def loaded(conn, cfg, feeds):
    f = Fetcher(cfg, session=FakeSession({"https://a.example/feed": feeds["a"],
                                          "https://b.example/feed": feeds["b"]}), sleep=lambda s: None)
    scrape_all(conn, cfg, f)


def test_queue_is_ranked_by_score_then_unrated_last(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    t = queries.triage(conn, [], now=NOW)
    assert [q["cve_id"] for q in t["queue"]] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert t["queue"][0]["cvss"] == 9.8 and t["queue"][-1]["cvss"] is None


def test_kpis_and_conflict(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    t = queries.triage(conn, [], now=NOW)
    assert t["kpis"] == {"critical": 1, "exploited": 1, "disagree": 1, "critical_unalerted": 1}
    assert t["queue"][0]["conflict"] == [9.8, 7.5] and t["queue"][0]["sources"] == 2
    assert t["mix"] == {"Critical": 1, "High": 0, "Medium": 1, "Low": 0, "Unrated": 1}
    assert [d["cve_id"] for d in t["disagreements"]] == ["CVE-2026-0001"]


def test_alert_status_wording(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    first = lambda rules: queries.triage(conn, rules, now=NOW)["queue"][0]
    assert first([])["alert"] == "Not sent: no rule is on" and first([])["alert_tone"] == "bad"
    assert first([{"name": "R", "min_cvss": 7.0, "channels": ["slack"]}])["alert"] == "Pending"
    assert first([{"name": "R", "min_cvss": 9.9, "channels": ["slack"]}])["alert"] == "Below your rules"
    unrated = queries.triage(conn, [{"name": "R", "min_cvss": 7.0}], now=NOW)["queue"][-1]
    assert unrated["alert"] == "Waiting for a score"


def test_sent_alert_clears_the_unalerted_count(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    conn.execute("INSERT INTO alerts_sent(rule,cve_id,article_id,sent_at) VALUES ('Crit','CVE-2026-0001',1,'2026-10-08T00:00:00Z')")
    conn.commit()
    t = queries.triage(conn, [], now=NOW)
    assert t["kpis"]["critical_unalerted"] == 0
    assert t["queue"][0]["alert"] == "Sent: Crit" and t["queue"][0]["alert_tone"] == "ok"


def test_old_cves_fall_out_of_windows(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    later = datetime(2026, 10, 20, tzinfo=timezone.utc)  # 13+ days after publication
    t = queries.triage(conn, [], now=later)
    assert t["kpis"]["critical"] == 0 and len(t["queue"]) == 3      # still in the 30-day queue
    gone = queries.triage(conn, [], now=datetime(2026, 12, 30, tzinfo=timezone.utc))
    assert gone["queue"] == [] and gone["total"] == 0


def test_limit_caps_the_queue(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    t = queries.triage(conn, [], now=NOW, limit=2)
    assert len(t["queue"]) == 2 and t["total"] == 3
