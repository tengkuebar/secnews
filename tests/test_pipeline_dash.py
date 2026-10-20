from datetime import datetime, timezone

from conftest import FakeSession
from secnews import db, queries
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)  # fixtures were published 5-7 October 2026


def fetcher(cfg, routes):
    return Fetcher(cfg, session=FakeSession(routes), sleep=lambda s: None)


def test_ago_formats():
    assert queries.ago("2026-10-08T11:50:00Z", NOW) == "10m"
    assert queries.ago("2026-10-08T07:00:00Z", NOW) == "5h"
    assert queries.ago("2026-10-05T12:00:00Z", NOW) == "3d"
    assert queries.ago(None, NOW) == ""


def test_source_states_and_squares(conn, cfg, feeds):
    # Source A fails twice then recovers; Source B always works.
    routes = {"https://a.example/feed": (503, "down"), "https://b.example/feed": feeds["b"]}
    scrape_all(conn, cfg, fetcher(cfg, routes))
    cfg["sources"][0]["enabled"] = True
    p = queries.pipeline(conn, cfg["sources"], now=NOW)
    a, b = p["sources"]
    assert a["status"] == "failing" and a["tone"] == "bad" and a["cells"] == ["Failed"] and "503" in a["error"]
    assert b["status"] == "ok" and b["cells"] == ["OK"] and b["fetched"] == 1
    assert p["kpis"]["failed_24h"] == 1 and p["kpis"]["healthy"] == 1 and p["kpis"]["active"] == 2

    scrape_all(conn, cfg, fetcher(cfg, {"https://a.example/feed": feeds["a"], "https://b.example/feed": feeds["b"]}))
    a = queries.pipeline(conn, cfg["sources"], now=NOW)["sources"][0]
    assert a["status"] == "recovered" and a["cells"] == ["Failed", "OK"] and a["error"] is None


def test_disabled_and_never_run_sources(conn, cfg):
    cfg["sources"][1]["enabled"] = False
    p = queries.pipeline(conn, cfg["sources"], now=NOW)
    assert [s["status"] for s in p["sources"]] == ["no runs yet", "off"]
    assert p["kpis"]["active"] == 1 and p["kpis"]["newest_age"] == "never"


def test_a_switched_off_source_keeps_its_last_error_as_a_note_not_an_alarm(conn, cfg, feeds):
    scrape_all(conn, cfg, fetcher(cfg, {"https://a.example/feed": (503, "down"), "https://b.example/feed": feeds["b"]}))
    cfg["sources"][0]["enabled"] = False
    a = queries.pipeline(conn, cfg["sources"], now=NOW)["sources"][0]
    assert a["status"] == "off" and a["error"] is None and "503" in a["off_reason"]


def test_newest_age_per_source(conn, cfg, feeds):
    scrape_all(conn, cfg, fetcher(cfg, {"https://a.example/feed": feeds["a"], "https://b.example/feed": feeds["b"]}))
    a, b = queries.pipeline(conn, cfg["sources"], now=NOW)["sources"]
    assert a["newest_age"] == "27h"      # newest Source A item: 7 Oct 08:30
    assert b["newest_age"] == "2d"       # only Source B item: 5 Oct 14:00


def test_who_reports_first_counts_only_shared_cves(conn, cfg, feeds):
    scrape_all(conn, cfg, fetcher(cfg, {"https://a.example/feed": feeds["a"], "https://b.example/feed": feeds["b"]}))
    p = queries.pipeline(conn, cfg["sources"], now=NOW)
    # CVE-2026-0001 is in both feeds; Source A's article is earlier. The other CVEs have one source.
    assert p["first"] == [("Source A", 1)] and p["first_max"] == 1


def test_who_reports_first_ignores_old_cves(conn, cfg, feeds):
    scrape_all(conn, cfg, fetcher(cfg, {"https://a.example/feed": feeds["a"], "https://b.example/feed": feeds["b"]}))
    later = datetime(2026, 12, 30, tzinfo=timezone.utc)
    assert queries.pipeline(conn, cfg["sources"], now=later)["first"] == []


def test_alert_delivery_is_read_from_the_run_log(conn, cfg):
    db.log_run(conn, "Crit", "OK", kind="Alert", detail="Sent to slack, email for CVE-2026-0001")
    db.log_run(conn, "Crit", "OK", kind="Alert", detail="Sent to slack for CVE-2026-0002 (CVSS rose to 9.8)")
    db.log_run(conn, "Crit", "Failed", kind="Alert", error="email: Email failed: timed out", detail="1 alert(s) not sent")
    p = queries.pipeline(conn, cfg["sources"], now=datetime.now(timezone.utc))
    assert p["channels"] == {"slack": {"sent": 2, "failed": 0}, "email": {"sent": 1, "failed": 1}}
    assert p["kpis"]["undelivered"] == 1
