from datetime import datetime, timedelta, timezone

from conftest import FakeSession
from secnews import queries, workflow
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)  # fixtures were published 5-7 October 2026


def loaded(conn, cfg, feeds):
    f = Fetcher(cfg, session=FakeSession({"https://a.example/feed": feeds["a"],
                                          "https://b.example/feed": feeds["b"]}), sleep=lambda s: None)
    scrape_all(conn, cfg, f)


def conf(cfg, watchlist=()):
    return {**cfg, "alert_rules": [], "watchlist": list(watchlist)}


def state(conn, cve, cvss, exploited, now=NOW):
    return workflow.state_of(workflow.load_reviews(conn).get(cve), cvss, exploited, now)


def test_unreviewed_cve_is_open(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    assert state(conn, "CVE-2026-0001", 9.8, True)["state"] == "open"


def test_reviewed_leaves_and_returns_when_score_rises_or_exploitation_appears(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    assert workflow.decide(conn, "CVE-2026-0002", "reviewed", now=NOW) == "Marked CVE-2026-0002 as reviewed."
    base = queries.cve_detail(conn, "CVE-2026-0002")
    assert state(conn, "CVE-2026-0002", base["cvss"], base["exploited"])["state"] == "reviewed"
    up = state(conn, "CVE-2026-0002", base["cvss"] + 1, base["exploited"])
    assert up["state"] == "open" and up["why"].startswith("Back in the queue: score rose from")
    assert state(conn, "CVE-2026-0002", base["cvss"] - 1, base["exploited"])["state"] == "reviewed"   # a fall is not news
    newly = state(conn, "CVE-2026-0002", base["cvss"], True)
    assert newly["state"] == "open" and "exploitation now reported" in newly["why"]


def test_snooze_ends_on_time_and_until_change_waits_for_a_change(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    workflow.decide(conn, "CVE-2026-0002", "snoozed", snooze="3", now=NOW)
    cvss = queries.cve_detail(conn, "CVE-2026-0002")["cvss"]
    s = state(conn, "CVE-2026-0002", cvss, False, NOW + timedelta(days=2))
    assert s["state"] == "snoozed" and s["label"] == "Snoozed until 11 Oct"
    ended = state(conn, "CVE-2026-0002", cvss, False, NOW + timedelta(days=3, seconds=1))
    assert ended["state"] == "open" and "snooze ended" in ended["why"]

    workflow.decide(conn, "CVE-2026-0002", "snoozed", snooze="change", now=NOW)
    assert state(conn, "CVE-2026-0002", cvss, False, NOW + timedelta(days=400))["state"] == "snoozed"
    assert state(conn, "CVE-2026-0002", cvss - 1, False)["state"] == "open"


def test_unrated_cve_reviewed_returns_when_a_score_appears(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    workflow.decide(conn, "CVE-2026-0003", "reviewed", now=NOW)
    assert state(conn, "CVE-2026-0003", None, False)["state"] == "reviewed"
    assert "score published" in state(conn, "CVE-2026-0003", 6.1, False)["why"]


def test_decide_rejects_unknown_input_and_reopen_clears(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    assert workflow.decide(conn, "CVE-2000-0000", "reviewed") is None
    assert workflow.decide(conn, "CVE-2026-0001", "bogus") is None
    assert workflow.decide(conn, "CVE-2026-0001", "snoozed", snooze="99") is None
    workflow.decide(conn, "CVE-2026-0001", "reviewed", now=NOW)
    workflow.decide(conn, "CVE-2026-0001", "open", now=NOW)
    assert workflow.load_reviews(conn) == {}


def test_notes_are_trimmed_capped_and_logged(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    assert not workflow.add_note(conn, "CVE-2026-0001", "   ")
    assert workflow.add_note(conn, "CVE-2026-0001", "  patched   on staging " + "x" * 600, now=NOW)
    (n,) = workflow.notes_for(conn, "CVE-2026-0001")
    assert n["text"].startswith("patched on staging") and len(n["text"]) == workflow.NOTE_MAX
    d = queries.cve_detail(conn, "CVE-2026-0001")
    assert any(e["text"] == "You added a note." for e in workflow.history(conn, d))


def test_history_lists_coverage_and_exploitation_newest_first(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    h = workflow.history(conn, queries.cve_detail(conn, "CVE-2026-0001"))
    texts = [e["text"] for e in h]
    assert any(t.startswith("First seen in") for t in texts) and any(t.startswith("Also covered by") for t in texts)
    assert any("reported exploitation" in t for t in texts)
    assert [e["at"] for e in h] == sorted((e["at"] for e in h), reverse=True)


def test_today_splits_watchlist_decisions_from_worth_a_look(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    t = workflow.today(conn, conf(cfg, [{"name": "Widget Server"}]), now=NOW)
    assert [i["cve_id"] for i in t["decisions"]] == ["CVE-2026-0002", "CVE-2026-0003"]     # one article names both\n    assert t["decisions"][0]["product"] == "Widget Server"
    assert [i["cve_id"] for i in t["worth"]] == ["CVE-2026-0001"]           # critical and exploited, not watched
    assert t["need_n"] == 2 and not t["all_clear"]
    for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
        workflow.decide(conn, cve, "reviewed", now=NOW)
    t = workflow.today(conn, conf(cfg, [{"name": "Widget Server"}]), now=NOW)
    assert t["all_clear"] and t["reviewed_today"] == 3


def test_threats_filters_counts_and_pages(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    c = conf(cfg, [{"name": "Widget Server"}])
    th = workflow.threats(conn, c, now=NOW)
    assert th["total"] == 3 and th["counts"] == {"open": 3, "snoozed": 0, "reviewed": 0, "all": 3}
    assert [i["cve_id"] for i in workflow.threats(conn, c, watch_only=True, now=NOW)["rows"]] == ["CVE-2026-0002", "CVE-2026-0003"]
    assert [i["cve_id"] for i in workflow.threats(conn, c, sev="Critical", now=NOW)["rows"]] == ["CVE-2026-0001"]
    assert workflow.threats(conn, c, q="widget", now=NOW)["total"] == 2
    workflow.decide(conn, "CVE-2026-0001", "reviewed", now=NOW)
    th = workflow.threats(conn, c, now=NOW)
    assert th["counts"]["open"] == 2 and th["counts"]["reviewed"] == 1
    paged = workflow.threats(conn, c, tab="all", per_page=2, page=9, now=NOW)
    assert paged["page"] == 2 and paged["pages"] == 2 and len(paged["rows"]) == 1


