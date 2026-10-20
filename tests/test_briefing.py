from datetime import datetime, timezone

from conftest import FakeSession
from secnews import queries
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all
from secnews.web import bar_chart

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)  # fixtures were published 5-7 October 2026


def loaded(conn, cfg, feeds):
    f = Fetcher(cfg, session=FakeSession({"https://a.example/feed": feeds["a"],
                                          "https://b.example/feed": feeds["b"]}), sleep=lambda s: None)
    scrape_all(conn, cfg, f)


def test_excerpt_cuts_at_a_word_and_says_so():
    long = "alpha beta gamma delta epsilon zeta eta theta"
    assert queries.excerpt(long, 20) == "alpha beta gamma…"
    assert queries.excerpt("short text", 50) == "short text"
    assert queries.excerpt(None, 10) == ""
    assert queries.excerpt("one   two\n three", 50) == "one two three"
    assert queries.excerpt("x" * 30, 10) == "x" * 10 + "…"        # no spaces: hard cut still marked
    assert not queries.excerpt("hello world, again and again", 14).endswith(",…")


def test_lead_story_and_deck_are_built_from_the_data(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    b = queries.briefing(conn, [], cfg["sources"], now=NOW)
    lead = b["lead"]
    assert lead["cve_id"] == "CVE-2026-0001" and lead["cvss"] == 9.8
    assert "scores 9.8 (highest score quoted)" in lead["deck"]
    assert "Sources quote different scores: 9.8 vs 7.5." in lead["deck"]
    assert "2 of 2 sources report exploitation." in lead["deck"]
    assert lead["deck"].endswith("No alert has been sent.")
    assert lead["url"].startswith("https://") and lead["source"] in ("Source A", "Source B")


def test_an_exploited_high_score_leads_over_a_higher_unexploited_one(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    conn.execute("INSERT INTO articles(id,source,url,title,summary,body,content_hash,scraped_at,published_at) VALUES "
                 "(900,'Source A','https://x/9','Unexploited bug','s','b','h9','2026-10-07T00:00:00Z','2026-10-07T00:00:00Z')")
    conn.execute("INSERT INTO cves(cve_id,article_id,cvss,severity,exploited) VALUES ('CVE-2026-0999',900,9.9,'Critical',0)")
    conn.commit()
    b = queries.briefing(conn, [], cfg["sources"], now=NOW)
    assert b["lead"]["cve_id"] == "CVE-2026-0001"                    # 9.8 and exploited beats 9.9 and not
    assert b["more"][0]["cve_id"] == "CVE-2026-0999"                 # the rest keep score order


def test_numbers_and_more_stories(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    b = queries.briefing(conn, [], cfg["sources"], now=NOW)
    assert b["numbers"] == {"new": 3, "new_note": "Up from 0 the week before.", "exploited": 1, "disagree": 1, "alerts": 0}
    assert [m["cve_id"] for m in b["more"]] == ["CVE-2026-0002", "CVE-2026-0003"]
    assert b["more"][0]["summary"]                                   # excerpt of the article summary
    assert b["articles_read"] == 4 and b["sources_n"] == 2
    assert b["weeks"][-1] == 3 and sum(b["weeks"]) == 3 and len(b["weeks"]) == 8


def test_week_over_week_wording(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    later = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)       # fixtures now sit in the previous week
    b = queries.briefing(conn, [], cfg["sources"], now=later)
    assert b["lead"] is None and b["numbers"]["new"] == 0
    assert b["numbers"]["new_note"] == "Down from 3 the week before."
    assert b["weeks"][-2] == 3


def test_changes_since_an_alert_and_source_problems(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    conn.execute("INSERT INTO alerts_sent(rule,cve_id,article_id,sent_at,last_cvss,last_exploited) "
                 "VALUES ('Crit','CVE-2026-0001',1,'2026-10-07T00:00:00Z',7.5,1)")
    conn.commit()
    b = queries.briefing(conn, [], cfg["sources"], now=NOW)
    assert any(c["k"] == "Score raised:" and "7.5" in c["t"] and "9.8" in c["t"] for c in b["changes"])
    cfg["sources"][0]["enabled"] = False
    from secnews import db
    db.log_run(conn, "Source A", "Failed", error="HTTP 403")
    b = queries.briefing(conn, [], cfg["sources"], now=NOW)
    assert any(c["k"] == "Source off:" and "HTTP 403" in c["t"] for c in b["changes"])


def test_bar_chart_geometry():
    bars = bar_chart([0, 5, 10])
    assert [b["h"] for b in bars] == [0, 71, 142] and bars[-1]["last"] and not bars[0]["last"]
    assert all(b["y"] + b["h"] == 200 for b in bars)
    assert bar_chart([0, 0])[0]["h"] == 0                      # all zero must not divide by zero
