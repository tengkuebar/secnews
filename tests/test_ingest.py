import pytest

from conftest import FakeSession
from secnews import db
from secnews.fetch import Fetcher, FetchError, parse_feed
from secnews.ingest import scrape_all, store_articles


def make_fetcher(cfg, routes):
    return Fetcher(cfg, session=FakeSession(routes), sleep=lambda s: None)


def test_parse_feed_fields(feeds):
    items = parse_feed(feeds["a"])
    assert len(items) == 3
    first = items[0]
    assert first["url"] == "https://a.example/acme-gateway"
    assert first["published_at"] == "2026-10-05T10:00:00Z"
    assert "<p>" not in first["body"] and "9.8" in first["body"]


def test_parse_garbage_raises():
    with pytest.raises(FetchError):
        parse_feed("this is not xml at all <<<")


def test_scrape_stores_articles_and_cves(conn, cfg, feeds):
    f = make_fetcher(cfg, {"https://a.example/feed": feeds["a"], "https://b.example/feed": feeds["b"]})
    res = scrape_all(conn, cfg, f)
    assert res["sources"]["Source A"]["new"] == 3 and res["sources"]["Source B"]["new"] == 1
    cves = conn.execute("SELECT cve_id, COUNT(*) n FROM cves GROUP BY cve_id").fetchall()
    assert {r["cve_id"]: r["n"] for r in cves}["CVE-2026-0001"] == 2  # same CVE, two sources


def test_second_run_inserts_nothing(conn, cfg, feeds):
    routes = {"https://a.example/feed": feeds["a"], "https://b.example/feed": feeds["b"]}
    scrape_all(conn, cfg, make_fetcher(cfg, routes))
    before = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    res = scrape_all(conn, cfg, make_fetcher(cfg, routes))
    assert conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0] == before
    assert all(s["new"] == 0 for s in res["sources"].values())


def test_same_content_new_url_is_deduped_by_hash(conn, feeds):
    items = parse_feed(feeds["a"])
    store_articles(conn, "A", items)
    clone = dict(items[0], url="https://mirror.example/copy")
    assert store_articles(conn, "B", [clone]) == []


def test_reindex_rebuilds_cves_and_keeps_everything_else(conn, cfg, feeds):
    from secnews.ingest import reindex_cves
    scrape_all(conn, cfg, make_fetcher(cfg, {"https://a.example/feed": feeds["a"], "https://b.example/feed": feeds["b"]}))
    conn.execute("UPDATE cves SET cvss = 1.0, severity = 'Low'")          # simulate stale extraction
    conn.execute("INSERT INTO alerts_sent(rule,cve_id,article_id,sent_at) VALUES ('R','CVE-2026-0001',1,'n')")
    conn.commit()
    articles = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    r = reindex_cves(conn)
    assert r["before"] == r["after"] > 0
    assert conn.execute("SELECT cvss FROM cves WHERE cve_id='CVE-2026-0002'").fetchone()[0] == 5.3
    assert conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0] == articles
    assert conn.execute("SELECT COUNT(*) FROM alerts_sent").fetchone()[0] == 1


def test_source_kind_override_labels_every_article(conn, feeds):
    store_articles(conn, "CISA", parse_feed(feeds["a"]), kind="Vendor advisory")
    kinds = {r[0] for r in conn.execute("SELECT kind FROM articles")}
    assert kinds == {"Vendor advisory"}


def test_failing_source_does_not_stop_others_and_is_logged(conn, cfg, feeds):
    f = make_fetcher(cfg, {"https://a.example/feed": (503, "down"), "https://b.example/feed": feeds["b"]})
    res = scrape_all(conn, cfg, f)
    assert res["sources"]["Source A"]["status"] == "Failed"
    assert res["sources"]["Source B"]["new"] == 1
    run = conn.execute("SELECT * FROM runs WHERE source='Source A'").fetchone()
    assert run["status"] == "Failed" and "503" in run["error"] and run["retries"] == 2


def test_retry_then_success(conn, cfg, feeds):
    f = make_fetcher(cfg, {"https://a.example/feed": [(500, "x"), (200, feeds["a"])],
                           "https://b.example/feed": feeds["b"]})
    res = scrape_all(conn, cfg, f)
    assert res["sources"]["Source A"]["new"] == 3
    assert conn.execute("SELECT retries FROM runs WHERE source='Source A'").fetchone()[0] == 1


def test_robots_txt_blocks(conn, cfg, feeds):
    robots = "User-agent: *\nDisallow: /feed"
    f = make_fetcher(cfg, {"https://a.example/robots.txt": robots, "https://a.example/feed": feeds["a"],
                           "https://b.example/feed": feeds["b"]})
    res = scrape_all(conn, cfg, f)
    assert res["sources"]["Source A"]["status"] == "Failed"
    assert "robots" in res["sources"]["Source A"]["error"]


def test_client_error_is_not_retried(cfg):
    f = make_fetcher(cfg, {"https://a.example/feed": (404, "no")})
    with pytest.raises(FetchError):
        f.get("https://a.example/feed")
    assert f.session.calls.count("https://a.example/feed") == 1
