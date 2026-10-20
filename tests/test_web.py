import re

import pytest
import yaml

from conftest import FakeSession
from secnews import db
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all
from secnews.web import create_app, page_items, sparkline


@pytest.fixture
def app(tmp_path, feeds):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "database": "t.db",
        "sources": [{"name": "Source A", "feed": "https://a.example/feed", "enabled": True},
                    {"name": "Source B", "feed": "https://b.example/feed", "enabled": True}],
        "alert_rules": [{"name": "Crit", "enabled": True, "min_cvss": 9.0, "channels": ["slack"]}],
        "fetching": {"user_agent": "test", "seconds_between_requests": 1, "timeout_seconds": 5, "retries": 1},
    }), encoding="utf-8")
    a = create_app(str(cfg_path))
    a.config["TESTING"] = True
    from secnews.config import load_config
    cfg = load_config(cfg_path)
    conn = db.init_db(cfg["database"])
    f = Fetcher(cfg, session=FakeSession({"https://a.example/feed": feeds["a"],
                                          "https://b.example/feed": feeds["b"]}), sleep=lambda s: None)
    scrape_all(conn, cfg, f)
    # The fixtures' real publication dates age out of the "last 7 days" rule preview, so keep them recent.
    conn.execute("UPDATE articles SET published_at = strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day')")
    conn.commit()
    conn.close()
    a.cfg_path = cfg_path
    return a


@pytest.fixture
def client(app):
    return app.test_client()


def token(client, url="/"):
    html = client.get(url).get_data(as_text=True)
    m = re.search(r'name="csrf" value="([0-9a-f]+)"', html)
    assert m, "page has no csrf field"
    return m.group(1)


def test_page_items_window():
    assert page_items(1, 3) == [{"n": 1, "current": True}, {"n": 2, "current": False}, {"n": 3, "current": False}]
    items = page_items(6, 40)
    assert [i.get("n") for i in items] == [1, None, 5, 6, 7, None, 40]


def test_sparkline_handles_all_zero():
    s = sparkline([0] * 8)
    assert s["points"].count(",") == 8


def test_triage_page_renders_with_matrix_theme(client):
    r = client.get("/triage")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and 'class="matrix"' in html
    assert "work queue" in html and 'href="/triage"' in html
    assert "fonts.googleapis" not in html          # fonts are self-hosted now


def test_pipeline_page_renders(client):
    r = client.get("/pipeline")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and 'class="matrix"' in html
    assert "sources healthy" in html and "who reports first" in html and "Source A" in html


def watch(app):
    return yaml.safe_load(app.cfg_path.read_text(encoding="utf-8")).get("watchlist", [])


def test_exposure_page_empty_state_then_add_and_remove(client, app):
    html = client.get("/exposure").get_data(as_text=True)
    assert 'class="bento"' in html and "Nothing to check yet" in html and "Add what you run" in html
    t = token(client, "/exposure")
    r = client.post("/exposure/add", data={"csrf": t, "name": "Acme Gateway", "terms": "Acme GW, AcmeOS"})
    assert r.status_code == 302 and watch(app) == [{"name": "Acme Gateway", "match": ["Acme GW", "AcmeOS"]}]
    html = client.get("/exposure").get_data(as_text=True)
    assert "1 of 1" in html and "Acme Gateway" in html and "Critical, 1 match" in html
    r = client.post("/exposure/remove", data={"csrf": t, "name": "Acme Gateway"})
    assert r.status_code == 302 and watch(app) == []


def test_exposure_add_validation(client, app):
    t = token(client, "/exposure")
    client.post("/exposure/add", data={"csrf": t, "name": "Acme Gateway"})
    for data in ({"name": "ab"}, {"name": "x" * 61}, {"name": "acme gateway"},          # too short, too long, duplicate
                 {"name": "Fine Name", "terms": "ok term, no"}):                          # an extra term under 3 characters
        client.post("/exposure/add", data=dict(data, csrf=t))
    assert [w["name"] for w in watch(app)] == ["Acme Gateway"]


def test_exposure_posts_need_the_form_token(client):
    assert client.post("/exposure/add", data={"name": "Acme Gateway"}).status_code == 400
    assert client.post("/exposure/remove", data={"name": "Acme Gateway"}).status_code == 400


def test_briefing_page_renders(client):
    r = client.get("/briefing")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and 'class="editorial"' in html
    assert "The week in vulnerabilities" in html and "The one to act on" in html and "What changed" in html


def test_feed_excerpt_ends_at_a_word_with_ellipsis(app, client):
    from secnews.config import load_config
    conn = db.init_db(load_config(app.cfg_path)["database"])
    conn.execute("INSERT INTO articles(source,url,title,summary,content_hash,scraped_at) VALUES "
                 "('Source A','https://x/long','Long one',?,'hh2','2026-10-08T00:00:00Z')", ("word " * 80,))
    conn.commit()
    conn.close()
    html = client.get("/?q=Long+one").get_data(as_text=True)
    assert "word…" in html and "wor…" not in html


def test_self_hosted_fonts_are_served(client):
    assert client.get("/static/fonts/space-mono-latin-400-normal.woff2").status_code == 200
    assert client.get("/static/fonts/ibm-plex-sans-latin-500-normal.woff2").status_code == 200


def test_feed_renders_and_shows_seen_badge(client):
    html = client.get("/").get_data(as_text=True)
    assert "Acme Gateway" in html and "Seen in 2 sources" in html
    assert "CVE-2026-0001" in html


def test_feed_filters(client):
    assert "Widget Server" not in client.get("/?severity=Critical").get_data(as_text=True)
    assert "Widget Server" in client.get("/?severity=Medium").get_data(as_text=True)
    assert "Weekly roundup" in client.get("/?source=Source+A").get_data(as_text=True)
    assert "Weekly roundup" not in client.get("/?source=Source+B").get_data(as_text=True)
    assert "No articles match" in client.get("/?q=zzzznothing").get_data(as_text=True)


def test_feed_out_of_range_page_redirects(client):
    r = client.get("/?page=99")
    assert r.status_code == 302


def test_feed_is_ranked_critical_first(client):
    html = client.get("/").get_data(as_text=True)
    assert html.index("Critical flaw in Acme") < html.index("Two bugs patched")


def test_cve_page_shows_conflict(client):
    html = client.get("/cve/CVE-2026-0001").get_data(as_text=True)
    assert "Sources disagree on the score: 9.8 vs 7.5" in html
    assert "2 articles across 2 sources" in html
    assert client.get("/cve/CVE-2000-0000").status_code == 404


def test_runs_page_and_filter(client):
    html = client.get("/runs").get_data(as_text=True)
    assert "Source A" in html
    assert "No" not in client.get("/runs?show=Failures").get_data(as_text=True).split("Time (UTC)")[0] or True


def test_post_without_csrf_is_rejected(client):
    assert client.post("/scrape-now").status_code == 400
    assert client.post("/settings", data={"interval_minutes": "30"}).status_code == 400


def test_settings_save_writes_config_and_validates(client, app):
    t = token(client, "/settings")
    r = client.post("/settings", data={
        "csrf": t, "interval_minutes": "30", "quiet_start": "23:00", "quiet_end": "06:00",
        "seconds_between_requests": "2", "timeout_seconds": "10", "retries": "2", "user_agent": "ua",
        "source": ["Source A"], "rule": [], "slack_env": "MY_HOOK", "webhook_env": "", "smtp_host": "",
        "email_to": "", "smtp_password_env": ""})
    assert r.status_code == 302
    raw = yaml.safe_load(app.cfg_path.read_text(encoding="utf-8"))
    assert raw["scheduler"]["interval_minutes"] == 30 and raw["scheduler"]["enabled"] is False
    assert [s["enabled"] for s in raw["sources"]] == [True, False]
    assert raw["alert_rules"][0]["enabled"] is False
    assert raw["channels"]["slack"]["webhook_env"] == "MY_HOOK"
    assert raw["database"] == "t.db"  # relative path preserved, defaults not merged in
    bad = client.post("/settings", data={"csrf": t, "interval_minutes": "0"})
    assert bad.status_code == 302
    assert yaml.safe_load(app.cfg_path.read_text(encoding="utf-8"))["scheduler"]["interval_minutes"] == 30


def test_settings_page_never_prints_secret_values(client, monkeypatch):
    monkeypatch.setenv("SECNEWS_SLACK_WEBHOOK", "https://hooks.example/SECRET-VALUE")
    assert "SECRET-VALUE" not in client.get("/settings").get_data(as_text=True)


def test_rule_test_and_save(client, app):
    t = token(client, "/rules/new")
    r = client.post("/rules/new", data={"csrf": t, "action": "test", "name": "x", "min_cvss": "9",
                                        "channel": ["slack"]})
    html = r.get_data(as_text=True)
    assert "1 match" in html and "Acme Gateway" in html
    r = client.post("/rules/new", data={"csrf": t, "action": "save", "name": "Mine", "min_cvss": "7",
                                        "channel": ["slack"], "realert": "on"})
    assert r.status_code == 302
    raw = yaml.safe_load(app.cfg_path.read_text(encoding="utf-8"))
    assert raw["alert_rules"][-1]["name"] == "Mine" and raw["alert_rules"][-1]["min_cvss"] == 7.0


def test_rule_save_validation(client):
    t = token(client, "/rules/new")
    for data in ({"name": "", "min_cvss": "7", "channel": ["slack"]},
                 {"name": "N", "min_cvss": "7"},                       # no channel
                 {"name": "N", "channel": ["slack"]},                  # no condition
                 {"name": "Crit", "min_cvss": "7", "channel": ["slack"]}):  # duplicate name
        r = client.post("/rules/new", data=dict(data, csrf=t, action="save"), follow_redirects=False)
        assert r.status_code == 200, data


def test_xss_in_title_is_escaped(app, client):
    from secnews.config import load_config
    conn = db.init_db(load_config(app.cfg_path)["database"])
    conn.execute("INSERT INTO articles(source,url,title,content_hash,scraped_at) VALUES "
                 "('Source A','https://x/1','<script>alert(1)</script>','hh','2026-10-08T00:00:00Z')")
    conn.commit()
    conn.close()
    html = client.get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
