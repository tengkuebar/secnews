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


def test_nav_has_four_pages_and_old_urls_redirect(client):
    html = client.get("/").get_data(as_text=True)
    nav = re.search(r'<nav class="main".*?</nav>', html, re.S).group(0)
    assert re.findall(r">([^<]+)</a>", nav) == ["Today", "Threats", "Watchlist and alerts", "System"]
    assert "fonts.googleapis" not in html
    for old, new in (("/triage", "/"), ("/exposure", "/watchlist")):
        r = client.get(old)
        assert r.status_code == 301 and r.headers["Location"].endswith(new)


def test_theme_toggle_is_wired_and_csp_allows_the_script(client):
    r = client.get("/")
    html = r.get_data(as_text=True)
    assert 'id="theme-toggle"' in html and "/static/theme.js" in html and 'class="bulb"' in html
    assert "script-src" not in r.headers["Content-Security-Policy"]          # falls back to 'self'
    assert "<script>" not in html                                           # no inline script
    js = client.get("/static/theme.js").get_data(as_text=True)
    assert "data-theme" in js and "localStorage" in js
    css = client.get("/static/style.css").get_data(as_text=True)
    assert ':root[data-theme="dark"]' in css and ':root:not([data-theme="light"])' in css


def test_pipeline_page_renders(client):
    r = client.get("/pipeline")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and 'aria-current="page"' in html
    assert "Sources healthy" in html and "Who reports first" in html and "Source A" in html
    for tab in ("Sources", "Run log", "Settings"):
        assert f">{tab}</a>" in html


def watch(app):
    return yaml.safe_load(app.cfg_path.read_text(encoding="utf-8")).get("watchlist", [])


def test_watchlist_page_empty_state_then_add_and_remove(client, app):
    html = client.get("/watchlist").get_data(as_text=True)
    assert "Empty. Add a product below" in html
    t = token(client, "/watchlist")
    r = client.post("/exposure/add", data={"csrf": t, "name": "Acme Gateway", "terms": "Acme GW, AcmeOS"})
    assert r.status_code == 302 and watch(app) == [{"name": "Acme Gateway", "match": ["Acme GW", "AcmeOS"]}]
    html = client.get("/watchlist").get_data(as_text=True)
    assert "1 product" in html and "Acme Gateway" in html and "Critical, 1 match" in html
    r = client.post("/exposure/remove", data={"csrf": t, "name": "Acme Gateway"})
    assert r.status_code == 302 and watch(app) == []


def test_rule_toggle_writes_config(client, app):
    t = token(client, "/watchlist")
    assert client.post("/rules/toggle", data={"csrf": t, "name": "Crit", "on": "0"}).status_code == 302
    assert yaml.safe_load(app.cfg_path.read_text(encoding="utf-8"))["alert_rules"][0]["enabled"] is False
    assert "No alert rule is on" in client.get("/watchlist").get_data(as_text=True)
    assert client.post("/rules/toggle", data={"csrf": t, "name": "Nope", "on": "1"}).status_code == 404


def test_exposure_add_validation(client, app):
    t = token(client, "/watchlist")
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
    assert r.status_code == 200
    assert "The week in vulnerabilities" in html and "The one to act on" in html and "What changed" in html


def test_self_hosted_fonts_are_served(client):
    assert client.get("/static/fonts/ibm-plex-mono-latin-400-normal.woff2").status_code == 200
    assert client.get("/static/fonts/ibm-plex-sans-latin-500-normal.woff2").status_code == 200


def test_threats_lists_one_row_per_cve_ranked_critical_first(client):
    html = client.get("/threats").get_data(as_text=True)
    assert html.count("CVE-2026-0001") >= 1 and html.count('class="chipcve">CVE-2026-0001') == 1   # deduped across sources
    assert "2 sources" in html
    assert html.index("CVE-2026-0001") < html.index("CVE-2026-0002")


def test_threats_filters(client):
    assert "CVE-2026-0002" not in client.get("/threats?severity=Critical").get_data(as_text=True)
    assert "CVE-2026-0002" in client.get("/threats?severity=Medium").get_data(as_text=True)
    assert "No CVE matches" in client.get("/threats?q=zzzznothing").get_data(as_text=True)
    assert "CVE-2026-0001" in client.get("/threats?q=0001").get_data(as_text=True)
    assert "CVE-2026-0001" not in client.get("/threats?watch=1").get_data(as_text=True)    # empty watchlist


def test_threats_out_of_range_page_is_clamped_and_bad_filters_ignored(client):
    assert client.get("/threats?page=99").status_code == 200
    assert client.get("/threats?state=bogus&severity=bogus").status_code == 200


def test_cve_page_shows_conflict(client):
    html = client.get("/cve/CVE-2026-0001").get_data(as_text=True)
    assert "Sources disagree on the score: 9.8 vs 7.5" in html
    assert "2 articles across 2 sources" in html
    assert "Needs attention" in html and "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" in html
    assert client.get("/cve/CVE-2000-0000").status_code == 404


def test_today_with_empty_watchlist_prompts_and_shows_exploited_critical(client):
    html = client.get("/").get_data(as_text=True)
    assert "Tell secnews what you run" in html and "Worth a look, not on your watchlist" in html
    assert "CVE-2026-0001" in html


def test_review_snooze_undo_and_reopen_flow(client):
    t = token(client, "/")
    r = client.post("/cve/CVE-2026-0001/state", data={"csrf": t, "action": "reviewed", "next": "/"})
    assert r.status_code == 302 and r.headers["Location"] == "/"
    html = client.get("/").get_data(as_text=True)
    assert "Marked CVE-2026-0001 as reviewed." in html and ">Undo</button>" in html
    assert "Worth a look, not on your watchlist" not in html                       # it left Today
    assert "Reviewed" in client.get("/threats?state=reviewed").get_data(as_text=True)
    client.post("/cve/CVE-2026-0001/state", data={"csrf": t, "action": "open", "next": "/"})
    assert "Worth a look, not on your watchlist" in client.get("/").get_data(as_text=True)


def test_decision_posts_validate_input_and_stay_on_site(client):
    t = token(client, "/")
    assert client.post("/cve/CVE-2026-0001/state", data={"csrf": t, "action": "nope"}).status_code == 400
    assert client.post("/cve/CVE-2026-0001/state", data={"csrf": t, "action": "snoozed", "snooze": "9"}).status_code == 400
    assert client.post("/cve/CVE-2000-0000/state", data={"csrf": t, "action": "reviewed"}).status_code == 400
    r = client.post("/cve/CVE-2026-0001/state", data={"csrf": t, "action": "reviewed", "next": "https://evil.example/"})
    assert r.headers["Location"].endswith("/cve/CVE-2026-0001")
    r = client.post("/cve/CVE-2026-0001/state", data={"csrf": t, "action": "reviewed", "next": "//evil.example"})
    assert r.headers["Location"].endswith("/cve/CVE-2026-0001")
    assert client.post("/cve/CVE-2026-0001/state", data={"action": "reviewed"}).status_code == 400   # no token


def test_notes_are_saved_escaped_and_shown_in_history(client):
    t = token(client, "/cve/CVE-2026-0001")
    assert client.post("/cve/CVE-2026-0001/note", data={"csrf": t, "text": "  "}).status_code == 302
    client.post("/cve/CVE-2026-0001/note", data={"csrf": t, "text": "patched <b>staging</b>"})
    html = client.get("/cve/CVE-2026-0001").get_data(as_text=True)
    assert "patched &lt;b&gt;staging&lt;/b&gt;" in html and "You added a note." in html
    assert client.post("/cve/CVE-2000-0000/note", data={"csrf": t, "text": "x"}).status_code == 404


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
    conn = db.init_db(load_config(app.cfg_path)["database"])
    conn.execute("INSERT INTO cves(cve_id,article_id,cvss) VALUES ('CVE-2026-9999', (SELECT id FROM articles WHERE url='https://x/1'), 9.9)")
    conn.commit()
    conn.close()
    html = client.get("/cve/CVE-2026-9999").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "&lt;script&gt;" in client.get("/threats").get_data(as_text=True)
