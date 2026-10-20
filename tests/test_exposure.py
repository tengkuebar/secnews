from datetime import datetime, timezone

import yaml

from conftest import FakeSession
from secnews import queries
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)  # fixtures were published 5-7 October 2026


def loaded(conn, cfg, feeds):
    f = Fetcher(cfg, session=FakeSession({"https://a.example/feed": feeds["a"],
                                          "https://b.example/feed": feeds["b"]}), sleep=lambda s: None)
    scrape_all(conn, cfg, f)


def test_watch_terms_rules():
    assert queries.watch_terms({"name": "Fortinet FortiGate", "match": ["FortiOS", "fortios", "ab"]}) == \
        ["fortinet fortigate", "fortios"]                       # lower-cased, de-duplicated, 3+ characters
    assert queries.watch_terms({"name": "  Acme   Gateway "}) == ["acme gateway"]
    assert queries.watch_terms({"name": "ab"}) == []


def test_products_are_matched_and_ranked(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    watch = [{"name": "Contoso VPN"}, {"name": "Widget Server"}, {"name": "Acme Gateway"}]
    x = queries.exposure(conn, watch, [], cfg["sources"], now=NOW)
    assert [p["name"] for p in x["products"]] == ["Acme Gateway", "Widget Server", "Contoso VPN"]   # worst first
    acme, widget, contoso = x["products"]
    assert (acme["level"], acme["top"], acme["tone"], acme["exploited"]) == ("Critical", 9.8, "bad", True)
    assert (widget["level"], widget["top"], widget["tone"]) == ("Medium", 5.3, "wait")
    assert (contoso["level"], contoso["hits"], contoso["tone"]) == ("Quiet", [], "ok")
    assert x["severe"] == 1 and x["total"] == 3 and x["quiet"] == 1


def test_matching_is_whole_word_and_case_insensitive(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    found = lambda name, **kw: queries.exposure(conn, [{"name": name, **kw}], [], cfg["sources"], now=NOW)["products"][0]["hits"]
    assert found("acme gateway")                       # case does not matter
    assert not found("Gate")                           # not a whole word inside "Gateway"
    assert not found("gat")                            # prefix of a word
    assert found("Something else", match=["Widget Server"])   # extra terms work
    assert not found("ab")                             # under 3 characters never matches


def test_matches_list_is_unique_per_cve_and_sorted(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    watch = [{"name": "Acme Gateway"}, {"name": "Gateway"}, {"name": "Widget Server"}]
    x = queries.exposure(conn, watch, [], cfg["sources"], now=NOW)
    ids = [m["cve_id"] for m in x["matches"]]
    assert ids == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"] and len(ids) == len(set(ids))
    assert x["matches"][0]["product"] == "Acme Gateway, Gateway"     # every product a CVE touches is listed
    assert x["matches"][0]["products"] == ["Acme Gateway", "Gateway"] and x["match_total"] == 3


def test_each_match_explains_why_it_matched(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    x = queries.exposure(conn, [{"name": "Acme Gateway"}], [], cfg["sources"], now=NOW)
    why = x["matches"][0]["why"][0]
    assert why["product"] == "Acme Gateway" and why["matched"].lower() == "acme gateway"
    assert "acme gateway" in why["snippet"].lower() and len(why["snippet"]) <= 161


def test_roundup_articles_only_match_near_the_cve(conn, cfg):
    from secnews.ingest import store_articles
    filler = " Unrelated filler sentence about nothing in particular." * 20
    body = ("Weekly catalog update. CVE-2026-0101 affects Cisco Catalyst and is exploited." + filler +
            "CVE-2026-0102 affects Fortinet FortiMail." + filler + "CVE-2026-0103 is in Contoso VPN." + filler +
            "CVE-2026-0104 is in Litware Backup.")
    store_articles(conn, "Source A", [{"url": "https://x/roundup", "title": "KEV roundup", "published_at": "2026-10-07T00:00:00Z",
                                       "summary": "Cisco, Fortinet, Contoso and Litware are all in this catalog update.",
                                       "body": body, "content_hash": "round1"}])
    watch = [{"name": "Cisco"}, {"name": "Fortinet"}]
    x = queries.exposure(conn, watch, [], cfg["sources"], now=NOW)
    by_name = {p["name"]: [h["cve_id"] for h in p["hits"]] for p in x["products"]}
    assert by_name == {"Cisco": ["CVE-2026-0101"], "Fortinet": ["CVE-2026-0102"]}   # not every CVE for every vendor


def test_empty_watchlist_and_old_cves(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    empty = queries.exposure(conn, [], [], cfg["sources"], now=NOW)
    assert empty["total"] == 0 and empty["products"] == [] and empty["matches"] == []
    old = queries.exposure(conn, [{"name": "Acme Gateway"}], [], cfg["sources"], now=datetime(2026, 12, 30, tzinfo=timezone.utc))
    assert old["products"][0]["level"] == "Quiet"       # CVEs older than 30 days are out of the window


def test_feed_health_is_reported(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    x = queries.exposure(conn, [], [], cfg["sources"], now=NOW)
    assert (x["feeds_ok"], x["feeds_active"]) == (2, 2)
