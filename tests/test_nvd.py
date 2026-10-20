import json
from datetime import datetime, timedelta, timezone

import requests

from conftest import FakeSession
from secnews import db, nvd, queries, workflow
from secnews.fetch import Fetcher
from secnews.ingest import scrape_all

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)  # fixtures were published 5-7 October 2026


def loaded(conn, cfg, feeds):
    f = Fetcher(cfg, session=FakeSession({"https://a.example/feed": feeds["a"],
                                          "https://b.example/feed": feeds["b"]}), sleep=lambda s: None)
    scrape_all(conn, cfg, f)


def nvd_cfg(cfg, **over):
    return {**cfg, "nvd": {"enabled": True, "api_key_env": "SECNEWS_TEST_NVD_KEY", "max_per_run": 20, **over}}


def record(score, version="3.1", status="Analyzed", key=None, sev="CRITICAL"):
    metric = {"source": "nvd@nist.gov", "type": "Primary",
              "cvssData": {"version": version, "vectorString": f"CVSS:{version}/AV:N", "baseScore": score,
                           "baseSeverity": sev}}
    key = key or {"3.1": "cvssMetricV31", "2.0": "cvssMetricV2"}[version]
    return json.dumps({"vulnerabilities": [{"cve": {"id": "x", "vulnStatus": status, "metrics": {key: [metric]}}}]})


def url(cve):
    return f"{nvd.API}?cveId={cve}"


def test_parse_prefers_v31_then_falls_back_and_handles_unscored():
    both = {"vulnerabilities": [{"cve": {"vulnStatus": "Analyzed", "metrics": {
        "cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 7.5}}],
        "cvssMetricV31": [{"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 6.0, "baseSeverity": "MEDIUM"}},
                          {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}
    r = nvd.parse(both)
    assert (r["cvss"], r["version"], r["severity"], r["status"]) == (9.8, "3.1", "Critical", "Analyzed")   # NVD's own, not the vendor's
    v2 = nvd.parse({"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV2": both["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"]}}}]})
    assert (v2["cvss"], v2["severity"]) == (7.5, "High")
    waiting = nvd.parse({"vulnerabilities": [{"cve": {"vulnStatus": "Awaiting Analysis", "metrics": {}}}]})
    assert waiting["cvss"] is None and waiting["status"] == "Awaiting Analysis"
    assert nvd.parse({"vulnerabilities": []}) is None and nvd.parse({}) is None


def test_enrich_stores_scores_waits_between_requests_and_logs(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    s = FakeSession({url("CVE-2026-0001"): record(9.8), url("CVE-2026-0002"): record(5.3, sev="MEDIUM"),
                     url("CVE-2026-0003"): json.dumps({"vulnerabilities": []})})
    sleeps = []
    r = nvd.enrich(conn, nvd_cfg(cfg), session=s, sleep=sleeps.append, now=NOW)
    assert r["asked"] == 3 and r["scored"] == 2 and r["error"] is None
    assert sleeps == [nvd.GAP_KEYLESS] * 2                          # between requests, not before the first
    assert s.headers["User-Agent"] == "test" and "apiKey" not in s.headers
    rows = {x["cve_id"]: x for x in conn.execute("SELECT * FROM nvd_scores")}
    assert rows["CVE-2026-0001"]["cvss"] == 9.8 and rows["CVE-2026-0003"]["cvss"] is None
    assert rows["CVE-2026-0003"]["status"] == "Not in NVD yet"
    run = conn.execute("SELECT * FROM runs WHERE source = 'NVD'").fetchone()
    assert run["status"] == "OK" and run["detail"] == "2 of 3 CVEs scored"


def test_api_key_comes_from_the_environment_and_speeds_things_up(conn, cfg, feeds, monkeypatch):
    loaded(conn, cfg, feeds)
    monkeypatch.setenv("SECNEWS_TEST_NVD_KEY", "k-123")
    s = FakeSession({url(c): record(5.0) for c in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")})
    sleeps = []
    nvd.enrich(conn, nvd_cfg(cfg), session=s, sleep=sleeps.append, now=NOW)
    assert s.headers["apiKey"] == "k-123" and sleeps == [nvd.GAP_KEYED] * 2


def test_cap_per_run_and_stop_at_first_rate_limit(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    s = FakeSession({url("CVE-2026-0001"): record(9.8), url("CVE-2026-0002"): (429, "slow down"),
                     url("CVE-2026-0003"): record(4.0)})
    r = nvd.enrich(conn, nvd_cfg(cfg), session=s, sleep=lambda x: None, now=NOW)
    assert r["error"].startswith("HTTP 429") and "API key" in r["error"] and r["asked"] == 1
    assert len(s.calls) == 2                                          # it did not go on to the third
    assert [x["cve_id"] for x in conn.execute("SELECT cve_id FROM nvd_scores")] == ["CVE-2026-0001"]
    assert conn.execute("SELECT status FROM runs WHERE source = 'NVD'").fetchone()[0] == "Failed"
    capped = FakeSession({url(c): record(5.0) for c in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")})
    r = nvd.enrich(conn, nvd_cfg(cfg, max_per_run=1), session=capped, sleep=lambda x: None, now=NOW)
    assert r["asked"] == 1 and len(capped.calls) == 1


def test_network_error_and_bad_json_stop_the_run_without_crashing(conn, cfg, feeds):
    loaded(conn, cfg, feeds)

    class Down(FakeSession):
        def get(self, url, timeout=None):
            raise requests.ConnectionError("no route")

    r = nvd.enrich(conn, nvd_cfg(cfg), session=Down({}), sleep=lambda x: None, now=NOW)
    assert "ConnectionError" in r["error"] and r["asked"] == 0
    r = nvd.enrich(conn, nvd_cfg(cfg), session=FakeSession({url("CVE-2026-0001"): "<html>"}), sleep=lambda x: None, now=NOW)
    assert "not JSON" in r["error"]


def test_disabled_makes_no_requests(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    s = FakeSession({})
    r = nvd.enrich(conn, {**cfg, "nvd": {"enabled": False}}, session=s)
    assert r["skipped"] and s.calls == []
    assert nvd.settings(cfg)["enabled"] is False                      # off unless config turns it on


def test_pending_order_and_retry_windows(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    assert nvd.pending(conn, NOW)[0] == "CVE-2026-0001"               # exploited first
    stamp = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.executemany("INSERT INTO nvd_scores(cve_id,cvss,status,fetched_at) VALUES (?,?,?,?)", [
        ("CVE-2026-0001", 9.8, "Analyzed", stamp(NOW - timedelta(days=1))),            # fresh score: leave alone
        ("CVE-2026-0002", None, "Awaiting Analysis", stamp(NOW - timedelta(hours=1))),  # unscored, asked recently
        ("CVE-2026-0003", None, "Awaiting Analysis", stamp(NOW - timedelta(hours=7)))])  # unscored, due again
    assert nvd.pending(conn, NOW) == ["CVE-2026-0003"]
    later = nvd.pending(conn, NOW + timedelta(days=8))
    assert later[-1] == "CVE-2026-0001"                  # a scored one is refreshed after a week, after the unscored ones
    assert nvd.pending(conn, NOW + timedelta(days=90)) == []                   # old CVEs are no longer chased


def test_official_score_wins_and_counts_as_a_disagreement(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    before = queries.cve_detail(conn, "CVE-2026-0002")
    assert before["cvss"] == 5.3 and before["nvd"] is None
    conn.execute("INSERT INTO nvd_scores(cve_id,cvss,severity,version,vector,status,fetched_at) "
                 "VALUES ('CVE-2026-0002', 8.1, 'High', '3.1', 'CVSS:3.1/AV:N', 'Analyzed', '2026-10-08T00:00:00Z')")
    conn.commit()
    d = queries.cve_detail(conn, "CVE-2026-0002")
    assert d["cvss"] == 8.1 and d["severity"] == "High" and d["score_source"] == "the official NVD score"
    assert d["conflict"] == [8.1, 5.3]
    top = {i["cve_id"]: i for i in queries.triage(conn, [], now=NOW)["queue"]}["CVE-2026-0002"]
    assert top["official"] is True and top["cvss"] == 8.1 and top["conflict"] == [8.1, 5.3]
    unscored = queries.cve_detail(conn, "CVE-2026-0003")
    assert unscored["nvd"] is None and unscored["nvd_status"] is None


def test_a_higher_official_score_brings_a_reviewed_cve_back(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    workflow.decide(conn, "CVE-2026-0002", "reviewed", now=NOW)
    conn.execute("INSERT INTO nvd_scores(cve_id,cvss,status,fetched_at) VALUES ('CVE-2026-0002', 8.1, 'Analyzed', '2026-10-08T00:00:00Z')")
    conn.commit()
    d = queries.cve_detail(conn, "CVE-2026-0002")
    st = workflow.state_of(workflow.load_reviews(conn)["CVE-2026-0002"], d["cvss"], d["exploited"], NOW)
    assert st["state"] == "open" and st["why"] == "Back in the queue: score rose from 5.3"


def test_unscored_nvd_record_is_explained_on_the_cve(conn, cfg, feeds):
    loaded(conn, cfg, feeds)
    conn.execute("INSERT INTO nvd_scores(cve_id,cvss,status,fetched_at) VALUES ('CVE-2026-0003', NULL, 'Awaiting Analysis', '2026-10-08T00:00:00Z')")
    conn.commit()
    d = queries.cve_detail(conn, "CVE-2026-0003")
    assert d["nvd"] is None and d["nvd_status"] == "Awaiting Analysis"
