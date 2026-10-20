from secnews.cve import (classify_kind, extract_cve_ids, extract_cves, find_scores,
                         severity_for)


def test_ids_case_insensitive_deduped_normalised():
    ids = extract_cve_ids("cve-2026-0003 and CVE-2026-0003 plus CVE-2025-123456")
    assert ids == ["CVE-2026-0003", "CVE-2025-123456"]


def test_ids_ignore_non_matches():
    assert extract_cve_ids("CVE-26-1 and CVE-2026-12 and ACVE-2026-1234") == []


def test_score_patterns():
    assert find_scores("CVSS score of 9.8") == [9.8]
    assert find_scores("rated CVSS 5.3") == [5.3]
    assert find_scores("CVSS v3.1 base score: 7.5") == [7.5]
    assert find_scores("a 9.1 CVSS flaw") == [9.1]
    assert find_scores("it scores 7.5 on CVSS") == [7.5]
    assert find_scores("8.8 out of 10 on the CVSS scale") == [8.8]


def test_score_out_of_range_ignored():
    assert find_scores("CVSS 11.0") == []


def test_severity_bands():
    assert [severity_for(x) for x in (9.8, 9.0, 8.9, 7.0, 5.3, 3.9, None)] == \
        ["Critical", "Critical", "High", "High", "Medium", "Low", "Unrated"]


def test_single_cve_takes_article_score_and_exploit_flag():
    r = extract_cves("Flaw exploited in the wild",
                     "CVE-2026-0001 has a CVSS score of 9.8 and affects Acme Gateway 4.x. Being exploited.")
    assert len(r) == 1
    assert r[0]["cvss"] == 9.8 and r[0]["severity"] == "Critical"
    assert r[0]["exploited"] == 1
    assert "Acme Gateway" in r[0]["affected"]


def test_two_cves_scores_not_mixed_up():
    body = ("CVE-2026-0002 is rated CVSS 5.3 and leaks data. " + "x " * 300 +
            "Separately, cve-2026-0003 is a denial of service with no score published.")
    r = {x["cve_id"]: x for x in extract_cves("Two bugs", body)}
    assert r["CVE-2026-0002"]["cvss"] == 5.3
    assert r["CVE-2026-0003"]["cvss"] is None
    assert r["CVE-2026-0003"]["severity"] == "Unrated"


def test_neighbouring_cves_do_not_share_a_score():
    body = "CVE-2026-0002 is rated CVSS 5.3 and leaks data. Separately, cve-2026-0003 has no score published."
    r = {x["cve_id"]: x for x in extract_cves("Two bugs", body)}
    assert r["CVE-2026-0002"]["cvss"] == 5.3
    assert r["CVE-2026-0003"]["cvss"] is None


def test_each_score_goes_to_its_own_cve():
    body = "CVE-2026-0001 carries a CVSS score of 9.8. CVE-2026-0002 is lower, at CVSS 4.3."
    r = {x["cve_id"]: x["cvss"] for x in extract_cves("Two flaws", body)}
    assert r == {"CVE-2026-0001": 9.8, "CVE-2026-0002": 4.3}


def test_no_cve_returns_empty():
    assert extract_cves("Roundup", "nothing here") == []


def test_classify_kind():
    assert classify_kind("Vendor security advisory for X", "") == "Vendor advisory"
    assert classify_kind("Researchers find new bug", "") == "Researcher write-up"
    assert classify_kind("Gateway flaw hit", "") == "News report"
