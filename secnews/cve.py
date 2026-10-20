"""CVE, CVSS and exploitation extraction from article text."""
from __future__ import annotations

import re

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)

# "CVSS 9.8", "CVSS v3.1 score of 9.8", "CVSS base score: 9.8", "9.8 CVSS", "rated 9.8 out of 10"
_CVSS_PATTERNS = [
    re.compile(r"CVSS(?:\s*v(?:ersion)?\s*\d(?:\.\d)?)?(?:\s*base)?(?:\s*(?:score|rating|severity))?"
               r"(?:\s*(?:of|is|:|=|rated|at))?\s*(\d{1,2}(?:\.\d)?)\b", re.IGNORECASE),
    re.compile(r"\b(\d{1,2}(?:\.\d))\s*(?:out of 10\s*)?(?:on (?:the )?)?CVSS", re.IGNORECASE),
    re.compile(r"\b(\d{1,2}(?:\.\d))\s*out of\s*10", re.IGNORECASE),
]

_EXPLOIT_RE = re.compile(
    r"actively exploited|exploited in the wild|being exploited|under active exploitation"
    r"|known exploited|added to (?:the )?(?:cisa )?kev|zero-day|exploitation (?:attempts|detected)",
    re.IGNORECASE)

_AFFECTED_RE = re.compile(
    r"(?:affect(?:s|ing|ed)|impact(?:s|ing|ed)|vulnerab(?:le|ility) in)\s+([^.;,\n]{3,70})",
    re.IGNORECASE)

WINDOW = 220  # characters either side of a CVE mention


def extract_cve_ids(text: str) -> list[str]:
    seen, out = set(), []
    for m in CVE_RE.finditer(text or ""):
        cid = f"CVE-{m.group(1)}-{m.group(2)}"
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def scores_with_pos(text: str) -> list[tuple[float, int]]:
    """Every CVSS-looking score in the text with its character position."""
    found: list[tuple[float, int]] = []
    for pat in _CVSS_PATTERNS:
        for m in pat.finditer(text or ""):
            try:
                v = float(m.group(1))
            except ValueError:
                continue
            if 0.0 < v <= 10.0 and not any(v == fv and abs(m.start(1) - fp) < 40 for fv, fp in found):
                found.append((v, m.start(1)))
    return sorted(found, key=lambda x: x[1])


def find_scores(text: str) -> list[float]:
    scores: list[float] = []
    for v, _ in scores_with_pos(text):
        if v not in scores:
            scores.append(v)
    return scores


def severity_for(cvss: float | None) -> str:
    if cvss is None:
        return "Unrated"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Unrated"


def classify_kind(title: str, text: str) -> str:
    t = (title or "").lower()
    if "advisory" in t or "security bulletin" in t or "patch tuesday" in t:
        return "Vendor advisory"
    if any(w in t for w in ("researchers", "research", "analysis", "technical details", "proof-of-concept")):
        return "Researcher write-up"
    return "News report"


def extract_cves(title: str, body: str) -> list[dict]:
    """Return one record per CVE id: cvss, severity, affected, exploited.

    A score is taken from the text near the CVE mention. If the article names
    exactly one CVE, an article-wide score is accepted too. Otherwise the CVE
    stays Unrated rather than guessing.
    """
    text = f"{title}. {body or ''}"
    ids = extract_cve_ids(text)
    if not ids:
        return []
    article_scores = find_scores(text)
    article_exploited = bool(_EXPLOIT_RE.search(text))
    # A score belongs to the closest CVE mentioned *before* it (scores follow the
    # name: "CVE-X is rated CVSS 9.8"). Only if none precedes it within the window
    # does it fall back to the closest one after it. This keeps two CVEs in
    # neighbouring sentences from sharing a score.
    mentions = [(m.start(), f"CVE-{m.group(1)}-{m.group(2)}") for m in CVE_RE.finditer(text)]
    assigned: dict[str, list[float]] = {cid: [] for cid in ids}
    for v, pos in scores_with_pos(text):
        before = [(pos - s, c) for s, c in mentions if s <= pos and pos - s <= WINDOW]
        after = [(s - pos, c) for s, c in mentions if s > pos and s - pos <= WINDOW]
        owner = min(before)[1] if before else (min(after)[1] if after else None)
        if owner:
            assigned[owner].append(v)
    records = []
    for cid in ids:
        near_scores, near_exploit, affected = assigned[cid], False, None
        for m in re.finditer(re.escape(cid), text, flags=re.IGNORECASE):
            lo, hi = max(0, m.start() - WINDOW), min(len(text), m.end() + WINDOW)
            window = text[lo:hi]
            near_exploit = near_exploit or bool(_EXPLOIT_RE.search(window))
            if affected is None:
                am = _AFFECTED_RE.search(window)
                if am:
                    affected = am.group(1).strip()
        cvss = max(near_scores) if near_scores else None
        if cvss is None and len(ids) == 1 and article_scores:
            cvss = max(article_scores)
        records.append({
            "cve_id": cid,
            "cvss": cvss,
            "severity": severity_for(cvss),
            "affected": affected,
            "exploited": 1 if (near_exploit or (len(ids) == 1 and article_exploited)) else 0,
        })
    return records
