"""Polite fetching: robots.txt, rate limit, retries, RSS parsing, HTML fallback."""
from __future__ import annotations

import hashlib
import re
import time
import urllib.robotparser
from calendar import timegm
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import feedparser
import requests
from bs4 import BeautifulSoup


class FetchError(Exception):
    def __init__(self, message, retries=0):
        super().__init__(message)
        self.retries = retries


def clean_text(html: str | None) -> str:
    if not html:
        return ""
    text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
    return re.sub(r"\s+", " ", text).strip()


def content_hash(title: str, body: str) -> str:
    norm = re.sub(r"\W+", " ", f"{title} {body}".lower()).strip()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


class Fetcher:
    def __init__(self, cfg: dict, session: requests.Session | None = None, sleep=time.sleep):
        f = cfg["fetching"]
        self.delay = float(f["seconds_between_requests"])
        self.timeout = float(f["timeout_seconds"])
        self.retries = int(f["retries"])
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = f["user_agent"]
        self._sleep = sleep
        self._last: dict[str, float] = {}
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    def _wait(self, host: str):
        gap = self.delay - (time.monotonic() - self._last.get(host, 0.0))
        if gap > 0:
            self._sleep(gap)
        self._last[host] = time.monotonic()

    def allowed(self, url: str) -> bool:
        p = urlparse(url)
        host = f"{p.scheme}://{p.netloc}"
        if host not in self._robots:
            rp = urllib.robotparser.RobotFileParser()
            try:
                self._wait(p.netloc)
                r = self.session.get(f"{host}/robots.txt", timeout=self.timeout)
                if r.status_code == 200:
                    rp.parse(r.text.splitlines())
                    self._robots[host] = rp
                else:
                    self._robots[host] = None  # no robots.txt: allowed
            except requests.RequestException:
                self._robots[host] = None
        rp = self._robots[host]
        return True if rp is None else rp.can_fetch(self.session.headers["User-Agent"], url)

    def get(self, url: str) -> tuple[str, int]:
        """Return (body, retries_used). Raises FetchError."""
        if not self.allowed(url):
            raise FetchError(f"blocked by robots.txt: {url}")
        host = urlparse(url).netloc
        last = "unknown error"
        for attempt in range(self.retries + 1):
            self._wait(host)
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    return r.text, attempt
                last = f"HTTP {r.status_code}"
                if r.status_code < 500 and r.status_code != 429:
                    raise FetchError(last, attempt)
            except requests.RequestException as e:
                last = f"{type(e).__name__}: {e}"
            if attempt < self.retries:
                self._sleep(min(2 ** attempt, 30))
        raise FetchError(f"{last} after {self.retries} retries", self.retries)


def _iso(entry) -> str | None:
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            return datetime.fromtimestamp(timegm(t), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def parse_feed(xml: str) -> list[dict]:
    parsed = feedparser.parse(xml)
    if parsed.bozo and not parsed.entries:
        raise FetchError(f"feed parse error: {parsed.bozo_exception}")
    items = []
    for e in parsed.entries:
        url, title = e.get("link"), clean_text(e.get("title"))
        if not url or not title:
            continue
        summary = clean_text(e.get("summary"))
        content = e.get("content")
        body = clean_text(content[0].get("value")) if content else summary
        items.append({"url": url, "title": title, "published_at": _iso(e),
                      "summary": summary[:500], "body": body or summary,
                      "content_hash": content_hash(title, body or summary)})
    return items


def fetch_html_listing(fetcher: Fetcher, html_cfg: dict, limit: int = 20) -> list[dict]:
    """Fallback for a source without a usable feed.

    html_cfg: {url, link_selector}. Article text is the page's <p> tags.
    """
    page, _ = fetcher.get(html_cfg["url"])
    soup = BeautifulSoup(page, "html.parser")
    items, seen = [], set()
    for a in soup.select(html_cfg["link_selector"])[:limit]:
        href = a.get("href")
        if not href:
            continue
        url = urljoin(html_cfg["url"], href)
        title = clean_text(a.get_text())
        if url in seen or not title:
            continue
        seen.add(url)
        try:
            art, _ = fetcher.get(url)
        except FetchError:
            continue
        paras = BeautifulSoup(art, "html.parser").find_all("p")
        body = " ".join(p.get_text(" ", strip=True) for p in paras)
        items.append({"url": url, "title": title, "published_at": None,
                      "summary": body[:500], "body": body,
                      "content_hash": content_hash(title, body)})
    return items


def fetch_source(fetcher: Fetcher, src: dict) -> tuple[list[dict], int]:
    """Return (articles, retries_used) for one configured source."""
    if src.get("feed"):
        xml, retries = fetcher.get(src["feed"])
        return parse_feed(xml), retries
    if src.get("html"):
        return fetch_html_listing(fetcher, src["html"]), 0
    raise FetchError("source has neither 'feed' nor 'html' configured")
