import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secnews import db  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


class FakeResp:
    def __init__(self, text="", status=200):
        self.text, self.status_code = text, status


class FakeSession:
    """Stands in for requests.Session. Maps url -> text or (status, text)."""

    def __init__(self, routes):
        self.routes, self.headers, self.calls = routes, {}, []

    def get(self, url, timeout=None):
        self.calls.append(url)
        r = self.routes.get(url)
        if r is None:
            return FakeResp("", 404)
        if isinstance(r, list):  # sequence of responses, last one repeats
            r = r.pop(0) if len(r) > 1 else r[0]
        if isinstance(r, tuple):
            return FakeResp(r[1], r[0])
        return FakeResp(r)


@pytest.fixture
def conn(tmp_path):
    c = db.init_db(str(tmp_path / "t.db"))
    yield c
    c.close()


@pytest.fixture
def cfg(tmp_path):
    return {
        "database": str(tmp_path / "t.db"),
        "fetching": {"user_agent": "test", "seconds_between_requests": 0,
                     "timeout_seconds": 1, "retries": 2},
        "sources": [
            {"name": "Source A", "feed": "https://a.example/feed", "enabled": True},
            {"name": "Source B", "feed": "https://b.example/feed", "enabled": True},
        ],
        "channels": {}, "alert_rules": [],
        "scheduler": {"enabled": True, "interval_minutes": 60,
                      "quiet_hours": {"start": "22:00", "end": "07:00"}},
    }


@pytest.fixture
def feeds():
    return {"a": (FIX / "feed_a.xml").read_text(encoding="utf-8"),
            "b": (FIX / "feed_b.xml").read_text(encoding="utf-8")}
