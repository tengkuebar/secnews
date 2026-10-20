"""Load config.yaml and apply defaults."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

DEFAULTS = {
    "database": "secnews.db",
    "scheduler": {"enabled": True, "interval_minutes": 60,
                  "quiet_hours": {"start": "22:00", "end": "07:00"}},
    "fetching": {"user_agent": "secnews/0.1", "seconds_between_requests": 1,
                 "timeout_seconds": 15, "retries": 3},
    "sources": [],
    "channels": {"slack": {}, "webhook": {}, "email": {}},
    "alert_rules": [],
    "watchlist": [],
    "nvd": {"enabled": False, "api_key_env": "NVD_API_KEY", "max_per_run": 20},
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | os.PathLike = "config.yaml") -> dict:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}
    cfg = _merge(DEFAULTS, data or {})
    # Resolve the database path relative to the config file.
    db = Path(cfg["database"])
    if not db.is_absolute():
        db = p.resolve().parent / db
    cfg["database"] = str(db)
    cfg["_path"] = str(p.resolve())
    return cfg


def update_config(path: str | os.PathLike, mutate) -> None:
    """Edit only what the file contains (no merged defaults, no resolved paths).

    `mutate(raw_dict)` changes the dict in place. Written atomically. Note that
    YAML comments are not preserved.
    """
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}
    raw = raw or {}
    mutate(raw)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
    tmp.replace(p)


def secret(env_name: str | None) -> str | None:
    """Read a secret from the environment by variable name."""
    return os.environ.get(env_name) if env_name else None
