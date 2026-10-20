"""Flask dashboard: Today, Threats, CVE detail, Watchlist and alerts, System (sources, run log, settings)."""
from __future__ import annotations

import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template, request, session,
                   url_for)

from . import db, nvd, queries, workflow
from .alerts import SENDERS, rule_matches, send_test
from .config import load_config, update_config
from .cve import severity_for
from .pipeline import run_cycle
from .queries import cve_detail

PER_PAGE = 10
SEVERITIES = ["Critical", "High", "Medium", "Low", "Unrated"]


def page_items(page: int, pages: int) -> list[dict]:
    nums = sorted({n for n in (1, pages, page - 1, page, page + 1) if 1 <= n <= pages})
    out = []
    for i, n in enumerate(nums):
        if i and n - nums[i - 1] > 1:
            out.append({"ellipsis": True})
        out.append({"n": n, "current": n == page})
    return out


def sparkline(counts: list[int], w=280, h=64, pad=6) -> dict:
    top = max(counts) or 1
    step = w / max(1, len(counts) - 1)
    pts = [(round(i * step, 1), round(h - 2 - (c / top) * (h - 2 - pad), 1)) for i, c in enumerate(counts)]
    return {"points": " ".join(f"{x},{y}" for x, y in pts), "last": pts[-1], "w": w, "h": h}


def bar_chart(values: list[int], w=560, h=220, base=200, top=142) -> list[dict]:
    """Geometry for a simple bar chart; the last bar is flagged as the current period."""
    peak = max(values) or 1
    step = w / len(values)
    bw = step * 0.74
    bars = []
    for i, v in enumerate(values):
        bh = max(2, round(v / peak * top)) if v else 0
        x = round(i * step + (step - bw) / 2, 1)
        bars.append({"x": x, "w": round(bw, 1), "y": base - bh, "h": bh, "v": v,
                     "cx": round(x + bw / 2, 1), "last": i == len(values) - 1})
    return bars


def create_app(config_path: str = "config.yaml", with_scheduler: bool = False) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECNEWS_SECRET") or secrets.token_hex(32)
    app.config["CONFIG_PATH"] = str(Path(config_path).resolve())
    app.config["SCHEDULER"] = None

    def cfg() -> dict:
        return load_config(app.config["CONFIG_PATH"])

    if with_scheduler:
        from .scheduler import make_scheduler
        app.config["SCHEDULER"] = make_scheduler(cfg)

    def conn():
        if "db" not in g:
            g.db = db.init_db(cfg()["database"])
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        c = g.pop("db", None)
        if c is not None:
            c.close()

    # ---- CSRF: every POST must carry the session token ----
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
                abort(400, "Bad or missing form token. Reload the page and try again.")

    app.jinja_env.globals["csrf_token"] = csrf_token

    app.jinja_env.filters["excerpt"] = queries.excerpt

    @app.template_filter("short")
    def short(ts):
        return ts[:16].replace("T", " ") if ts else ""

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = \
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'"
        return resp

    def safe_next(default: str) -> str:
        """Only follow a redirect target that stays on this site."""
        n = request.form.get("next", "")
        return n if n.startswith("/") and not n.startswith("//") and "\\" not in n else default

    @app.context_processor
    def toast():
        return {"undo": session.pop("undo", None)}

    # ----------------------------------------------------------- today
    @app.get("/")
    def today_page():
        conf = cfg()
        c = conn()
        counts = queries.weekly_cve_counts(c)
        return render_template(
            "today.html", nav="today", t=workflow.today(c, conf), spark=sparkline(counts),
            week_count=counts[-1], last_run=queries.run_stats(c)["last_ok"],
            today_label=datetime.now().strftime("%A %d %B").replace(" 0", " "))

    @app.get("/triage")
    def triage_page():
        return redirect(url_for("today_page"), 301)

    # --------------------------------------------------------- threats
    @app.get("/threats")
    def threats_page():
        tab = request.args.get("state", "open")
        sev = request.args.get("severity", "All")
        q = request.args.get("q", "").strip()[:80]
        watch_only = request.args.get("watch") == "1"
        page = max(1, request.args.get("page", 1, type=int))
        tab = tab if tab in dict(workflow.TABS) else "open"
        sev = sev if sev in SEVERITIES else "All"
        th = workflow.threats(conn(), cfg(), tab=tab, sev=sev, q=q, watch_only=watch_only, page=page,
                              per_page=PER_PAGE)

        def link(**over):
            args = {"state": tab, "severity": sev, "q": q, "watch": "1" if watch_only else None, "page": None}
            args.update(over)
            return url_for("threats_page", **{k: v for k, v in args.items()
                                              if v not in (None, "", "All") and not (k == "state" and v == "open")})

        return render_template("threats.html", nav="threats", th=th, tab=tab, sev=sev, q=q,
                               watch_only=watch_only, tabs=workflow.TABS, severities=["All"] + SEVERITIES,
                               pitems=page_items(th["page"], th["pages"]), link=link,
                               here=request.full_path.rstrip("?"))

    # ------------------------------------------------------- watchlist
    def channel_rows(conf: dict) -> list[dict]:
        ch = conf["channels"]
        rows = []
        for name, env in (("Slack", ch["slack"].get("webhook_env")), ("Email", ch["email"].get("password_env")),
                          ("Webhook", ch["webhook"].get("url_env"))):
            ok = bool(env and os.environ.get(env))
            if name == "Email":
                ok = ok and bool(ch["email"].get("smtp_host") and ch["email"].get("to"))
            rows.append({"name": name, "key": name.lower(), "env": env or "not named yet", "ok": ok})
        return rows

    @app.get("/watchlist")
    def watchlist_page():
        conf = cfg()
        x = queries.exposure(conn(), conf["watchlist"], conf["alert_rules"], conf["sources"])
        return render_template("watchlist.html", nav="watch", x=x, rules=conf["alert_rules"],
                               channels=channel_rows(conf),
                               rules_on=sum(1 for r in conf["alert_rules"] if r.get("enabled", True)))

    @app.get("/exposure")
    def exposure_page():
        return redirect(url_for("watchlist_page"), 301)

    @app.post("/exposure/add")
    def exposure_add():
        name = " ".join(request.form.get("name", "").split())
        terms = [" ".join(t.split()) for t in request.form.get("terms", "").split(",") if t.strip()]
        current = cfg()["watchlist"]
        if not 3 <= len(name) <= 60:
            flash("Give the product a name of 3 to 60 characters, for example “Fortinet FortiGate”.", "error")
        elif any(w["name"].lower() == name.lower() for w in current):
            flash(f"{name} is already on the watchlist.", "error")
        elif len(current) >= 50:
            flash("The watchlist is limited to 50 products.", "error")
        elif any(len(t) < 3 or len(t) > 60 for t in terms):
            flash("Each extra search term needs 3 to 60 characters.", "error")
        else:
            entry = {"name": name}
            if terms:
                entry["match"] = terms
            update_config(app.config["CONFIG_PATH"], lambda raw: raw.setdefault("watchlist", []).append(entry))
            flash(f"Now watching {name}.", "ok")
        return redirect(url_for("watchlist_page"))

    @app.post("/exposure/remove")
    def exposure_remove():
        name = request.form.get("name", "")

        def mutate(raw):
            raw["watchlist"] = [w for w in raw.get("watchlist", []) if w.get("name") != name]

        update_config(app.config["CONFIG_PATH"], mutate)
        flash(f"Stopped watching {name}.", "ok")
        return redirect(url_for("watchlist_page"))

    @app.post("/rules/toggle")
    def rule_toggle():
        name, on = request.form.get("name", ""), request.form.get("on") == "1"

        def mutate(raw):
            for r in raw.get("alert_rules", []):
                if r.get("name") == name:
                    r["enabled"] = on

        if not any(r["name"] == name for r in cfg()["alert_rules"]):
            abort(404)
        update_config(app.config["CONFIG_PATH"], mutate)
        flash(f"Rule “{name}” is {'on' if on else 'off'}.", "ok")
        return redirect(url_for("watchlist_page"))

    # -------------------------------------------------------- briefing
    @app.get("/briefing")
    def briefing_page():
        conf = cfg()
        b = queries.briefing(conn(), conf["alert_rules"], conf["sources"])
        return render_template("briefing.html", nav="today", b=b, bars=bar_chart(b["weeks"]))

    # --------------------------------------------------------- pipeline
    @app.get("/pipeline")
    def pipeline_page():
        p = queries.pipeline(conn(), cfg()["sources"])
        return render_template("pipeline.html", nav="system", tab="sources", p=p)

    @app.get("/system")
    def system_page():
        return redirect(url_for("pipeline_page"))

    # ------------------------------------------------------- CVE detail
    @app.get("/cve/<cve_id>")
    def cve_page(cve_id):
        c, conf = conn(), cfg()
        d = cve_detail(c, cve_id)
        if not d:
            abort(404)
        row = workflow.load_reviews(c).get(d["cve_id"])
        st = workflow.state_of(row, d["cvss"], d["exploited"], datetime.now(timezone.utc))
        return render_template(
            "cve.html", nav="threats", d=d, st=st, watch=queries.watch_names(d, conf["watchlist"]),
            nvd_on=nvd.settings(conf)["enabled"],
            alert=queries.alert_status(d, conf["alert_rules"]),
            exploit_sources=sorted({a["source"] for a in d["articles"] if a["exploited"]}),
            notes=workflow.notes_for(c, d["cve_id"]), events=workflow.history(c, d),
            snoozes=[(k, v[0]) for k, v in workflow.SNOOZES.items()],
            advisories=[a for a in d["articles"] if a["kind"] == "Vendor advisory"])

    @app.post("/cve/<cve_id>/state")
    def cve_state(cve_id):
        action = request.form.get("action", "")
        msg = workflow.decide(conn(), cve_id, "reviewed" if action == "dismiss" else action,
                              snooze=request.form.get("snooze"))
        if not msg:
            abort(400, "That decision is not recognised.")
        if action == "dismiss":
            msg = f"Dismissed {cve_id.upper()}."
        if action == "open":
            flash(msg, "ok")
        else:
            session["undo"] = {"cve": cve_id.upper(), "text": msg}
        return redirect(safe_next(url_for("cve_page", cve_id=cve_id)))

    @app.post("/cve/<cve_id>/note")
    def cve_note(cve_id):
        if not cve_detail(conn(), cve_id):
            abort(404)
        if workflow.add_note(conn(), cve_id, request.form.get("text", "")):
            flash("Note saved.", "ok")
        else:
            flash("Type a note first.", "error")
        return redirect(url_for("cve_page", cve_id=cve_id) + "#decision")

    # ------------------------------------------------------------ runs
    @app.get("/runs")
    def runs():
        show = request.args.get("show", "All")
        kind = {"Scrapes": "Scrape", "Alerts": "Alert"}.get(show)
        rows = queries.list_runs(conn(), kind=kind, failures=(show == "Failures"))
        return render_template("runs.html", nav="system", tab="log", rows=rows, show=show,
                               tabs=["All", "Scrapes", "Alerts", "Failures"],
                               stats=queries.run_stats(conn()))

    # --------------------------------------------------------- settings
    @app.get("/settings")
    def settings():
        conf = cfg()
        c = conn()
        health = {h["name"]: h for h in queries.source_health(c, [s["name"] for s in conf["sources"]])}
        from .scheduler import next_run
        n = nvd.settings(conf)
        return render_template("settings.html", nav="system", tab="settings", conf=conf, health=health,
                               nvd=n, nvd_key_set=bool(os.environ.get(n["api_key_env"])), nvd_counts=nvd.counts(c),
                               next_run=next_run(app.config["SCHEDULER"]),
                               has_scheduler=app.config["SCHEDULER"] is not None)

    @app.post("/settings")
    def settings_save():
        f = request.form
        try:
            minutes = int(f.get("interval_minutes", 60))
            if not 1 <= minutes <= 10080:
                raise ValueError
            gap = float(f.get("seconds_between_requests", 1))
            timeout = float(f.get("timeout_seconds", 15))
            retries = int(f.get("retries", 3))
            if gap < 1 or timeout < 1 or not 0 <= retries <= 10:
                raise ValueError
            nvd_max = int(f.get("nvd_max", nvd.DEFAULT_MAX_PER_RUN))
            nvd_env = f.get("nvd_key_env", "NVD_API_KEY").strip() or "NVD_API_KEY"
            if not 1 <= nvd_max <= 200 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", nvd_env):
                raise ValueError
        except ValueError:
            flash("Some values were out of range. Nothing was saved.", "error")
            return redirect(url_for("settings"))
        enabled_sources = set(f.getlist("source"))
        enabled_rules = set(f.getlist("rule"))

        def mutate(raw):
            sch = raw.setdefault("scheduler", {})
            sch["enabled"] = f.get("scheduler_enabled") == "on"
            sch["interval_minutes"] = minutes
            sch["quiet_hours"] = {"start": f.get("quiet_start", "22:00"), "end": f.get("quiet_end", "07:00")}
            fe = raw.setdefault("fetching", {})
            fe.update({"seconds_between_requests": gap, "timeout_seconds": timeout, "retries": retries})
            if f.get("user_agent", "").strip():
                fe["user_agent"] = f["user_agent"].strip()
            for s in raw.get("sources", []):
                s["enabled"] = s["name"] in enabled_sources
            for r in raw.get("alert_rules", []):
                r["enabled"] = r["name"] in enabled_rules
            ch = raw.setdefault("channels", {})
            ch.setdefault("slack", {})["webhook_env"] = f.get("slack_env", "").strip()
            ch.setdefault("webhook", {})["url_env"] = f.get("webhook_env", "").strip()
            em = ch.setdefault("email", {})
            em["smtp_host"] = f.get("smtp_host", "").strip()
            em["to"] = f.get("email_to", "").strip()
            em["password_env"] = f.get("smtp_password_env", "").strip()
            raw["nvd"] = {"enabled": f.get("nvd_enabled") == "on", "api_key_env": nvd_env, "max_per_run": nvd_max}

        update_config(app.config["CONFIG_PATH"], mutate)
        if app.config["SCHEDULER"]:
            from .scheduler import apply_schedule
            apply_schedule(app.config["SCHEDULER"], cfg)
        flash("Settings saved.", "ok")
        return redirect(url_for("settings"))

    @app.post("/scrape-now")
    def scrape_now():
        threading.Thread(target=lambda: run_cycle(cfg()), daemon=True).start()
        flash("Scrape started. Refresh the run log in a moment.", "ok")
        return redirect(safe_next(url_for("runs")))

    @app.post("/settings/test/<channel>")
    def test_channel(channel):
        if channel not in SENDERS:
            abort(404)
        ok, msg = send_test(cfg(), channel)
        flash(f"{channel.title()} test: {msg}", "ok" if ok else "error")
        return redirect(safe_next(url_for("settings")))

    # ------------------------------------------------------ rule editor
    def rule_from_form(f) -> dict:
        r = {"name": f.get("name", "").strip(), "enabled": True,
             "channels": f.getlist("channel"), "realert_on_change": f.get("realert") == "on"}
        kws = [k.strip() for k in f.get("keywords", "").split(",") if k.strip()]
        if kws:
            r["keywords"] = kws
        try:
            m = float(f.get("min_cvss", 0))
        except ValueError:
            m = 0.0
        if m > 0:
            r["min_cvss"] = max(0.0, min(10.0, m))
        srcs = f.getlist("source")
        if srcs:
            r["sources"] = srcs
        r["unrated"] = "alert" if f.get("unrated") == "alert" else "skip"
        return r

    def preview(rule: dict) -> list[dict]:
        c = conn()
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ids = [r[0] for r in c.execute(
            "SELECT DISTINCT c.cve_id FROM cves c JOIN articles a ON a.id=c.article_id "
            "WHERE COALESCE(a.published_at,a.scraped_at) >= ?", (since,))]
        out = []
        for cid in ids:
            d = cve_detail(c, cid)
            if rule_matches(rule, d):
                out.append(d)
        out.sort(key=lambda d: -(d["cvss"] or 0))
        return out

    @app.route("/rules/new", methods=["GET", "POST"])
    def rule_new():
        conf = cfg()
        names = [s["name"] for s in conf["sources"]]
        posted = request.method == "POST"
        form = request.form if posted else {}
        rule = rule_from_form(form) if posted else {
            "channels": ["slack"], "realert_on_change": True, "unrated": "skip",
            "keywords": [k.strip() for k in request.args.get("keywords", "").split(",") if k.strip()]}
        matches = preview(rule)[:10] if form else []
        if request.method == "POST" and form.get("action") == "save":
            existing = {r["name"] for r in conf["alert_rules"]}
            if not rule["name"]:
                flash("Give the rule a name.", "error")
            elif rule["name"] in existing:
                flash("A rule with that name already exists.", "error")
            elif not rule["channels"]:
                flash("Pick at least one channel.", "error")
            elif not (rule.get("min_cvss") or rule.get("keywords") or rule.get("sources")):
                flash("Add at least one condition (keywords, minimum CVSS or sources).", "error")
            else:
                update_config(app.config["CONFIG_PATH"],
                              lambda raw: raw.setdefault("alert_rules", []).append(rule))
                flash(f"Rule '{rule['name']}' saved.", "ok")
                return redirect(url_for("watchlist_page"))
        return render_template("rule.html", nav="watch", rule=rule, sources=names,
                               channels=list(SENDERS), matches=matches, tested=bool(form),
                               match_count=len(preview(rule)) if form else 0)

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", nav="", code=404, msg="Not found"), 404

    @app.errorhandler(400)
    def bad(e):
        return render_template("error.html", nav="", code=400, msg=getattr(e, "description", "Bad request")), 400

    return app
