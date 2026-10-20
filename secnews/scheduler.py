"""APScheduler wiring. The same job id lets the settings page reschedule live."""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from .pipeline import run_cycle

JOB_ID = "secnews-cycle"
log = logging.getLogger("secnews.scheduler")


def make_scheduler(cfg_getter) -> BackgroundScheduler:
    """cfg_getter returns the current config dict, so edits apply on the next run."""
    sched = BackgroundScheduler(timezone="UTC")
    sched.start(paused=False)
    apply_schedule(sched, cfg_getter)
    return sched


def apply_schedule(sched, cfg_getter) -> None:
    cfg = cfg_getter()
    if sched.get_job(JOB_ID):
        sched.remove_job(JOB_ID)
    s = cfg["scheduler"]
    if not s.get("enabled", True):
        log.info("scheduler disabled by config")
        return
    minutes = max(1, int(s.get("interval_minutes", 60)))
    sched.add_job(lambda: run_cycle(cfg_getter()), "interval", minutes=minutes, id=JOB_ID,
                  max_instances=1, coalesce=True, misfire_grace_time=300)
    log.info("scheduled every %s minutes", minutes)


def next_run(sched):
    job = sched.get_job(JOB_ID) if sched else None
    return job.next_run_time if job else None
