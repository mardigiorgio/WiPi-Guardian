# src/wids/sensor/main.py
from wids.common import load_config
from wids.db import get_engine, init_db, session, Event, Alert
from sqlmodel import select, text
from datetime import datetime, timedelta
import argparse, json, time, signal
from sqlmodel import text

def detect_deauths(db, window_sec=10, per_src_limit=30, global_limit=80):
    since = datetime.utcnow() - timedelta(seconds=window_sec)
    rows = db.exec(select(Event).where(Event.ts >= since)).all()
    counts = {}
    total = 0
    for e in rows:
        if e.type == "mgmt.deauth":
            src = e.src or "unknown"
            counts[src] = counts.get(src, 0) + 1
            total += 1
    offenders = [s for s,c in counts.items() if c >= per_src_limit]
    triggered = bool(offenders) or total >= global_limit
    return triggered, total, offenders, counts

def loop(cfg):
    engine = get_engine(cfg["database"]["path"])
    init_db(engine)

    with session(engine) as db:
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_ts ON event(ts);"))
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_type_ts ON event(type, ts);"))
        db.commit()
    print("[db] indexes ensured")

    w = cfg.get("thresholds", {}).get("deauth", {}).get("window_sec", 10)
    per_src = cfg.get("thresholds", {}).get("deauth", {}).get("per_src_limit", 30)
    glob = cfg.get("thresholds", {}).get("deauth", {}).get("global_limit", 80)
    cooldown = cfg.get("thresholds", {}).get("deauth", {}).get("cooldown_sec", 60)

    print(f"[sensor] deauth window={w}s per_src={per_src} global={glob} cooldown={cooldown}s")

    last_fire_ts = 0
    last_sig = None

    stop = False
    def _sig(*_):
        nonlocal stop
        stop = True
        print("\n[sensor] stopping...")

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    with session(engine) as db:
        while not stop:
            trig, total, offenders, counts = detect_deauths(db, w, per_src, glob)

            # Build a simple signature of the current situation
            sig = ("deauth_flood", total, tuple(sorted(offenders)))

            now = time.time()
            too_soon = (now - last_fire_ts) < cooldown
            same_as_before = (sig == last_sig)

            if trig and not (too_soon and same_as_before):
                details = {
                    "type": "deauth_flood",
                    "total": total,
                    "offenders": offenders,
                    "window_s": w,
                    "per_src_counts": counts,
                }
                a = Alert(
                    ts=datetime.utcnow(),
                    severity="critical" if total >= glob*2 or offenders else "warn",
                    kind="deauth_flood",
                    summary=f"Deauth burst: total={total}, offenders={len(offenders)}",
                )
                db.add(a); db.commit()
                print(f"[ALERT] {a.summary}")

                last_fire_ts = now
                last_sig = sig

            time.sleep(2)

    print("[sensor] exited cleanly")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    cfg = load_config(args.config)
    loop(cfg)

if __name__ == "__main__":
    main()