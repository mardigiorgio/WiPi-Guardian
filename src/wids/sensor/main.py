# src/wids/sensor/main.py
from wids.common import load_config
from wids.db import get_engine, init_db, ensure_schema, session, Event, Alert
from wids.alerts import send_discord, send_email

from sqlmodel import select, text
from datetime import datetime, timedelta
import argparse, time, signal

def detect_deauths(db, defense: dict, window_sec=10, per_src_limit=30, global_limit=80):
    "Count deauths scoped to the defended SSID."
    since = datetime.utcnow() - timedelta(seconds=window_sec)
    rows = db.exec(select(Event).where(Event.ts >= since)).all()
    counts = {}
    total = 0

    def_ssid = (defense.get("ssid") or "").strip()
    allow_bssids = set(b.lower() for b in defense.get("allowed_bssids", []) if isinstance(b, str))

    # Build known BSSIDs for defended SSID when no explicit allowlist
    known_bssids = set()
    if def_ssid and not allow_bssids:
        lookback = datetime.utcnow() - timedelta(minutes=10)
        beacons = db.exec(
            select(Event)
            .where(Event.ts >= lookback)
            .where(Event.type == "mgmt.beacon")
            .where(Event.ssid == def_ssid)
        ).all()
        known_bssids = set(b.bssid.lower() for b in beacons if b.bssid)

    for e in rows:
        if e.type != "mgmt.deauth":
            continue
        # Scope to defense
        if not def_ssid:
            continue
        if allow_bssids:
            if not e.bssid or e.bssid.lower() not in allow_bssids:
                continue
        else:
            if e.bssid:
                if e.bssid.lower() not in known_bssids:
                    continue
            else:
                # No BSSID: check if src or dst is a known BSSID
                sd = (e.src or "").lower(), (e.dst or "").lower()
                if not any(x in known_bssids for x in sd):
                    continue

        src = e.src or "unknown"
        counts[src] = counts.get(src, 0) + 1
        total += 1

    offenders = [s for s, c in counts.items() if c >= per_src_limit]
    triggered = bool(offenders) or total >= global_limit
    return triggered, total, offenders, counts

def loop(cfg):
    engine = get_engine(cfg["database"]["path"])
    init_db(engine)

    # Ensure schema + indexes
    with session(engine) as db:
        ensure_schema(engine)
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_ts ON event(ts);"))
        db.exec(text("CREATE INDEX IF NOT EXISTS idx_events_type_ts ON event(type, ts);"))
        db.commit()
    print("[db] indexes ensured")

    w = cfg.get("thresholds", {}).get("deauth", {}).get("window_sec", 10)
    per_src = cfg.get("thresholds", {}).get("deauth", {}).get("per_src_limit", 30)
    glob = cfg.get("thresholds", {}).get("deauth", {}).get("global_limit", 80)
    cooldown = cfg.get("thresholds", {}).get("deauth", {}).get("cooldown_sec", 60)

    print(f"[sensor] deauth window={w}s per_src={per_src} global={glob} cooldown={cooldown}s")

    last_fire_ts = 0.0
    last_sig = None
    stop = False

    def _sig(*_):
        nonlocal stop
        stop = True
        print("\n[sensor] stopping...")

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    defense = cfg.get("defense", {})
    def_ssid = (defense.get("ssid") or "").strip()
    armed = bool(def_ssid)
    if not armed:
        print("[sensor] not armed (no defended SSID)")

    # In-memory RSN baseline per allowed BSSID
    rsn_baseline = {}  # bssid(lower) -> { 'akms': set, 'ciphers': set }

    with session(engine) as db:
        while not stop:
            # --- Deauth detection (scoped) ---
            trig, total, offenders, counts = detect_deauths(db, defense, w, per_src, glob)
            sig = ("deauth_flood", total, tuple(sorted(offenders)))
            now = time.time()
            too_soon = (now - last_fire_ts) < cooldown
            same_as_before = (sig == last_sig)

            if armed and trig and not (too_soon and same_as_before):
                a = Alert(
                    ts=datetime.utcnow(),
                    severity="critical" if total >= glob*2 or offenders else "warn",
                    kind="deauth_flood",
                    summary=f"Deauth burst: total={total}, offenders={len(offenders)}",
                )
                db.add(a); db.commit()
                print(f"[ALERT] {a.summary}")

                # Notifications (best-effort)
                try:
                    cfg_alerts = cfg.get("alerts", {})
                    msg = f"[WIDS] {a.kind} ({a.severity}) — {a.summary}"
                    if cfg_alerts.get("discord_webhook"):
                        send_discord(cfg_alerts["discord_webhook"], msg)
                    em = cfg_alerts.get("email", {})
                    if em and em.get("to"):
                        send_email(
                            em.get("smtp_host", "smtp.gmail.com"),
                            int(em.get("smtp_port", 587)),
                            em.get("username", ""),
                            em.get("password", ""),
                            em.get("from", "WIDS <alerts@example.com>"),
                            em.get("to", []),
                            subject=f"[WIDS] {a.kind} {a.severity}",
                            body=msg,
                        )
                except Exception as e:
                    print(f"[notify] failed: {e}")

                last_fire_ts = now
                last_sig = sig

            # --- Rogue AP check (over recent beacons for defended SSID) ---
            since = datetime.utcnow() - timedelta(seconds=w)
            beacons = db.exec(
                select(Event)
                .where(Event.ts >= since)
                .where(Event.type == "mgmt.beacon")
            ).all()
            for e in beacons:
                if not armed:
                    break
                if not e.ssid or e.ssid != def_ssid:
                    continue

                bssid = (e.bssid or "").lower()
                allowed_bssids = set(b.lower() for b in defense.get("allowed_bssids", []) if isinstance(b, str))
                allowed_channels = set(int(c) for c in defense.get("allowed_channels", []) if isinstance(c, (int, str)))
                allowed_bands = set(str(b) for b in defense.get("allowed_bands", []) if isinstance(b, (int, str)))

                # Build/update RSN baseline for allowed BSSIDs
                akms = set((e.rsn_akms or "").split(",")) if e.rsn_akms else set()
                ciphers = set((e.rsn_ciphers or "").split(",")) if e.rsn_ciphers else set()
                if bssid and bssid in allowed_bssids and (akms or ciphers):
                    if bssid not in rsn_baseline:
                        rsn_baseline[bssid] = {"akms": akms.copy(), "ciphers": ciphers.copy()}

                reason = None
                if allowed_bssids and (not bssid or bssid not in allowed_bssids):
                    reason = f"SSID {def_ssid} from unknown BSSID {e.bssid}"
                elif allowed_channels and e.chan not in allowed_channels:
                    reason = f"SSID {def_ssid} on unapproved channel {e.chan}"
                elif allowed_bands and str(e.band) not in allowed_bands:
                    reason = f"SSID {def_ssid} on unapproved band {e.band}"
                else:
                    # RSN mismatch check (only if we have a baseline from allowed BSSIDs)
                    if allowed_bssids and rsn_baseline and (akms or ciphers):
                        # Compare against any one baseline (simple approach)
                        base = next(iter(rsn_baseline.values()))
                        if ((base.get("akms") and akms and akms != base["akms"]) or
                            (base.get("ciphers") and ciphers and ciphers != base["ciphers"])):
                            reason = f"SSID {def_ssid} RSN mismatch (akm/cipher) at {e.bssid}"

                if reason:
                    a = Alert(
                        ts=datetime.utcnow(),
                        severity="warn",
                        kind="rogue_ap",
                        summary=reason,
                    )
                    db.add(a); db.commit()
                    print(f"[ALERT] {a.summary}")

                    # Optional: minimal Discord notify for rogue AP
                    try:
                        cfg_alerts = cfg.get("alerts", {})
                        if cfg_alerts.get("discord_webhook"):
                            send_discord(cfg_alerts["discord_webhook"], f"[WIDS] {a.kind} — {a.summary}")
                    except Exception as ex:
                        print(f"[notify] failed: {ex}")

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
