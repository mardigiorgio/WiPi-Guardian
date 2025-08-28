from datetime import datetime
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt, RadioTap

from wids.db import get_engine, init_db, ensure_schema, session, Event
from wids.ie.rsn import parse_rsn_info


def _extract_ssid(pkt):
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if getattr(elt, 'ID', None) == 0:  # SSID
                return elt.info.decode(errors="ignore")
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return None


def _derive_chan_band(pkt):
    # Try DS Parameter Set first (ID=3)
    chan = None
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if getattr(elt, 'ID', None) == 3 and len(elt.info) >= 1:
                chan = int(elt.info[0])
                break
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass

    # Band inference
    band = "?"
    if chan is not None:
        if 1 <= chan <= 14:
            band = "2.4"
        elif 36 <= chan <= 196:
            band = "5"
        elif 1 <= chan <= 233:  # ambiguous; without freq assume 6GHz if not 2.4 range
            band = "6"

    # If no channel from DS, try RadioTap frequency
    if chan is None:
        try:
            if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'ChannelFrequency'):
                freq = int(pkt[RadioTap].ChannelFrequency)
                if 2412 <= freq <= 2484:
                    chan = int(round((freq - 2407) / 5.0))
                    band = "2.4"
                elif 5000 <= freq <= 5900:
                    chan = int(round((freq - 5000) / 5.0))
                    band = "5"
                elif 5955 <= freq <= 7115:
                    chan = int(round((freq - 5955) / 5.0) + 1)
                    band = "6"
                else:
                    chan = 0
                    band = "?"
        except Exception:
            chan = 0
            band = "?"

    if chan is None:
        chan = 0
    return int(chan), str(band)


def _extract_rssi(pkt):
    try:
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
            return int(pkt[RadioTap].dBm_AntSignal)
    except Exception:
        return None
    return None


def run_sniffer(cfg: dict):
    """Start a Scapy sniffer on cfg['capture']['iface'] and insert Event rows."""
    iface = cfg.get("capture", {}).get("iface")
    if not iface:
        raise RuntimeError("capture.iface not configured")

    engine = get_engine(cfg["database"]["path"])
    init_db(engine)
    ensure_schema(engine)

    def handle(pkt):
        if not pkt.haslayer(Dot11):
            return

        d11 = pkt[Dot11]
        ev_type = None
        ssid = None
        if pkt.haslayer(Dot11Beacon):
            ev_type = "mgmt.beacon"
            ssid = _extract_ssid(pkt)
        elif pkt.haslayer(Dot11Deauth):
            ev_type = "mgmt.deauth"
        elif pkt.haslayer(Dot11Disas):
            ev_type = "mgmt.disassoc"
        else:
            return

        src = getattr(d11, 'addr2', None)
        dst = getattr(d11, 'addr1', None)
        bssid = getattr(d11, 'addr3', None)
        chan, band = _derive_chan_band(pkt)
        rssi = _extract_rssi(pkt)

        # Defensive scoping: always insert beacons. For deauth/disassoc, apply basic scoping
        defense = cfg.get("defense", {})
        defense_ssid = (defense.get("ssid") or "").strip()
        allowed_bssids = set(b.lower() for b in defense.get("allowed_bssids", []) if isinstance(b, str))
        if ev_type in ("mgmt.deauth", "mgmt.disassoc") and defense_ssid:
            if allowed_bssids and (not bssid or bssid.lower() not in allowed_bssids):
                return
            # else, if no allowlist, insert and let detectors filter

        rsn = {}
        if ev_type == "mgmt.beacon":
            rsn = parse_rsn_info(pkt) or {}

        e = Event(
            ts=datetime.utcnow(),
            type=ev_type,
            band=str(band),
            chan=int(chan),
            src=src,
            dst=dst,
            bssid=bssid,
            ssid=ssid,
            rssi=rssi,
            rsn_akms=",".join(sorted(rsn.get("akms", []))) if rsn else None,
            rsn_ciphers=",".join(sorted(rsn.get("ciphers", []))) if rsn else None,
        )

        # Batch insertions
        if not hasattr(handle, "_buf"):
            handle._buf = []  # type: ignore[attr-defined]
        handle._buf.append(e)  # type: ignore[attr-defined]
        if len(handle._buf) >= 200:  # type: ignore[attr-defined]
            with session(engine) as db:
                for x in handle._buf:  # type: ignore[attr-defined]
                    db.add(x)
                db.commit()
            handle._buf.clear()  # type: ignore[attr-defined]

    # Flush any remaining buffered events periodically
    def flush():
        if hasattr(handle, "_buf") and handle._buf:  # type: ignore[attr-defined]
            with session(engine) as db:
                for x in handle._buf:  # type: ignore[attr-defined]
                    db.add(x)
                db.commit()
            handle._buf.clear()  # type: ignore[attr-defined]

    try:
        sniff(iface=iface, store=False, prn=handle)
    finally:
        flush()

