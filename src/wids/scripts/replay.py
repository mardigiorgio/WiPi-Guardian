# src/wids/scripts/replay.py
from wids.common import load_config
from wids.db import get_engine, init_db, ensure_schema, session, Event
from wids.ie.rsn import parse_rsn_info
from datetime import datetime
from scapy.all import (
    PcapReader, Dot11, Dot11Deauth, Dot11Disas, Dot11Beacon, Dot11Elt, RadioTap
)
import argparse, os

def extract_ssid(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return None
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        try:
            if elt.ID == 0:  # SSID Parameter Set
                return elt.info.decode(errors="ignore")
        except Exception:
            return None
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def replay(cfg, pcap_path, band, chan):
    engine = get_engine(cfg["database"]["path"])
    init_db(engine)
    ensure_schema(engine)
    count = 0
    with session(engine) as db:
        if not os.path.exists(pcap_path):
            print(f"[!] PCAP not found: {pcap_path}")
            return
        for pkt in PcapReader(pcap_path):
            if not pkt.haslayer(Dot11):
                continue

            ev_type = None
            ssid = None
            if pkt.haslayer(Dot11Deauth):
                ev_type = "mgmt.deauth"
            elif pkt.haslayer(Dot11Disas):
                ev_type = "mgmt.disassoc"
            elif pkt.haslayer(Dot11Beacon):
                ev_type = "mgmt.beacon"
                ssid = extract_ssid(pkt)
            else:
                continue

            d11 = pkt[Dot11]
            src = d11.addr2
            dst = d11.addr1
            bssid = d11.addr3

            rssi = None
            if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal"):
                try:
                    rssi = int(pkt[RadioTap].dBm_AntSignal)
                except Exception:
                    rssi = None

            rsn = parse_rsn_info(pkt) if ev_type == "mgmt.beacon" else {}

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
            db.add(e)
            count += 1
            if count % 500 == 0:
                db.commit()
        db.commit()
    print(f"[ok] Replayed {count} frames into {cfg['database']['path']}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--band", default="5")
    ap.add_argument("--chan", default="36")
    args = ap.parse_args()
    cfg = load_config(args.config)
    replay(cfg, args.pcap, args.band, args.chan)

if __name__ == "__main__":
    main()
