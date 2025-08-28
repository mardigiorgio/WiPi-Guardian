from scapy.all import Dot11Elt

def _fmt_selector(b: bytes) -> str:
    if len(b) != 4:
        return b.hex()
    return f"{b[0]:02x}:{b[1]:02x}:{b[2]:02x}:{b[3]}"

def parse_rsn_info(pkt) -> dict:
    """
    Return {'akms': set([...]), 'ciphers': set([...])} from RSN IE (ID=48).
    Uses raw selector format '00:0f:ac:4' etc. Returns {} if not found or parse fails.
    """
    try:
        elt = pkt.getlayer(Dot11Elt)
        # Find RSN element (ID=48)
        while elt is not None:
            if getattr(elt, 'ID', None) == 48:
                data = bytes(elt.info)
                off = 0
                if len(data) < 2:
                    return {}
                # version
                off += 2
                if len(data) < off + 4:
                    return {}
                # group cipher suite
                group = data[off:off+4]
                off += 4
                ciphers = { _fmt_selector(group) }
                # pairwise count
                if len(data) < off + 2:
                    return {}
                pcnt = int.from_bytes(data[off:off+2], 'little')
                off += 2
                for _ in range(pcnt):
                    if len(data) < off + 4:
                        break
                    ciphers.add(_fmt_selector(data[off:off+4]))
                    off += 4
                # AKM count
                if len(data) < off + 2:
                    return {'akms': set(), 'ciphers': ciphers}
                akmcnt = int.from_bytes(data[off:off+2], 'little')
                off += 2
                akms = set()
                for _ in range(akmcnt):
                    if len(data) < off + 4:
                        break
                    akms.add(_fmt_selector(data[off:off+4]))
                    off += 4
                return {'akms': akms, 'ciphers': ciphers}
            elt = elt.payload.getlayer(Dot11Elt)
        return {}
    except Exception:
        return {}

