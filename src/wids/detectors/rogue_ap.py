# src/wids/detectors/rogue_ap.py
from typing import Dict, Any, Tuple, Optional

def build_ssid_index(policy: Dict[str, Any]):
    idx = {}
    for p in policy.get("ssids", []):
        idx[p["name"]] = {
            "bssids": set(b.lower() for b in p.get("allowed_bssids", [])),
            "channels": set(p.get("allowed_channels", [])),
            "bands": set(p.get("allowed_bands", [])),
        }
    return idx

def check_rogue(ssid: Optional[str], bssid: Optional[str], band: str, chan: int, idx) -> Tuple[bool, str]:
    if not ssid:
        return False, ""
    pol = idx.get(ssid)
    if not pol:
        return False, ""  # SSID not protected by policy
    if pol["channels"] and chan not in pol["channels"]:
        return True, f"SSID {ssid} on unapproved channel {chan}"
    if pol["bands"] and band not in pol["bands"]:
        return True, f"SSID {ssid} on unapproved band {band}"
    if pol["bssids"] and (not bssid or bssid.lower() not in pol["bssids"]):
        return True, f"SSID {ssid} from unknown BSSID {bssid}"
    return False, ""
