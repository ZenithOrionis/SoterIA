"""
SoterIA -- Geospatial Intelligence Module
=============================================
Deterministic, offline IP-to-coordinate resolver.
No external API calls - fully air-gap compliant.

Known threat IPs are mapped to their real-world known hosting locations.
Internal RFC-1918 IPs are mapped to a configurable corporate HQ cluster.
Unknown public IPs are resolved via a seeded hash spread across realistic
cyber-attacker source regions.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

# ── Known threat actor IP pinpoints ─────────────────────────────────────
# These are well-documented Tor exit nodes / bulletproof hosting locations
_KNOWN_THREAT_IPS: dict[str, Tuple[float, float, str]] = {
    "185.220.101.42": (52.3740, 4.8897,  "Amsterdam, NL"),   # Tor exit - NL
    "91.240.118.7":   (55.7558, 37.6173, "Moscow, RU"),       # Bulletproof hosting
    "23.129.64.13":   (34.0195, -118.4912, "Los Angeles, US"), # Tor exit - US
    "45.155.205.99":  (44.4328, 26.1036, "Bucharest, RO"),    # Dark web C2
}

# ── Corporate HQ cluster (RFC-1918 internal IPs) ─────────────────────────
_CORPORATE_HQ: Tuple[float, float, str] = (37.7749, -122.4194, "San Francisco, US")

# ── Attacker source region pool for unknown public IPs ──────────────────
_ATTACKER_REGIONS = [
    (55.7558,  37.6173, "Moscow, RU"),
    (39.9042, 116.4074, "Beijing, CN"),
    (12.9716,  77.5946, "Bangalore, IN"),
    (51.5074,  -0.1278, "London, GB"),
    (48.8566,   2.3522, "Paris, FR"),
    (52.5200,  13.4050, "Berlin, DE"),
    (1.3521,  103.8198, "Singapore, SG"),
    (35.6762, 139.6503, "Tokyo, JP"),
    (37.5665, 126.9780, "Seoul, KR"),
    (-23.5505, -46.6333, "Sao Paulo, BR"),
    (41.0082,  28.9784, "Istanbul, TR"),
    (30.0444,  31.2357, "Cairo, EG"),
    (6.5244,   3.3792, "Lagos, NG"),
    (19.0760,  72.8777, "Mumbai, IN"),
    (55.6761,  12.5683, "Copenhagen, DK"),
    (50.0755,  14.4378, "Prague, CZ"),
    (44.4268,  26.1025, "Bucharest, RO"),
    (47.4979,  19.0402, "Budapest, HU"),
    (59.3293,  18.0686, "Stockholm, SE"),
    (60.1699,  24.9384, "Helsinki, FI"),
]


def _is_rfc1918(ip: str) -> bool:
    """Return True if IP is a private/internal RFC-1918 address."""
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
    except Exception:
        pass
    return False


def ip_to_geo(ip: str) -> Tuple[float, float, str]:
    """
    Resolve an IP address to (lat, lon, location_label) deterministically.
    Fully offline - no external API calls.
    """
    # 1. Known threat IPs → pinpoint accuracy
    if ip in _KNOWN_THREAT_IPS:
        return _KNOWN_THREAT_IPS[ip]

    # 2. Internal IPs → corporate HQ cluster with small jitter
    if _is_rfc1918(ip):
        seed = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        jitter_lat = ((seed % 100) - 50) / 500.0   # ±0.1 degrees
        jitter_lon = (((seed >> 8) % 100) - 50) / 500.0
        lat, lon, label = _CORPORATE_HQ
        return (lat + jitter_lat, lon + jitter_lon, f"Corp Network ({ip})")

    # 3. Unknown public IPs → deterministic region selection
    seed = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    region = _ATTACKER_REGIONS[seed % len(_ATTACKER_REGIONS)]
    jitter_lat = ((seed % 200) - 100) / 1000.0
    jitter_lon = (((seed >> 8) % 200) - 100) / 1000.0
    lat, lon, label = region
    return (lat + jitter_lat, lon + jitter_lon, label)
