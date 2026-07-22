from __future__ import annotations

import ipaddress
import logging
import os
import random
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger(__name__)

try:
    import requests
except Exception:  # pragma: no cover - optional dependency
    requests = None

DEMO_COORDS = {
    "8.8.8.8": ("United States", "Mountain View", "Google", 37.386, -122.0838),
    "1.1.1.1": ("Australia", "Sydney", "Cloudflare", -33.8688, 151.2093),
    "13.107.42.14": ("United States", "Redmond", "Microsoft", 47.674, -122.1215),
    "34.120.88.10": ("United States", "Kansas City", "Google Cloud", 39.0997, -94.5786),
    "45.133.32.156": ("Netherlands", "Amsterdam", "Demo suspicious host", 52.3676, 4.9041),
    "45.33.32.156": ("United States", "Fremont", "Linode", 37.5485, -121.9886),
    "104.18.12.123": ("United States", "San Francisco", "Cloudflare", 37.7749, -122.4194),
    "185.199.108.133": ("United States", "San Francisco", "GitHub", 37.7749, -122.4194),
    "93.184.216.34": ("United States", "Los Angeles", "Example Net", 34.0522, -118.2437),
    "203.0.113.99": ("Documentation Net", "Example City", "Reserved demo IP", 35.6895, 139.6917),
    "10.0.0.23": ("LAN", "Private Network", "Internal suspicious host", 27.7172, 85.3240),
}

OFFLINE_WORLD_POINTS = [
    ("United States", "New York", 40.7128, -74.0060),
    ("United Kingdom", "London", 51.5074, -0.1278),
    ("Germany", "Frankfurt", 50.1109, 8.6821),
    ("Singapore", "Singapore", 1.3521, 103.8198),
    ("Japan", "Tokyo", 35.6762, 139.6503),
    ("India", "Mumbai", 19.0760, 72.8777),
    ("Australia", "Sydney", -33.8688, 151.2093),
]


@dataclass(slots=True)
class GeoResult:
    ip: str
    country: str
    city: str
    org: str
    latitude: float | None = None
    longitude: float | None = None
    source: str = "local"

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "country": self.country,
            "city": self.city,
            "org": self.org,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "source": self.source,
        }


class GeoLocator:
    """Best-effort IP enrichment that degrades cleanly offline."""

    def __init__(self, timeout: float = 1.2, allow_network: bool | None = None) -> None:
        self.timeout = timeout
        self.allow_network = bool(os.getenv("NETWATCH_ENABLE_GEOIP_API")) if allow_network is None else allow_network
        self.cache: dict[str, GeoResult] = {}

    def lookup(self, ip: str) -> GeoResult:
        if ip in self.cache:
            return self.cache[ip]
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            result = GeoResult(ip, "Unknown", "Unknown", "Invalid address")
            self.cache[ip] = result
            return result

        if ip in DEMO_COORDS:
            country, city, org, latitude, longitude = DEMO_COORDS[ip]
            result = GeoResult(ip, country, city, org, latitude, longitude, source="demo")
            self.cache[ip] = result
            return result

        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            result = GeoResult(ip, "Private Network", "Local LAN", "RFC1918/Internal", 27.7172, 85.3240, source="local")
            self.cache[ip] = result
            return result

        if not self.allow_network or requests is None:
            result = self._offline_public_result(ip)
            self.cache[ip] = result
            return result

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,org,lat,lon,message"},
                timeout=self.timeout,
            )
            data = response.json()
            if response.ok and data.get("status") == "success":
                result = GeoResult(
                    ip=ip,
                    country=data.get("country") or "Unknown",
                    city=data.get("city") or "Unknown",
                    org=data.get("org") or "Unknown",
                    latitude=data.get("lat"),
                    longitude=data.get("lon"),
                    source="ip-api",
                )
            else:
                result = GeoResult(ip, "Internet", "Unknown", data.get("message", "Geo lookup unavailable"))
        except Exception:
            LOGGER.info("Geo lookup failed for %s", ip, exc_info=True)
            result = GeoResult(ip, "Internet", "Offline", "Lookup unavailable")
        self.cache[ip] = result
        return result

    @staticmethod
    def _offline_public_result(ip: str) -> GeoResult:
        rng = random.Random(ip)
        country, city, latitude, longitude = rng.choice(OFFLINE_WORLD_POINTS)
        return GeoResult(ip, country, city, "Offline demo geolocation", latitude, longitude, source="offline")
