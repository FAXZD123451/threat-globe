"""Geolocalización de IPs.

- IPs públicas: base de datos MMDB (GeoLite2-City de MaxMind o dbip-city-lite), si existe.
- IPs de documentación/privadas (las que usa el simulador): un país de demostración
  asignado de forma determinista, para que la demo se vea realista sin inventar
  la ubicación de IPs reales.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path

try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # geoip2 es opcional
    geoip2 = None


@dataclass(frozen=True)
class Location:
    country: str
    country_code: str
    lat: float | None
    lng: float | None


UNKNOWN = Location("Desconocido", "??", None, None)

# País, código, lat, lng, peso. El peso imita la distribución típica que ven los honeypots.
DEMO_COUNTRIES = [
    ("China", "CN", 35.9, 104.2, 18),
    ("Rusia", "RU", 61.5, 105.3, 14),
    ("Estados Unidos", "US", 39.8, -98.6, 12),
    ("Brasil", "BR", -14.2, -51.9, 8),
    ("India", "IN", 20.6, 78.9, 8),
    ("Vietnam", "VN", 14.1, 108.3, 6),
    ("Irán", "IR", 32.4, 53.7, 5),
    ("Indonesia", "ID", -0.8, 113.9, 5),
    ("Corea del Sur", "KR", 35.9, 127.8, 4),
    ("Ucrania", "UA", 48.4, 31.2, 4),
    ("México", "MX", 23.6, -102.5, 3),
    ("Colombia", "CO", 4.6, -74.1, 3),
    ("Turquía", "TR", 38.9, 35.2, 3),
    ("Nigeria", "NG", 9.1, 8.7, 2),
    ("Sudáfrica", "ZA", -30.6, 22.9, 2),
    ("Alemania", "DE", 51.2, 10.4, 2),
]
_DEMO_TOTAL = sum(c[4] for c in DEMO_COUNTRIES)


class GeoLocator:
    def __init__(self, db_path: Path | None = None) -> None:
        self._reader = None
        if db_path and db_path.exists() and geoip2 is not None:
            self._reader = geoip2.database.Reader(str(db_path))

    @property
    def has_database(self) -> bool:
        return self._reader is not None

    def locate(self, ip: str) -> Location:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return UNKNOWN

        if not addr.is_global:
            return demo_location(ip)

        if self._reader is None:
            return UNKNOWN
        try:
            city = self._reader.city(ip)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return UNKNOWN
        names = city.country.names
        return Location(
            country=names.get("es") or names.get("en") or "Desconocido",
            country_code=city.country.iso_code or "??",
            lat=city.location.latitude,
            lng=city.location.longitude,
        )

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()


def demo_location(ip: str) -> Location:
    """Misma IP → mismo país y punto, siempre. Elige país según el peso."""
    digest = hashlib.sha256(ip.encode()).digest()
    roll = int.from_bytes(digest[:4], "big") % _DEMO_TOTAL
    for name, code, lat, lng, weight in DEMO_COUNTRIES:
        if roll < weight:
            break
        roll -= weight
    # Dispersión de hasta ±4° para que no salgan todos del mismo punto.
    dlat = (digest[4] / 255 - 0.5) * 8
    dlng = (digest[5] / 255 - 0.5) * 8
    return Location(name, code, round(lat + dlat, 3), round(lng + dlng, 3))


def mask_ip(ip: str) -> str:
    """Oculta el último octeto (IPv4) o los últimos 80 bits (IPv6) antes de publicar."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    if addr.version == 4:
        return ".".join(ip.split(".")[:3] + ["x"])
    network = ipaddress.ip_network(f"{ip}/48", strict=False)
    return f"{network.network_address}/48"
