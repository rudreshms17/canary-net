"""GeoIP lookup helpers for Canary-Net honeypot alerts."""

import ipaddress
import json
from datetime import datetime, timedelta
from urllib import error, request


class GeoIPService:
    """Resolve IP geolocation information with simple caching."""

    def __init__(self):
        self.cache = {}
        self.ttl = timedelta(hours=1)

    def lookup(self, ip: str) -> dict:
        """Look up geolocation information for an IP address."""
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            return self._unknown_result()

        if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local:
            return {
                "country": "Local Network",
                "country_code": "LAN",
                "city": "LAN",
                "lat": 0.0,
                "lon": 0.0,
                "isp": "Internal",
            }

        now = datetime.utcnow()
        cached = self.cache.get(ip)
        if cached and now - cached["cached_at"] < self.ttl:
            return cached["result"]

        try:
            url = (
                f"http://ip-api.com/json/{ip}?fields=status,country,"
                f"countryCode,city,lat,lon,isp"
            )
            with request.urlopen(url, timeout=3) as response:
                payload = json.load(response)

            if payload.get("status") != "success":
                result = self._unknown_result()
            else:
                result = {
                    "country": payload.get("country", "Unknown"),
                    "country_code": payload.get("countryCode", "??"),
                    "city": payload.get("city", "Unknown"),
                    "lat": float(payload.get("lat", 0.0) or 0.0),
                    "lon": float(payload.get("lon", 0.0) or 0.0),
                    "isp": payload.get("isp", "Unknown"),
                }
        except (error.URLError, error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError):
            result = self._unknown_result()

        self.cache[ip] = {"result": result, "cached_at": now}
        return result

    def format_location(self, ip: str) -> str:
        """Format a location string for display."""
        info = self.lookup(ip)
        country = info.get("country", "Unknown")
        city = info.get("city", "Unknown")

        if country == "Local Network":
            return "Local Network"
        if country == "Unknown" and city == "Unknown":
            return "Unknown Location"
        if city in {"Unknown", "LAN"}:
            return country
        return f"{city}, {country}"

    def get_country_stats(self, alerts: list) -> list:
        """Group alerts by geo country and count them."""
        counts = {}
        for alert in alerts:
            country = alert.get("geo_country")
            if not country:
                continue
            counts[country] = counts.get(country, 0) + 1

        stats = []
        for country, count in counts.items():
            stats.append({
                "country": country,
                "country_code": self.lookup(country).get("country_code", "??"),
                "count": count,
            })

        return sorted(stats, key=lambda item: item["count"], reverse=True)

    def _unknown_result(self) -> dict:
        return {
            "country": "Unknown",
            "country_code": "??",
            "city": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Unknown",
        }


if __name__ == "__main__":
    service = GeoIPService()
    for ip in ["8.8.8.8", "192.168.1.10", "not-an-ip"]:
        result = service.lookup(ip)
        print(f"IP {ip}: {result}")
        print(f"Location: {service.format_location(ip)}")
