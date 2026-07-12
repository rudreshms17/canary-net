"""Proxy detection utilities for Canary-Net honeypot alerts."""

import json
from datetime import datetime, timedelta
from urllib import request, error


class ProxyDetector:
    """Check whether an IP appears to be a proxy, TOR exit node, or datacenter."""

    def __init__(self):
        self.cache = {}
        self.ttl = timedelta(hours=1)

    def check_ip(self, ip: str) -> dict:
        """Check an IP address and return a proxy risk profile."""
        now = datetime.utcnow()
        cached = self.cache.get(ip)
        if cached and now - cached["cached_at"] < self.ttl:
            return cached["result"]

        defaults = {
            "is_proxy": False,
            "is_tor": False,
            "is_datacenter": False,
            "country": "Unknown",
            "country_code": "??",
            "city": "Unknown",
            "isp": "Unknown",
            "risk_level": "UNKNOWN",
        }

        try:
            url = (
                f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,"
                f"tor,country,countryCode,city,isp"
            )
            with request.urlopen(url, timeout=3) as response:
                payload = json.load(response)

            if payload.get("status") != "success":
                result = defaults
            else:
                result = {
                    "is_proxy": bool(payload.get("proxy", False)),
                    "is_tor": bool(payload.get("tor", False)),
                    "is_datacenter": bool(payload.get("hosting", False)),
                    "country": payload.get("country", "Unknown"),
                    "country_code": payload.get("countryCode", "??"),
                    "city": payload.get("city", "Unknown"),
                    "isp": payload.get("isp", "Unknown"),
                    "risk_level": self._get_risk_level(
                        bool(payload.get("tor", False)),
                        bool(payload.get("proxy", False)),
                        bool(payload.get("hosting", False)),
                    ),
                }
        except (error.URLError, error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError):
            result = defaults

        self.cache[ip] = {"result": result, "cached_at": now}
        return result

    def get_score_bonus(self, ip: str) -> int:
        """Return a threat scoring bonus for the given IP."""
        info = self.check_ip(ip)
        if info.get("is_tor"):
            return 50
        if info.get("is_proxy"):
            return 40
        if info.get("is_datacenter"):
            return 30
        return 0

    def _get_risk_level(self, is_tor: bool, is_proxy: bool, is_datacenter: bool) -> str:
        if is_tor:
            return "HIGH"
        if is_proxy or is_datacenter:
            return "MEDIUM"
        return "LOW"


if __name__ == "__main__":
    detector = ProxyDetector()
    for ip in ["8.8.8.8", "1.1.1.1"]:
        result = detector.check_ip(ip)
        print(f"IP {ip}: {result}")
        print(f"Bonus: {detector.get_score_bonus(ip)}")
