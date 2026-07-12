"""Threat scoring utilities for Canary-Net honeypot alerts."""


class ThreatScorer:
    """Score suspicious activity and map it to a threat level."""

    COMMON_USERNAMES = [
        "admin",
        "root",
        "test",
        "guest",
        "administrator",
        "user",
        "oracle",
        "postgres",
    ]
    COMMON_PASSWORDS = [
        "password",
        "123456",
        "admin",
        "root",
        "letmein",
        "qwerty",
        "abc123",
        "password1",
        "password123",
        "12345678",
    ]

    def score(self, alert: dict) -> int:
        """Calculate a threat score for an alert."""
        points = 0
        behavior = alert.get("behavior", "")
        canary_name = alert.get("canary_name", "")

        if "ftp_login" in behavior:
            points += 30
        if "username=admin" in behavior or "username=root" in behavior:
            points += 35
        if "password=123456" in behavior or "password=password123" in behavior:
            points += 25
        if "password=password" in behavior:
            points += 20

        if "username=root" in behavior and "password=123456" in behavior:
            points += 20

        if "/admin" in behavior and "post" in behavior.lower():
            points += 45
        elif "/admin" in behavior:
            points += 30
        if "/api/v1/keys" in behavior:
            points += 50
        if "/api/v1/status" in behavior:
            points += 20

        if "ssh" in canary_name.lower() or "ssh" in behavior.lower():
            points += 60

        return min(points, 100)

    def get_threat_level(self, score: int) -> str:
        """Convert a numeric score to a threat level."""
        if score >= 85:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "WARNING"
        return "INFO"

    def should_block(self, score: int) -> bool:
        """Return True when the score is high enough to block."""
        return score >= 85
