"""Behavior classification helpers for Canary-Net honeypot sessions."""


class BehaviorClassifier:
    """Classify a session based on observed attack patterns."""

    def classify(self, session: dict) -> str:
        """Return the behavior classification for a session."""
        unique_services_hit = session.get("unique_services_hit", 0)
        unique_ports_hit = session.get("unique_ports_hit", 0)
        if unique_services_hit > 1 or unique_ports_hit > 3:
            return "SCANNER"

        total_attempts = session.get("total_attempts", 0)
        avg_interval_ms = session.get("avg_interval_ms", 0.0)
        if total_attempts > 5 and avg_interval_ms < 300:
            return "BRUTE_FORCE"

        if avg_interval_ms < 100:
            return "BOT"

        if avg_interval_ms > 2000:
            return "HUMAN"

        return "UNKNOWN"

    def get_risk_description(self, behavior: str) -> str:
        """Get a human-readable description for a behavior type."""
        descriptions = {
            "SCANNER": "Actively scanning multiple services, likely reconnaissance",
            "BRUTE_FORCE": "Repeated login attempts, password attack in progress",
            "BOT": "Fully automated, part of a botnet or scanning tool",
            "HUMAN": "Human speed access, possibly a genuine user or insider",
            "UNKNOWN": "Insufficient data to classify",
        }
        return descriptions.get(behavior, descriptions["UNKNOWN"])


if __name__ == "__main__":
    classifier = BehaviorClassifier()
    sessions = [
        {
            "total_attempts": 3,
            "unique_ports_hit": 4,
            "unique_services_hit": 2,
            "avg_interval_ms": 1200,
        },
        {
            "total_attempts": 8,
            "unique_ports_hit": 2,
            "unique_services_hit": 1,
            "avg_interval_ms": 150,
        },
        {
            "total_attempts": 2,
            "unique_ports_hit": 1,
            "unique_services_hit": 1,
            "avg_interval_ms": 50,
        },
        {
            "total_attempts": 1,
            "unique_ports_hit": 1,
            "unique_services_hit": 1,
            "avg_interval_ms": 5000,
        },
    ]

    for session in sessions:
        behavior = classifier.classify(session)
        print(f"Behavior: {behavior} | {classifier.get_risk_description(behavior)}")
