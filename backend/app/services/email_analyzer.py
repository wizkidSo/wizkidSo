import re
from urllib.parse import urlparse

URGENT_PHRASES = [
    "urgent",
    "immediately",
    "act now",
    "account suspended",
    "account blocked",
    "verify your account",
    "final warning",
    "unauthorized login",
]

SENSITIVE_REQUESTS = [
    "enter your password",
    "confirm your password",
    "share your password",
    "credit card details",
    "bank account details",
    "one time password",
    "otp",
]

PRIZE_PHRASES = [
    "you have won",
    "claim your prize",
    "claim your reward",
    "you are a winner",
    "free gift",
    "claim your lottery",
]


def extract_urls(text: str) -> list[str]:
    pattern = r"""https?://[^\s<>"']+"""
    urls = re.findall(pattern, text, flags=re.IGNORECASE)
    return [url.rstrip(".,!?;:)") for url in urls]


def analyze_email(email_text: str) -> dict:
    text = email_text.strip()

    if not text:
        return {
            "result": "UNKNOWN",
            "risk_score": 0,
            "explanation": "Please provide email content to analyze.",
            "indicators": [],
            "extracted_urls": [],
            "recommendations": [
                "Paste the email subject and body before scanning."
            ],
        }

    lowered_text = text.lower()
    indicators = []
    score = 0

    matched_urgent = [
        phrase for phrase in URGENT_PHRASES
        if phrase in lowered_text
    ]

    if matched_urgent:
        score += min(25, len(matched_urgent) * 10)
        indicators.append(
            "Urgent language detected: " + ", ".join(matched_urgent)
        )

    matched_sensitive = [
        phrase for phrase in SENSITIVE_REQUESTS
        if phrase in lowered_text
    ]

    if matched_sensitive:
        score += min(35, len(matched_sensitive) * 15)
        indicators.append(
            "Possible request for sensitive information: "
            + ", ".join(matched_sensitive)
        )

    matched_prizes = [
        phrase for phrase in PRIZE_PHRASES
        if phrase in lowered_text
    ]

    if matched_prizes:
        score += min(20, len(matched_prizes) * 10)
        indicators.append(
            "Prize or reward language detected: "
            + ", ".join(matched_prizes)
        )

    urls = extract_urls(text)

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            reasons = []

            if parsed.scheme.lower() != "https":
                reasons.append("does not use HTTPS")

            if "@" in parsed.netloc:
                reasons.append("contains an @ symbol in the authority")

            if hostname.startswith("xn--"):
                reasons.append("uses internationalized domain encoding")

            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
                reasons.append("uses an IP address as the hostname")

            if reasons:
                score += 15
                indicators.append(
                    f"URL indicator in {url}: " + ", ".join(reasons)
                )

        except ValueError:
            score += 15
            indicators.append(f"Could not parse URL: {url}")

    score = min(score, 100)

    if score >= 60:
        result = "PHISHING"
    elif score >= 25:
        result = "SUSPICIOUS"
    else:
        result = "LOW_RISK"

    if indicators:
        explanation = (
            f"Detected {len(indicators)} potential phishing indicator(s). "
            "This rule-based result does not definitively establish "
            "whether the email is malicious."
        )
    else:
        explanation = (
            "No configured phishing indicators were detected. "
            "This does not guarantee that the email is safe."
        )

    recommendations = [
        "Do not click suspicious links or open unexpected attachments.",
        "Never share passwords, OTPs, or banking details in response to an email.",
        "Verify the sender through an independently obtained official contact method.",
    ]

    return {
        "result": result,
        "risk_score": score,
        "explanation": explanation,
        "indicators": indicators,
        "extracted_urls": urls,
        "recommendations": recommendations,
    }