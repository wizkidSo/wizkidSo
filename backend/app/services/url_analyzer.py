from urllib.parse import urlparse
import re


def analyze_url(url: str):
    """
    Analyze a URL using rule-based phishing indicators.
    Returns risk score, result, explanation and indicators.
    """

    original_url = url.strip()

    # Add scheme if the user didn't provide one
    url_to_check = original_url

    if not url_to_check.startswith(("http://", "https://")):
        url_to_check = "http://" + url_to_check

    parsed = urlparse(url_to_check)

    risk_score = 0
    indicators = []

    # -----------------------------------------
    # 1. HTTPS check
    # -----------------------------------------

    if parsed.scheme != "https":
        risk_score += 15
        indicators.append("URL does not use HTTPS")
    else:
        indicators.append("URL uses HTTPS")


    # -----------------------------------------
    # 2. IP address check
    # -----------------------------------------

    hostname = parsed.hostname or ""

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, hostname):
        risk_score += 25
        indicators.append("URL uses an IP address instead of a domain name")


    # -----------------------------------------
    # 3. Suspicious keywords
    # -----------------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "security",
        "password",
        "signin",
        "confirm",
        "bank",
        "wallet",
        "payment",
        "credential",
        "unlock"
    ]

    url_lower = original_url.lower()

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:
        risk_score += min(len(found_keywords) * 5, 20)

        indicators.append(
            "Suspicious keywords found: "
            + ", ".join(found_keywords)
        )


    # -----------------------------------------
    # 4. URL length
    # -----------------------------------------

    if len(original_url) > 100:
        risk_score += 10
        indicators.append("URL is unusually long")

    elif len(original_url) > 75:
        risk_score += 5
        indicators.append("URL is longer than normal")


    # -----------------------------------------
    # 5. @ symbol
    # -----------------------------------------

    if "@" in original_url:
        risk_score += 20
        indicators.append("URL contains @ symbol")


    # -----------------------------------------
    # 6. Too many subdomains
    # -----------------------------------------

    domain_parts = hostname.split(".")

    if len(domain_parts) >= 4:
        risk_score += 10
        indicators.append("URL contains multiple subdomains")


    # -----------------------------------------
    # 7. Hyphen check
    # -----------------------------------------

    if hostname.count("-") >= 2:
        risk_score += 5
        indicators.append("Domain contains multiple hyphens")


    # -----------------------------------------
    # 8. Suspicious TLD
    # -----------------------------------------

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    for tld in suspicious_tlds:

        if hostname.endswith(tld):

            risk_score += 15

            indicators.append(
                f"Suspicious top-level domain: {tld}"
            )

            break


    # -----------------------------------------
    # Limit score to 100
    # -----------------------------------------

    risk_score = min(risk_score, 100)


    # -----------------------------------------
    # Determine result
    # -----------------------------------------

    if risk_score >= 60:

        result = "PHISHING"

    elif risk_score >= 30:

        result = "SUSPICIOUS"

    else:

        result = "SAFE"


    # -----------------------------------------
    # Generate explanation
    # -----------------------------------------

    if result == "PHISHING":

        explanation = (
            "This URL contains multiple characteristics "
            "commonly associated with phishing or malicious websites."
        )

    elif result == "SUSPICIOUS":

        explanation = (
            "This URL contains some potentially suspicious "
            "characteristics. Proceed with caution."
        )

    else:

        explanation = (
            "No major phishing indicators were detected "
            "using the current rule-based analysis."
        )


    return {
        "url": original_url,
        "result": result,
        "risk_score": risk_score,
        "explanation": explanation,
        "indicators": indicators
    }