import re


# Suspicious words and their risk scores
SUSPICIOUS_KEYWORDS = {
    "urgent": 15,
    "verify": 15,
    "click": 10,
    "otp": 20,
    "password": 20,
    "blocked": 15,
    "prize": 15,
    "winner": 15,
    "reward": 15,
    "claim": 10,
    "login": 10,
    "account": 5
}


def analyze_message(message):

    message = message.lower()

    score = 0
    reasons = []

    # Check suspicious keywords
    for keyword, points in SUSPICIOUS_KEYWORDS.items():

        if keyword in message:

            score += points

            reasons.append(
                f"Suspicious keyword detected: {keyword}"
            )

    # Check for HTTP links
    if "http://" in message:

        score += 10

        reasons.append(
            "Unsecured HTTP link detected"
        )

    # Check for HTTPS
    elif "https://" in message:

        reasons.append(
            "HTTPS link detected"
        )

    # Check for IP address in URL
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    if re.search(ip_pattern, message):

        score += 20

        reasons.append(
            "IP address used instead of a normal domain"
        )

    # Check URL length
    urls = re.findall(r'https?://\S+', message)

    for url in urls:

        if len(url) > 60:

            score += 10

            reasons.append(
                "Unusually long URL detected"
            )

    # Limit score to 100
    if score > 100:

        score = 100

    # Determine risk level
    if score <= 30:

        level = "SAFE"

        recommendation = (
            "No major phishing indicators detected. "
            "Still verify unexpected messages before taking action."
        )

    elif score <= 60:

        level = "SUSPICIOUS"

        recommendation = (
            "Be careful. Verify the sender and avoid "
            "clicking unknown links."
        )

    else:

        level = "HIGH RISK"

        recommendation = (
            "Do not click the link or share your password, "
            "OTP, or personal information."
        )

    # If no reasons were found
    if not reasons:

        reasons.append(
            "No major suspicious patterns detected"
        )

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "recommendation": recommendation
    }


# Test the detector
if __name__ == "__main__":

    test_message = """
    URGENT! Your bank account will be blocked.
    Verify your account immediately.
    Click http://bank-login-verify.xyz
    """

    result = analyze_message(test_message)

    print("Risk Score:", result["score"])
    print("Risk Level:", result["level"])

    print("\nReasons:")

    for reason in result["reasons"]:
        print("-", reason)

    print("\nRecommendation:")
    print(result["recommendation"])

