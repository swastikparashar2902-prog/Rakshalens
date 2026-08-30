import re
from urllib.parse import urlparse


# ---------------- URL ANALYSIS ----------------

def analyze_url(url):

    score = 0
    reasons = []

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "update",
        "bank",
        "payment",
        "upi",
        "reward",
        "free",
        "gift",
        "urgent",
        "account"
    ]

    try:
        parsed = urlparse(url)

        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        # Check HTTPS
        if not url.startswith("https://"):
            score += 15
            reasons.append(
                "Website does not use HTTPS encryption."
            )

        # Check if domain is an IP address
        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
            score += 30
            reasons.append(
                "URL uses an IP address instead of a normal domain."
            )

        # Check suspicious words
        for word in suspicious_words:
            if word in domain or word in path:
                score += 8
                reasons.append(
                    f"Suspicious keyword detected: '{word}'."
                )

        # Check multiple hyphens
        if domain.count("-") >= 2:
            score += 15
            reasons.append(
                "Domain contains multiple hyphens."
            )

        # Check long URL
        if len(url) > 100:
            score += 10
            reasons.append(
                "URL is unusually long."
            )

        # Check @ symbol
        if "@" in url:
            score += 25
            reasons.append(
                "URL contains '@', which can hide the actual destination."
            )

    except Exception:
        score += 30
        reasons.append(
            "Unable to safely parse this URL."
        )

    return create_result(score, reasons)


# ---------------- TEXT ANALYSIS ----------------

def analyze_text(text):

    score = 0
    reasons = []

    text_lower = text.lower()

    scam_patterns = {
        "urgent": 10,
        "immediately": 10,
        "act now": 12,
        "account blocked": 25,
        "account suspended": 25,
        "verify your account": 20,
        "click here": 15,
        "click the link": 15,
        "you won": 15,
        "lottery": 20,
        "free gift": 15,
        "claim now": 15,
        "send otp": 30,
        "share otp": 35,
        "upi pin": 30,
        "refund": 10,
        "payment failed": 12,
        "call immediately": 15
    }

    for phrase, risk in scam_patterns.items():
        if phrase in text_lower:
            score += risk
            reasons.append(
                f"Suspicious phrase detected: '{phrase}'."
            )

    # Check links
    links = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text_lower
    )

    if links:
        score += 15
        reasons.append(
            "Message contains an external link."
        )

    # Check excessive exclamation marks
    if text.count("!") >= 3:
        score += 8
        reasons.append(
            "Message uses excessive urgency punctuation."
        )

    return create_result(score, reasons)


# ---------------- CREATE FINAL RESULT ----------------

def create_result(score, reasons):

    # Maximum score is 100
    score = min(score, 100)

    if score >= 60:

        risk_level = "HIGH RISK"

        action = (
            "Do not click links or make payments. "
            "Block or report the sender. "
            "If money was lost, contact your bank and call 1930."
        )

    elif score >= 30:

        risk_level = "CAUTION"

        action = (
            "Do not interact immediately. "
            "Verify the sender using an official website "
            "or official contact method."
        )

    else:

        risk_level = "SAFE"

        action = (
            "No major risk indicators were detected. "
            "Still verify sensitive requests before sharing "
            "money, OTPs or personal information."
        )

    confidence = min(
        55 + len(reasons) * 8,
        95
    )

    if not reasons:
        reasons.append(
            "No major known risk patterns were detected."
        )

    return {
        "score": score,
        "risk_level": risk_level,
        "confidence": confidence,
        "reasons": reasons,
        "action": action
    }