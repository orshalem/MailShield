from app.models import EmailRequest, AnalysisResponse
from app.url_reputation import check_urls


URGENCY_WORDS = [
    "urgent", "immediately", "act now", "within 24 hours",
    "account suspended", "blocked", "security alert",
    "unusual activity", "limited time", "expires today"
]

SENSITIVE_INFO_WORDS = [
    "password", "credit card", "verification code", "otp",
    "login", "verify your account", "confirm your identity",
    "update payment", "billing information"
]

GENERIC_GREETINGS = [
    "dear user", "dear customer", "hello customer",
    "valued customer", "לקוח יקר", "משתמש יקר"
]

SUSPICIOUS_SCENARIOS = [
    "you won", "prize", "free gift", "package delivery",
    "bank account", "account locked", "refund", "invoice",
    "זכית", "פרס", "חבילה", "חשבון בנק", "החזר כספי"
]

TYPO_INDICATORS = [
    "amaz0n", "paypa1", "paypai", "g00gle", "micros0ft"
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".js", ".bat", ".cmd", ".scr",
    ".zip", ".rar", ".html", ".htm"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ru", ".top", ".click"
]


def analyse(email: EmailRequest) -> AnalysisResponse:
    score = 0
    reasons = []

    subject = email.subject or ""
    sender = email.sender or ""
    body = email.body or ""
    links = email.links or []
    attachments = email.attachments or []

    text = f"{subject} {body}".lower()
    sender_lower = sender.lower()

    # 1. Suspicious sender domain
    if "@" in sender_lower:
        domain = sender_lower.split("@")[-1].replace(">", "").strip()

        if any(tld in domain for tld in SUSPICIOUS_TLDS):
            score += 20
            reasons.append(
                f"Sender domain '{domain}' uses a suspicious top-level domain"
            )

        if any(fake in domain for fake in TYPO_INDICATORS):
            score += 20
            reasons.append("Sender domain may imitate a trusted brand")

        if "gmail.com" in domain and any(
            brand in text for brand in ["paypal", "amazon", "google", "bank"]
        ):
            score += 15
            reasons.append("Brand-like email sent from a free email provider")

    # 2. Urgency / fear language
    if any(word in text for word in URGENCY_WORDS):
        score += 15
        reasons.append(
            "Urgency or fear-based language detected - common phishing pressure tactic"
        )

    # 3. Request for personal / sensitive information
    if any(word in text for word in SENSITIVE_INFO_WORDS):
        score += 20
        reasons.append(
            "Sensitive information request detected - legitimate services rarely ask by email"
        )

    # 4. Advanced URL reputation checks
    if len(links) > 5:
        score += 10
        reasons.append(
            f"{len(links)} links detected - high volume increases phishing risk"
        )

    suspicious_url_count, url_reasons = check_urls(links)

    if suspicious_url_count > 0:
        score += min(suspicious_url_count * 10, 30)
        reasons.extend(url_reasons)

    # 5. Weird language / typo indicators
    if any(fake in text for fake in TYPO_INDICATORS):
        score += 15
        reasons.append("Possible brand impersonation or typo detected")

    if text.count("!!!") > 0 or (subject.isupper() and len(subject) > 5):
        score += 10
        reasons.append(
            "Aggressive or unusual formatting detected - often used to create urgency"
        )

    # 6. Risky attachments
    for attachment in attachments:
        attachment_lower = attachment.lower()

        if any(attachment_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            score += 25
            reasons.append(
                "Risky attachment type detected - may contain executable content"
            )
            break

    # 7. Generic greeting
    if any(greeting in text for greeting in GENERIC_GREETINGS):
        score += 10
        reasons.append(
            "Generic greeting detected - message does not address the recipient personally"
        )

    # 8. Suspicious scenario
    if any(word in text for word in SUSPICIOUS_SCENARIOS):
        score += 10
        reasons.append(
            "Common phishing scenario detected - reward, delivery, refund, or account issue"
        )

    score = min(score, 100)

    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    reasons = list(dict.fromkeys(reasons))

    if not reasons:
        reasons.append("No suspicious signals detected")

    return AnalysisResponse(
        score=score,
        verdict=verdict,
        reasons=reasons,
    )