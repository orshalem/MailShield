
from app.models import EmailRequest, AnalysisResponse


SUSPICIOUS_WORDS = [
    "urgent",
    "verify",
    "password",
    "click now",
    "account suspended",
    "immediately",
    "login",
    "security alert",
]

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".js",
    ".bat",
    ".cmd",
    ".scr",
    ".zip",
    ".rar",
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
]


def analyse(email: EmailRequest) -> AnalysisResponse:
    score = 0
    reasons = []

    subject_lower = email.subject.lower()
    body_lower = email.body.lower()

    # Combine subject + body
    text = f"{subject_lower} {body_lower}"

    # 1. Suspicious wording
    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in text:
            score += 15
            found_words.append(word)

    if found_words:
        reasons.append(
            f"Suspicious wording detected: {', '.join(found_words)}"
        )

    # 2. Too many links
    if len(email.links) > 3:
        score += 10
        reasons.append("Email contains many links")

    # 3. Suspicious URLs
    for link in email.links:
        link_lower = link.lower()

        # HTTP instead of HTTPS
        if link_lower.startswith("http://"):
            score += 10
            reasons.append(f"Insecure HTTP link detected: {link}")

        # URL shorteners
        for shortener in URL_SHORTENERS:
            if shortener in link_lower:
                score += 20
                reasons.append(f"URL shortener detected: {link}")

    # 4. Dangerous attachments
    for attachment in email.attachments:
        attachment_lower = attachment.lower()

        for ext in DANGEROUS_EXTENSIONS:
            if attachment_lower.endswith(ext):
                score += 25
                reasons.append(f"Risky attachment detected: {attachment}")
                break

    # 5. Suspicious sender domain
    sender_lower = email.sender.lower()

    if "@" in sender_lower:
        domain = sender_lower.split("@")[-1]

        suspicious_domains = ["xyz", "tk", "ml", "ru"]

        if any(bad in domain for bad in suspicious_domains):
            score += 15
            reasons.append(
                f"Suspicious sender domain detected: {domain}"
            )

    # Keep score between 0 and 100
    score = min(score, 100)

    # Verdict
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # No suspicious signals
    if not reasons:
        reasons.append("No suspicious signals detected")

    return AnalysisResponse(
        score=score,
        verdict=verdict,
        reasons=reasons,
    )

