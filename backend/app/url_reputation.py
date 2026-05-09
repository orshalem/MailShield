import ipaddress
from typing import List, Tuple
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".link", ".download",
    ".ru", ".cn",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "shorturl.at"
}

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "linkedin.com", "facebook.com",
}

PHISHING_KEYWORDS = [
    "secure", "login", "verify", "account", "update",
    "confirm", "banking", "paypal", "amazon", "apple", "microsoft"
]


def check_urls(urls: List[str]) -> Tuple[int, List[str]]:
    flagged_count = 0
    details = []

    for url in urls or []:
        is_suspicious, reason = assess_url(url)

        if is_suspicious:
            flagged_count += 1
            details.append(reason)

    return flagged_count, list(dict.fromkeys(details))


def assess_url(url: str) -> Tuple[bool, str]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if not host:
        return True, "Malformed URL detected - destination cannot be verified"

    try:
        ipaddress.ip_address(host)
        return True, "IP-based URL detected - attackers often hide domains this way"
    except ValueError:
        pass

    if any(host == trusted or host.endswith("." + trusted) for trusted in TRUSTED_DOMAINS):
        return False, ""

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return True, "Suspicious domain extension detected - often abused in phishing"

    if any(shortener in host for shortener in URL_SHORTENERS):
        return True, "URL shortener detected - final destination is hidden"

    if len(host.split(".")) >= 5:
        return True, "Too many subdomains detected - may hide the real destination"

    if "@" in url:
        return True, "Deceptive URL detected - @ symbol can hide the real domain"

    if any(keyword in host for keyword in PHISHING_KEYWORDS) and not any(
        host == trusted or host.endswith("." + trusted)
        for trusted in TRUSTED_DOMAINS
    ):
        return True, "Brand or login keywords found in an untrusted domain"

    return False, ""