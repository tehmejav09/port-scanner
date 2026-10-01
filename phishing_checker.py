"""
Phishing Email Checker
Looks at the text of an email and flags things that commonly signal phishing:
sender/link mismatches, lookalike domains, and urgent language.
Part of the Cipherora Projects series.

This is a learning tool, not a spam filter. It works on plain text you paste
in, not on live inboxes.
"""

import re

# Words that create false urgency, a common phishing tactic.
URGENT_PHRASES = [
    "verify your account", "act now", "your account will be suspended",
    "click immediately", "urgent action required", "confirm your identity",
    "unusual activity", "limited time", "final notice",
]

# A few brands commonly impersonated, paired with their real domains.
# A real tool would use a much larger, maintained list.
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "bank": None,  # no single real domain, just a trigger word
}

LINK_PATTERN = re.compile(r'href=["\']?(https?://[^\s"\'>]+)', re.IGNORECASE)
URL_PATTERN = re.compile(r'https?://[^\s"\'>]+')


def extract_domain(url):
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1).lower() if match else None


def looks_like_lookalike(domain, real_domain):
    """Very rough check: same length and only 1-2 characters different."""
    if domain == real_domain:
        return False
    if abs(len(domain) - len(real_domain)) > 2:
        return False
    diffs = sum(1 for a, b in zip(domain, real_domain) if a != b)
    return diffs <= 2


def check_email(text):
    text_lower = text.lower()
    findings = []

    # 1. Urgent / pressure language
    for phrase in URGENT_PHRASES:
        if phrase in text_lower:
            findings.append(f"Pressure language found: \"{phrase}\"")

    # 2. Brand mention vs. the domains actually linked in the email
    links = LINK_PATTERN.findall(text) or URL_PATTERN.findall(text)
    domains_found = {extract_domain(l) for l in links if extract_domain(l)}

    for brand, real_domain in KNOWN_BRANDS.items():
        if brand in text_lower and real_domain:
            if not any(d == real_domain or d.endswith("." + real_domain) for d in domains_found):
                if domains_found:
                    findings.append(
                        f"Mentions \"{brand}\" but links point to {', '.join(domains_found)}, "
                        f"not {real_domain}."
                    )
                for d in domains_found:
                    if looks_like_lookalike(d, real_domain):
                        findings.append(f"\"{d}\" looks like a lookalike of \"{real_domain}\".")

    # 3. Link text vs. actual destination (basic HTML check)
    href_mismatches = re.findall(
        r'<a[^>]+href=["\']?(https?://[^\s"\'>]+)["\']?[^>]*>([^<]+)</a>',
        text, re.IGNORECASE
    )
    for href, link_text in href_mismatches:
        if "http" in link_text.lower() and extract_domain(link_text) != extract_domain(href):
            findings.append(f"Link text says \"{link_text.strip()}\" but goes to {href}")

    return findings


if __name__ == "__main__":
    import sys

    print("Phishing Email Checker")
    print("Paste the email's text or HTML below, then press Ctrl+D (Mac/Linux)")
    print("or Ctrl+Z then Enter (Windows) when you're done.\n")

    email_text = sys.stdin.read()
    findings = check_email(email_text)

    print("\n--- Results ---")
    if findings:
        print(f"{len(findings)} possible issue(s) found:\n")
        for f in findings:
            print(f"  - {f}")
    else:
        print("No obvious red flags found. This doesn't guarantee the email is safe.")
