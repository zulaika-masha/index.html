from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import ipaddress
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "bank",
    "update",
    "secure",
    "password",
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
}

ENCODED_CHAR_RE = re.compile(r"%[0-9a-fA-F]{2}")


def analyze_url(url):
    """Analyze a URL for common phishing and scam indicators and return a risk score."""
    score = 0
    reasons = []
    checks = []

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path_and_query = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")

    # 1. HTTP vs HTTPS protocol check
    if scheme == "http":
        score += 10
        reasons.append("Uses HTTP instead of HTTPS (+10)")
        checks.append({"name": "Protocol Security", "status": "warn", "detail": "Unencrypted HTTP"})
    else:
        checks.append({"name": "Protocol Security", "status": "pass", "detail": "HTTPS encryption"})

    # 2. IP address in URL
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        score += 25
        reasons.append("Uses an IP address instead of a domain name (+25)")
        checks.append({"name": "Host Identity", "status": "warn", "detail": f"Raw IP ({host})"})
    except ValueError:
        checks.append({"name": "Host Identity", "status": "pass", "detail": host})

    # 3. Suspicious keywords
    lower_url = url.lower()
    matched_keywords = []
    for word in SUSPICIOUS_KEYWORDS:
        if word in lower_url:
            score += 10
            matched_keywords.append(word)
            reasons.append(f"Suspicious keyword detected: '{word}' (+10)")

    if matched_keywords:
        checks.append({
            "name": "Keyword Scan",
            "status": "warn",
            "detail": ", ".join(matched_keywords),
        })
    else:
        checks.append({"name": "Keyword Scan", "status": "pass", "detail": "No flagged keywords"})

    # 4. Unusually long URL
    url_length = len(url)
    if url_length > 75:
        score += 15
        reasons.append(f"Unusually long URL ({url_length} characters > 75) (+15)")
        checks.append({"name": "URL Length", "status": "warn", "detail": f"{url_length} chars"})
    else:
        checks.append({"name": "URL Length", "status": "pass", "detail": f"{url_length} chars"})

    # 5. Excessive subdomains
    if not is_ip and host:
        parts = [p for p in host.split(".") if p]
        subdomain_count = max(0, len(parts) - 2)
        if len(parts) > 3:
            score += 15
            reasons.append(f"Excessive subdomains detected ({subdomain_count} subdomains) (+15)")
            checks.append({"name": "Subdomain Depth", "status": "warn", "detail": f"{subdomain_count} subdomains"})
        else:
            checks.append({"name": "Subdomain Depth", "status": "pass", "detail": f"{subdomain_count} subdomain(s)"})
    else:
        checks.append({"name": "Subdomain Depth", "status": "info", "detail": "N/A for IP host"})

    # 6. URL shorteners
    is_shortener = any(host == shortener or host.endswith("." + shortener) for shortener in URL_SHORTENERS)
    if is_shortener:
        score += 20
        reasons.append(f"Uses a URL shortener service ({host}) (+20)")
        checks.append({"name": "URL Shortener", "status": "warn", "detail": host})
    else:
        checks.append({"name": "URL Shortener", "status": "pass", "detail": "Direct domain"})

    # 7. Suspicious symbols and encoded characters
    symbol_flags = []
    if "@" in url:
        score += 20
        symbol_flags.append("contains '@'")
        reasons.append("Contains '@' symbol which can mask destination (+20)")
    if "xn--" in host:
        score += 20
        symbol_flags.append("punycode 'xn--'")
        reasons.append("Uses Punycode ('xn--') which may indicate lookalike domain (+20)")
    if "//" in path_and_query:
        score += 10
        symbol_flags.append("embedded '//' in path")
        reasons.append("Contains '//' redirect pattern in URL path (+10)")
    encoded_matches = ENCODED_CHAR_RE.findall(url)
    if len(encoded_matches) >= 2:
        score += 10
        symbol_flags.append(f"{len(encoded_matches)} encoded sequences")
        reasons.append(f"Contains multiple URL-encoded characters ({len(encoded_matches)}) (+10)")
    if host.count("-") >= 3:
        score += 10
        symbol_flags.append("excessive hyphens in host")
        reasons.append("Domain contains excessive hyphens (+10)")

    if symbol_flags:
        checks.append({"name": "Symbols & Encoding", "status": "warn", "detail": ", ".join(symbol_flags)})
    else:
        checks.append({"name": "Symbols & Encoding", "status": "pass", "detail": "Clean syntax"})

    score = min(score, 100)

    if score >= 50:
        status = "Suspicious"
    elif score >= 20:
        status = "Needs Verification"
    else:
        status = "No Obvious Warning Signs"

    return {
        "url": url,
        "score": score,
        "status": status,
        "reasons": reasons,
        "checks": checks,
        "meta": {
            "scheme": scheme.upper(),
            "host": host,
            "length": url_length,
        },
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")

    if not raw_url or not isinstance(raw_url, str):
        return jsonify({"error": "Invalid URL: please enter a non-empty URL string."}), 400

    url = raw_url.strip()
    if not url:
        return jsonify({"error": "Invalid URL: please enter a URL to scan."}), 400

    if len(url) > 2048:
        return jsonify({"error": "URL is too long (maximum 2048 characters)."}), 400

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return jsonify({
            "error": "Please enter a complete URL starting with http:// or https:// (e.g., https://example.com)."
        }), 400

    result = analyze_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
