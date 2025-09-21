# ssrf_secure.py
# Safer version of the SSRF example
# Blocks requests to private IP ranges, loopback, and enforces an allowlist.

from flask import Flask, request, abort, Response
import requests
from urllib.parse import urlparse
import ipaddress
import socket

app = Flask(__name__)

# ✅ Define an allowlist of safe domains
ALLOWED_DOMAINS = {"example.com", "api.github.com"}

def hostname_to_ip(hostname: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def is_private_ip(ip_str: str) -> bool:
    """Check if an IP is private, loopback, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_link_local
        )
    except ValueError:
        return True  # treat invalid IP as unsafe

@app.route("/safe_fetch")
def safe_fetch():
    target_url = request.args.get("url")
    if not target_url:
        abort(400, "Missing ?url parameter")

    parsed = urlparse(target_url)

    # ✅ Enforce http/https only
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        abort(400, "Invalid URL scheme or hostname")

    # ✅ Check against allowlist
    if parsed.hostname not in ALLOWED_DOMAINS:
        abort(403, "Domain not allowed")

    # ✅ Resolve and check IP
    ip = hostname_to_ip(parsed.hostname)
    if not ip or is_private_ip(ip):
        abort(403, "Blocked unsafe destination")

    try:
        # ✅ Set timeouts and block redirects
        resp = requests.get(target_url, timeout=5, allow_redirects=False)
    except requests.RequestException:
        abort(502, "Error fetching target")

    return Response(
        resp.content,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", "text/plain"),
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
