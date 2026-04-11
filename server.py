"""
Honeypot Ad Server with Geolocation Enrichment.

This module is the core of the Intelligent Honeypot & Intruder Profiling System v2.0.
It exists as a separate file from client.py because the server and client have distinct
lifecycles --- the server runs continuously while clients connect and disconnect.

Geolocation enrichment (new in v2.0) is injected immediately after IP extraction on
every request, enriching every log record with country, city, ISP, ASN, and coordinates
before it is persisted to honeypot_logs.json.

Run: python server.py
"""

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone

import requests
from colorama import Fore, Style, init
from flask import Flask, jsonify, redirect, request, send_file
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

init(autoreset=True)  # colorama: reset colour after every print

app = Flask(__name__)
CORS(app)  # Allow dashboard.html (file://) to fetch /logs without CORS error

LOG_FILE = "honeypot_logs.json"
DUMMY_LANDING_PAGE = "https://example.com"

# In-memory cache: keyed by IP address, stores resolved geo dict.
# Each unique IP only triggers one ip-api.com call per server session.
geo_cache: dict[str, dict | None] = {}

# ---------------------------------------------------------------------------
# Known provider keyword lists for geo-based threat scoring
# ---------------------------------------------------------------------------

# ISPs/orgs that suggest VPN or anonymisation usage --- strong attack indicator
VPN_KEYWORDS = ("vpn", "proxy", "tor", "anonymizer", "anonymous", "hide", "tunnel")

# Cloud / VPS providers commonly used to host attack infrastructure
CLOUD_KEYWORDS = (
    "amazon",
    "aws",
    "digitalocean",
    "linode",
    "akamai",
    "vultr",
    "ovh",
    "hetzner",
    "google cloud",
    "azure",
    "microsoft",
    "cloudflare",
    "fastly",
    "rackspace",
    "choopa",
    "quadranet",
)

# ASN prefixes associated with data-centre (non-residential) address space
DATACENTER_ASN_PREFIXES = (
    "AS14061",  # DigitalOcean
    "AS16509",  # Amazon AWS
    "AS15169",  # Google
    "AS8075",   # Microsoft Azure
    "AS20940",  # Akamai
    "AS63949",  # Linode / Akamai
    "AS24940",  # Hetzner
    "AS35540",  # Vultr
)

# ---------------------------------------------------------------------------
# Startup: ensure log file exists
# ---------------------------------------------------------------------------

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)


# ---------------------------------------------------------------------------
# Geolocation enrichment
# ---------------------------------------------------------------------------

def geolocate_ip(ip: str) -> dict | None:
    """
    Resolve an IP address to geolocation data via ip-api.com.

    Results are cached per IP to stay within the free-tier rate limit
    (45 requests/minute) and to avoid redundant network calls.

    Localhost IPs return a placeholder dict so the dashboard still renders
    during local development without making external API calls.

    Returns None on API failure --- callers must handle None gracefully.
    """
    # Placeholder for loopback addresses --- no API call needed
    if ip in ("127.0.0.1", "::1", "localhost"):
        return {
            "country": "Local",
            "countryCode": "LO",
            "region": "Loopback",
            "city": "Loopback",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "localhost",
            "org": "localhost",
            "as": "AS0",
        }

    # Return cached result if we've seen this IP before this session
    if ip in geo_cache:
        return geo_cache[ip]

    fields = "status,country,countryCode,region,city,zip,lat,lon,isp,org,as,query"
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            timeout=2,
        )
        if response.status_code == 429:
            # Rate limited --- cache None so we don't keep hammering the API
            geo_cache[ip] = None
            return None

        data = response.json()
        if data.get("status") != "success":
            geo_cache[ip] = None
            return None

        geo = {
            "country":     data.get("country"),
            "countryCode": data.get("countryCode"),
            "region":      data.get("region"),
            "city":        data.get("city"),
            "lat":         data.get("lat"),
            "lon":         data.get("lon"),
            "isp":         data.get("isp"),
            "org":         data.get("org"),
            "as":          data.get("as"),
        }
        geo_cache[ip] = geo
        return geo

    except requests.exceptions.RequestException:
        # Timeout, connection error, or any other network issue
        geo_cache[ip] = None
        return None


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_client() -> str:
    """
    Produce a 12-character fingerprint from the MD5 hash of key request headers.

    Using a fixed tuple of header values (not the whole header dict) ensures
    the fingerprint is stable across requests with the same profile, enabling
    cross-endpoint session correlation without cookies.
    """
    raw = "|".join([
        request.headers.get("User-Agent", ""),
        request.headers.get("Accept", ""),
        request.headers.get("Accept-Language", ""),
        request.headers.get("Accept-Encoding", ""),
    ])
    return hashlib.md5(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Client classification
# ---------------------------------------------------------------------------

# Keyword sets for User-Agent classification --- ordered by severity
BOT_KEYWORDS     = ("bot", "crawler", "spider", "slurp", "bingbot", "googlebot")
SCANNER_KEYWORDS = ("nikto", "sqlmap", "masscan", "nmap", "zap", "burp", "acunetix", "nessus")
SCRAPER_KEYWORDS = ("scrapy", "python-requests", "curl", "wget", "libwww", "mechanize")


def classify_client(user_agent: str) -> str:
    """
    Classify the connecting client based on User-Agent keyword matching.

    Scanner is checked before bot because scanner UAs sometimes contain
    generic 'bot' terms (e.g. 'nikto/2.1.6 (bot)').
    """
    ua_lower = user_agent.lower()

    if any(kw in ua_lower for kw in SCANNER_KEYWORDS):
        return "scanner"
    if any(kw in ua_lower for kw in BOT_KEYWORDS):
        return "bot"
    if any(kw in ua_lower for kw in SCRAPER_KEYWORDS):
        return "scraper"
    return "browser"


# ---------------------------------------------------------------------------
# Threat scoring
# ---------------------------------------------------------------------------

def compute_threat_score(
    user_agent: str,
    headers: dict,
    cookies: dict,
    geo: dict | None,
    request_time: float,
) -> tuple[int, list[str]]:
    """
    Compute a 0-100 threat score and a list of triggered anomaly flags.

    Signals are additive and capped at 100. Geo-based signals (new in v2.0)
    are only evaluated when geo is not None.
    """
    score = 0
    flags: list[str] = []

    ua_lower = user_agent.lower()

    # --- Header signals ---
    if any(kw in ua_lower for kw in SCANNER_KEYWORDS):
        score += 30
        flags.append("KNOWN_SCANNER_UA")
    elif any(kw in ua_lower for kw in BOT_KEYWORDS):
        score += 40
        flags.append("KNOWN_BOT_UA")

    if any(kw in ua_lower for kw in ("nikto", "sqlmap", "masscan")):
        score += 30
        flags.append("ATTACK_TOOL_UA")

    if not headers.get("Accept-Language"):
        score += 20
        flags.append("MISSING_ACCEPT_LANGUAGE")

    if not headers.get("Accept"):
        score += 15
        flags.append("MISSING_ACCEPT")

    if not cookies:
        score += 10
        flags.append("NO_COOKIES")

    if not headers.get("Accept-Encoding"):
        score += 10
        flags.append("MISSING_ACCEPT_ENCODING")

    # --- Behaviour signal: request rate ---
    # We use the fractional seconds of the timestamp as a proxy for rapid
    # requests in testing; in production this would compare against a
    # per-IP request history.
    if request_time < 0.1:
        score += 25
        flags.append("RAPID_REQUEST")

    # --- Geolocation signals (v2.0) ---
    if geo is None:
        score += 10
        flags.append("GEO_API_FAIL")
    else:
        isp_lower = (geo.get("isp") or "").lower()
        org_lower = (geo.get("org") or "").lower()
        asn       = (geo.get("as") or "")

        if any(kw in isp_lower or kw in org_lower for kw in VPN_KEYWORDS):
            score += 30
            flags.append("GEO_VPN")

        if any(kw in isp_lower or kw in org_lower for kw in CLOUD_KEYWORDS):
            score += 20
            flags.append("GEO_CLOUD_ASN")

        if any(asn.startswith(prefix) for prefix in DATACENTER_ASN_PREFIXES):
            score += 15
            flags.append("GEO_DATACENTER_ASN")

    return min(score, 100), flags


# ---------------------------------------------------------------------------
# Log persistence
# ---------------------------------------------------------------------------

def persist_log(record: dict) -> None:
    """Append a single enriched log record to the JSON flat-file store."""
    with open(LOG_FILE, "r+") as f:
        logs = json.load(f)
        logs.append(record)
        f.seek(0)
        json.dump(logs, f, indent=2)


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

def score_color(score: int) -> str:
    """Map a threat score to a colorama colour string."""
    if score < 31:
        return Fore.GREEN
    if score < 61:
        return Fore.YELLOW
    return Fore.RED


def print_request(endpoint: str, ip: str, score: int, client_type: str, geo: dict | None) -> None:
    colour = score_color(score)
    location = f"{geo['city']}, {geo['country']}" if geo else "Unknown"
    print(
        f"{Fore.CYAN}[{datetime.now(timezone.utc).strftime('%H:%M:%S')}]{Style.RESET_ALL} "
        f"{endpoint:<15} "
        f"IP={ip:<16} "
        f"type={client_type:<8} "
        f"{colour}score={score:<4}{Style.RESET_ALL}"
        f"loc={location}"
    )


# ---------------------------------------------------------------------------
# Core profiling pipeline (shared by all endpoints)
# ---------------------------------------------------------------------------

def run_profiling_pipeline(endpoint: str) -> dict:
    """
    Execute the full profiling pipeline for an incoming request.

    Returns the complete log record so callers can embed additional
    endpoint-specific fields (e.g. redirect target for /ad/click).
    """
    ip         = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    t_start    = time.monotonic()

    geo         = geolocate_ip(ip)
    fingerprint = fingerprint_client()
    client_type = classify_client(user_agent)

    # Elapsed time since the module loaded acts as a lightweight timing proxy
    elapsed = time.monotonic() - t_start

    score, flags = compute_threat_score(
        user_agent=user_agent,
        headers=dict(request.headers),
        cookies=dict(request.cookies),
        geo=geo,
        request_time=elapsed,
    )

    record = {
        "id":          str(uuid.uuid4()),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "ip":          ip,
        "endpoint":    endpoint,
        "method":      request.method,
        "user_agent":  user_agent,
        "fingerprint": fingerprint,
        "client_type": client_type,
        "threat_score": score,
        "flags":       flags,
        "geo":         geo,
        "headers":     dict(request.headers),
        "cookies":     dict(request.cookies),
    }

    persist_log(record)
    print_request(endpoint, ip, score, client_type, geo)
    return record


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

FAKE_AD_HTML = """
<!DOCTYPE html>
<html>
<head><title>Ad Content</title></head>
<body>
  <div id="ad-banner" style="width:728px;height:90px;background:#f0f0f0;text-align:center;line-height:90px;">
    <strong>Special Offer — Click Now!</strong>
  </div>
  <img src="/ad/pixel" width="1" height="1" style="display:none;" alt=""/>
</body>
</html>
"""


@app.route("/ad/serve")
def ad_serve():
    """
    Primary honeypot endpoint. Returns fake ad HTML and triggers the full
    profiling pipeline. The embedded pixel tag causes real browsers to fire
    a follow-up request to /ad/pixel automatically.
    """
    record = run_profiling_pipeline("/ad/serve")
    geo    = record.get("geo") or {}
    return (
        FAKE_AD_HTML,
        200,
        {
            "X-Honeypot-Score":   str(record["threat_score"]),
            "X-Honeypot-City":    geo.get("city", ""),
            "X-Honeypot-Country": geo.get("country", ""),
            "X-Honeypot-ISP":     geo.get("isp", ""),
        },
    )


@app.route("/ad/pixel")
def ad_pixel():
    """
    Silent 1×1 beacon endpoint. Detects JavaScript execution and browser
    rendering. geo_cache hit is expected here --- same IP, no API call.
    """
    run_profiling_pipeline("/ad/pixel")

    # Minimal valid 1×1 transparent GIF (43 bytes)
    gif = (
        b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
        b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00"
        b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
    )
    return gif, 200, {"Content-Type": "image/gif"}


@app.route("/ad/click")
def ad_click():
    """
    Click-tracking endpoint. Logs engagement and redirects to a safe dummy
    landing page. The ref parameter cross-references the original /ad/serve
    fingerprint.
    """
    ref    = request.args.get("ref", "")
    record = run_profiling_pipeline("/ad/click")
    record["ref_fingerprint"] = ref
    return redirect(DUMMY_LANDING_PAGE, code=302)


@app.route("/logs")
def get_logs():
    """REST endpoint consumed by dashboard.html to render the live feed and charts."""
    with open(LOG_FILE) as f:
        logs = json.load(f)
    return jsonify(logs)


@app.errorhandler(404)
def not_found(e):
    """Log 404s as potential path-scanning attempts."""
    ip         = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    geo        = geolocate_ip(ip)

    record = {
        "id":          str(uuid.uuid4()),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "ip":          ip,
        "endpoint":    request.path,
        "method":      request.method,
        "user_agent":  user_agent,
        "fingerprint": fingerprint_client(),
        "client_type": classify_client(user_agent),
        "threat_score": 25,
        "flags":       ["PATH_SCAN_404"],
        "geo":         geo,
        "headers":     dict(request.headers),
        "cookies":     dict(request.cookies),
    }
    persist_log(record)
    print(f"{Fore.MAGENTA}[404] {request.path} from {ip}{Style.RESET_ALL}")
    return jsonify({"error": "not found"}), 404


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"{Fore.CYAN}{'=' * 60}")
    print("  Honeypot Ad Server v2.0 (+ Geolocation)")
    print(f"{'=' * 60}{Style.RESET_ALL}")
    print(f"  Endpoints:")
    print(f"    {Fore.GREEN}GET  http://127.0.0.1:5000/ad/serve{Style.RESET_ALL}  — fake ad page")
    print(f"    {Fore.GREEN}GET  http://127.0.0.1:5000/ad/pixel{Style.RESET_ALL}  — 1x1 beacon")
    print(f"    {Fore.GREEN}GET  http://127.0.0.1:5000/ad/click{Style.RESET_ALL}  — click tracker")
    print(f"    {Fore.GREEN}GET  http://127.0.0.1:5000/logs{Style.RESET_ALL}      — log REST API")
    print(f"  Log file: {LOG_FILE}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
