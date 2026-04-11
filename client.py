"""
Browser Simulator for Honeypot Testing.

This module simulates four distinct client profiles (browser, bot, scanner, scraper),
each with characteristic headers and cookies. It exists separately from server.py
because the client and server have independent lifecycles --- the server runs
continuously while this script is run on demand to generate test traffic.

Usage:
    python client.py --profile browser
    python client.py --profile bot
    python client.py --profile scanner
    python client.py --profile scraper
"""

import argparse
import sys
import time

import requests
from colorama import Fore, Style, init

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

init(autoreset=True)

BASE_URL = "http://127.0.0.1:5000"

# ---------------------------------------------------------------------------
# Client profile definitions
#
# Each profile is a dict with:
#   headers  — HTTP headers sent with every request
#   cookies  — Cookies attached to every request
#
# Profiles are deliberately distinct so the server's classifier can assign
# different client_type values and threat scores.
# ---------------------------------------------------------------------------

PROFILES: dict[str, dict] = {
    "browser": {
        "headers": {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer":         "https://google.com",
            "DNT":             "1",
        },
        "cookies": {
            "session_id": "abc123def456",
            "user_pref":  "dark_mode=1",
        },
    },
    "bot": {
        "headers": {
            "User-Agent":      "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Accept":          "text/html",
            "Accept-Language": "en",
            "Accept-Encoding": "gzip",
        },
        "cookies": {},  # Bots typically carry no session cookies
    },
    "scanner": {
        "headers": {
            "User-Agent": "Nikto/2.1.6 (Evasions:None)",
            "Accept":     "*/*",
            # Deliberately omits Accept-Language and Accept-Encoding
        },
        "cookies": {},
    },
    "scraper": {
        "headers": {
            "User-Agent":      "python-requests/2.31.0",
            "Accept":          "*/*",
            "Accept-Encoding": "gzip, deflate",
            # Deliberately omits Accept-Language
        },
        "cookies": {
            "scrape_session": "xyz789",
        },
    },
}

# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def send_request(
    session: requests.Session,
    path: str,
    profile_name: str,
    allow_redirects: bool = False,
) -> requests.Response | None:
    """
    Send a GET request to the honeypot server and print the outcome.

    allow_redirects is False for /ad/click so we can log the 302 destination
    before the client follows it, matching the flow document's intent.
    """
    url = f"{BASE_URL}{path}"
    print(f"  {Fore.CYAN}→ GET {path}{Style.RESET_ALL}", end="  ", flush=True)
    try:
        response = session.get(url, allow_redirects=allow_redirects, timeout=5)
        status_colour = Fore.GREEN if response.status_code < 400 else Fore.RED
        print(f"{status_colour}HTTP {response.status_code}{Style.RESET_ALL}")
        return response
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}CONNECTION REFUSED{Style.RESET_ALL}")
        print(
            f"\n{Fore.RED}Error: Could not connect to {BASE_URL}. "
            f"Is the server running?{Style.RESET_ALL}"
        )
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{Fore.YELLOW}TIMEOUT{Style.RESET_ALL}")
        return None


def extract_geo_from_response(response: requests.Response | None) -> dict:
    """
    Extract geolocation data from response headers set by the honeypot server.

    The server embeds resolved geo fields in custom X-Honeypot-* headers so
    the client can display them in the session summary without parsing HTML.
    """
    if response is None:
        return {}
    return {
        "city":    response.headers.get("X-Honeypot-City", ""),
        "country": response.headers.get("X-Honeypot-Country", ""),
        "isp":     response.headers.get("X-Honeypot-ISP", ""),
        "score":   response.headers.get("X-Honeypot-Score", ""),
    }


# ---------------------------------------------------------------------------
# Session report
# ---------------------------------------------------------------------------

def print_session_report(profile_name: str, geo: dict, fingerprint_hint: str) -> None:
    """Print a formatted summary after the three-request sequence completes."""
    score      = geo.get("score", "N/A")
    city       = geo.get("city") or "Unknown"
    country    = geo.get("country") or "Unknown"
    isp        = geo.get("isp") or "Unknown"

    try:
        score_int = int(score)
        if score_int < 31:
            score_colour = Fore.GREEN
            risk_label   = "LOW RISK"
        elif score_int < 61:
            score_colour = Fore.YELLOW
            risk_label   = "SUSPICIOUS"
        else:
            score_colour = Fore.RED
            risk_label   = "HIGH RISK"
    except (ValueError, TypeError):
        score_colour = Fore.WHITE
        risk_label   = "UNKNOWN"

    print(f"\n{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")
    print(f"  Session Report — Profile: {Fore.YELLOW}{profile_name.upper()}{Style.RESET_ALL}")
    print(f"{'─' * 50}")
    print(f"  Threat Score : {score_colour}{score} ({risk_label}){Style.RESET_ALL}")
    print(f"  Location     : {city}, {country}")
    print(f"  ISP          : {isp}")
    print(f"  Fingerprint  : {fingerprint_hint or 'N/A'}")
    print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}\n")


# ---------------------------------------------------------------------------
# Main simulation sequence
# ---------------------------------------------------------------------------

def run_simulation(profile_name: str) -> None:
    """
    Execute the three-request honeypot interaction sequence:
      1. GET /ad/serve  — request the fake ad page
      2. GET /ad/pixel  — fire the tracking beacon
      3. GET /ad/click  — simulate an ad click (302 redirect)

    This mirrors the End-to-End Flow Document (v2.0) Phase 2 interaction.
    """
    profile = PROFILES[profile_name]

    print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"  Honeypot Client Simulator v2.0")
    print(f"  Profile : {Fore.YELLOW}{profile_name.upper()}{Style.RESET_ALL}")
    print(f"  Target  : {BASE_URL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}\n")

    # Build a session so cookies persist across requests, matching browser behaviour
    session = requests.Session()
    session.headers.update(profile["headers"])
    session.cookies.update(profile["cookies"])

    # Step 1: Ad serve
    serve_response = send_request(session, "/ad/serve", profile_name)
    geo            = extract_geo_from_response(serve_response)

    # Brief pause to simulate realistic inter-request timing
    time.sleep(0.5)

    # Step 2: Pixel beacon
    send_request(session, "/ad/pixel", profile_name)

    time.sleep(0.3)

    # Step 3: Ad click (capture 302 before following redirect)
    score    = geo.get("score", "0")
    click_url = f"/ad/click?ref={score}"
    click_response = send_request(session, click_url, profile_name, allow_redirects=False)

    if click_response is not None and click_response.status_code == 302:
        destination = click_response.headers.get("Location", "unknown")
        print(f"  {Fore.BLUE}↪ Redirect → {destination}{Style.RESET_ALL}")

    # Derive a fingerprint hint from the serve response to include in the report
    fingerprint_hint = ""
    if serve_response is not None:
        # The server embeds the score in the header; use it as a proxy for the
        # fingerprint since the full fingerprint is only in the JSON log
        fingerprint_hint = f"(see honeypot_logs.json for full 12-char MD5)"

    print_session_report(profile_name, geo, fingerprint_hint)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Honeypot client simulator — sends three requests using a chosen profile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles:
  browser  — Chrome-like headers + cookies, low threat score expected
  bot      — Googlebot User-Agent, medium threat score expected
  scanner  — Nikto scanner UA, high threat score expected
  scraper  — python-requests UA, medium threat score expected

Example:
  python client.py --profile scanner
        """,
    )
    parser.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default="browser",
        help="Client profile to simulate (default: browser)",
    )
    args = parser.parse_args()
    run_simulation(args.profile)


if __name__ == "__main__":
    main()
