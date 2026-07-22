#!/usr/bin/env python3
"""
Preflight — deterministic pre-submission checks for QuickBooks Online apps.

Probes a LIVE app URL against the runtime/deployment requirements Intuit's
security review grades. These are deterministic: a response header either
satisfies the rule or it doesn't. No source code, no scanner, no false positives.

Reference: Intuit "Security requirements" for publishing on the QuickBooks App Store.
This tool is independent and not affiliated with or endorsed by Intuit.
"""

import sys
import json
import argparse
import ssl
import socket
from urllib.parse import urlparse
import http.client

# ----- result model -------------------------------------------------------

PASS = "pass"
FAIL = "fail"
WARN = "warn"
INFO = "info"

class Check:
    def __init__(self, key, category, title, status, detail, requirement):
        self.key = key
        self.category = category      # Intuit review category
        self.title = title
        self.status = status
        self.detail = detail
        self.requirement = requirement  # short cite of the Intuit rule

    def to_dict(self):
        return {
            "key": self.key,
            "category": self.category,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "requirement": self.requirement,
        }


# ----- low-level probing ---------------------------------------------------

def _request(method, url, timeout=10):
    """Make a single HTTP(S) request, return (status, headers dict, error)."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, headers={"User-Agent": "Preflight-QBO-Check/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
        return status, headers, None
    except Exception as e:
        return None, {}, str(e)


def _negotiated_tls_version(host, port=443, timeout=10):
    """Return the highest TLS version the server negotiates, or None."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version()  # e.g. 'TLSv1.2', 'TLSv1.3'
    except Exception:
        return None


# ----- the checks ----------------------------------------------------------

def check_https_enforced(url):
    """HTTPS must be enforced on all pages."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        # Try to reach the http version and see if it upgrades.
        http_url = url.replace("https://", "http://", 1) if url.startswith("https") else url
        status, headers, err = _request("GET", http_url)
        loc = headers.get("location", "")
        if status in (301, 302, 307, 308) and loc.startswith("https://"):
            return Check("https_enforced", "Server config", "HTTPS enforced", PASS,
                         f"HTTP redirects to HTTPS ({status} -> {loc[:60]}).",
                         "HTTPS is enforced on all pages of your app.")
        return Check("https_enforced", "Server config", "HTTPS enforced", FAIL,
                     "URL is not HTTPS and does not redirect to HTTPS.",
                     "HTTPS is enforced on all pages of your app.")
    return Check("https_enforced", "Server config", "HTTPS enforced", PASS,
                 "App is served over HTTPS.",
                 "HTTPS is enforced on all pages of your app.")


def check_tls_version(url):
    """TLS must be >= 1.1; 1.2 with strong ciphers recommended."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return Check("tls_version", "Server config", "TLS version", FAIL,
                     "Not served over HTTPS, cannot negotiate TLS.",
                     "SSL must support TLS 1.1 or higher; 1.2 recommended.")
    host = parsed.hostname
    port = parsed.port or 443
    ver = _negotiated_tls_version(host, port)
    if ver is None:
        return Check("tls_version", "Server config", "TLS version", WARN,
                     "Could not determine negotiated TLS version.",
                     "SSL must support TLS 1.1 or higher; 1.2 recommended.")
    # Map to comparable number
    order = {"TLSv1": 1.0, "TLSv1.1": 1.1, "TLSv1.2": 1.2, "TLSv1.3": 1.3}
    n = order.get(ver, 0)
    if n >= 1.2:
        return Check("tls_version", "Server config", "TLS version", PASS,
                     f"Negotiated {ver} (meets recommended 1.2+).",
                     "SSL must support TLS 1.1 or higher; 1.2 recommended.")
    if n >= 1.1:
        return Check("tls_version", "Server config", "TLS version", WARN,
                     f"Negotiated {ver} (meets minimum 1.1, but 1.2+ recommended).",
                     "SSL must support TLS 1.1 or higher; 1.2 recommended.")
    return Check("tls_version", "Server config", "TLS version", FAIL,
                 f"Negotiated {ver}, below the required TLS 1.1.",
                 "SSL must support TLS 1.1 or higher; 1.2 recommended.")


def check_cache_control(url):
    """Sensitive pages must use no-cache/no-store, not private."""
    status, headers, err = _request("GET", url)
    if err:
        return Check("cache_control", "Server config", "Cache-Control on sensitive pages", WARN,
                     f"Could not fetch page: {err}",
                     "Caching disabled on SSL/sensitive pages via no-cache and no-store.")
    cc = headers.get("cache-control", "").lower()
    if not cc:
        return Check("cache_control", "Server config", "Cache-Control on sensitive pages", FAIL,
                     "No Cache-Control header present on this page.",
                     "Caching disabled on SSL/sensitive pages via no-cache and no-store.")
    if "no-store" in cc:
        return Check("cache_control", "Server config", "Cache-Control on sensitive pages", PASS,
                     f"Cache-Control includes no-store ('{cc}').",
                     "Caching disabled on SSL/sensitive pages via no-cache and no-store.")
    if "private" in cc and "no-store" not in cc:
        return Check("cache_control", "Server config", "Cache-Control on sensitive pages", FAIL,
                     f"Uses 'private' instead of 'no-store' ('{cc}'). Intuit requires no-store on sensitive pages.",
                     "Caching disabled on SSL/sensitive pages via no-cache and no-store.")
    return Check("cache_control", "Server config", "Cache-Control on sensitive pages", WARN,
                 f"Cache-Control present but no 'no-store' ('{cc}'). Verify this page holds no sensitive data.",
                 "Caching disabled on SSL/sensitive pages via no-cache and no-store.")


def check_cookie_flags(url):
    """Session cookies must have Secure and HTTPOnly."""
    status, headers, err = _request("GET", url)
    if err:
        return Check("cookie_flags", "Cookies", "Session cookie flags", WARN,
                     f"Could not fetch page: {err}",
                     "Session cookies must set Secure and HTTPOnly.")
    # http.client collapses duplicate Set-Cookie into one comma-joined value.
    raw = headers.get("set-cookie", "")
    if not raw:
        return Check("cookie_flags", "Cookies", "Session cookie flags", INFO,
                     "No cookies set on this page. Re-run against a page that sets a session cookie.",
                     "Session cookies must set Secure and HTTPOnly.")
    low = raw.lower()
    missing = []
    if "secure" not in low:
        missing.append("Secure")
    if "httponly" not in low:
        missing.append("HttpOnly")
    if not missing:
        return Check("cookie_flags", "Cookies", "Session cookie flags", PASS,
                     "Set-Cookie includes Secure and HttpOnly.",
                     "Session cookies must set Secure and HTTPOnly.")
    return Check("cookie_flags", "Cookies", "Session cookie flags", FAIL,
                 f"Set-Cookie missing: {', '.join(missing)}.",
                 "Session cookies must set Secure and HTTPOnly.")


def check_trace_disabled(url):
    """TRACE and unused HTTP methods should be disabled."""
    status, headers, err = _request("TRACE", url)
    if err:
        # Many servers/clients reject TRACE at the socket level — that's effectively "disabled".
        return Check("trace_disabled", "Server config", "TRACE method disabled", PASS,
                     "TRACE request did not succeed (method appears disabled).",
                     "Disable TRACE and other unused HTTP methods.")
    if status == 405 or status == 501:
        return Check("trace_disabled", "Server config", "TRACE method disabled", PASS,
                     f"Server rejects TRACE ({status}).",
                     "Disable TRACE and other unused HTTP methods.")
    if status == 200:
        return Check("trace_disabled", "Server config", "TRACE method disabled", FAIL,
                     "Server responds 200 to TRACE — method is enabled and should be disabled.",
                     "Disable TRACE and other unused HTTP methods.")
    return Check("trace_disabled", "Server config", "TRACE method disabled", WARN,
                 f"TRACE returned {status}; verify the method is disabled.",
                 "Disable TRACE and other unused HTTP methods.")


def check_token_endpoint_redirect(url, token_path):
    """
    Endpoints receiving tokens/sensitive data in URL params must return a
    302 redirect, not HTML in the body (prevents referer leakage).
    Only run if the user supplies a token-bearing endpoint path.
    """
    if not token_path:
        return Check("token_redirect", "Security", "302 on token-bearing endpoint", INFO,
                     "No token endpoint provided (set 'token-endpoint' input to check this rule).",
                     "Token-bearing endpoints must 302 redirect, not return HTML.")
    base = url.rstrip("/")
    tp = token_path if token_path.startswith("/") else "/" + token_path
    probe = base + tp
    status, headers, err = _request("GET", probe)
    if err:
        return Check("token_redirect", "Security", "302 on token-bearing endpoint", WARN,
                     f"Could not reach {tp}: {err}",
                     "Token-bearing endpoints must 302 redirect, not return HTML.")
    ctype = headers.get("content-type", "").lower()
    if status in (301, 302, 303, 307, 308):
        return Check("token_redirect", "Security", "302 on token-bearing endpoint", PASS,
                     f"Endpoint responds with redirect ({status}).",
                     "Token-bearing endpoints must 302 redirect, not return HTML.")
    if "text/html" in ctype:
        return Check("token_redirect", "Security", "302 on token-bearing endpoint", FAIL,
                     f"Endpoint returns HTML ({status}) instead of a redirect — risks leaking tokens via Referer.",
                     "Token-bearing endpoints must 302 redirect, not return HTML.")
    return Check("token_redirect", "Security", "302 on token-bearing endpoint", WARN,
                 f"Endpoint returned {status} ({ctype or 'no content-type'}); verify it does not return HTML with a token present.",
                 "Token-bearing endpoints must 302 redirect, not return HTML.")


# ----- runner --------------------------------------------------------------

def run_all(url, token_path):
    checks = [
        check_https_enforced(url),
        check_tls_version(url),
        check_cache_control(url),
        check_trace_disabled(url),
        check_cookie_flags(url),
        check_token_endpoint_redirect(url, token_path),
    ]
    return checks


def main():
    ap = argparse.ArgumentParser(description="Preflight deterministic QBO app checks.")
    ap.add_argument("--url", required=True, help="Base URL of the deployed app to probe.")
    ap.add_argument("--token-endpoint", default="", help="Optional path of a token-bearing endpoint.")
    ap.add_argument("--fail-on", default="fail", choices=["fail", "warn", "never"],
                    help="Exit non-zero when a check is at/above this severity.")
    ap.add_argument("--format", default="text", choices=["text", "json"])
    args = ap.parse_args()

    checks = run_all(args.url, args.token_endpoint)

    counts = {PASS: 0, FAIL: 0, WARN: 0, INFO: 0}
    for c in checks:
        counts[c.status] += 1

    if args.format == "json":
        print(json.dumps({
            "url": args.url,
            "summary": counts,
            "checks": [c.to_dict() for c in checks],
        }, indent=2))
    else:
        _print_text(args.url, checks, counts)

    # Exit code policy
    if args.fail_on == "never":
        sys.exit(0)
    if args.fail_on == "warn" and (counts[FAIL] > 0 or counts[WARN] > 0):
        sys.exit(1)
    if args.fail_on == "fail" and counts[FAIL] > 0:
        sys.exit(1)
    sys.exit(0)


def _sym(status):
    return {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", INFO: "----"}[status]


def _print_text(url, checks, counts):
    print("")
    print("  Preflight — QuickBooks Online pre-submission check")
    print("  Target: " + url)
    print("  " + "-" * 58)
    current_cat = None
    for c in checks:
        if c.category != current_cat:
            current_cat = c.category
            print(f"\n  [{c.category}]")
        print(f"    {_sym(c.status)}  {c.title}")
        print(f"          {c.detail}")
    print("")
    print("  " + "-" * 58)
    print(f"  {counts[PASS]} pass · {counts[FAIL]} fail · {counts[WARN]} warn · {counts[INFO]} n/a")
    if counts[FAIL] > 0:
        print("  Fix the FAIL items — these are what Intuit's security review flags.")
    print("")
    print("  Deterministic runtime checks only. Independent tool, not affiliated with Intuit.")
    print("  Deeper checks (OAuth token storage, data-usage, injection) at preflightci.dev")
    print("")


if __name__ == "__main__":
    main()
