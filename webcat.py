#!/usr/bin/env python3
# -*- coding: utf8 -*-

"""
=^.^= WEBCAT =^.^=

WEBCAT is a multithreaded website scanner designed to discover interesting files and directories using 
customizable wordlists. It supports HTTP method enumeration, security header analysis, sensitive file detection, 
and TLS certificate inspection, enabling security-focused assessments inspired by the OWASP Web Security Testing Guide. 
The tool provides flexible output options and concurrency controls to efficiently scan target web applications.

Version: 0.9

Core features:
- Multithreaded scanning of web directories and files using customizable wordlists
- HTTP status code filtering and verbose output options
- Detection of supported HTTP methods via OPTIONS requests
- Analysis of missing critical security headers (e.g., Content-Security-Policy, HSTS)
- Identification of sensitive files and directories based on a top 20 pattern list
- TLS certificate information retrieval for HTTPS targets (issuer and expiry)
- Flexible output to console and tab-separated output file with detailed scan results
- Optional activation of advanced OWASP WSTG-inspired security tests
- Proxy support

Webcat features with optional OWASP WSTG-inspired features:
- Directory & file fuzzing
- Optional HTTP methods testing (WSTG-CONF-06)
- Optional Security header analysis (WSTG-HTT-02)
- Optional Sensitive file detection (WSTG-INFO-05)
- TLS information extraction for base URL (WSTG-CRYP-01) only if extra checks enabled
- Consolidated output to file with all scan results

Author: Peter "kangafoo" Bartels, https://www.kangafoo.de
"""

import sys
import argparse
import os
import ssl
import socket
import requests
import urllib3
from datetime import datetime
from urllib.parse import urlparse
from threading import Thread, Lock
from queue import Queue

# Global lock for writing to file
write_lock = Lock()
queue = Queue()

# Track certificate warnings so self-signed certificates are reported once per host
ssl_warning_hosts = set()

# We print our own explicit warning before retrying without certificate verification.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sensitive file patterns (Top 20 common sensitive files and directories)
SENSITIVE_PATHS = [
    ".git",
    ".env",
    ".bash_history",
    "id_rsa",
    "id_dsa",
    "wp-config.php",
    "config.php",
    ".htaccess",
    "backup",
    "db_backup",
    "database.sql",
    "dump.sql",
    "phpinfo.php",
    "adminer.php",
    "web.config",
    "robots.txt",
    "server-status",
    "config.yaml",
    "credentials.json",
    "error.log"
]

def clear():
    """
    Clear screen for Linux and Windows.

    Called as: clear()
    Input: None
    Output: None
    """
    os.system("cls" if os.name == "nt" else "clear")

def infoheader():
    """
    Print header with scan settings.

    Called as: infoheader()
    Input: None (uses global options)
    Output: None (prints to stdout)
    """
    clear()
    print("=^.^= WEBCAT =^.^=")
    print("-" * 60)
    print(f"->>  Target URL     : {options.url}")
    print(f"->>  Wordlist       : {options.file}")
    print(f"->>  Status Filter  : {', '.join(map(str, options.display_list))}")
    if options.output_file:
        print(f"->>  Output File    : {options.output_file}")
    print(f"->>  Extra Checks   : {'enabled' if options.extra_checks else 'disabled'}")
    print(f"->>  Check OPTIONS  : {'enabled' if options.check_options else 'disabled'} (legacy)")
    if options.proxy:
        print(f"->>  Proxy          : {options.proxy}")
    print(f"->>  Threads        : {options.threads}")
    print("-" * 60)

def printhelp():
    """
    Print help and header if no arguments are given.

    Called as: printhelp()
    Input: None
    Output: None (prints help to stdout)
    """
    clear()
    print("=^.^= WEBCAT =^.^=")
    parser.print_help()

def get_proxies() -> dict or None:
    """
    Build proxies dict for requests if proxy option provided.

    Called as: get_proxies()
    Input: None (uses global options.proxy)
    Output: dict or None
    """
    if options.proxy:
        # Use http proxy for both http and https (HTTP(S) proxy)
        return {
            "http": f"http://{options.proxy}",
            "https": f"http://{options.proxy}"
        }
    return None


def warn_ssl_and_continue(url: str, error: Exception):
    """
    Print a warning once per host when TLS certificate verification fails.

    Called as: warn_ssl_and_continue("https://example.com", error)
    Input:
      url (str)
      error (Exception)
    Output: None (prints warning to stdout)
    """
    parsed = urlparse(url)
    host = parsed.hostname or url
    with write_lock:
        if host not in ssl_warning_hosts:
            ssl_warning_hosts.add(host)
            print(f"[SSL WARNING] Certificate verification failed for {host}: {error}")
            print("[SSL WARNING] Continuing scan with certificate verification disabled for this request.")


def request_with_ssl_warning(method: str, url: str, **kwargs) -> requests.Response:
    """
    Perform an HTTP request. If certificate verification fails, warn and retry with verify=False.

    Called as: request_with_ssl_warning("GET", "https://example.com", timeout=5)
    Input:
      method (str): HTTP method
      url (str): target URL
      **kwargs: passed through to requests.request
    Output:
      requests.Response
    """
    try:
        return requests.request(method, url, **kwargs)
    except requests.exceptions.SSLError as e:
        warn_ssl_and_continue(url, e)
        retry_kwargs = dict(kwargs)
        retry_kwargs["verify"] = False
        return requests.request(method, url, **retry_kwargs)

def createlist(myfile: str, mytarget: str) -> list:
    """
    Read wordlist and combine with base URL.

    Called as: createlist("wordlist.txt", "https://example.com")
    Input:
      myfile (str): path to wordlist file
      mytarget (str): base target URL
    Output:
      list of full URLs (list of str)
    """
    with open(myfile, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    return [mytarget.rstrip("/") + "/" + line.lstrip("/") for line in lines]

def list_supported_methods(url: str) -> list or None:
    """
    Send OPTIONS request and return supported HTTP methods.

    Called as: list_supported_methods("https://example.com/admin/")
    Input:
      url (str): URL to send OPTIONS request to
    Output:
      list of HTTP methods (list of str) or None if no Allow header or error
    """
    try:
        resp = request_with_ssl_warning("OPTIONS", url, timeout=5, proxies=get_proxies())
        allow = resp.headers.get("Allow")
        if allow:
            return [m.strip() for m in allow.split(",")]
    except requests.RequestException:
        pass
    return None

def is_likely_directory(url: str) -> bool:
    """
    Heuristically determine if the URL is a directory based on the path.

    Called as: is_likely_directory("https://example.com/backup/")
    Input:
      url (str)
    Output:
      True if URL looks like a directory, False otherwise (bool)
    """
    path = url.split('?')[0].split('#')[0]
    last_part = path.rstrip('/').split('/')[-1]
    return '.' not in last_part

def is_sensitive_path(url: str) -> bool:
    """
    Check if URL path contains sensitive file or folder names.

    Called as: is_sensitive_path("https://example.com/.git")
    Input:
      url (str)
    Output:
      True if sensitive pattern found, False otherwise (bool)
    """
    lower = url.lower()
    return any(sens.lower() in lower for sens in SENSITIVE_PATHS)

def analyze_security_headers(response: requests.Response) -> list:
    """
    Check for missing important security headers in HTTP response.

    Called as: analyze_security_headers(response_obj)
    Input:
      response (requests.Response)
    Output:
      list of missing header names (list of str), empty if all present
    """
    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]
    missing = [h for h in required if h not in response.headers]
    return missing

def get_tls_info(target_url: str) -> dict or None:
    """
    Retrieve TLS certificate information for the base URL.

    Called as: get_tls_info("https://example.com")
    Input:
      target_url (str) - must start with https://
    Output:
      dict with keys 'issuer' and 'expires' (str) or None if not HTTPS/error
    """
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname
    port = parsed.port or 443
    def read_certificate(ctx):
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()

    try:
        ctx = ssl.create_default_context()
        try:
            cert = read_certificate(ctx)
        except ssl.SSLCertVerificationError as e:
            warn_ssl_and_continue(target_url, e)
            unverified_ctx = ssl._create_unverified_context()
            cert = read_certificate(unverified_ctx)

        issuer = dict(x[0] for x in cert.get('issuer', ()))
        issued_by = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
        not_after = cert.get('notAfter')
        # Parse notAfter; if format unexpected, return raw string
        try:
            expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expires = expires_dt.strftime("%Y-%m-%d")
        except Exception:
            expires = str(not_after)
        return {"issuer": issued_by, "expires": expires}
    except Exception:
        return None

def get_server_header(base_url: str) -> str or None:
    """
    Retrieve the Server header from the base URL (single check).

    Called as: get_server_header("https://example.com") when extra_checks enabled.
    Input:
      base_url (str)
    Output:
      Server header string or None
    """
    try:
        resp = request_with_ssl_warning("GET", base_url, timeout=5, proxies=get_proxies())
        server = resp.headers.get("Server")
        if server:
            print(f"[WSTG] Server header for {base_url}: {server}")
            return server
        else:
            print(f"[WSTG] No Server header for {base_url}")
            return None
    except requests.RequestException as e:
        print(f"[WSTG] Could not retrieve Server header for {base_url}: {e}")
        return None

def worker():
    """
    Thread worker function to scan each URL in the queue.

    Called as: runs inside threading.Thread target
    Input: None (fetches URL from global queue)
    Output: None
    """
    while True:
        url = queue.get()
        if url is None:
            break
        scantarget(url, options.display_list, options.check_options, options.extra_checks, options.output_file)
        queue.task_done()

def scantarget(url: str, status_filter: list, check_options: bool, extra_checks: bool, output_file: str or None):
    """
    Perform GET request, optionally perform extra OWASP WSTG checks, and write results.

    Called as: scantarget("https://example.com/backup", [200], True, True, "results.txt")
    Input:
      url (str)
      status_filter (list of int)
      check_options (bool) - legacy OPTIONS check behavior
      extra_checks (bool) - run full WSTG-inspired checks
      output_file (str|None)
    Output:
      None (prints to stdout and writes to file if specified)
    """
    user_agent = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip'
    }

    try:
        resp = request_with_ssl_warning("GET", url, headers=user_agent, timeout=5, proxies=get_proxies())
        code = resp.status_code
        show = options.verbose_switch or code in status_filter

        methods = None
        missing_headers = []
        sensitive = False

        if extra_checks:
            # full mode: always try OPTIONS and header analysis and sensitive check
            methods = list_supported_methods(url)
            missing_headers = analyze_security_headers(resp)
            sensitive = is_sensitive_path(url)
        else:
            # legacy behavior: only do OPTIONS if user explicitly asked and URL likely directory
            if check_options and is_likely_directory(url):
                methods = list_supported_methods(url)

        if show:
            print(f"[{code}] {url}")
            if methods:
                print(f"    --> Supported Methods: {', '.join(methods)}")
            if missing_headers:
                print(f"    --> Missing Security Headers: {', '.join(missing_headers)}")
            if sensitive:
                print(f"    --> [!] Sensitive Path Detected")

        if output_file and show:
            with write_lock:
                with open(output_file, "a") as f:
                    parts = [
                        url,
                        str(code),
                        ",".join(methods) if methods else "",
                        ",".join(missing_headers) if missing_headers else "",
                        "Sensitive" if sensitive else ""
                    ]
                    # Append TLS info only for base URL and only if extra_checks enabled and TLS_INFO available
                    if extra_checks and url.rstrip('/') == options.url.rstrip('/') and TLS_INFO:
                        parts.append(f"TLS Issuer: {TLS_INFO.get('issuer','')}, Expires: {TLS_INFO.get('expires','')}")
                    f.write("\t".join(parts) + "\n")

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        pass  # silently ignore network errors (could be extended to logging)

# Argument parsing
parser = argparse.ArgumentParser(description="WEBCAT - simple threaded website scanner with optional WSTG checks")
parser.add_argument("-u", "--url", dest="url", required=True,
                    help="Specify the target URL (e.g. https://example.com)")
parser.add_argument("-f", "--file", dest="file", required=True,
                    help="Wordlist file with paths to scan")
parser.add_argument("-v", "--verbose", dest="verbose_switch", default=False,
                    action="store_true", help="Show all results")
parser.add_argument("-d", "--display", dest="display_list", default=[200],
                    nargs='+', type=int, help="Filter output by status codes")
parser.add_argument("--check-opt", dest="check_options", default=False,
                    action="store_true", help="Check supported HTTP methods via OPTIONS request (legacy)")
parser.add_argument("-o", "--output", dest="output_file", default=None,
                    help="Output results to file (tab-separated URL,status,methods,missing_headers,sensitive,TLS)")
parser.add_argument("-t", "--threads", dest="threads", default=10, type=int,
                    help="Number of concurrent threads (default: 10)")
parser.add_argument("-x", "--extra-checks", dest="extra_checks", default=False,
                    action="store_true", help="Perform additional OWASP WSTG-inspired checks")
parser.add_argument("-p", "--proxy", dest="proxy", default=None,
                    help="Use a proxy for all HTTP/HTTPS requests (format: ip:port)")

options = parser.parse_args()

def validate_options(opts):
    """
    Validate input options for correctness.

    Called as: validate_options(options)
    Input:
      opts (argparse.Namespace)
    Output:
      None (exits with parser.error on invalid options)
    """
    parsed = urlparse(opts.url)
    if parsed.scheme not in ("http", "https"):
        parser.error("URL must start with http:// or https://")
    if not os.path.isfile(opts.file):
        parser.error(f"Wordlist file '{opts.file}' does not exist.")
    for code in opts.display_list:
        if not (100 <= code <= 599):
            parser.error(f"Invalid HTTP status code: {code}")
    if opts.threads <= 0:
        parser.error("Threads must be greater than 0.")
    if opts.proxy:
        if ":" not in opts.proxy:
            parser.error("Proxy must be in format ip:port")

# TLS info placeholder (will be set in main if extra_checks)
TLS_INFO = None

def main():
    """
    Main execution function.

    Called as: main()
    Input: None (uses global options)
    Output: None
    """
    global TLS_INFO

    # Validate CLI options first
    validate_options(options)

    # If extra checks enabled, get TLS info for base URL once
    if options.extra_checks:
        TLS_INFO = get_tls_info(options.url)

    # Print header
    infoheader()

    # If extra checks enabled, do single Server header check for base URL
    if options.extra_checks:
        get_server_header(options.url)

    try:
        targets = createlist(options.file, options.url)
        if options.output_file:
            # clear/initialize output file
            open(options.output_file, "w").close()
        for item in targets:
            queue.put(item)

        threads = []
        for _ in range(options.threads):
            t = Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        queue.join()

    except KeyboardInterrupt:
        print("\nAborted by user. Exiting.")
        sys.exit(0)

    # Gracefully shut down threads
    for _ in threads:
        queue.put(None)
    for t in threads:
        t.join()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        printhelp()
        sys.exit(1)
    main()
