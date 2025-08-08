#!/usr/bin/env python3
# -*- coding: utf8 -*-

"""
=^.^= WEBCAT =^.^=

WEBCAT EXTENDED is a multithreaded website scanner designed to discover interesting files and directories using 
customizable wordlists. It supports HTTP method enumeration, security header analysis, sensitive file detection, 
and TLS certificate inspection, enabling security-focused assessments inspired by the OWASP Web Security Testing Guide. 
The tool provides flexible output options and concurrency controls to efficiently scan target web applications.

Version: 0.8

Core features:
- Multithreaded scanning of web directories and files using customizable wordlists
- HTTP status code filtering and verbose output options
- Detection of supported HTTP methods via OPTIONS requests
- Analysis of missing critical security headers (e.g., Content-Security-Policy, HSTS)
- Identification of sensitive files and directories based on a top 20 pattern list
- TLS certificate information retrieval for HTTPS targets (issuer and expiry)
- Flexible output to console and tab-separated output file with detailed scan results
- Optional activation of advanced OWASP WSTG-inspired security tests

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
from datetime import datetime
from urllib.parse import urlparse
from threading import Thread, Lock
from queue import Queue

# Global lock for writing to file
write_lock = Lock()
queue = Queue()

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
    print("-" * 50)
    print(f"->>  Target URL     : {options.url}")
    print(f"->>  Wordlist       : {options.file}")
    print(f"->>  Status Filter  : {', '.join(map(str, options.display_list))}")
    if options.output_file:
        print(f"->>  Output File    : {options.output_file}")
    if options.extra_checks:
        print(f"->>  OWASP WSTG Checks: enabled")
    else:
        print(f"->>  OWASP WSTG Checks: disabled")
    print(f"->>  Threads        : {options.threads}")
    print("-" * 50)

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
        response = requests.options(url, timeout=5)
        allow = response.headers.get("Allow")
        if allow:
            return [method.strip() for method in allow.split(",")]
    except requests.RequestException:
        pass
    return None

def is_likely_directory(url: str) -> bool:
    """
    Heuristically determine if the URL is a directory based on the path.

    Called as: is_likely_directory("https://example.com/backup/")
    Input:
      url (str): URL to check
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
      url (str): URL to check
    Output:
      True if sensitive pattern found, False otherwise (bool)
    """
    lower_path = url.lower()
    return any(sens.lower() in lower_path for sens in SENSITIVE_PATHS)

def analyze_security_headers(response: requests.Response) -> list:
    """
    Check for missing important security headers in HTTP response.

    Called as: analyze_security_headers(response_object)
    Input:
      response (requests.Response): HTTP response object
    Output:
      list of missing header names (list of str), empty if all present
    """
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]
    missing = [h for h in required_headers if h not in response.headers]
    return missing

def get_tls_info(target_url: str) -> dict or None:
    """
    Retrieve TLS certificate information for the base URL.

    Called as: get_tls_info("https://example.com")
    Input:
      target_url (str): base URL (must start with https://)
    Output:
      dict with keys 'issuer' and 'expires' (str), or None if not HTTPS or error
    """
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issued_by = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return {
                    "issuer": issued_by,
                    "expires": not_after.strftime("%Y-%m-%d")
                }
    except Exception:
        return None

def worker():
    """
    Thread worker function to scan each URL in the queue.

    Called as: runs inside threading.Thread target, no args
    Input:
      None (fetches URL from global queue)
    Output:
      None
    """
    while True:
        url = queue.get()
        if url is None:
            break
        scantarget(url, options.display_list, options.extra_checks, options.output_file)
        queue.task_done()

def scantarget(url: str, status_filter: list, extra_checks: bool, output_file: str or None):
    """
    Perform GET request, optionally perform extra OWASP WSTG checks, and write results.

    Called as: scantarget("https://example.com/backup", [200], True, "results.txt")
    Input:
      url (str): URL to scan
      status_filter (list of int): HTTP status codes to display
      extra_checks (bool): whether to perform OWASP extra tests
      output_file (str or None): output file path, or None to disable file output
    Output:
      None (prints to stdout and optionally writes to file)
    """
    user_agent = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip'
    }

    try:
        response = requests.get(url, headers=user_agent, timeout=5)
        code = response.status_code
        show = options.verbose_switch or code in status_filter

        methods = None
        missing_headers = []
        sensitive = False

        if extra_checks:
            # Always check methods (OPTIONS)
            methods = list_supported_methods(url)
            # Check security headers
            missing_headers = analyze_security_headers(response)
            # Check sensitive files/paths
            sensitive = is_sensitive_path(url)
        else:
            # Old behavior: only check OPTIONS if -check-opt set and is directory
            if options.check_options and is_likely_directory(url):
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
                    # Append TLS info only for base URL and only if extra_checks enabled
                    if extra_checks and url.rstrip('/') == options.url.rstrip('/') and TLS_INFO:
                        parts.append(f"TLS Issuer: {TLS_INFO['issuer']}, Expires: {TLS_INFO['expires']}")
                    f.write("\t".join(parts) + "\n")

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        pass  # optionally log errors

# Argument parsing
parser = argparse.ArgumentParser()
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
                    help="Output results to file (tab-separated URL, status code, methods, missing headers, sensitive flag, TLS info)")
parser.add_argument("-t", "--threads", dest="threads", default=10, type=int,
                    help="Number of concurrent threads (default: 10)")
parser.add_argument("-x", "--extra-checks", dest="extra_checks", default=False,
                    action="store_true", help="Enable extra OWASP WSTG inspired checks")

options = parser.parse_args()

TLS_INFO = None
def main():
    global TLS_INFO
    infoheader()
    try:
        targets = createlist(options.file, options.url)
        if options.output_file:
            open(options.output_file, "w").close()  # clear output file

        # If extra checks enabled, get TLS info for base URL once
        if options.extra_checks:
            TLS_INFO = get_tls_info(options.url)

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
