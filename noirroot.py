#!/usr/bin/env python3
"""
VulnScan - Basic Website/Domain Vulnerability Checker
For authorized security testing on domains/servers you own or have permission to test.
Works on Termux and Kali Linux.
"""

import sys
import socket
import requests
import concurrent.futures
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════╗
║              NoirRoot                 ║
║   Basic Web Vulnerability Checker     ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
]


def normalize_target(target):
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    parsed = urlparse(target)
    return parsed.hostname, target


def scan_ports(host):
    print(f"\n{Fore.YELLOW}[*] Scanning common ports on {host}...{Style.RESET_ALL}")
    open_ports = []
    for port, name in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"{Fore.GREEN}  [OPEN] Port {port} ({name}){Style.RESET_ALL}")
            open_ports.append((port, name))
        sock.close()
    if not open_ports:
        print(f"{Fore.RED}  No common ports open (or host blocks scans).{Style.RESET_ALL}")
    return open_ports


def check_headers(url):
    print(f"\n{Fore.YELLOW}[*] Checking HTTP security headers on {url}...{Style.RESET_ALL}")
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException as e:
        print(f"{Fore.RED}  Could not connect: {e}{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}  Status: {resp.status_code} | Server: {resp.headers.get('Server', 'unknown')}{Style.RESET_ALL}")

    for header in SECURITY_HEADERS:
        if header in resp.headers:
            print(f"{Fore.GREEN}  [OK] {header}: {resp.headers[header]}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}  [MISSING] {header}{Style.RESET_ALL}")


def check_ssl(host):
    print(f"\n{Fore.YELLOW}[*] Checking HTTPS availability...{Style.RESET_ALL}")
    try:
        r = requests.get(f"https://{host}", timeout=8, verify=True)
        print(f"{Fore.GREEN}  [OK] HTTPS reachable, valid certificate.{Style.RESET_ALL}")
    except requests.exceptions.SSLError:
        print(f"{Fore.RED}  [WARNING] SSL certificate issue detected.{Style.RESET_ALL}")
    except requests.RequestException:
        print(f"{Fore.RED}  [FAIL] HTTPS not reachable on this host.{Style.RESET_ALL}")


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "webmail", "api", "dev", "staging",
    "test", "portal", "blog", "shop", "store", "app", "cpanel", "vpn",
    "ns1", "ns2", "smtp", "secure", "beta", "m", "dashboard", "panel"
]

COMMON_DIRS = [
    "admin", "login", "wp-admin", "backup", "config", "uploads",
    ".env", ".git", "api", "test", "dashboard", "db", "phpmyadmin",
    "server-status", "console", "old", "tmp", "install"
]

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND '1'='1", "1;--"]


def check_subdomains(domain):
    print(f"\n{Fore.YELLOW}[*] Enumerating common subdomains for {domain}...{Style.RESET_ALL}")
    found = []

    def try_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = ex.map(try_sub, COMMON_SUBDOMAINS)
        for r in results:
            if r:
                print(f"{Fore.GREEN}  [FOUND] {r}{Style.RESET_ALL}")
                found.append(r)

    if not found:
        print(f"{Fore.RED}  No common subdomains resolved.{Style.RESET_ALL}")
    return found


def check_directories(base_url):
    print(f"\n{Fore.YELLOW}[*] Probing common paths on {base_url}...{Style.RESET_ALL}")
    found = []

    def try_dir(path):
        url = urljoin(base_url + "/", path)
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                return (path, r.status_code)
        except requests.RequestException:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = ex.map(try_dir, COMMON_DIRS)
        for r in results:
            if r:
                path, code = r
                color = Fore.GREEN if code == 200 else Fore.YELLOW
                print(f"{color}  [{code}] /{path}{Style.RESET_ALL}")
                found.append((path, code))

    if not found:
        print(f"{Fore.RED}  No common paths found accessible.{Style.RESET_ALL}")
    return found


def check_sqli_basic(base_url):
    """
    Very basic, non-destructive check: appends common SQLi trigger
    characters to a dummy query param and looks for SQL error strings
    in the response. This does NOT attempt exploitation.
    """
    print(f"\n{Fore.YELLOW}[*] Running basic SQL error-based probe on {base_url}...{Style.RESET_ALL}")
    error_signatures = [
        "sql syntax", "mysql_fetch", "odbc drivers", "pg_query",
        "sqlite3", "unclosed quotation", "syntax error", "warning: mysql"
    ]
    test_param = "id"
    any_flagged = False

    for payload in SQLI_PAYLOADS:
        test_url = f"{base_url}?{test_param}={payload}"
        try:
            r = requests.get(test_url, timeout=8)
            body = r.text.lower()
            if any(sig in body for sig in error_signatures):
                print(f"{Fore.RED}  [POSSIBLE SQLi] Payload '{payload}' triggered a DB error response.{Style.RESET_ALL}")
                any_flagged = True
        except requests.RequestException:
            continue

    if not any_flagged:
        print(f"{Fore.GREEN}  No obvious SQL error signatures triggered (not a guarantee of safety).{Style.RESET_ALL}")


def main():
    print(BANNER)
    if len(sys.argv) < 2:
        target_input = input("Enter target domain/IP (only scan systems you own or have permission for): ").strip()
    else:
        target_input = sys.argv[1]

    host, url = normalize_target(target_input)
    if not host:
        print(f"{Fore.RED}Invalid target.{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}Target host: {host}{Style.RESET_ALL}")

    scan_ports(host)
    check_headers(url)
    check_ssl(host)
    check_subdomains(host)
    check_directories(url)
    check_sqli_basic(url)

    print(f"\n{Fore.CYAN}[*] Scan complete. Review results above.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    print(f"{Fore.MAGENTA}Reminder: Only scan domains/servers you own or are authorized to test.{Style.RESET_ALL}")
    main()
