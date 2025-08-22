#!/usr/bin/env python3
import os
import sys
import json
import socket
import ssl
import whois
import dns.resolver
import subprocess
import shutil
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init as colorama_init
from datetime import datetime
from functools import wraps
import re

# ===============================
# Init
# ===============================
colorama_init(autoreset=True)
LOG_FILE = "./bf_reports/activity.log"
MAX_THREADS = 10  # Limit threads for performance

# ===============================
# Helpers
# ===============================
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
╔══════════════════════════════════════════╗
║        🐺 BlackFang Recon 🐺             ║
║     Local OSINT & Security Scanner       ║
╚══════════════════════════════════════════╝
""" + Style.RESET_ALL)
    print(Fore.GREEN + "Author: Security Toolkit" + Style.RESET_ALL)
    print(Fore.YELLOW + f"Run Time: {timestamp()}" + Style.RESET_ALL)

def log_session_start():
    os.makedirs("./bf_reports", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n" + "="*40 + "\n")
        f.write(f"=== New Session: {timestamp()} ===\n")
        f.write("="*40 + "\n")

def log_activity(action: str, target: str = None, extra: str = None):
    os.makedirs("./bf_reports", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp()}] ACTION: {action}")
        if target:
            f.write(f" | Target: {target}")
        if extra:
            f.write(f" | Info: {extra}")
        f.write("\n")

def sanitize_target_for_path(target: str) -> str:
    return re.sub(r"[\/:\\\*\?\"<>\|]", "_", target)

def save_report(target: str, name: str, data):
    outdir = f"./bf_reports/{sanitize_target_for_path(target)}/"
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{name}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"=== Report: {name.upper()} ===\n")
            f.write(f"Generated at: {timestamp()}\n")
            f.write(f"Target: {target}\n")
            f.write("="*60 + "\n\n")
            if isinstance(data, str):
                f.write(data)
            else:
                f.write(json.dumps(data, indent=2, default=str))
        print(Fore.GREEN + f"[SAVED] Report: {path}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to save report {path}: {e}" + Style.RESET_ALL)

# ===============================
# Decorator
# ===============================
def log_run(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        target = args[0] if args else None
        print(Fore.MAGENTA + f"\n[+] Running {func.__name__} on {target} at {timestamp()}" + Style.RESET_ALL)
        log_activity(func.__name__, target)
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(Fore.RED + f"[!] Error in {func.__name__}: {e}" + Style.RESET_ALL)
            log_activity(f"{func.__name__}_error", target, extra=str(e))
            return None
    return wrapper

# ===============================
# Recon Functions (Local Only)
# ===============================
@log_run
def dns_lookup(domain: str):
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception as e:
            records[rtype] = f"Error: {e}"
    save_report(domain, "dns_lookup", records)
    return records

@log_run
def whois_lookup(domain: str):
    try:
        domain_info = whois.whois(domain)
        save_report(domain, "whois_lookup", str(domain_info))
        return domain_info
    except Exception as e:
        print(Fore.RED + f"[!] WHOIS lookup failed: {e}" + Style.RESET_ALL)
        return None

@log_run
def http_headers(domain: str):
    import requests
    try:
        response = requests.get(f"http://{domain}", timeout=10)
        result = {"headers": dict(response.headers), "status_code": response.status_code}
        save_report(domain, "http_headers", result)
        return result
    except Exception as e:
        print(Fore.RED + f"[!] HTTP headers fetch failed: {e}" + Style.RESET_ALL)
        return None

@log_run
def tls_snapshot(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                save_report(domain, "tls_snapshot", cert)
                return cert
    except Exception as e:
        print(Fore.RED + f"[!] TLS snapshot failed: {e}" + Style.RESET_ALL)
        return None

@log_run
def safe_port_scan(domain: str):
    common_ports = [21,22,25,53,80,110,143,443,3306,3389]
    open_ports = []
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((domain, port)) == 0:
                    open_ports.append(port)
        except:
            pass
    save_report(domain, "port_scan", {"open_ports": open_ports})
    return open_ports

def check_subdomain(subdomain: str) -> bool:
    try:
        socket.gethostbyname(subdomain)
        return True
    except:
        return False

@log_run
def subdomain_finder(domain: str, wordlist: str = None):
    if not wordlist:
        wordlist = "/usr/share/wordlists/subdomains-top1million-5000.txt"
    try:
        with open(wordlist, "r") as f:
            subdomains = [f"{line.strip()}.{domain}" for line in f]
    except Exception as e:
        print(Fore.RED + f"[!] Wordlist read failed: {e}" + Style.RESET_ALL)
        return None

    found = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            if future.result():
                found.append(futures[future])

    save_report(domain, "subdomain_finder", {"found": found})
    return found

@log_run
def dir_bruteforce(domain: str, wordlist: str = None):
    import requests
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    try:
        with open(wordlist, "r") as f:
            paths = [line.strip() for line in f]
    except Exception as e:
        print(Fore.RED + f"[!] Wordlist read failed: {e}" + Style.RESET_ALL)
        return None

    found = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(lambda p: requests.get(f"http://{domain}/{p}", timeout=5).status_code==200, path): path for path in paths}
        for future in as_completed(futures):
            if future.result():
                found.append(futures[future])

    save_report(domain, "dir_bruteforce", {"found": found})
    return found

@log_run
def ssl_cert_analysis(domain: str):
    try:
        if shutil.which("openssl") is None:
            raise RuntimeError("openssl not installed")
        command = ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain]
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, _ = proc.communicate(input="\n")
        save_report(domain, "ssl_cert_analysis", output)
        return output
    except Exception as e:
        print(Fore.RED + f"[!] SSL analysis failed: {e}" + Style.RESET_ALL)
        return None

# ===============================
# External Tool Runner
# ===============================
def run_external_tool(name: str, command, report_file: str = None):
    if shutil.which(command[0]) is None:
        print(Fore.RED + f"[!] {name} not installed" + Style.RESET_ALL)
        return
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output, _ = proc.communicate()
    if report_file:
        with open(report_file, "w") as f:
            f.write(output)
    print(output)

# ===============================
# Menu
# ===============================
def menu():
    log_session_start()
    while True:
        clear_screen()
        banner()
        print("""
[1] DNS Records
[2] WHOIS Lookup
[3] HTTP Headers
[4] TLS Snapshot
[5] Safe Port Scan
[6] Subdomain Finder
[7] Directory Bruteforce
[8] SSL Certificate Analysis
[9] WPScan
[10] Nikto
[11] Skipfish
[12] Maltego
[0] Exit
""")
        choice = input(Fore.YELLOW + "Select option: " + Style.RESET_ALL).strip()
        if choice == "0": break
        domain = input("Enter target domain: ").strip()
        if choice == "1": dns_lookup(domain)
        elif choice == "2": whois_lookup(domain)
        elif choice == "3": http_headers(domain)
        elif choice == "4": tls_snapshot(domain)
        elif choice == "5": safe_port_scan(domain)
        elif choice == "6": subdomain_finder(domain)
        elif choice == "7": dir_bruteforce(domain)
        elif choice == "8": ssl_cert_analysis(domain)
        elif choice == "9": run_external_tool("WPScan", ["wpscan", "--url", domain])
        elif choice == "10": run_external_tool("Nikto", ["nikto", "-h", domain])
        elif choice == "11": run_external_tool("Skipfish", ["skipfish", "-o", f"./bf_reports/{sanitize_target_for_path(domain)}/skipfish", domain])
        elif choice == "12": run_external_tool("Maltego", ["maltego"])
        input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
