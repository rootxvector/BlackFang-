🐺 BlackFang Recon

Local OSINT & Security Scanner

BlackFang Recon is a modular reconnaissance toolkit for penetration testers, red teamers, and OSINT researchers. It provides an interactive CLI to run common recon modules safely and quickly.

Developer: rootxvector
Follow: Instagram — @rootxvector

✨ Features

DNS records enumeration

WHOIS lookup

HTTP headers inspection

TLS/SSL snapshot & certificate analysis

Safe port scanning (nmap, rate-limited)

Subdomain discovery

Directory brute force (Gobuster/Dirb)

WordPress enumeration (WPScan)

Web vulnerability scanners (Nikto, Skipfish)

Maltego handoff for graph-based OSINT

⚙️ Requirements

Python: 3.8+

Python packages:

pip install requests dnspython python-whois colorama


External tools (install separately & ensure they’re in PATH):

nmap, gobuster (or dirb), wpscan, nikto, skipfish, maltego

Tip: On Debian/Ubuntu:

sudo apt update && sudo apt install -y nmap gobuster nikto
# WPScan (Ruby):
sudo gem install wpscan

🚀 Usage

Run the toolkit:

python3 blackfang.py


Menu:

╔══════════════════════════════════════════╗
║        🐺 BlackFang Recon 🐺             ║
║     Local OSINT & Security Scanner       ║
╚══════════════════════════════════════════╝

Developer: rootxvector
Follow: Instagram — @rootxvector

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

🔒 Safety & Ethics

Designed for authorized security testing and research only.

Respects reasonable rate limits to reduce noise and detection.

Logs are stored locally; review before sharing.

Legal Disclaimer: Unauthorized scanning or reconnaissance of systems without explicit written permission is illegal. The developer is not responsible for misuse.
