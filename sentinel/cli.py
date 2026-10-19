import argparse
import json
import sys
from sentinel.scanner import scan_host
from sentinel.auditor import audit_url
from sentinel.crypto import evaluate_password, identify_hash

BANNER = """
   ______      __               _____             _____            __  _            __
  / ____/_  __/ /_  ___  _____ / ___/___  _____  / ___/___  ____  / /_(_)___  ___  / /
 / /   / / / / __ \/ _ \/ ___/ \__ \/ _ \/ ___/  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
/ /___/ /_/ / /_/ /  __/ /    ___/ /  __/ /__   ___/ /  __/ / / / /_/ / / / /  __/ /  
\____/\__, /_.___/\___/_/    /____/\___/\___/  /____/\___/_/ /_/\__/_/_/ /_/\___/_/   
     /____/                                         by Sergio Andrés Ipuz Saavedra
"""

def main():
    parser = argparse.ArgumentParser(description="CyberSec Sentinel - Security Analysis Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # Port scanner
    p_scan = subparsers.add_parser("scan", help="Scan host ports")
    p_scan.add_argument("host", help="Target IP or hostname")
    p_scan.add_argument("-p", "--ports", help="Comma-separated ports (e.g. 80,443,22)", default="")

    # Web headers auditor
    p_audit = subparsers.add_parser("audit", help="Audit HTTP security headers")
    p_audit.add_argument("url", help="Target URL (e.g. example.com)")

    # Password / Hash
    p_crypto = subparsers.add_parser("crypto", help="Analyze password entropy or identify hash")
    p_crypto.add_argument("--password", "-p", help="Evaluate password strength")
    p_crypto.add_argument("--hash", help="Identify hash algorithm")

    args = parser.parse_args()

    print(BANNER)
    if args.command == "scan":
        ports = [int(p) for p in args.ports.split(",") if p.isdigit()] if args.ports else None
        print(f"[*] Scanning host {args.host}...")
        results = scan_host(args.host, ports=ports)
        print(f"[+] Found {len(results)} open port(s):")
        for r in results:
            print(f"    - Port {r['port']} ({r['service']}): {r['banner']}")

    elif args.command == "audit":
        print(f"[*] Auditing headers for {args.url}...")
        res = audit_url(args.url)
        print(f"[+] Security Grade: {res.get('grade')}")
        print(f"[+] Present Headers ({len(res.get('present_headers', {}))}):")
        for k, v in res.get("present_headers", {}).items():
            print(f"    ✔️ {k}: {v[:50]}...")
        print(f"[-] Missing Headers ({len(res.get('missing_headers', {}))}):")
        for k in res.get("missing_headers", {}).keys():
            print(f"    ❌ {k}")
        if res.get("leaked_headers"):
            print(f"[!] Information Leakage ({len(res.get('leaked_headers', {}))}):")
            for k, v in res.get("leaked_headers", {}).items():
                print(f"    ⚠️ {k}: {v}")

    elif args.command == "crypto":
        if args.password:
            res = evaluate_password(args.password)
            print(f"[*] Password Analysis:")
            print(f"    - Length: {res['length']}")
            print(f"    - Entropy: {res['entropy_bits']} bits")
            print(f"    - Strength Rating: {res['strength']}")
        elif args.hash:
            algo = identify_hash(args.hash)
            print(f"[*] Hash: {args.hash}")
            print(f"[+] Detected Algorithm: {algo}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
