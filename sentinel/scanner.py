import socket
import concurrent.futures
from typing import Dict, List, Tuple

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy", 27017: "MongoDB"
}

def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """Scan a single port and attempt banner grab."""
    service = COMMON_PORTS.get(port, "Unknown")
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            if res == 0:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').splitlines()[0]
                except Exception:
                    banner = service
                return port, True, banner
    except Exception:
        pass
    return port, False, ""

def scan_host(host: str, ports: List[int] = None, max_workers: int = 50) -> List[Dict]:
    """Concurrently scan a range of ports on the specified target host."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                results.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Custom"),
                    "banner": banner
                })
    return sorted(results, key=lambda x: x["port"])
