import urllib.request
import urllib.parse
from typing import Dict, Any

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against man-in-the-middle attacks and cookie hijacking.",
    "Content-Security-Policy": "Mitigates Cross-Site Scripting (XSS) and data injection vulnerabilities.",
    "X-Frame-Options": "Prevents clickjacking attacks by forbidding iframe rendering.",
    "X-Content-Type-Options": "Stops MIME-type sniffing by enforcing declared content types.",
    "Referrer-Policy": "Governs how much referrer information is sent with requests.",
    "Permissions-Policy": "Restricts browser features and hardware APIs like camera/microphone."
}

def audit_url(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Audits HTTP headers of target URL for security compliance and leakage."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    report = {
        "url": url,
        "present_headers": {},
        "missing_headers": {},
        "leaked_headers": {},
        "grade": "F"
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberSec-Sentinel/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            
            # Check security headers
            for h, desc in SECURITY_HEADERS.items():
                match = next((v for k, v in headers.items() if k.lower() == h.lower()), None)
                if match:
                    report["present_headers"][h] = match
                else:
                    report["missing_headers"][h] = desc

            # Check server leakage
            for leak in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                match = next((v for k, v in headers.items() if k.lower() == leak.lower()), None)
                if match:
                    report["leaked_headers"][leak] = match

            score = len(report["present_headers"]) / len(SECURITY_HEADERS) * 100
            if score >= 90: report["grade"] = "A+"
            elif score >= 75: report["grade"] = "A"
            elif score >= 60: report["grade"] = "B"
            elif score >= 40: report["grade"] = "C"
            else: report["grade"] = "D"

    except Exception as e:
        report["error"] = str(e)

    return report
