from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import os   
NMAP = os.environ.get("NMAP_PATH", "nmap")

app = FastAPI(title="Wi-Fi Security Auditor API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://wifi-scanner-pearl.vercel.app", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ManualAuditRequest(BaseModel):
    protocol: str
    band: str
    password_length: str
    ssid_visibility: str
    firewall: str
    remote_management: str
    guest_network: str
    firmware: str

class ScanRequest(BaseModel):
    target: Optional[str] = None

class Finding(BaseModel):
    severity: str
    title: str
    description: str
    recommendation: str

class AuditResult(BaseModel):
    score: int
    grade: str
    findings: List[Finding]
    device_count: Optional[int] = None
    open_ports: Optional[List[Dict[str, Any]]] = None
    scan_performed: bool = False

CHECKS: Dict[str, Dict[str, tuple]] = {
    "protocol": {
        "wpa3":     (0,  "pass",     "WPA3 encryption",         "Current gold standard.",                        "No action needed."),
        "wpa2":     (5,  "notice",   "WPA2-AES encryption",     "Solid but aging; WPA3 preferred.",              "Upgrade firmware or hardware to enable WPA3."),
        "wpa2tkip": (20, "warning",  "WPA2-TKIP encryption",    "TKIP is deprecated with known weaknesses.",     "Switch to WPA2-AES or WPA3 in router settings."),
        "wpa":      (35, "critical", "WPA (original)",          "Crackable with modern tools.",                  "Upgrade to WPA2-AES or WPA3 immediately."),
        "wep":      (60, "critical", "WEP encryption",          "Completely broken — crackable in under 2 min.", "Replace router or upgrade firmware."),
        "open":     (80, "critical", "Open network",            "No encryption — all traffic visible nearby.",   "Enable WPA3 or WPA2-AES with a strong password now."),
    },
    "password_length": {
        "20+":   (0,  "pass",     "Strong password",   "20+ chars — highly brute-force resistant.", "No action needed."),
        "12-19": (3,  "notice",   "Adequate password", "Acceptable but 20+ is ideal.",              "Increase to 20+ random characters."),
        "8-11":  (12, "warning",  "Short password",    "Crackable in hours via GPU attacks.",       "Use 12+ chars minimum; prefer 20+."),
        "<8":    (25, "critical", "Weak password",     "Brute-forceable in minutes.",               "Change immediately to 20+ random characters."),
    },
    "firewall": {
        "yes":     (0,  "pass",     "Firewall enabled",        "Blocking unsolicited inbound connections.",    "No action needed."),
        "no":      (15, "critical", "Firewall disabled",       "Devices directly exposed to inbound traffic.", "Enable firewall in router admin panel immediately."),
        "unknown": (8,  "warning",  "Firewall status unknown", "Cannot verify protection.",                    "Log into router admin panel and confirm firewall is on."),
    },
    "remote_management": {
        "no":      (0,  "pass",     "Remote management off",     "Router admin not exposed to internet.",  "No action needed."),
        "yes":     (15, "critical", "Remote management on",      "Internet-accessible router login.",      "Disable remote management unless strictly required."),
        "unknown": (5,  "warning",  "Remote management unknown", "Common attack vector if enabled.",       "Check router settings and disable remote management."),
    },
    "firmware": {
        "recent":  (0,  "pass",     "Firmware up to date",    "Recent patches protect against known CVEs.", "No action needed."),
        "old":     (10, "warning",  "Firmware outdated",      "1+ year without updates = unpatched CVEs.",  "Apply latest firmware from manufacturer site."),
        "unknown": (15, "critical", "Firmware never updated", "Unpatched routers are a primary target.",    "Update firmware via router admin panel immediately."),
    },
    "guest_network": {
        "isolated": (0, "pass",    "Guest network isolated",     "Guest devices sandboxed from main network.", "No action needed."),
        "no":       (0, "pass",    "No guest network",           "Consider isolated guest for IoT/visitors.",  "Enable isolated guest network for untrusted devices."),
        "yes":      (8, "warning", "Guest network not isolated", "Guests can reach main network devices.",     "Enable AP isolation in guest network settings."),
    },
    "ssid_visibility": {
        "hidden":  (0,  "pass",    "SSID hidden",  "Not broadcast — discoverable only by passive scan.", "No action needed."),
        "visible": (0,  "pass",    "SSID visible", "Normal broadcast; hiding adds minimal security.",    "No action needed."),
        "default": (10, "warning", "Default SSID", "Router model exposed in network name.",              "Change SSID to hide router brand/model."),
    },
    "band": {
        "5ghz":  (0, "pass",   "5 GHz band",   "Shorter range reduces eavesdropping radius.", "No action needed."),
        "dual":  (0, "pass",   "Dual band",    "Good flexibility with two bands.",            "Confirm both bands use the same protocol and password."),
        "24ghz": (2, "notice", "2.4 GHz only", "Longer range increases signal exposure area.","Consider dual-band router for better containment."),
    },
}

SEV_ORDER = ["critical", "warning", "notice", "pass"]


def score_audit(req: ManualAuditRequest) -> AuditResult:
    fields = {
        "protocol": req.protocol, "password_length": req.password_length,
        "firewall": req.firewall, "remote_management": req.remote_management,
        "firmware": req.firmware, "guest_network": req.guest_network,
        "ssid_visibility": req.ssid_visibility, "band": req.band,
    }
    findings = []
    deduction = 0
    for field, value in fields.items():
        table = CHECKS[field]
        pts, sev, title, desc, rec = table.get(value, list(table.values())[0])
        deduction += pts
        findings.append(Finding(severity=sev, title=title, description=desc, recommendation=rec))
    score = max(0, min(100, 100 - deduction))
    grade = "Secure" if score >= 80 else "At risk" if score >= 55 else "Vulnerable"
    findings.sort(key=lambda f: SEV_ORDER.index(f.severity))
    return AuditResult(score=score, grade=grade, findings=findings, scan_performed=False)


def get_local_subnet() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        base = int(parts[3]) & 0xF0
        return f"{parts[0]}.{parts[1]}.{parts[2]}.{base}/28"
    except Exception:
        return "192.168.1.0/28"


PORT_RISK: Dict[int, str] = {
    23: "critical", 8080: "warning", 8888: "warning",
    80: "notice", 443: "pass", 22: "notice", 8443: "notice",
}


def _do_scan(target: str):
    r1 = subprocess.run(
        [NMAP, "-sn", "-T4", target],
        capture_output=True, text=True, timeout=120
    )
    gateway = target.split("/")[0].rsplit(".", 1)[0] + ".1"
    r2 = subprocess.run(
        [NMAP, "-p", "22,23,80,443,8080,8443,8888", "-T4", gateway],
        capture_output=True, text=True, timeout=60
    )
    return r1.stdout, r2.stdout


async def run_nmap(target: str) -> dict:
    try:
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            out1, out2 = await loop.run_in_executor(pool, _do_scan, target)

        hosts = re.findall(r"Nmap scan report for (.+)", out1)
        open_ports = []
        for line in out2.splitlines():
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if m:
                port, svc = int(m.group(1)), m.group(2)
                open_ports.append({"port": port, "service": svc, "risk": PORT_RISK.get(port, "notice")})

        return {"hosts": hosts, "device_count": len(hosts), "open_ports": open_ports}

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Scan timed out.")
    except FileNotFoundError:
        raise HTTPException(status_code=501, detail=f"nmap not found at {NMAP}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan error: {type(e).__name__}: {e}")


@app.get("/")
def root():
    return {"status": "ok", "service": "Wi-Fi Security Auditor API v1.0"}

@app.post("/audit/manual", response_model=AuditResult)
def manual_audit(req: ManualAuditRequest):
    return score_audit(req)

@app.post("/audit/scan", response_model=AuditResult)
async def scan_audit(req: ScanRequest):
    target = req.target or get_local_subnet()
    data = await run_nmap(target)
    findings = []

    for p in data["open_ports"]:
        if p["risk"] == "critical":
            findings.append(Finding(
                severity="critical",
                title=f"Port {p['port']} ({p['service']}) open",
                description=f"Port {p['port']} on your gateway is a major security risk.",
                recommendation=f"Close port {p['port']} in router firewall settings immediately.",
            ))
        elif p["risk"] == "warning":
            findings.append(Finding(
                severity="warning",
                title=f"Port {p['port']} ({p['service']}) open",
                description=f"Port {p['port']} may expose router admin panel.",
                recommendation=f"Disable remote access on port {p['port']} unless required.",
            ))
        else:
            findings.append(Finding(
                severity="pass",
                title=f"Port {p['port']} ({p['service']}) checked",
                description=f"Port {p['port']} is open but low risk.",
                recommendation="No action needed.",
            ))

    dc = data["device_count"]
    if dc > 20:
        findings.append(Finding(severity="warning", title=f"{dc} devices on network",
            description="High device count increases attack surface.",
            recommendation="Audit connected devices and remove any unrecognized ones."))
    elif dc > 0:
        findings.append(Finding(severity="pass", title=f"{dc} devices on network",
            description="Device count looks normal.",
            recommendation="Periodically review devices in your router admin panel."))
    else:
        findings.append(Finding(severity="notice", title="No devices detected",
            description="Scan completed but no hosts found.",
            recommendation="Try specifying your subnet manually e.g. 10.27.175.29/28"))

    findings.sort(key=lambda f: SEV_ORDER.index(f.severity))
    criticals = sum(1 for f in findings if f.severity == "critical")
    warnings  = sum(1 for f in findings if f.severity == "warning")
    score = max(0, 100 - criticals * 20 - warnings * 10)
    grade = "Secure" if score >= 80 else "At risk" if score >= 55 else "Vulnerable"

    return AuditResult(score=score, grade=grade, findings=findings,
                       device_count=dc, open_ports=data["open_ports"], scan_performed=True)

@app.get("/subnet/detect")
def detect_subnet():
    return {"subnet": get_local_subnet()}
