import os
import httpx
from typing import Optional
from models import AuditRequest, AuditReport, Finding, DeviceInfo


RULES = {
    "protocol": {
        "wpa3":    (0,  "pass",     "WPA3",         "WPA3 active — current gold standard.",                          "No action needed."),
        "wpa2":    (5,  "notice",   "Protocol",     "WPA2-AES is solid but aging.",                                  "Upgrade to WPA3 on supported routers."),
        "wpa2tkip":(20, "warning",  "Protocol",     "WPA2-TKIP has known weaknesses.",                               "Switch your router to AES mode immediately."),
        "wpa":     (35, "critical", "Protocol",     "WPA (original) is deprecated and crackable.",                   "Upgrade router firmware or replace the router."),
        "wep":     (60, "critical", "Protocol",     "WEP is completely broken — crackable in minutes.",              "Replace router immediately. This network is not safe."),
        "open":    (100,"critical", "Protocol",     "No encryption — all traffic is visible to nearby attackers.",   "Enable WPA2 or WPA3 immediately."),
    },
    "password": {
        "20":   (0,  "pass",    "Password",  "20+ chars — excellent, very brute-force resistant.",       "No action needed."),
        "12":   (3,  "notice",  "Password",  "12–19 chars is acceptable.",                                "Consider upgrading to 20+ random characters."),
        "8":    (12, "warning", "Password",  "8–11 chars is risky with modern hardware.",                 "Change to a 16+ character random passphrase now."),
        "short":(25, "critical","Password",  "Under 8 chars — brute-forceable within hours.",             "Change your password immediately to 16+ characters."),
    },
    "firewall": {
        "yes":    (0,  "pass",    "Firewall", "Firewall is active.",                          "No action needed."),
        "unknown":(8,  "warning", "Firewall", "Firewall status unknown.",                     "Log into your router admin panel and confirm firewall is on."),
        "no":     (15, "critical","Firewall", "Firewall disabled — devices are exposed.",     "Enable the firewall in your router settings immediately."),
    },
    "remote": {
        "no":     (0,  "pass",    "Remote management", "Remote management is off.",                                 "No action needed."),
        "unknown":(5,  "notice",  "Remote management", "Remote management status unknown.",                         "Check router settings — disable if not needed."),
        "yes":    (15, "critical","Remote management", "Anyone on the internet can access your router admin panel.", "Disable remote management unless you actively need it."),
    },
    "ssid": {
        "hidden": (0, "pass",    "SSID",  "SSID hidden.",                                                        "Note: determined attackers can still detect it passively."),
        "visible":(0, "pass",    "SSID",  "Visible SSID is normal — hiding it adds minimal security.",          "No action needed."),
        "default":(10,"warning", "SSID",  "Default SSID reveals your router model to attackers.",               "Rename your SSID to something that doesn't identify the router brand."),
    },
    "firmware": {
        "recent": (0,  "pass",    "Firmware", "Firmware is up to date.",                                  "No action needed."),
        "old":    (10, "warning", "Firmware", "1+ year without updates means unpatched CVEs.",             "Check manufacturer site for firmware updates and apply them."),
        "unknown":(15, "critical","Firmware", "Firmware never updated — likely contains known exploits.",  "Visit your router manufacturer's website and update firmware now."),
    },
    "guest": {
        "isolated":  (0, "pass",    "Guest network", "Guest network is isolated — good sandboxing.",              "No action needed."),
        "no":        (0, "pass",    "Guest network", "No guest network.",                                         "Consider adding an isolated guest network for IoT devices."),
        "yes":       (8, "warning", "Guest network", "Guest network exists but isn't isolated from main network.","Enable AP isolation / client isolation in your router settings."),
    },
    "band": {
        "5ghz":  (0, "pass",   "Band", "5 GHz has a shorter range — reduces eavesdropping radius.", "No action needed."),
        "dual":  (0, "pass",   "Band", "Dual-band setup is fine.",                                  "No action needed."),
        "24ghz": (2, "notice", "Band", "2.4 GHz has longer range — slightly wider attack surface.", "Use 5 GHz for sensitive devices where possible."),
    },
}


class AuditAnalyzer:

    def rule_based_audit(self, req: AuditRequest) -> AuditReport:
        score = 100
        findings = []

        checks = [
            ("protocol", req.protocol.value),
            ("password", req.password_length),
            ("firewall", req.firewall),
            ("remote",   req.remote_management),
            ("ssid",     req.ssid_visible),
            ("firmware", req.firmware.value),
            ("guest",    req.guest_network.value),
            ("band",     req.band),
        ]

        for key, val in checks:
            rule = RULES[key].get(val)
            if not rule:
                continue
            deduction, severity, title, desc, rec = rule
            score -= deduction
            findings.append(Finding(
                severity=severity,
                title=title,
                description=desc,
                recommendation=rec
            ))

        score = max(0, min(100, score))
        grade = "Secure" if score >= 80 else ("At risk" if score >= 55 else "Vulnerable")

        sev_order = ["critical", "warning", "notice", "pass"]
        findings.sort(key=lambda f: sev_order.index(f.severity))

        return AuditReport(
            score=score,
            grade=grade,
            findings=findings,
            critical_count=sum(1 for f in findings if f.severity == "critical"),
            warning_count=sum(1 for f in findings if f.severity == "warning"),
            pass_count=sum(1 for f in findings if f.severity == "pass"),
        )

    def scan_based_audit(self, scan_data: dict) -> AuditReport:
        """Convert live nmap scan data into an AuditReport."""
        findings = []
        score = 100

        devices: list[DeviceInfo] = scan_data.get("devices", [])
        risky_ports: list = scan_data.get("risky_ports", [])

        if len(devices) > 20:
            score -= 5
            findings.append(Finding(
                severity="warning",
                title="Many connected devices",
                description=f"{len(devices)} devices found on network. Large device counts increase attack surface.",
                recommendation="Audit all devices. Remove unknown or unused devices."
            ))

        for rp in risky_ports:
            score -= 10
            findings.append(Finding(
                severity="critical",
                title=f"Risky port open: {rp['port']}",
                description=f"{rp['ip']} has port {rp['port']} open ({rp['service']}).",
                recommendation=f"Disable {rp['service']} if not needed, or restrict access via firewall rules."
            ))

        score = max(0, min(100, score))
        grade = "Secure" if score >= 80 else ("At risk" if score >= 55 else "Vulnerable")

        return AuditReport(
            score=score,
            grade=grade,
            findings=findings,
            devices=devices,
            critical_count=sum(1 for f in findings if f.severity == "critical"),
            warning_count=sum(1 for f in findings if f.severity == "warning"),
            pass_count=sum(1 for f in findings if f.severity == "pass"),
        )

    async def ai_enhanced_audit(
        self,
        rule_report: AuditReport,
        scan_data: Optional[dict] = None
    ) -> AuditReport:
        """
        Call Claude API to generate a personalized fix plan
        based on the rule-based findings + optional live scan data.
        """
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            rule_report.ai_fix_plan = "Set ANTHROPIC_API_KEY env var to enable AI fix plans."
            return rule_report

        critical = [f for f in rule_report.findings if f.severity == "critical"]
        warnings = [f for f in rule_report.findings if f.severity == "warning"]

        prompt = f"""You are a network security expert. A user ran a Wi-Fi security audit and got these results:

Score: {rule_report.score}/100 ({rule_report.grade})
Critical issues: {rule_report.critical_count}
Warnings: {rule_report.warning_count}

Critical findings:
{chr(10).join(f'- {f.title}: {f.description}' for f in critical)}

Warnings:
{chr(10).join(f'- {f.title}: {f.description}' for f in warnings)}
"""

        if scan_data:
            prompt += f"\nLive scan found {scan_data.get('device_count', 0)} devices on the network."
            if scan_data.get("risky_ports"):
                prompt += f"\nRisky open ports detected: {scan_data['risky_ports']}"

        prompt += """

Write a clear, prioritized 5-step fix plan in plain English. 
Number each step. Be specific and actionable. 
Start with the most critical issue. Keep it under 300 words."""

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 500,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=30.0
            )
            resp.raise_for_status()
            data = resp.json()
            rule_report.ai_fix_plan = data["content"][0]["text"]

        return rule_report
