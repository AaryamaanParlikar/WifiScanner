import subprocess
import shutil
import json
from typing import Optional
from models import DeviceInfo


class NetworkScanner:
    """
    Wraps nmap for real network scanning.
    Install nmap: sudo apt install nmap (Linux) / brew install nmap (Mac)
    """

    def nmap_available(self) -> bool:
        return shutil.which("nmap") is not None

    def scan_network(self, target: str = "192.168.1.0/24") -> dict:
        """
        Run a fast nmap scan on the target subnet.
        Returns parsed scan data: devices, open ports, OS guesses.

        Flags used:
          -sV   version detection
          -O    OS detection (requires root)
          -T4   faster timing
          --open  only show open ports
          -oJ - output JSON to stdout
        """
        cmd = [
            "nmap", "-sV", "-T4", "--open",
            "-oX", "-",   # XML output to stdout
            target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                raise RuntimeError(f"nmap error: {result.stderr}")

            return self._parse_nmap_xml(result.stdout)

        except subprocess.TimeoutExpired:
            raise RuntimeError("Network scan timed out after 120s")

    def _parse_nmap_xml(self, xml_output: str) -> dict:
        """Parse nmap XML output into structured device list."""
        import xml.etree.ElementTree as ET

        devices = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                # Only include hosts that are up
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue

                ip = None
                hostname = None
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip = addr.get("addr")

                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name")

                open_ports = []
                ports_el = host.find("ports")
                if ports_el is not None:
                    for port in ports_el.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            open_ports.append(int(port.get("portid", 0)))

                os_guess = None
                os_el = host.find("os")
                if os_el is not None:
                    osmatch = os_el.find("osmatch")
                    if osmatch is not None:
                        os_guess = osmatch.get("name")

                if ip:
                    devices.append(DeviceInfo(
                        ip=ip,
                        hostname=hostname,
                        open_ports=open_ports,
                        os_guess=os_guess
                    ))

        except ET.ParseError as e:
            raise RuntimeError(f"Failed to parse nmap output: {e}")

        return {
            "devices": devices,
            "device_count": len(devices),
            "risky_ports": self._find_risky_ports(devices),
        }

    def _find_risky_ports(self, devices: list) -> list:
        """Flag known risky open ports across all devices."""
        RISKY = {
            23: "Telnet (unencrypted)",
            21: "FTP (unencrypted)",
            80: "HTTP (unencrypted web)",
            8080: "HTTP alt (unencrypted)",
            3389: "RDP (remote desktop)",
            22: "SSH (exposed — check if intentional)",
            445: "SMB (Windows file sharing)",
            5900: "VNC (remote desktop)",
        }

        found = []
        for device in devices:
            for port in device.open_ports:
                if port in RISKY:
                    found.append({
                        "ip": device.ip,
                        "port": port,
                        "service": RISKY[port]
                    })
        return found
