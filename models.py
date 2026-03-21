from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class SecurityProtocol(str, Enum):
    wpa3 = "wpa3"
    wpa2 = "wpa2"
    wpa2_tkip = "wpa2tkip"
    wpa = "wpa"
    wep = "wep"
    open = "open"


class FirmwareStatus(str, Enum):
    recent = "recent"
    old = "old"
    unknown = "unknown"


class GuestNetwork(str, Enum):
    isolated = "isolated"
    not_isolated = "yes"
    disabled = "no"


class AuditRequest(BaseModel):
    protocol: SecurityProtocol = Field(..., description="Wi-Fi security protocol in use")
    password_length: str = Field(..., description="Password length category: 20, 12, 8, or short")
    ssid_visible: str = Field(default="visible", description="SSID visibility: hidden, visible, or default")
    firewall: str = Field(default="yes", description="Firewall status: yes, no, unknown")
    remote_management: str = Field(default="no", description="Remote management: yes, no, unknown")
    guest_network: GuestNetwork = Field(default=GuestNetwork.disabled)
    firmware: FirmwareStatus = Field(default=FirmwareStatus.old)
    band: str = Field(default="24ghz", description="Band: 5ghz, 24ghz, dual")


class Finding(BaseModel):
    severity: str          # critical, warning, notice, pass
    title: str
    description: str
    recommendation: str


class DeviceInfo(BaseModel):
    ip: str
    hostname: Optional[str] = None
    open_ports: List[int] = []
    os_guess: Optional[str] = None


class AuditReport(BaseModel):
    score: int = Field(..., ge=0, le=100)
    grade: str                             # Secure, At risk, Vulnerable
    findings: List[Finding]
    devices: List[DeviceInfo] = []
    ai_fix_plan: Optional[str] = None     # populated by /audit/full
    critical_count: int
    warning_count: int
    pass_count: int
