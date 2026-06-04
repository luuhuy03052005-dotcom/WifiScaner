"""
LAN Watcher Pro - aggressive realtime LAN inventory.

Install:
    pip install scapy requests beautifulsoup4 zeroconf

Windows:
    - Install Npcap: https://npcap.com/
    - Tick "WinPcap API-compatible Mode".
    - Run terminal as Administrator.

Scope:
    Local/authorized LAN inventory only. No MITM, no deauth, no brute-force,
    no exploit. Detection is client-side best effort if you do not have
    router/AP/controller access.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import queue
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import textwrap
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    from .vendor import UNKNOWN_VENDOR, ensure_oui_db, lookup_vendor_local
except ImportError:  # Allow direct execution during local debugging.
    from vendor import UNKNOWN_VENDOR, ensure_oui_db, lookup_vendor_local  # type: ignore

try:
    import requests
    import urllib3
    from bs4 import BeautifulSoup
    from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Raw, Ether, conf, get_if_addr, get_working_if, sniff, srp  # type: ignore
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf  # type: ignore
except ImportError as exc:
    print("[-] Missing Python dependency:", exc)
    print("[+] Install:")
    print("    pip install scapy requests beautifulsoup4 zeroconf")
    print("[!] Windows also needs Npcap with WinPcap API-compatible Mode.")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================
# CONFIG
# =========================
SCHEMA_VERSION = 2

OBSERVATION_QUEUE_MAX = 2000
FAST_QUEUE_MAX = 1000
SLOW_QUEUE_MAX = 500
TRAFFIC_FLUSH_INTERVAL = 0.5

DEFAULT_PROFILE = "aggressive"
DEFAULT_OFFLINE_AFTER = 10.0
DEFAULT_OFFLINE_FAIL_THRESHOLD = 3
DEFAULT_UI_INTERVAL = 0.5
DEFAULT_SWEEP_INTERVAL = 2.0
DEFAULT_TCP_WORKERS = 64
DEFAULT_SLOW_WORKERS = 12
DEFAULT_STATE_FILE = "lan_watcher_state.json"
DEFAULT_STATE_DIR = "state"
DEFAULT_ALIAS_FILE = "device_aliases.json"
DEFAULT_TRAFFIC_WINDOW = 5.0
DEFAULT_CACHE_DIR = "cache"
DEFAULT_OUI_DB = os.path.join(DEFAULT_CACHE_DIR, "oui.csv")

FAST_TTL = 60.0
SLOW_TTL = 600.0
STATE_SAVE_INTERVAL = 10.0
SHUTDOWN_DRAIN_SECONDS = 2.0

ARP_SWEEP_TIMEOUT = 0.55
TCP_CONNECT_TIMEOUT = 0.22
HTTP_TIMEOUT = 0.8
NETBIOS_TIMEOUT = 0.45
DNS_TIMEOUT = 0.6
TLS_TIMEOUT = 0.8

FAST_WORKER_COUNT = 4
VENDOR_WORKERS = 8

GENERIC_NIC_VENDORS = [
    "azurewave",
    "intel",
    "realtek",
    "qualcomm",
    "atheros",
    "broadcom",
    "mediatek",
    "liteon",
    "hon hai",
    "foxconn",
]

TCP_LIVENESS_PORTS = [80, 443, 445, 139, 22, 23, 554, 8008, 8009, 8080, 8443, 9100]
COMMON_TCP_PORTS = [21, 22, 23, 53, 80, 81, 139, 443, 445, 554, 631, 8000, 8008, 8009, 8080, 8443, 8888, 9000, 9100]
HTTP_PORTS = [80, 81, 443, 8000, 8008, 8080, 8443, 8888, 9000]
TLS_PORTS = [443, 8443]

MDNS_TYPES = [
    "_workstation._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_ipp._tcp.local.",
    "_hap._tcp.local.",
]

LIVE_KINDS = {
    "arp",
    "dhcp",
    "mdns",
    "ssdp",
    "llmnr",
    "nbns",
    "netbios",
    "dns",
    "icmp",
    "tcp",
    "http",
    "tls",
}

CRITICAL_KINDS = {"arp", "dhcp"}
NAME_SCORES = {
    "dhcp": 100,
    "mdns": 95,
    "netbios": 80,
    "dns": 65,
    "llmnr": 55,
    "nbns": 55,
    "http": 40,
    "ssdp": 35,
}


# =========================
# GLOBAL RUNTIME
# =========================
STOP_EVENT = threading.Event()

OBSERVATION_QUEUE: "queue.Queue[Observation]" = queue.Queue(maxsize=OBSERVATION_QUEUE_MAX)
FAST_QUEUE: "queue.Queue[FingerprintJob]" = queue.Queue(maxsize=FAST_QUEUE_MAX)
SLOW_QUEUE: "queue.Queue[FingerprintJob]" = queue.Queue(maxsize=SLOW_QUEUE_MAX)

DROP_LOCK = threading.Lock()
DROPPED_BY_KIND: Counter[str] = Counter()
DROPPED_TOTAL = 0

SNAPSHOT_LOCK = threading.Lock()
CURRENT_SNAPSHOT: Optional["StateSnapshot"] = None

TRAFFIC_LOCK = threading.Lock()
TRAFFIC_PENDING: Dict[Tuple[str, str], Tuple[int, int, float]] = {}

VENDOR_CACHE: Dict[str, str] = {}
VENDOR_LOCK = threading.Lock()
VENDOR_SEM = threading.BoundedSemaphore(VENDOR_WORKERS)
OUI_DB_PATH = DEFAULT_OUI_DB
ENABLE_OUI_DOWNLOAD = True

ENABLE_TCP_PROBE = True
ENABLE_VENDOR_API = True
ENABLE_MDNS = True
ENABLE_SSDP = True


# =========================
# DATA MODEL
# =========================
@dataclass(frozen=True)
class Observation:
    kind: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    name: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    packet_bytes: int = 0
    packet_count: int = 1
    value: Optional[str] = None
    source: Optional[str] = None
    confidence: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class FingerprintJob:
    mac: str
    ip: str
    reason: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class NameCandidate:
    value: str
    source: str
    score: int
    last_seen: float

    def to_json(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: Dict[str, object]) -> "NameCandidate":
        return cls(
            value=str(data["value"]),
            source=str(data["source"]),
            score=int(data["score"]),
            last_seen=float(data["last_seen"]),
        )


@dataclass
class DeviceRecord:
    device_id: str
    mac: str
    ips: Dict[str, float] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    online: bool = False
    sources: Set[str] = field(default_factory=set)
    vendor: Optional[str] = None
    names: List[NameCandidate] = field(default_factory=list)
    services: Set[str] = field(default_factory=set)
    http_titles: Dict[str, str] = field(default_factory=dict)
    tls_names: Dict[str, str] = field(default_factory=dict)
    device_type: Optional[str] = None
    confidence: int = 0
    evidence: List[str] = field(default_factory=list)
    offline_fail_count: int = 0
    last_probe_at: float = 0.0
    returning_count: int = 0
    last_fast_scan: float = 0.0
    last_slow_scan: float = 0.0
    rx_bytes_total: int = 0
    tx_bytes_total: int = 0
    rx_packets_total: int = 0
    tx_packets_total: int = 0
    last_traffic_at: float = 0.0
    traffic_samples: Deque[Tuple[float, int, int, int, int]] = field(default_factory=lambda: deque(maxlen=600))

    def current_ip(self) -> Optional[str]:
        if not self.ips:
            return None
        return max(self.ips.items(), key=lambda item: item[1])[0]

    def best_name(self) -> Optional[str]:
        if not self.names:
            return None
        best = max(self.names, key=lambda item: (item.score, item.last_seen))
        return best.value

    def service_text(self) -> str:
        return summarize_services(self.services)

    def source_text(self) -> str:
        return ",".join(sorted(self.sources)[:6])

    def to_json(self) -> Dict[str, object]:
        return {
            "device_id": self.device_id,
            "mac": self.mac,
            "ips": self.ips,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "online": False,
            "sources": sorted(self.sources),
            "vendor": self.vendor,
            "names": [name.to_json() for name in self.names],
            "services": sorted(self.services),
            "http_titles": self.http_titles,
            "tls_names": self.tls_names,
            "device_type": self.device_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "offline_fail_count": self.offline_fail_count,
            "last_probe_at": self.last_probe_at,
            "returning_count": self.returning_count,
            "last_fast_scan": self.last_fast_scan,
            "last_slow_scan": self.last_slow_scan,
            "rx_bytes_total": self.rx_bytes_total,
            "tx_bytes_total": self.tx_bytes_total,
            "rx_packets_total": self.rx_packets_total,
            "tx_packets_total": self.tx_packets_total,
            "last_traffic_at": self.last_traffic_at,
        }

    @classmethod
    def from_json(cls, data: Dict[str, object]) -> "DeviceRecord":
        required = ("device_id", "mac", "ips", "first_seen", "last_seen", "sources")
        for field_name in required:
            if field_name not in data:
                raise ValueError(f"state device missing {field_name}")
        record = cls(
            device_id=str(data["device_id"]),
            mac=normalize_mac(str(data["mac"])),
            ips={str(k): float(v) for k, v in dict(data.get("ips", {})).items()},
            first_seen=float(data["first_seen"]),
            last_seen=float(data["last_seen"]),
            online=False,
            sources=set(str(v) for v in list(data.get("sources", []))),
            vendor=optional_str(data.get("vendor")),
            names=[NameCandidate.from_json(item) for item in list(data.get("names", []))],
            services=set(str(v) for v in list(data.get("services", []))),
            http_titles={str(k): str(v) for k, v in dict(data.get("http_titles", {})).items()},
            tls_names={str(k): str(v) for k, v in dict(data.get("tls_names", {})).items()},
            device_type=optional_str(data.get("device_type")),
            confidence=int(data.get("confidence", 0)),
            evidence=[str(v) for v in list(data.get("evidence", []))],
            offline_fail_count=int(data.get("offline_fail_count", 0)),
            last_probe_at=float(data.get("last_probe_at", 0.0)),
            returning_count=int(data.get("returning_count", 0)),
            last_fast_scan=float(data.get("last_fast_scan", 0.0)),
            last_slow_scan=float(data.get("last_slow_scan", 0.0)),
            rx_bytes_total=int(data.get("rx_bytes_total", 0)),
            tx_bytes_total=int(data.get("tx_bytes_total", 0)),
            rx_packets_total=int(data.get("rx_packets_total", 0)),
            tx_packets_total=int(data.get("tx_packets_total", 0)),
            last_traffic_at=float(data.get("last_traffic_at", 0.0)),
        )
        return record


@dataclass(frozen=True)
class DeviceView:
    ip: str
    mac: str
    status: str
    role: str
    likely: str
    vendor: str
    nic_vendor: str
    name: str
    device_type: str
    confidence: int
    services: str
    sources: str
    evidence: str
    identity_hint: str
    why: str
    rx_kbps: float
    tx_kbps: float
    packet_rate: float
    total_mb: float
    traffic_text: str
    usage_bar: str
    last_traffic: str
    seen: str
    online: bool


@dataclass(frozen=True)
class StateSnapshot:
    devices_online: Tuple[DeviceView, ...]
    all_targets: Tuple[Tuple[str, str], ...]
    online_count: int
    hidden_offline_count: int
    fast_qsize: int
    slow_qsize: int
    obs_qsize: int
    dropped_total: int
    dropped_by_kind: Dict[str, int]
    obs_rate: float
    traffic_enabled: bool
    total_rx_kbps: float
    total_tx_kbps: float
    top_talker: str
    device_type_counts: Dict[str, int]
    events: Tuple[str, ...]
    show_events: bool = True
    show_legend: bool = True
    sort_mode: str = "traffic"


# =========================
# UTILS
# =========================
def optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def now_text(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")


def compact(text: object, width: int) -> str:
    value = "-" if text is None or text == "" else fix_mojibake(str(text))
    value = value.replace("\r", " ").replace("\n", " ")
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) <= width:
        return value
    return value[: max(1, width - 3)] + "..."


def fix_mojibake(value: str) -> str:
    if not value:
        return value
    if any(marker in value for marker in ("Ã", "Â", "áº", "á»")):
        try:
            fixed = value.encode("latin1", errors="strict").decode("utf-8", errors="strict")
            if fixed and fixed.count("\ufffd") <= value.count("\ufffd"):
                return fixed
        except Exception:
            pass
    return value


def normalize_search_text(value: str) -> str:
    value = fix_mojibake(value).lower()
    replacements = {
        "á": "a",
        "à": "a",
        "ả": "a",
        "ã": "a",
        "ạ": "a",
        "ă": "a",
        "ằ": "a",
        "ắ": "a",
        "ẳ": "a",
        "ẵ": "a",
        "ặ": "a",
        "â": "a",
        "ầ": "a",
        "ấ": "a",
        "ẩ": "a",
        "ẫ": "a",
        "ậ": "a",
        "đ": "d",
        "é": "e",
        "è": "e",
        "ẻ": "e",
        "ẽ": "e",
        "ẹ": "e",
        "ê": "e",
        "ề": "e",
        "ế": "e",
        "ể": "e",
        "ễ": "e",
        "ệ": "e",
        "í": "i",
        "ì": "i",
        "ỉ": "i",
        "ĩ": "i",
        "ị": "i",
        "ó": "o",
        "ò": "o",
        "ỏ": "o",
        "õ": "o",
        "ọ": "o",
        "ô": "o",
        "ồ": "o",
        "ố": "o",
        "ổ": "o",
        "ỗ": "o",
        "ộ": "o",
        "ơ": "o",
        "ờ": "o",
        "ớ": "o",
        "ở": "o",
        "ỡ": "o",
        "ợ": "o",
        "ú": "u",
        "ù": "u",
        "ủ": "u",
        "ũ": "u",
        "ụ": "u",
        "ư": "u",
        "ừ": "u",
        "ứ": "u",
        "ử": "u",
        "ữ": "u",
        "ự": "u",
        "ý": "y",
        "ỳ": "y",
        "ỷ": "y",
        "ỹ": "y",
        "ỵ": "y",
    }
    for src, dst in replacements.items():
        value = value.replace(src, dst)
    return value


def summarize_services(services: Iterable[str], limit: int = 5) -> str:
    labels: List[str] = []
    for service in sorted(str(item) for item in services if item):
        lower = service.lower()
        label = None
        if "445/smb" in lower or "139/netbios" in lower:
            label = "Windows/SMB file sharing"
        elif "22/ssh" in lower:
            label = "SSH"
        elif "80/http" in lower or "443/" in lower or "8080/http" in lower or "8443/" in lower:
            label = "Web interface"
        elif "53/dns" in lower:
            label = "DNS"
        elif "9100/printer" in lower or "631/ipp" in lower:
            label = "Printer service"
        elif "554/rtsp" in lower:
            label = "Camera stream"
        elif "8008/cast" in lower or "8009/cast" in lower or "chromecast" in lower:
            label = "Cast/TV"
        elif "ssdp" in lower or "upnp" in lower:
            label = "UPnP/SSDP"
        elif service and len(service) <= 28 and "uuid:" not in lower and "location:" not in lower:
            label = compact(service, 28)
        if label and label not in labels:
            labels.append(label)
        if len(labels) >= limit:
            break
    return ", ".join(labels) if labels else "-"


def summarize_evidence(evidence: Iterable[str], services: str, sources: str) -> str:
    friendly: List[str] = []
    mapping = [
        ("default-gateway", "default gateway"),
        ("dns+web", "DNS + web admin"),
        ("smb/netbios", "SMB/NetBIOS sharing"),
        ("file-share", "file sharing ports"),
        ("ssh+web-admin", "SSH + web admin"),
        ("ssh+web", "SSH + web service"),
        ("print-port", "printer ports"),
        ("rtsp", "RTSP camera stream"),
        ("cast", "Cast/TV service"),
        ("private-mac", "private/randomized MAC"),
        ("generic-wifi-nic", "generic Wi-Fi/NIC vendor"),
        ("named-wifi-client", "has LAN hostname"),
        ("oui:apple", "Apple OUI vendor"),
        ("oui:android-vendor", "Android vendor OUI"),
        ("oui:network-vendor", "network equipment vendor"),
        ("apple-name", "Apple device name"),
        ("apple-mobile-name", "iPhone/iPad name"),
    ]
    joined = " ".join(evidence)
    for key, label in mapping:
        if key in joined and label not in friendly:
            friendly.append(label)
    if "arp" in sources and not friendly:
        friendly.append("ARP presence")
    if services and services != "-" and len(friendly) < 4:
        friendly.append(f"services: {services}")
    return ", ".join(friendly[:4]) if friendly else "low-level LAN presence only"


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def is_real_mac(mac: Optional[str]) -> bool:
    if not mac:
        return False
    value = normalize_mac(mac)
    return bool(re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", value)) and value != "00:00:00:00:00:00"


def is_private_mac(mac: str) -> bool:
    try:
        first_octet = int(normalize_mac(mac).split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


def valid_ip(ip: Optional[str]) -> bool:
    if not ip or ip == "0.0.0.0":
        return False
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def is_unicast_host_ip(ip: Optional[str], network: Optional[ipaddress.IPv4Network] = None) -> bool:
    if not valid_ip(ip):
        return False
    try:
        addr = ipaddress.IPv4Address(str(ip))
        if addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False
        if network and (addr == network.network_address or addr == network.broadcast_address):
            return False
        return True
    except Exception:
        return False


def ip_in_network(ip: Optional[str], network: ipaddress.IPv4Network) -> bool:
    if not valid_ip(ip):
        return False
    try:
        return ipaddress.IPv4Address(str(ip)) in network
    except Exception:
        return False


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "default"


def subnet_state_file(network: ipaddress.IPv4Network, state_dir: str = DEFAULT_STATE_DIR) -> str:
    subnet_key = str(network).replace("/", "_").replace(".", ".")
    return os.path.join(state_dir, f"{safe_filename(subnet_key)}.json")


def load_aliases(path: Optional[str]) -> Dict[str, str]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return {}
        aliases: Dict[str, str] = {}
        for key, value in data.items():
            alias = compact(value, 80)
            if not alias or alias == "-":
                continue
            key_text = str(key).strip().lower()
            aliases[normalize_mac(key_text) if ":" in key_text or "-" in key_text else key_text] = alias
        return aliases
    except Exception:
        return {}


def ip_sort_key(ip: str) -> int:
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return 0


def format_rate(kbps: float) -> str:
    if kbps >= 1024:
        return f"{kbps / 1024:.2f} MB/s"
    if kbps >= 10:
        return f"{kbps:.0f} KB/s"
    return f"{kbps:.1f} KB/s"


def format_bytes(total_bytes: int) -> str:
    mb = total_bytes / (1024 * 1024)
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    if mb >= 10:
        return f"{mb:.0f} MB"
    return f"{mb:.2f} MB"


def age_text(timestamp: float, now: Optional[float] = None) -> str:
    if timestamp <= 0:
        return "no traffic"
    current = time.time() if now is None else now
    age = max(0, int(current - timestamp))
    if age < 60:
        return f"{age}s ago"
    if age < 3600:
        return f"{age // 60}m ago"
    return f"{age // 3600}h ago"


def usage_bar(value: float, peak: float, width: int = 14) -> str:
    if peak <= 0 or value <= 0:
        return "[" + "." * width + "]"
    filled = max(1, min(width, int(round((value / peak) * width))))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def nic_vendor_text(mac: str, vendor: Optional[str]) -> str:
    if is_private_mac(mac):
        return "Private/Randomized MAC"
    if vendor:
        return vendor
    return "Unknown NIC/Wi-Fi card"


def is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0 if hasattr(os, "geteuid") else True


def die_setup(msg: str) -> None:
    print("[-]", msg)
    print("[+] Install:")
    print("    pip install scapy requests beautifulsoup4 zeroconf")
    if os.name == "nt":
        print("[!] Windows: install Npcap, tick WinPcap API-compatible Mode, then Run as Administrator.")
    sys.exit(1)


def get_default_interface() -> str:
    try:
        return str(get_working_if())
    except Exception:
        return str(conf.iface)


def get_local_ip(interface: str) -> str:
    try:
        ip = get_if_addr(interface)
        if ip and ip != "0.0.0.0":
            return ip
    except Exception:
        pass
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    finally:
        sock.close()


def mask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def network_from_ipconfig(local_ip: str) -> Optional[ipaddress.IPv4Network]:
    if os.name != "nt":
        return None
    try:
        output = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
    except Exception:
        return None
    lines = output.splitlines()
    for idx, line in enumerate(lines):
        if local_ip not in line:
            continue
        for next_line in lines[idx : idx + 8]:
            if "Subnet Mask" not in next_line:
                continue
            match = re.search(r"([0-9]+(?:\.[0-9]+){3})", next_line)
            if not match:
                continue
            try:
                return ipaddress.IPv4Network(f"{local_ip}/{mask_to_prefix(match.group(1))}", strict=False)
            except Exception:
                return None
    return None


def detect_network(interface: str, forced_cidr: Optional[str]) -> ipaddress.IPv4Network:
    if forced_cidr:
        return ipaddress.IPv4Network(forced_cidr, strict=False)
    local_ip = get_local_ip(interface)
    detected = network_from_ipconfig(local_ip)
    if detected:
        return detected
    return ipaddress.IPv4Network(f"{local_ip}/24", strict=False)


def display_interface(interface: str) -> str:
    match = re.search(r"\{([0-9A-Fa-f-]{8})[0-9A-Fa-f-]*\}$", interface)
    if match:
        return f"NPF:{match.group(1)}"
    return compact(interface, 30)


def get_default_gateway_ip() -> Optional[str]:
    try:
        if os.name == "nt":
            output = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
            matches = re.findall(r"Default Gateway[^:\n]*:\s*([0-9]+(?:\.[0-9]+){3})", output)
            for match in matches:
                if valid_ip(match):
                    return match
            return None
        output = subprocess.check_output("ip route", shell=True, text=True, errors="ignore")
        match = re.search(r"default\s+via\s+([0-9]+(?:\.[0-9]+){3})", output)
        return match.group(1) if match else None
    except Exception:
        return None


def service_name(port: int) -> str:
    names = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        53: "dns",
        80: "http",
        81: "http",
        139: "netbios",
        443: "https",
        445: "smb",
        554: "rtsp",
        631: "ipp",
        8000: "http",
        8008: "cast",
        8009: "cast",
        8080: "http",
        8443: "https",
        8888: "http",
        9000: "http",
        9100: "printer",
    }
    return names.get(port, "tcp")


# =========================
# QUEUE HELPERS
# =========================
def increment_drop(kind: str, count: int = 1) -> None:
    global DROPPED_TOTAL
    with DROP_LOCK:
        DROPPED_TOTAL += count
        DROPPED_BY_KIND[kind] += count


def dropped_snapshot() -> Tuple[int, Dict[str, int]]:
    with DROP_LOCK:
        return DROPPED_TOTAL, dict(DROPPED_BY_KIND)


def submit_observation(obs: Observation, critical: Optional[bool] = None) -> bool:
    if STOP_EVENT.is_set():
        return False
    is_critical = critical if critical is not None else obs.kind in CRITICAL_KINDS
    try:
        OBSERVATION_QUEUE.put_nowait(obs)
        return True
    except queue.Full:
        if not is_critical:
            increment_drop(obs.kind)
            return False
        try:
            old = OBSERVATION_QUEUE.get_nowait()
            OBSERVATION_QUEUE.task_done()
            increment_drop(f"evicted:{old.kind}")
        except queue.Empty:
            pass
        try:
            OBSERVATION_QUEUE.put_nowait(obs)
            return True
        except queue.Full:
            increment_drop(obs.kind)
            return False


def submit_fast_job(job: FingerprintJob) -> bool:
    try:
        FAST_QUEUE.put_nowait(job)
        return True
    except queue.Full:
        increment_drop("fast_job")
        return False


def submit_slow_job(job: FingerprintJob) -> bool:
    try:
        SLOW_QUEUE.put_nowait(job)
        return True
    except queue.Full:
        increment_drop("slow_job")
        return False


def read_snapshot() -> Optional[StateSnapshot]:
    with SNAPSHOT_LOCK:
        return CURRENT_SNAPSHOT


def publish_snapshot(snapshot: StateSnapshot) -> None:
    global CURRENT_SNAPSHOT
    with SNAPSHOT_LOCK:
        CURRENT_SNAPSHOT = snapshot


# =========================
# STATE PERSISTENCE
# =========================
def corrupt_state_path(path: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{path}.corrupt.{stamp}"


def load_state(path: str) -> Dict[str, DeviceRecord]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("schema_version mismatch")
        devices_raw = data.get("devices")
        if not isinstance(devices_raw, list):
            raise ValueError("devices must be a list")
        devices: Dict[str, DeviceRecord] = {}
        for item in devices_raw:
            if not isinstance(item, dict):
                raise ValueError("device entry is not an object")
            record = DeviceRecord.from_json(item)
            record.online = False
            record.names = []
            record.vendor = None
            record.services = set()
            record.http_titles = {}
            record.tls_names = {}
            record.device_type = None
            record.confidence = 0
            record.evidence = []
            record.rx_bytes_total = 0
            record.tx_bytes_total = 0
            record.rx_packets_total = 0
            record.tx_packets_total = 0
            record.last_traffic_at = 0.0
            record.traffic_samples.clear()
            devices[record.mac] = record
        return devices
    except Exception as exc:
        bad_path = corrupt_state_path(path)
        try:
            os.replace(path, bad_path)
            print(f"[!] State file corrupt, renamed to: {bad_path} ({exc})")
        except Exception:
            print(f"[!] State file corrupt and could not be renamed: {path} ({exc})")
        return {}


def save_state_atomic(path: str, devices: Dict[str, DeviceRecord]) -> None:
    if not path:
        return
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.tmp"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "saved_at": time.time(),
        "devices": [record.to_json() for record in sorted(devices.values(), key=lambda item: item.mac)],
    }
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


# =========================
# STATE MANAGER
# =========================
class StateManager:
    def __init__(
        self,
        devices: Dict[str, DeviceRecord],
        offline_after: float,
        offline_fail_threshold: int,
        state_file: str,
        event_log: Optional[str],
        gateway_ip: Optional[str] = None,
        traffic_window: float = DEFAULT_TRAFFIC_WINDOW,
        traffic_enabled: bool = True,
        network: Optional[ipaddress.IPv4Network] = None,
        aliases: Optional[Dict[str, str]] = None,
        sort_mode: str = "traffic",
        only_active_traffic: bool = False,
        hide_unknown: bool = False,
        min_confidence: int = 0,
        show_events: bool = True,
        show_legend: bool = True,
    ):
        self.devices = devices
        self.offline_after = offline_after
        self.offline_fail_threshold = offline_fail_threshold
        self.state_file = state_file
        self.event_log = event_log
        self.gateway_ip = gateway_ip
        self.traffic_window = max(1.0, traffic_window)
        self.traffic_enabled = traffic_enabled
        self.network = network
        self.aliases = aliases or {}
        self.sort_mode = sort_mode
        self.only_active_traffic = only_active_traffic
        self.hide_unknown = hide_unknown
        self.min_confidence = max(0, min(100, min_confidence))
        self.show_events = show_events
        self.show_legend = show_legend
        self.ip_to_mac: Dict[str, str] = {}
        self.events: Deque[str] = deque(maxlen=8)
        self.recent_event_keys: Dict[str, float] = {}
        self.seen_this_run: Set[str] = set()
        self.observations_seen = 0
        self.rate_window_start = time.time()
        self.rate_window_count = 0
        self.obs_rate = 0.0
        self.rebuild_ip_index()

    def rebuild_ip_index(self) -> None:
        self.ip_to_mac.clear()
        for mac, record in self.devices.items():
            for ip in record.ips:
                if self.ip_in_scope(ip):
                    self.ip_to_mac[ip] = mac

    def ip_in_scope(self, ip: Optional[str]) -> bool:
        if not valid_ip(ip):
            return False
        return True if self.network is None else ip_in_network(ip, self.network)

    def current_ip(self, record: DeviceRecord) -> Optional[str]:
        scoped = [(ip, ts) for ip, ts in record.ips.items() if self.ip_in_scope(ip)]
        if not scoped:
            return None
        return max(scoped, key=lambda item: item[1])[0]

    def display_name(self, record: DeviceRecord, ip: Optional[str] = None) -> str:
        mac_key = normalize_mac(record.mac)
        if mac_key in self.aliases:
            return self.aliases[mac_key]
        if ip and ip in self.aliases:
            return self.aliases[ip]
        return record.best_name() or "not learned yet"

    def device_role(self, record: DeviceRecord, ip: str) -> str:
        if self.gateway_ip and ip == self.gateway_ip:
            return "Gateway"
        dtype = record.device_type or "Unknown"
        if dtype in {"NAS/Server", "Linux/Server"}:
            return "Server"
        if dtype in {"Printer"}:
            return "Printer"
        if dtype in {"Camera/NVR"}:
            return "Camera"
        if dtype in {"Router/AP"}:
            return "Network"
        return "Client"

    def device_status(self, record: DeviceRecord, now: float, rx_kbps: float, tx_kbps: float, packet_rate: float) -> str:
        if not record.online:
            return "OFFLINE"
        age = now - record.last_seen
        if rx_kbps + tx_kbps >= 1.0 or packet_rate >= 1.0:
            return "ACTIVE"
        if age >= max(8.0, self.offline_after / 2):
            return "SLEEP?"
        return "QUIET"

    def run(self) -> None:
        self.publish()
        next_save = time.time() + STATE_SAVE_INTERVAL
        while not STOP_EVENT.is_set():
            self.process_one(timeout=0.2)
            self.process_available(limit=500)
            self.update_offline()
            self.publish()
            if time.time() >= next_save:
                self.save()
                next_save = time.time() + STATE_SAVE_INTERVAL

        deadline = time.time() + SHUTDOWN_DRAIN_SECONDS
        while time.time() < deadline and not OBSERVATION_QUEUE.empty():
            self.process_one(timeout=0.05)
        self.update_offline()
        self.publish()
        self.save()

    def process_available(self, limit: int) -> None:
        for _ in range(limit):
            try:
                obs = OBSERVATION_QUEUE.get_nowait()
            except queue.Empty:
                return
            try:
                self.apply_observation(obs)
            finally:
                OBSERVATION_QUEUE.task_done()

    def process_one(self, timeout: float) -> None:
        try:
            obs = OBSERVATION_QUEUE.get(timeout=timeout)
        except queue.Empty:
            return
        try:
            self.apply_observation(obs)
        finally:
            OBSERVATION_QUEUE.task_done()

    def apply_observation(self, obs: Observation) -> None:
        self.observations_seen += 1
        self.rate_window_count += 1
        now = obs.timestamp
        if now - self.rate_window_start >= 1.0:
            self.obs_rate = self.rate_window_count / max(0.001, now - self.rate_window_start)
            self.rate_window_count = 0
            self.rate_window_start = now

        if obs.kind == "traffic":
            self.apply_traffic(obs)
            return

        if obs.ip and valid_ip(obs.ip) and not self.ip_in_scope(obs.ip):
            return

        mac = normalize_mac(obs.mac) if is_real_mac(obs.mac) else None
        if mac is None and obs.ip:
            mac = self.ip_to_mac.get(obs.ip)
        if mac is None:
            return

        record = self.devices.get(mac)
        is_new = False
        if record is None:
            record = DeviceRecord(device_id=mac, mac=mac, first_seen=now, last_seen=now)
            self.devices[mac] = record
            is_new = True
            self.add_event("NEW", record, obs.source or obs.kind)

        if obs.ip and valid_ip(obs.ip):
            record.ips[obs.ip] = now
            self.ip_to_mac[obs.ip] = mac

        if obs.kind == "probe_fail":
            record.last_probe_at = now
            record.offline_fail_count += 1
            if record.online and now - record.last_seen > self.offline_after and record.offline_fail_count >= self.offline_fail_threshold:
                record.online = False
                self.add_event("OFFLINE-HIDDEN", record, f"fails={record.offline_fail_count}")
            return

        if obs.kind in LIVE_KINDS:
            was_online = record.online
            record.last_seen = max(record.last_seen, now)
            record.online = True
            record.offline_fail_count = 0
            self.seen_this_run.add(record.mac)
            if not is_new and not was_online:
                record.returning_count += 1
                self.add_event("RETURNING", record, obs.source or obs.kind)

        if obs.source or obs.kind:
            record.sources.add(obs.source or obs.kind)

        if obs.name:
            self.merge_name(record, obs.name, obs.kind, now)

        if obs.kind == "vendor" and obs.value:
            record.vendor = obs.value
        elif obs.kind == "http":
            if obs.port:
                if obs.name:
                    record.http_titles[str(obs.port)] = obs.name
                record.services.add(f"{obs.port}/http")
            if obs.value:
                record.services.add(compact(obs.value, 28))
        elif obs.kind == "tls":
            if obs.port and obs.value:
                record.tls_names[str(obs.port)] = obs.value
                record.services.add(f"{obs.port}/tls")
        elif obs.kind == "tcp" and obs.port:
            record.services.add(f"{obs.port}/{service_name(obs.port)}")
        elif obs.kind == "ssdp":
            if obs.service:
                record.services.add(compact(obs.service, 28))
            if obs.value:
                record.services.add(compact(obs.value, 28))

        self.classify(record)
        self.schedule_fingerprint(record, now, is_new)

    def apply_traffic(self, obs: Observation) -> None:
        if not self.traffic_enabled or obs.packet_bytes <= 0:
            return
        now = obs.timestamp
        src_mac = self.ip_to_mac.get(obs.src_ip or "")
        dst_mac = self.ip_to_mac.get(obs.dst_ip or "")
        if not src_mac and not dst_mac:
            return

        packet_bytes = max(0, int(obs.packet_bytes))
        packet_count = max(1, int(obs.packet_count))
        touched: Set[str] = set()
        if src_mac:
            record = self.devices.get(src_mac)
            if record:
                record.tx_bytes_total += packet_bytes
                record.tx_packets_total += packet_count
                record.last_traffic_at = now
                record.traffic_samples.append((now, 0, packet_bytes, 0, packet_count))
                touched.add(src_mac)
                self.seen_this_run.add(src_mac)
        if dst_mac and dst_mac != src_mac:
            record = self.devices.get(dst_mac)
            if record:
                record.rx_bytes_total += packet_bytes
                record.rx_packets_total += packet_count
                record.last_traffic_at = now
                record.traffic_samples.append((now, packet_bytes, 0, packet_count, 0))
                touched.add(dst_mac)
                self.seen_this_run.add(dst_mac)

        cutoff = now - max(30.0, self.traffic_window * 4)
        for mac in touched:
            record = self.devices.get(mac)
            if not record:
                continue
            while record.traffic_samples and record.traffic_samples[0][0] < cutoff:
                record.traffic_samples.popleft()
            record.last_seen = max(record.last_seen, now)
            record.online = True
            record.offline_fail_count = 0

    def traffic_stats(self, record: DeviceRecord, now: float) -> Tuple[float, float, float, float, str]:
        cutoff = now - self.traffic_window
        rx_bytes = 0
        tx_bytes = 0
        packets = 0
        while record.traffic_samples and record.traffic_samples[0][0] < now - max(30.0, self.traffic_window * 4):
            record.traffic_samples.popleft()
        for ts, rx_b, tx_b, rx_p, tx_p in record.traffic_samples:
            if ts >= cutoff:
                rx_bytes += rx_b
                tx_bytes += tx_b
                packets += rx_p + tx_p
        window = max(1.0, self.traffic_window)
        rx_kbps = rx_bytes / 1024.0 / window
        tx_kbps = tx_bytes / 1024.0 / window
        packet_rate = packets / window
        total_mb = (record.rx_bytes_total + record.tx_bytes_total) / (1024.0 * 1024.0)
        text = f"RX {format_rate(rx_kbps)} | TX {format_rate(tx_kbps)} | {packet_rate:.1f} pkt/s | total {format_bytes(record.rx_bytes_total + record.tx_bytes_total)}"
        return rx_kbps, tx_kbps, packet_rate, total_mb, text

    def merge_name(self, record: DeviceRecord, value: str, source: str, timestamp: float) -> None:
        clean = compact(value, 80)
        if not clean or clean == "-":
            return
        score = NAME_SCORES.get(source, 30)
        before = record.best_name()
        for candidate in record.names:
            if candidate.value.lower() == clean.lower() and candidate.source == source:
                candidate.last_seen = timestamp
                candidate.score = max(candidate.score, score)
                break
        else:
            record.names.append(NameCandidate(clean, source, score, timestamp))
            record.names = sorted(record.names, key=lambda item: (item.score, item.last_seen), reverse=True)[:10]
        after = record.best_name()
        if after and after != before:
            self.add_event("NAME", record, after)

    def schedule_fingerprint(self, record: DeviceRecord, now: float, is_new: bool) -> None:
        ip = self.current_ip(record)
        if not ip:
            return
        if is_new or now - record.last_fast_scan >= FAST_TTL:
            if submit_fast_job(FingerprintJob(record.mac, ip, "ttl" if not is_new else "new")):
                record.last_fast_scan = now
        if is_new or now - record.last_slow_scan >= SLOW_TTL:
            if submit_slow_job(FingerprintJob(record.mac, ip, "ttl" if not is_new else "new")):
                record.last_slow_scan = now

    def classify(self, record: DeviceRecord) -> None:
        current_ip = self.current_ip(record)
        name = record.best_name() or ""
        vendor = record.vendor or ""
        raw_text = " ".join(
            [
                vendor,
                name,
                " ".join(record.services),
                " ".join(record.http_titles.values()),
                " ".join(record.tls_names.values()),
            ]
        )
        text = normalize_search_text(raw_text)
        old_type = record.device_type
        scores = {
            "Router/AP": 0,
            "Windows Desktop": 0,
            "Windows Laptop/PC": 0,
            "MacBook": 0,
            "iPhone/iPad": 0,
            "Apple Device": 0,
            "Android Phone": 0,
            "Camera/NVR": 0,
            "Printer": 0,
            "TV/Cast": 0,
            "NAS/Server": 0,
            "Linux/Server": 0,
            "Unknown": 1,
        }
        evidence: List[str] = []

        def add(kind: str, points: int, why: str) -> None:
            if kind in scores:
                scores[kind] += points
                evidence.append(f"{why}:{points}")

        if self.gateway_ip and current_ip == self.gateway_ip:
            add("Router/AP", 70, "default-gateway")
        if "53/dns" in record.services and any(s.startswith("80/") or s.startswith("443/") for s in record.services):
            add("Router/AP", 20, "dns+web")
        if any("445/smb" in s or "139/netbios" in s for s in record.services):
            add("Windows Desktop", 34, "smb/netbios")
            add("Windows Laptop/PC", 32, "smb/netbios")
            add("NAS/Server", 8, "file-share")
        if "22/ssh" in record.services and any(s.startswith(("80/", "443/", "8080/", "8443/")) for s in record.services):
            add("Router/AP", 12, "ssh+web-admin")
            add("NAS/Server", 10, "ssh+web")
            add("Linux/Server", 8, "ssh+web")
        elif "22/ssh" in record.services:
            add("Linux/Server", 16, "ssh")
        if any("9100/printer" in s or "631/ipp" in s for s in record.services):
            add("Printer", 25, "print-port")
        if "554/rtsp" in record.services or "rtsp" in text:
            add("Camera/NVR", 24, "rtsp")
        if "8008/cast" in record.services or "8009/cast" in record.services or "chromecast" in text:
            add("TV/Cast", 24, "cast")

        keyword_map = [
            ("Router/AP", ["router", "gateway", "openwrt", "tplink", "tp-link", "tp link", "mikrotik", "tenda", "asus", "tplinkwifi", "wr841", "archer"]),
            ("MacBook", ["macbook", "mac os", "macos"]),
            ("iPhone/iPad", ["iphone", "ipad"]),
            ("Apple Device", ["apple", "airplay", "bonjour", "raop"]),
            ("Android Phone", ["android", "samsung", "xiaomi", "oppo", "vivo", "huawei", "realme"]),
            ("Camera/NVR", ["camera", "nvr", "dvr", "hikvision", "dahua"]),
            ("Printer", ["printer", "canon", "epson", "brother", "xerox", "ipp"]),
            ("TV/Cast", ["chromecast", "google tv", "android tv", "bravia", "tizen", "webos"]),
            ("NAS/Server", ["synology", "qnap", "truenas", "nas", "ubuntu", "debian"]),
            ("Linux/Server", ["ubuntu", "debian", "linux", "kali", "centos", "fedora"]),
            ("Windows Desktop", ["desktop", "workgroup", "microsoft", "may tinh de ban"]),
            ("Windows Laptop/PC", ["windows", "laptop", "notebook", "pc", "may tinh", "xach tay", "huy"]),
        ]
        for kind, keywords in keyword_map:
            if any(word in text for word in keywords):
                add(kind, 12, f"keyword:{kind}")

        vendor_l = vendor.lower()
        if "apple" in vendor_l:
            add("Apple Device", 22, "oui:apple")
            if any(token in text for token in ["macbook", "mac os", "macos"]):
                add("MacBook", 32, "apple-name")
            if any(token in text for token in ["iphone", "ipad"]):
                add("iPhone/iPad", 32, "apple-mobile-name")
        if any(v in vendor_l for v in ["samsung", "xiaomi", "oppo", "vivo", "huawei", "oneplus", "realme"]):
            add("Android Phone", 18, "oui:android-vendor")
        if any(v in vendor_l for v in ["intel", "realtek", "azurewave", "liteon", "lite-on", "hon hai", "foxconn", "qualcomm", "atheros", "broadcom", "mediatek"]):
            add("Windows Laptop/PC", 12, "generic-wifi-nic")
            add("Android Phone", 3, "generic-wifi-nic")
        if any(v in vendor_l for v in ["tp-link", "tplink", "tenda", "mikrotik", "ubiquiti", "ruijie", "netgear", "asus"]):
            add("Router/AP", 22, "oui:network-vendor")

        if is_private_mac(record.mac):
            private_points = 3 if any("445/smb" in s or "139/netbios" in s for s in record.services) else 8
            add("Android Phone", private_points, "private-mac")
            add("iPhone/iPad", private_points, "private-mac")
            add("Windows Laptop/PC", 5, "private-mac")

        if record.best_name() and record.vendor and any(v in record.vendor.lower() for v in GENERIC_NIC_VENDORS):
            add("Windows Laptop/PC", 12, "named-wifi-client")
        if record.best_name() and any(token in text for token in ["desktop", "laptop", "notebook", "may tinh", "xach tay"]):
            add("Windows Laptop/PC", 20, "computer-name")

        best_type, raw_score = max(scores.items(), key=lambda item: item[1])
        record.device_type = best_type
        record.confidence = min(100, max(0, raw_score if best_type != "Unknown" else 10))
        record.evidence = evidence[:6]
        if old_type and old_type != record.device_type:
            self.add_event("TYPE", record, record.device_type)

    def update_offline(self) -> None:
        now = time.time()
        for record in self.devices.values():
            if record.online and now - record.last_seen > self.offline_after:
                record.online = False
                self.add_event("OFFLINE-HIDDEN", record, f"age={int(now - record.last_seen)}s")

    def add_event(self, kind: str, record: DeviceRecord, detail: str) -> None:
        now = time.time()
        event_key = f"{kind}|{record.mac}|{detail}"
        last_event = self.recent_event_keys.get(event_key, 0.0)
        if now - last_event < 8.0:
            return
        self.recent_event_keys[event_key] = now
        if len(self.recent_event_keys) > 256:
            cutoff = now - 60.0
            self.recent_event_keys = {key: ts for key, ts in self.recent_event_keys.items() if ts >= cutoff}
        ip = self.current_ip(record) or "-"
        name = record.best_name() or "-"
        event = f"[{kind}] {ip} {record.mac} {compact(name, 24)} {compact(detail, 36)}"
        self.events.appendleft(event)
        if self.event_log:
            try:
                with open(self.event_log, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"ts": time.time(), "kind": kind, "mac": record.mac, "ip": ip, "name": name, "detail": detail}, ensure_ascii=False) + "\n")
            except Exception:
                pass

    def publish(self) -> None:
        now = time.time()
        dropped_total, dropped_by_kind = dropped_snapshot()
        visible: List[DeviceView] = []
        targets: List[Tuple[str, str]] = []
        hidden = 0
        type_counts: Counter[str] = Counter()
        traffic_rows: List[Tuple[str, float, float]] = []
        for record in sorted(self.devices.values(), key=lambda item: ip_sort_key(self.current_ip(item) or "0.0.0.0")):
            ip = self.current_ip(record)
            if ip and record.mac in self.seen_this_run and record.online:
                targets.append((record.mac, ip))
            if not ip or record.mac not in self.seen_this_run:
                continue
            age = now - record.last_seen
            if not record.online or age > self.offline_after:
                hidden += 1
                record.online = False
                continue
            seen = f"{int(age)}s"
            likely, identity_hint, why = self.explain_device(record)
            rx_kbps, tx_kbps, packet_rate, total_mb, traffic_text = self.traffic_stats(record, now)
            status = self.device_status(record, now, rx_kbps, tx_kbps, packet_rate)
            if self.only_active_traffic and status != "ACTIVE":
                continue
            if self.hide_unknown and (record.device_type or "Unknown") == "Unknown":
                continue
            if record.confidence < self.min_confidence:
                continue
            traffic_rows.append((record.mac, rx_kbps, tx_kbps))
            type_counts[record.device_type or "Unknown"] += 1
            visible.append(
                DeviceView(
                    ip=ip or "-",
                    mac=record.mac,
                    status=status,
                    role=self.device_role(record, ip),
                    likely=likely,
                    vendor=record.vendor or ("Private MAC" if is_private_mac(record.mac) else "-"),
                    nic_vendor=nic_vendor_text(record.mac, record.vendor),
                    name=self.display_name(record, ip),
                    device_type=record.device_type or "Unknown",
                    confidence=record.confidence,
                    services=record.service_text() or "-",
                    sources=record.source_text() or "-",
                    evidence=", ".join(record.evidence) or "-",
                    identity_hint=identity_hint,
                    why=why,
                    rx_kbps=rx_kbps,
                    tx_kbps=tx_kbps,
                    packet_rate=packet_rate,
                    total_mb=total_mb,
                    traffic_text=traffic_text,
                    usage_bar="",
                    last_traffic=age_text(record.last_traffic_at, now),
                    seen=seen,
                    online=True,
                )
            )
        peak = max((item.rx_kbps + item.tx_kbps for item in visible), default=0.0)
        visible = [
            DeviceView(
                ip=item.ip,
                mac=item.mac,
                status=item.status,
                role=item.role,
                likely=item.likely,
                vendor=item.vendor,
                nic_vendor=item.nic_vendor,
                name=item.name,
                device_type=item.device_type,
                confidence=item.confidence,
                services=item.services,
                sources=item.sources,
                evidence=item.evidence,
                identity_hint=item.identity_hint,
                why=item.why,
                rx_kbps=item.rx_kbps,
                tx_kbps=item.tx_kbps,
                packet_rate=item.packet_rate,
                total_mb=item.total_mb,
                traffic_text=item.traffic_text,
                usage_bar=usage_bar(item.rx_kbps + item.tx_kbps, peak),
                last_traffic=item.last_traffic,
                seen=item.seen,
                online=item.online,
            )
            for item in visible
        ]
        total_rx = sum(item.rx_kbps for item in visible)
        total_tx = sum(item.tx_kbps for item in visible)
        top_device = max(visible, key=lambda item: item.rx_kbps + item.tx_kbps, default=None)
        top_talker = "-"
        if top_device and top_device.rx_kbps + top_device.tx_kbps > 0:
            top_talker = f"{top_device.ip} {top_device.name} ({format_rate(top_device.rx_kbps + top_device.tx_kbps)})"
        online_count = sum(1 for item in visible if item.status != "OFFLINE")
        publish_snapshot(
            StateSnapshot(
                devices_online=tuple(visible),
                all_targets=tuple(targets),
                online_count=online_count,
                hidden_offline_count=hidden,
                fast_qsize=FAST_QUEUE.qsize(),
                slow_qsize=SLOW_QUEUE.qsize(),
                obs_qsize=OBSERVATION_QUEUE.qsize(),
                dropped_total=dropped_total,
                dropped_by_kind=dropped_by_kind,
                obs_rate=self.obs_rate,
                traffic_enabled=self.traffic_enabled,
                total_rx_kbps=total_rx,
                total_tx_kbps=total_tx,
                top_talker=top_talker,
                device_type_counts=dict(type_counts),
                events=tuple(self.events),
                show_events=self.show_events,
                show_legend=self.show_legend,
                sort_mode=self.sort_mode,
            )
        )

    def explain_device(self, record: DeviceRecord) -> Tuple[str, str, str]:
        name = record.best_name()
        vendor = record.vendor or ""
        services = record.service_text()
        evidence = ", ".join(record.evidence)
        dtype = record.device_type or "Unknown"
        confidence = record.confidence

        if dtype == "Unknown" and is_private_mac(record.mac):
            likely = "Phone/Tablet or IoT using Private MAC"
        elif dtype == "Unknown" and name:
            likely = f"Named LAN device, likely PC/phone ({confidence}%)"
        elif dtype == "Unknown" and vendor and any(v in vendor.lower() for v in GENERIC_NIC_VENDORS):
            likely = "WiFi client, likely laptop/phone"
        elif dtype == "Unknown":
            likely = "Unknown LAN device - only low-level signal seen"
        else:
            likely = f"{dtype} ({confidence}%)"

        identity_parts: List[str] = []
        if name:
            identity_parts.append(f"name={name}")
        else:
            identity_parts.append("name=not learned yet")
        identity_parts.append(f"nic={nic_vendor_text(record.mac, vendor)}")
        if is_private_mac(record.mac):
            identity_parts.append("private-mac=yes")
        identity_hint = " | ".join(identity_parts)

        why_parts: List[str] = []
        if evidence:
            why_parts.append(evidence)
        if services:
            why_parts.append(summarize_evidence(record.evidence, services, record.source_text()))
        if record.source_text():
            if not why_parts:
                why_parts.append(f"sources: {record.source_text()}")
        if not evidence and not services:
            why_parts.append("only ARP/DHCP-level presence so far; wait for mDNS/NetBIOS/HTTP or wake the device")
        why = summarize_evidence(record.evidence, services, record.source_text()) if evidence or services else " | ".join(why_parts)
        return likely, identity_hint, why

    def save(self) -> None:
        try:
            save_state_atomic(self.state_file, self.devices)
        except Exception as exc:
            self.events.appendleft(f"[STATE-SAVE-ERROR] {compact(exc, 80)}")

    def export_json(self, path: str) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "exported_at": time.time(),
            "devices": [record.to_json() for record in sorted(self.devices.values(), key=lambda item: item.mac)],
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)

    def export_csv(self, path: str) -> None:
        fields = ["ip", "mac", "vendor", "best_name", "type", "confidence", "services", "sources", "first_seen", "last_seen", "online", "returning_count"]
        with open(path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for record in sorted(self.devices.values(), key=lambda item: item.mac):
                writer.writerow(
                    {
                        "ip": record.current_ip() or "",
                        "mac": record.mac,
                        "vendor": record.vendor or "",
                        "best_name": record.best_name() or "",
                        "type": record.device_type or "",
                        "confidence": record.confidence,
                        "services": record.service_text(),
                        "sources": record.source_text(),
                        "first_seen": now_text(record.first_seen),
                        "last_seen": now_text(record.last_seen),
                        "online": str(record.online),
                        "returning_count": record.returning_count,
                    }
                )


# =========================
# PACKET SNIFFING
# =========================
def packet_length(packet) -> int:
    try:
        return int(len(packet))
    except Exception:
        try:
            return len(bytes(packet))
        except Exception:
            return 0


def submit_traffic_observation(src_ip: str, dst_ip: str, packet_bytes: int, timestamp: float) -> None:
    if packet_bytes <= 0:
        return
    key = (src_ip, dst_ip)
    with TRAFFIC_LOCK:
        pending_bytes, pending_packets, first_seen = TRAFFIC_PENDING.get(key, (0, 0, timestamp))
        pending_bytes += packet_bytes
        pending_packets += 1
        if timestamp - first_seen < TRAFFIC_FLUSH_INTERVAL:
            TRAFFIC_PENDING[key] = (pending_bytes, pending_packets, first_seen)
            return
        TRAFFIC_PENDING.pop(key, None)
    submit_observation(
        Observation(
            kind="traffic",
            src_ip=src_ip,
            dst_ip=dst_ip,
            packet_bytes=pending_bytes,
            packet_count=pending_packets,
            source="traffic-sniff",
            confidence=0,
            timestamp=timestamp,
        )
    )


def flush_traffic_pending() -> None:
    now = time.time()
    ready: List[Tuple[str, str, int, int, float]] = []
    with TRAFFIC_LOCK:
        for (src_ip, dst_ip), (pending_bytes, pending_packets, first_seen) in list(TRAFFIC_PENDING.items()):
            if now - first_seen >= TRAFFIC_FLUSH_INTERVAL:
                ready.append((src_ip, dst_ip, pending_bytes, pending_packets, now))
                TRAFFIC_PENDING.pop((src_ip, dst_ip), None)
    for src_ip, dst_ip, pending_bytes, pending_packets, timestamp in ready:
        submit_observation(
            Observation(
                kind="traffic",
                src_ip=src_ip,
                dst_ip=dst_ip,
                packet_bytes=pending_bytes,
                packet_count=pending_packets,
                source="traffic-sniff",
                confidence=0,
                timestamp=timestamp,
            )
        )


def handle_packet(packet, network: ipaddress.IPv4Network, use_traffic: bool = True) -> None:
    try:
        if use_traffic and packet.haslayer(IP):
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
            if (
                is_unicast_host_ip(src_ip, network)
                and is_unicast_host_ip(dst_ip, None)
                and (ip_in_network(src_ip, network) or ip_in_network(dst_ip, network))
            ):
                snapshot = read_snapshot()
                known_ips = {ip for _, ip in snapshot.all_targets} if snapshot else set()
                if src_ip not in known_ips and dst_ip not in known_ips:
                    return
                submit_traffic_observation(src_ip, dst_ip, packet_length(packet), time.time())

        if packet.haslayer(ARP):
            arp = packet[ARP]
            ip = str(arp.psrc)
            mac = normalize_mac(str(arp.hwsrc))
            if ip_in_network(ip, network) and is_real_mac(mac):
                submit_observation(Observation(kind="arp", ip=ip, mac=mac, source="arp-sniff", confidence=100), critical=True)
            return

        if not packet.haslayer(IP) or not packet.haslayer(UDP):
            return
        src_ip = str(packet[IP].src)
        if not ip_in_network(src_ip, network):
            return

        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)

        if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
            obs = parse_dhcp(packet)
            if obs:
                submit_observation(obs, critical=True)
            return

        payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
        if not payload:
            return

        if (sport == 5353 or dport == 5353) and ENABLE_MDNS:
            name = extract_mdns_name(payload)
            if name:
                submit_observation(Observation(kind="mdns", ip=src_ip, name=name, source="mdns-passive", confidence=80))
        elif (sport == 1900 or dport == 1900) and ENABLE_SSDP:
            service, value = parse_ssdp(payload)
            if service or value:
                submit_observation(Observation(kind="ssdp", ip=src_ip, service=service, value=value, source="ssdp-passive", confidence=60))
        elif sport == 5355 or dport == 5355:
            name = extract_plain_name(payload)
            if name:
                submit_observation(Observation(kind="llmnr", ip=src_ip, name=name, source="llmnr-passive", confidence=50))
        elif sport == 137 or dport == 137:
            name = extract_plain_name(payload)
            if name:
                submit_observation(Observation(kind="nbns", ip=src_ip, name=name, source="nbns-passive", confidence=50))
    except Exception:
        return


def parse_dhcp(packet) -> Optional[Observation]:
    try:
        bootp = packet[BOOTP]
        hlen = int(bootp.hlen)
        raw_mac = bytes(bootp.chaddr[:hlen])
        mac = ":".join(f"{b:02x}" for b in raw_mac[:6])
        if not is_real_mac(mac):
            return None
        ip = None
        if valid_ip(str(getattr(bootp, "yiaddr", ""))):
            ip = str(bootp.yiaddr)
        elif valid_ip(str(getattr(bootp, "ciaddr", ""))):
            ip = str(bootp.ciaddr)
        hostname = None
        vendor_class = None
        requested_ip = None
        for option in packet[DHCP].options:
            if not isinstance(option, tuple) or len(option) < 2:
                continue
            key, value = option[0], option[1]
            if key == "hostname":
                hostname = decode_option(value)
            elif key == "vendor_class_id":
                vendor_class = decode_option(value)
            elif key == "requested_addr":
                requested_ip = str(value)
        if ip is None and valid_ip(requested_ip):
            ip = requested_ip
        return Observation(kind="dhcp", ip=ip, mac=mac, name=hostname, value=vendor_class, source="dhcp-sniff", confidence=95)
    except Exception:
        return None


def decode_option(value: object) -> Optional[str]:
    try:
        if isinstance(value, bytes):
            return compact(value.decode("utf-8", errors="ignore"), 80)
        return compact(str(value), 80)
    except Exception:
        return None


def extract_mdns_name(payload: bytes) -> Optional[str]:
    text = payload.decode("latin1", errors="ignore")
    matches = re.findall(r"([A-Za-z0-9][A-Za-z0-9._ -]{1,64}\.local)", text)
    return compact(matches[0].replace("\x00", ""), 80) if matches else None


def extract_plain_name(payload: bytes) -> Optional[str]:
    text = payload.decode("latin1", errors="ignore").replace("\x00", " ")
    matches = re.findall(r"\b([A-Za-z0-9][A-Za-z0-9_-]{2,31})\b", text)
    noise = {"http", "ssdp", "upnp", "uuid", "local", "workgroup"}
    for match in matches:
        if match.lower() not in noise and not match.isdigit():
            return compact(match, 64)
    return None


def parse_ssdp(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    text = payload.decode("utf-8", errors="ignore")
    headers: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().upper()] = value.strip()
    service = headers.get("ST") or headers.get("NT") or headers.get("USN")
    value = headers.get("SERVER") or headers.get("LOCATION")
    return compact(service, 100) if service else None, compact(value, 100) if value else None


def packet_sniffer_loop(interface: str, network: ipaddress.IPv4Network, use_traffic: bool = True) -> None:
    identity_bpf = "arp or udp port 67 or udp port 68 or udp port 5353 or udp port 1900 or udp port 5355 or udp port 137"
    bpf = f"ip or {identity_bpf}" if use_traffic else identity_bpf
    while not STOP_EVENT.is_set():
        try:
            sniff(iface=interface, filter=bpf, prn=lambda pkt: handle_packet(pkt, network, use_traffic), store=False, timeout=1)
            if use_traffic:
                flush_traffic_pending()
        except PermissionError:
            die_setup("No permission to sniff packets. Run as Administrator/root.")
        except Exception:
            try:
                sniff(iface=interface, filter="arp", prn=lambda pkt: handle_packet(pkt, network, False), store=False, timeout=1)
            except Exception:
                time.sleep(0.5)


# =========================
# ACTIVE DISCOVERY
# =========================
def arp_sweep_collect(interface: str, network: ipaddress.IPv4Network, timeout: float) -> List[Tuple[str, str]]:
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered = srp(packet, timeout=timeout, verbose=False, iface=interface)[0]
        result = []
        for _, received in answered:
            ip = str(received.psrc)
            mac = normalize_mac(str(received.hwsrc))
            if ip_in_network(ip, network) and is_real_mac(mac):
                result.append((ip, mac))
        return result
    except PermissionError:
        die_setup("No permission for ARP sweep. Run as Administrator/root.")
    except Exception:
        return []


def ping_once(ip: str) -> bool:
    try:
        if os.name == "nt":
            cmd = ["ping", "-n", "1", "-w", "250", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.2)
        return result.returncode == 0
    except Exception:
        return False


def scan_tcp_ports(ip: str, ports: Iterable[int], timeout: float = TCP_CONNECT_TIMEOUT) -> List[int]:
    open_ports: List[int] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()
    return open_ports


def liveness_probe(ip: str, use_tcp: bool, use_icmp: bool) -> Tuple[bool, List[int], bool]:
    open_ports = scan_tcp_ports(ip, TCP_LIVENESS_PORTS) if use_tcp else []
    if open_ports:
        return True, open_ports, False
    icmp_ok = ping_once(ip) if use_icmp else False
    return icmp_ok, [], icmp_ok


def active_discovery_loop(interface: str, network: ipaddress.IPv4Network, interval: float, tcp_workers: int, use_tcp: bool, use_icmp: bool) -> None:
    with ThreadPoolExecutor(max_workers=tcp_workers) as executor:
        while not STOP_EVENT.is_set():
            cycle_start = time.time()
            responses = arp_sweep_collect(interface, network, ARP_SWEEP_TIMEOUT)
            responded_macs: Set[str] = set()
            for ip, mac in responses:
                responded_macs.add(mac)
                submit_observation(Observation(kind="arp", ip=ip, mac=mac, source="arp-sweep", confidence=100), critical=True)

            snapshot = read_snapshot()
            targets = list(snapshot.all_targets) if snapshot else []
            futures = {}
            for mac, ip in targets:
                if mac in responded_macs:
                    continue
                futures[executor.submit(liveness_probe, ip, use_tcp, use_icmp)] = (mac, ip)

            for future in as_completed(futures):
                mac, ip = futures[future]
                try:
                    alive, open_ports, icmp_ok = future.result()
                except Exception:
                    alive, open_ports, icmp_ok = False, [], False
                if alive:
                    if icmp_ok:
                        submit_observation(Observation(kind="icmp", ip=ip, mac=mac, source="icmp", confidence=50))
                    for port in open_ports:
                        submit_observation(Observation(kind="tcp", ip=ip, mac=mac, port=port, service=service_name(port), source="tcp-liveness", confidence=65))
                else:
                    submit_observation(Observation(kind="probe_fail", ip=ip, mac=mac, source="active-probe", confidence=20))

            elapsed = time.time() - cycle_start
            STOP_EVENT.wait(max(0.05, interval - elapsed))


# =========================
# FINGERPRINT WORKERS
# =========================
def netbios_query(ip: str) -> Optional[str]:
    packet = (
        b"\x80\xf0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b" + b"\x41" * 30 + b"\x00\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(NETBIOS_TIMEOUT)
    try:
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(2048)
        if len(data) < 57:
            return None
        count = data[56]
        offset = 57
        for _ in range(count):
            raw = data[offset : offset + 15]
            suffix = data[offset + 15] if offset + 15 < len(data) else 0
            offset += 18
            name = raw.decode("ascii", errors="ignore").strip()
            if name and name != "*" and suffix in {0x00, 0x20, 0x03}:
                return compact(name, 64)
    except Exception:
        return None
    finally:
        sock.close()
    return None


def reverse_dns(ip: str) -> Optional[str]:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        host = socket.gethostbyaddr(ip)[0]
        return compact(host.split(".")[0], 64)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def fetch_http_title(session: requests.Session, ip: str, port: int) -> Tuple[Optional[str], Optional[str]]:
    schemes = ["https"] if port in TLS_PORTS else ["http"]
    if port in {443, 8443}:
        schemes = ["https", "http"]
    for scheme in schemes:
        try:
            response = session.get(f"{scheme}://{ip}:{port}/", timeout=HTTP_TIMEOUT, verify=False, allow_redirects=True)
            text = response.text[:100_000] if response.text else ""
            title = None
            if text:
                soup = BeautifulSoup(text, "html.parser")
                if soup.title and soup.title.string:
                    title = compact(soup.title.string, 80)
            server = compact(response.headers.get("server", ""), 80) if response.headers.get("server") else None
            if title or server:
                return title, server
        except Exception:
            continue
    return None, None


def tls_name(ip: str, port: int) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
        values: List[str] = []
        for tup in cert.get("subject", []):
            for key, value in tup:
                if key == "commonName":
                    values.append(str(value))
        for typ, value in cert.get("subjectAltName", []):
            if typ in {"DNS", "IP Address"}:
                values.append(str(value))
        return compact(values[0], 80) if values else None
    except Exception:
        return None


def lookup_vendor(mac: str) -> str:
    oui = normalize_mac(mac)[:8]
    with VENDOR_LOCK:
        cached = VENDOR_CACHE.get(oui)
    if cached:
        return cached
    with VENDOR_SEM:
        with VENDOR_LOCK:
            cached = VENDOR_CACHE.get(oui)
            if cached:
                return cached
        try:
            vendor = compact(lookup_vendor_local(mac, OUI_DB_PATH, allow_download=ENABLE_OUI_DOWNLOAD), 80)
        except Exception:
            vendor = UNKNOWN_VENDOR
        with VENDOR_LOCK:
            VENDOR_CACHE[oui] = vendor
        return vendor


def fast_fingerprint_worker() -> None:
    while not STOP_EVENT.is_set():
        try:
            job = FAST_QUEUE.get(timeout=0.3)
        except queue.Empty:
            continue
        try:
            name = netbios_query(job.ip)
            if name:
                submit_observation(Observation(kind="netbios", ip=job.ip, mac=job.mac, name=name, source="netbios-query", confidence=80))
            rdns = reverse_dns(job.ip)
            if rdns:
                submit_observation(Observation(kind="dns", ip=job.ip, mac=job.mac, name=rdns, source="reverse-dns", confidence=60))
        finally:
            FAST_QUEUE.task_done()


def slow_fingerprint_worker() -> None:
    session = requests.Session()
    session.headers.update({"User-Agent": "LAN-Watcher-Pro/2.0"})
    while not STOP_EVENT.is_set():
        try:
            job = SLOW_QUEUE.get(timeout=0.3)
        except queue.Empty:
            continue
        try:
            if ENABLE_TCP_PROBE:
                open_ports = scan_tcp_ports(job.ip, COMMON_TCP_PORTS, timeout=TCP_CONNECT_TIMEOUT)
                for port in open_ports:
                    submit_observation(Observation(kind="tcp", ip=job.ip, mac=job.mac, port=port, service=service_name(port), source="tcp-fingerprint", confidence=65))
                for port in [p for p in HTTP_PORTS if p in open_ports or p in {80, 443}]:
                    title, server = fetch_http_title(session, job.ip, port)
                    if title or server:
                        submit_observation(Observation(kind="http", ip=job.ip, mac=job.mac, name=title, port=port, value=server, source="http-title", confidence=55))
                for port in [p for p in TLS_PORTS if p in open_ports or p == 443]:
                    cert_name = tls_name(job.ip, port)
                    if cert_name:
                        submit_observation(Observation(kind="tls", ip=job.ip, mac=job.mac, port=port, value=cert_name, source="tls-cert", confidence=50))
            if ENABLE_VENDOR_API:
                vendor = lookup_vendor(job.mac)
                if vendor:
                    submit_observation(Observation(kind="vendor", ip=job.ip, mac=job.mac, value=vendor, source="oui-local", confidence=35))
        finally:
            SLOW_QUEUE.task_done()


# =========================
# ZEROCONF / MDNS
# =========================
def service_name_to_device_name(service_type: str, service_name: str, server: str) -> str:
    name = service_name
    if service_type and name.endswith(service_type):
        name = name[: -len(service_type)]
    name = name.strip(". ")
    if name:
        return compact(name, 80)
    return compact(server.rstrip("."), 80) if server else "-"


class MDNSListener(ServiceListener):
    def __init__(self, network: ipaddress.IPv4Network):
        self.network = network

    def add_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self._handle(zeroconf, service_type, name)

    def update_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self._handle(zeroconf, service_type, name)

    def remove_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        return

    def _handle(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        try:
            info = zeroconf.get_service_info(service_type, name, timeout=900)
            if not info:
                return
            try:
                ips = [ip for ip in info.parsed_addresses() if "." in ip]
            except Exception:
                ips = []
                for raw in getattr(info, "addresses", []):
                    if len(raw) == 4:
                        ips.append(socket.inet_ntoa(raw))
            device_name = service_name_to_device_name(service_type, name, getattr(info, "server", ""))
            for ip in ips:
                if ip_in_network(ip, self.network):
                    submit_observation(Observation(kind="mdns", ip=ip, name=device_name, service=service_type, source="mdns-zeroconf", confidence=95))
        except Exception:
            return


def mdns_loop(network: ipaddress.IPv4Network) -> None:
    zeroconf = Zeroconf()
    listener = MDNSListener(network)
    browsers = []
    try:
        for service_type in MDNS_TYPES:
            browsers.append(ServiceBrowser(zeroconf, service_type, listener))
        while not STOP_EVENT.is_set():
            time.sleep(0.5)
    finally:
        for browser in browsers:
            try:
                browser.cancel()
            except Exception:
                pass
        zeroconf.close()


# =========================
# TERMINAL UI
# =========================
def clear_screen() -> None:
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


class TerminalRenderer:
    def __init__(self) -> None:
        self.last_lines = 0
        self.started = False

    def draw(self, text: str) -> None:
        lines = text.splitlines()
        if not self.started:
            sys.stdout.write("\033[2J\033[H\033[?25l")
            self.started = True
        else:
            sys.stdout.write("\033[H")
        sys.stdout.write(text)
        sys.stdout.write("\033[J")
        sys.stdout.flush()
        self.last_lines = len(lines)

    def close(self) -> None:
        if self.started:
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()


def compute_columns(width: int) -> List[Tuple[str, int]]:
    width = max(92, width)
    fixed = [("IP", 15), ("MAC", 17), ("Conf", 4), ("Seen", 7)]
    remaining = width - 2 - sum(w + 3 for _, w in fixed) - 3 * 5
    vendor = max(12, min(24, remaining // 6))
    name = max(14, min(32, remaining // 4))
    dtype = max(10, min(16, remaining // 7))
    services = max(12, min(30, remaining // 4))
    sources = max(10, min(18, remaining // 8))
    traffic = max(18, min(34, remaining // 3))
    return [("IP", 15), ("MAC", 17), ("Likely", dtype + 8), ("NIC", vendor), ("Name", name), ("Conf", 4), ("Traffic", traffic), ("Seen", 7)]


def metric_line(snapshot: StateSnapshot, interval: float) -> str:
    traffic = "traffic=off"
    if snapshot.traffic_enabled:
        traffic = f"traffic RX={format_rate(snapshot.total_rx_kbps)} TX={format_rate(snapshot.total_tx_kbps)} top={snapshot.top_talker}"
    return (
        f"obs_q={snapshot.obs_qsize} | fast_q={snapshot.fast_qsize} | slow_q={snapshot.slow_qsize} | "
        f"dropped={snapshot.dropped_total} | obs/s={snapshot.obs_rate:.1f} | {traffic} | ui={interval:.2f}s"
    )


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    codes = {
        "green": "32",
        "yellow": "33",
        "red": "31",
        "cyan": "36",
        "blue": "34",
        "magenta": "35",
        "white": "37",
        "dim": "90",
        "bold": "1",
    }
    code = codes.get(color)
    return f"\033[{code}m{text}\033[0m" if code else text


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def visible_len(value: str) -> int:
    return len(ANSI_RE.sub("", value))


def pad_visible(value: str, width: int) -> str:
    plain_len = visible_len(value)
    if plain_len >= width:
        return value
    return value + " " * (width - plain_len)


def cell(value: object, width: int, color_name: Optional[str] = None, color: bool = False) -> str:
    text = compact(value, width)
    if color_name:
        text = colorize(text, color_name, color)
    return pad_visible(text, width)


def confidence_color(confidence: int) -> str:
    if confidence >= 70:
        return "green"
    if confidence >= 35:
        return "yellow"
    return "red"


def traffic_color(device: DeviceView) -> str:
    speed = device.rx_kbps + device.tx_kbps
    if speed >= 100:
        return "green"
    if speed >= 5:
        return "cyan"
    return "dim"


def status_color(status: str) -> str:
    return {
        "ACTIVE": "green",
        "ONLINE": "green",
        "QUIET": "dim",
        "SLEEP?": "yellow",
        "OFFLINE": "red",
    }.get(status, "white")


def role_color(role: str) -> str:
    return {
        "Gateway": "cyan",
        "Network": "cyan",
        "Client": "white",
        "Server": "yellow",
        "Printer": "blue",
        "Camera": "yellow",
    }.get(role, "white")


def device_type_color(device_type: str) -> str:
    mapping = {
        "Router/AP": "cyan",
        "Windows Desktop": "green",
        "Windows Laptop/PC": "green",
        "MacBook": "magenta",
        "iPhone/iPad": "magenta",
        "Apple Device": "magenta",
        "Android Phone": "green",
        "Camera/NVR": "yellow",
        "Printer": "blue",
        "TV/Cast": "cyan",
        "NAS/Server": "yellow",
        "Linux/Server": "yellow",
        "Unknown": "red",
    }
    return mapping.get(device_type, "white")


def type_summary(snapshot: StateSnapshot, width: int) -> str:
    if not snapshot.device_type_counts:
        return "Types     : none"
    parts = [f"{name}={count}" for name, count in sorted(snapshot.device_type_counts.items(), key=lambda item: (-item[1], item[0]))]
    return "Types     : " + compact(" | ".join(parts), max(40, width - 12))


def render_events(snapshot: StateSnapshot, width: int, color: bool = False) -> List[str]:
    rows: List[str] = []
    if snapshot.events:
        rows.append("")
        rows.append(colorize("Recent events", "bold", color))
        rows.append("-" * min(width, 120))
        for event in snapshot.events[:3]:
            event_color = "green"
            if "OFFLINE" in event:
                event_color = "yellow"
            elif "ERROR" in event or "DROP" in event:
                event_color = "red"
            rows.append("  " + colorize(compact(event, max(40, width - 4)), event_color, color))
    if snapshot.dropped_by_kind:
        drop_text = ", ".join(f"{k}:{v}" for k, v in sorted(snapshot.dropped_by_kind.items())[:8])
        rows.append(colorize(f"Drops: {compact(drop_text, max(40, width - 7))}", "red", color))
    return rows


def legend_line(label: str, description: str, width: int, color: bool, label_color: str = "cyan") -> str:
    prefix_plain = f"{label}: "
    available = max(20, width - len(prefix_plain))
    prefix = colorize(label, label_color, color) + ": "
    return prefix + compact(description, available)


def render_legend(width: int, color: bool = False) -> List[str]:
    rows = [
        "",
        colorize("Chú thích", "bold", color),
        "-" * min(width, 120),
        legend_line("IP", "địa chỉ thiết bị trong subnet hiện tại", width, color, "cyan"),
        legend_line("Name", "tên máy học từ DHCP/mDNS/NetBIOS/DNS/HTTP", width, color, "cyan"),
        legend_line("Type", "loại thiết bị dự đoán như Router/AP, Windows Laptop/PC, iPhone/iPad, Camera/NVR", width, color, "magenta"),
        legend_line("Conf", "độ tin cậy dự đoán; cao hơn nghĩa là có nhiều bằng chứng hơn", width, color, "yellow"),
        legend_line("NIC/Card", "hãng card mạng; Private/Randomized MAC nghĩa là thiết bị đang ẩn vendor thật", width, color, "cyan"),
        legend_line("RX/TX", "lưu lượng nhận/gửi mà máy này quan sát được", width, color, "green"),
        legend_line("Pkt/s", "số gói mỗi giây; cao liên tục thường là máy đang hoạt động mạng", width, color, "green"),
        legend_line("Seen", "lần cuối thiết bị còn được thấy online", width, color, "yellow"),
        legend_line("Status", "ACTIVE/QUIET/SLEEP? chỉ áp dụng cho thiết bị còn online trong 10 giây gần nhất", width, color, "green"),
        legend_line("Role", "vai trò dự đoán: Gateway, Client, Server, Printer, Camera, Network", width, color, "cyan"),
        legend_line("hidden", "thiết bị đã thấy trong phiên này nhưng offline quá 10 giây nên bị ẩn khỏi bảng chính", width, color, "yellow"),
        legend_line("queues", "hàng đợi xử lý obs/fast/slow", width, color, "cyan"),
        legend_line("dropped", "dữ liệu bị bỏ khi quá tải; nếu tăng nhiều thì nên giảm tốc độ quét", width, color, "red"),
        legend_line("Màu", "xanh=tốt/đang hoạt động | vàng=trung bình | đỏ=thấp/không chắc | tím=Apple | xanh lam=router/IP", width, color, "bold"),
        legend_line("Lưu ý", "Traffic là lưu lượng quan sát được bằng Npcap trên máy này, không phải tổng traffic từ router", width, color, "red"),
        "",
        colorize("Mẹo đọc nhanh", "bold", color),
        "-" * min(width, 120),
        legend_line("Máy đang dùng mạng", "RX/TX hoặc Pkt/s tăng liên tục; TX cao thường là máy đang upload/gửi dữ liệu", width, color, "green"),
        legend_line("Máy tải dữ liệu", "RX cao; video call/game/stream thường làm RX/TX và Pkt/s thay đổi liên tục", width, color, "green"),
        legend_line("Máy có thể đang off", "biến mất khỏi bảng online hoặc hidden tăng; quá 10 giây không thấy sẽ bị ẩn", width, color, "yellow"),
        legend_line("Máy ngủ/tiết kiệm pin", "có thể vẫn hiện nếu còn trả lời ARP/TCP, nhưng traffic gần 0 và Seen tăng chậm", width, color, "yellow"),
        legend_line("Private/Randomized MAC", "thiết bị dùng MAC riêng tư nên vendor thật có thể không xác định được", width, color, "magenta"),
        legend_line("Conf thấp", "không phải lỗi; nghĩa là tool chưa có đủ hostname/service/vendor để đoán chắc loại thiết bị", width, color, "red"),
        legend_line("Dữ liệu cũ", "state cũ không tự tạo hàng trên bảng; chỉ thiết bị có tín hiệu trong phiên chạy hiện tại mới hiện", width, color, "red"),
    ]
    return rows


def render_wide_table(snapshot: StateSnapshot, interface: str, network: ipaddress.IPv4Network, interval: float, width: int) -> str:
    columns = compute_columns(width)
    line = "+" + "+".join("-" * (width + 2) for _, width in columns) + "+"
    rows = [
        "LAN Watcher Pro | online devices only | wide table",
        f"Interface: {display_interface(interface)} | Subnet: {network} | Online: {snapshot.online_count} | Hidden offline: {snapshot.hidden_offline_count}",
        metric_line(snapshot, interval),
        line,
        "|" + "|".join(f" {name:<{width}} " for name, width in columns) + "|",
        line,
    ]
    if not snapshot.devices_online:
        empty = "No online devices visible yet. ARP heartbeat is running; sleeping clients may stay hidden."
        total_width = len(line) - 4
        rows.append(f"| {compact(empty, total_width):<{total_width}} |")
    for device in snapshot.devices_online:
        values = {
            "IP": device.ip,
            "MAC": device.mac,
            "Likely": device.likely,
            "NIC": device.nic_vendor,
            "Name": device.name,
            "Type": device.device_type,
            "Conf": str(device.confidence),
            "Traffic": f"{format_rate(device.rx_kbps + device.tx_kbps)} {device.usage_bar}",
            "Sources": device.sources,
            "Seen": device.seen,
        }
        rows.append("|" + "|".join(f" {compact(values[name], width):<{width}} " for name, width in columns) + "|")
    rows.append(line)
    rows.extend(render_events(snapshot, width))
    return "\n".join(rows)


def table_column_widths(width: int) -> List[Tuple[str, int]]:
    width = max(96, min(width, 220))
    sep_total = lambda count: 3 * max(0, count - 1)

    if width < 128:
        fixed = [("#", 3), ("IP", 15), ("Status", 8), ("RX", 9), ("TX", 9), ("Seen", 6)]
        remaining = width - sum(col_width for _, col_width in fixed) - sep_total(len(fixed) + 2)
        name = max(12, min(22, remaining - 12))
        dtype = max(10, remaining - name)
        return [("#", 3), ("IP", 15), ("Name", name), ("Status", 8), ("Type", dtype), ("RX", 9), ("TX", 9), ("Seen", 6)]

    if width < 170:
        fixed = [("#", 3), ("IP", 15), ("Status", 8), ("Role", 8), ("Conf", 5), ("RX", 9), ("TX", 9), ("Seen", 6)]
        remaining = width - sum(col_width for _, col_width in fixed) - sep_total(len(fixed) + 3)
        name = max(14, min(28, int(remaining * 0.42)))
        dtype = max(12, min(18, int(remaining * 0.30)))
        nic = max(8, remaining - name - dtype)
        return [
            ("#", 3),
            ("IP", 15),
            ("Name", name),
            ("Status", 8),
            ("Role", 8),
            ("Type", dtype),
            ("Conf", 5),
            ("NIC/Card", nic),
            ("RX", 9),
            ("TX", 9),
            ("Seen", 6),
        ]

    fixed = [("#", 3), ("IP", 15), ("Status", 8), ("Role", 8), ("Conf", 5), ("RX", 9), ("TX", 9), ("Pkt/s", 7), ("Seen", 6)]
    remaining = width - sum(col_width for _, col_width in fixed) - sep_total(len(fixed) + 3)
    name = max(18, min(46, int(remaining * 0.38)))
    dtype = max(16, min(22, int(remaining * 0.24)))
    nic = max(18, remaining - name - dtype)
    return [
        ("#", 3),
        ("IP", 15),
        ("Name", name),
        ("Status", 8),
        ("Role", 8),
        ("Type", dtype),
        ("Conf", 5),
        ("NIC/Card", nic),
        ("RX", 9),
        ("TX", 9),
        ("Pkt/s", 7),
        ("Seen", 6),
    ]


def table_divider(columns: List[Tuple[str, int]], char: str = "-") -> str:
    return "-+-".join(char * width for _, width in columns)


def render_device_table(snapshot: StateSnapshot, interface: str, network: ipaddress.IPv4Network, interval: float, width: int, color: bool = True) -> str:
    width = max(96, min(width, 220))
    columns = table_column_widths(width)
    col_width = dict(columns)
    sep = " | "
    divider = table_divider(columns)
    strong_divider = table_divider(columns, "=")
    header = sep.join(cell(name, col_width, "bold", color) for name, col_width in columns)
    rows = [
        colorize("LAN WATCHER PRO - ONLINE DEVICES", "bold", color),
        compact(f"Subnet {network} | Interface {display_interface(interface)}", width),
        compact(f"Online {snapshot.online_count} | Hidden {snapshot.hidden_offline_count} | {type_summary(snapshot, width).replace('Types     : ', 'Types ')}", width),
        compact(f"Traffic RX {format_rate(snapshot.total_rx_kbps)} | TX {format_rate(snapshot.total_tx_kbps)} | Top {snapshot.top_talker}", width),
        compact(f"Runtime obs/s {snapshot.obs_rate:.1f} | queues obs/fast/slow {snapshot.obs_qsize}/{snapshot.fast_qsize}/{snapshot.slow_qsize} | dropped {snapshot.dropped_total} | refresh {interval:.2f}s", width),
        strong_divider,
        header,
        strong_divider,
    ]
    if not snapshot.devices_online:
        rows.append(colorize("No online devices visible yet. Waiting for ARP/DHCP/mDNS/active probes.", "yellow", color))
        if snapshot.show_events:
            rows.extend(render_events(snapshot, width, color=color))
        if snapshot.show_legend:
            rows.extend(render_legend(width, color=color))
        return "\n".join(rows)

    def sort_key(item: DeviceView) -> Tuple[object, ...]:
        if snapshot.sort_mode == "ip":
            return (ip_sort_key(item.ip),)
        if snapshot.sort_mode == "confidence":
            return (-item.confidence, ip_sort_key(item.ip))
        return (-(item.rx_kbps + item.tx_kbps), ip_sort_key(item.ip))

    ordered_devices = sorted(snapshot.devices_online, key=sort_key)
    for index, device in enumerate(ordered_devices, start=1):
        row_cells = {
            "#": cell(f"{index:02d}", col_width.get("#", 3), "bold", color),
            "IP": cell(device.ip, col_width.get("IP", 15), "cyan", color),
            "Name": cell(device.name if device.name != "not learned yet" else "-", col_width.get("Name", 18), None if device.name != "not learned yet" else "dim", color),
            "Status": cell(device.status, col_width.get("Status", 8), status_color(device.status), color),
            "Role": cell(device.role, col_width.get("Role", 8), role_color(device.role), color),
            "Type": cell(device.device_type, col_width.get("Type", 16), device_type_color(device.device_type), color),
            "Conf": cell(f"{device.confidence}%", col_width.get("Conf", 5), confidence_color(device.confidence), color),
            "NIC/Card": cell(device.nic_vendor, col_width.get("NIC/Card", 18), None, color),
            "RX": cell(format_rate(device.rx_kbps), col_width.get("RX", 9), traffic_color(device), color),
            "TX": cell(format_rate(device.tx_kbps), col_width.get("TX", 9), traffic_color(device), color),
            "Pkt/s": cell(f"{device.packet_rate:.1f}", col_width.get("Pkt/s", 7), traffic_color(device), color),
            "Seen": cell(device.seen, col_width.get("Seen", 6), None, color),
        }
        rows.append(sep.join(row_cells[name] for name, _ in columns))
    rows.append(divider)
    if snapshot.show_events:
        rows.extend(render_events(snapshot, width, color=color))
    else:
        rows.append(colorize(compact("Hint: events hidden. Remove --no-events to show them.", width), "dim", color))
    if snapshot.show_legend:
        rows.extend(render_legend(width, color=color))
    else:
        rows.append(colorize(compact("Hint: dùng --show-help để hiện chú thích tiếng Việt; --ui-mode detail để xem bằng chứng từng máy.", width), "dim", color))
    return "\n".join(rows)


def card_border(width: int) -> str:
    return "+" + "-" * (width - 2) + "+"


def card_line(text: str, width: int) -> str:
    inner = width - 4
    return f"| {compact(text, inner):<{inner}} |"


def card_wrapped(label: str, value: str, width: int) -> List[str]:
    inner = width - 4
    prefix = f"{label:<10}: "
    wrap_width = max(20, inner - len(prefix))
    chunks = textwrap.wrap(str(value or "-"), width=wrap_width, replace_whitespace=True, drop_whitespace=True) or ["-"]
    rows = [card_line(prefix + chunks[0], width)]
    for chunk in chunks[1:4]:
        rows.append(card_line(" " * len(prefix) + chunk, width))
    return rows


def render_card_view(snapshot: StateSnapshot, interface: str, network: ipaddress.IPv4Network, interval: float, width: int, color: bool = True) -> str:
    width = max(88, min(width, 140))
    divider = "-" * min(width, 120)
    traffic_state = "observed traffic only" if snapshot.traffic_enabled else "disabled"
    rows = [
        colorize("LAN WATCHER PRO - ONLINE DEVICE DASHBOARD", "bold", color),
        f"{colorize('Network', 'cyan', color)}   {display_interface(interface)} | {network}",
        f"{colorize('Devices', 'cyan', color)}   online={colorize(str(snapshot.online_count), 'green', color)} | hidden_offline={snapshot.hidden_offline_count} | {type_summary(snapshot, width).replace('Types     : ', 'types=')}",
        f"{colorize('Traffic', 'cyan', color)}   {traffic_state} | RX={colorize(format_rate(snapshot.total_rx_kbps), 'green', color)} | TX={colorize(format_rate(snapshot.total_tx_kbps), 'green', color)} | top={compact(snapshot.top_talker, 54)}",
        f"{colorize('Runtime', 'cyan', color)}   obs/s={snapshot.obs_rate:.1f} | queues obs={snapshot.obs_qsize} fast={snapshot.fast_qsize} slow={snapshot.slow_qsize} | dropped={colorize(str(snapshot.dropped_total), 'red' if snapshot.dropped_total else 'green', color)} | ui={interval:.2f}s",
        divider,
    ]
    if not snapshot.devices_online:
        rows.append(colorize("No online devices visible yet. Waiting for ARP/DHCP/mDNS/active probes.", "yellow", color))
        rows.extend(render_events(snapshot, width, color=color))
        return "\n".join(rows)

    ordered_devices = sorted(snapshot.devices_online, key=lambda item: (-(item.rx_kbps + item.tx_kbps), ip_sort_key(item.ip)))
    for index, device in enumerate(ordered_devices, start=1):
        speed = device.rx_kbps + device.tx_kbps
        dtype = colorize(device.device_type, device_type_color(device.device_type), color)
        conf = colorize(f"{device.confidence}%", confidence_color(device.confidence), color)
        traffic = colorize(f"{format_rate(speed)} {device.usage_bar}", traffic_color(device), color)
        name = compact(device.name, 34)
        if name == "not learned yet":
            name = colorize(name, "dim", color)
        rows.append(f"{colorize(f'[{index:02d}]', 'bold', color)} {colorize(device.ip, 'cyan', color)}  {name}  {dtype} {conf}  {traffic}")
        rows.append(f"     MAC {device.mac} | NIC {compact(device.nic_vendor, 34)} | seen {device.seen} | last traffic {device.last_traffic}")
        rows.append(f"     Traffic  RX {colorize(format_rate(device.rx_kbps), 'green', color)} | TX {colorize(format_rate(device.tx_kbps), 'green', color)} | {device.packet_rate:.1f} pkt/s | total {device.total_mb:.2f} MB")
        rows.append(f"     Services {compact(device.services, max(48, width - 14))}")
        rows.append(f"     Evidence {compact(device.why, max(48, width - 14))}")
        rows.append(divider)
    rows.extend(render_events(snapshot, width, color=color))
    return "\n".join(rows)


def render_dashboard(snapshot: StateSnapshot, interface: str, network: ipaddress.IPv4Network, interval: float, width: int, color: bool = True) -> str:
    return render_device_table(snapshot, interface, network, interval, width, color=color)


def render_table(snapshot: StateSnapshot, interface: str, network: ipaddress.IPv4Network, interval: float, ui_mode: str = "dashboard", color: bool = True) -> str:
    term = shutil.get_terminal_size((140, 30))
    if ui_mode == "table":
        return render_device_table(snapshot, interface, network, interval, term.columns, color=color)
    if ui_mode in {"cards", "detail"}:
        return render_card_view(snapshot, interface, network, interval, term.columns, color=color)
    return render_dashboard(snapshot, interface, network, interval, term.columns, color=color)


def ui_loop(interface: str, network: ipaddress.IPv4Network, interval: float, ui_mode: str = "dashboard", color: bool = True) -> None:
    renderer = TerminalRenderer()
    try:
        while not STOP_EVENT.is_set():
            snapshot = read_snapshot()
            if snapshot:
                frame = render_table(snapshot, interface, network, interval, ui_mode=ui_mode, color=color)
            else:
                frame = "LAN Watcher Pro starting..."
            renderer.draw(frame)
            STOP_EVENT.wait(interval)
    finally:
        renderer.close()


# =========================
# CLI / MAIN
# =========================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LAN Watcher Pro - aggressive realtime LAN inventory.")
    parser.add_argument("--profile", choices=["aggressive", "balanced", "passive"], default=DEFAULT_PROFILE)
    parser.add_argument("--iface", help="Interface/Npcap device. Empty means auto.")
    parser.add_argument("--subnet", help="CIDR override, e.g. 192.168.1.0/24.")
    parser.add_argument("--range", dest="range_cidr", help="Backward-compatible alias for --subnet.")
    parser.add_argument("--offline-after", type=float, default=DEFAULT_OFFLINE_AFTER)
    parser.add_argument("--offline-fail-threshold", type=int, default=DEFAULT_OFFLINE_FAIL_THRESHOLD)
    parser.add_argument("--ui-interval", type=float, default=DEFAULT_UI_INTERVAL)
    parser.add_argument("--sweep-interval", type=float, default=DEFAULT_SWEEP_INTERVAL)
    parser.add_argument("--tcp-workers", type=int, default=DEFAULT_TCP_WORKERS)
    parser.add_argument("--slow-workers", type=int, default=DEFAULT_SLOW_WORKERS)
    parser.add_argument("--state-file", help="State file override. Default is state/<current-subnet>.json.")
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help="Directory for per-subnet state files.")
    parser.add_argument("--alias-file", default=DEFAULT_ALIAS_FILE, help="Optional JSON map of MAC/IP to friendly names.")
    parser.add_argument("--ui-mode", choices=["dashboard", "cards", "detail", "table"], default="table", help="Terminal UI layout.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in the terminal UI.")
    parser.add_argument("--no-events", dest="show_events", action="store_false", default=True, help="Hide Recent events.")
    parser.add_argument("--show-events", dest="show_events", action="store_true", help="Show Recent events.")
    parser.add_argument("--no-legend", dest="show_legend", action="store_false", default=False, help="Keep Vietnamese legend/help hidden. This is the default.")
    parser.add_argument("--show-help", dest="show_legend", action="store_true", help="Show Vietnamese legend/help.")
    parser.add_argument("--sort", choices=["traffic", "ip", "confidence"], default="traffic", help="Sort devices in the table.")
    parser.add_argument("--only-active-traffic", action="store_true", help="Show only devices with active observed traffic.")
    parser.add_argument("--hide-unknown", action="store_true", help="Hide devices classified as Unknown.")
    parser.add_argument("--min-confidence", type=int, default=0, help="Hide devices below this confidence percentage.")
    parser.add_argument("--traffic-window", type=float, default=DEFAULT_TRAFFIC_WINDOW, help="Seconds used for live RX/TX rate smoothing.")
    parser.add_argument("--no-traffic", action="store_true", help="Disable best-effort per-device traffic accounting.")
    parser.add_argument("--oui-db", default=DEFAULT_OUI_DB, help="Offline OUI CSV cache path for NIC/Wi-Fi vendor lookup.")
    parser.add_argument("--refresh-oui-db", action="store_true", help="Download and replace the local OUI CSV before scanning.")
    parser.add_argument("--no-oui-download", action="store_true", help="Do not auto-download the OUI CSV when it is missing.")
    parser.add_argument("--export-json")
    parser.add_argument("--export-csv")
    parser.add_argument("--event-log")
    parser.add_argument("--no-icmp", action="store_true")
    parser.add_argument("--no-tcp-probe", action="store_true")
    parser.add_argument("--no-mdns", action="store_true")
    parser.add_argument("--no-ssdp", action="store_true")
    parser.add_argument("--no-vendor-api", action="store_true", help="Backward-compatible alias: disable vendor/OUI lookup.")
    return parser.parse_args()


def apply_profile(args: argparse.Namespace) -> None:
    if args.profile == "balanced":
        if args.sweep_interval == DEFAULT_SWEEP_INTERVAL:
            args.sweep_interval = 4.0
        if args.tcp_workers == DEFAULT_TCP_WORKERS:
            args.tcp_workers = 32
        if args.slow_workers == DEFAULT_SLOW_WORKERS:
            args.slow_workers = 6
    elif args.profile == "passive":
        args.no_tcp_probe = True
        if args.sweep_interval == DEFAULT_SWEEP_INTERVAL:
            args.sweep_interval = 10.0
        if args.slow_workers == DEFAULT_SLOW_WORKERS:
            args.slow_workers = 2


def install_signal_handlers() -> None:
    def handler(_signum, _frame) -> None:
        STOP_EVENT.set()

    try:
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    except Exception:
        pass


def startup_warning() -> None:
    print("[!] Dependencies: pip install scapy requests beautifulsoup4 zeroconf")
    if os.name == "nt":
        print("[!] Windows: install Npcap, enable WinPcap API-compatible Mode, run as Administrator.")
    print("[!] Authorized LAN only. No MITM/deauth/bruteforce/exploit.")


def configure_windows_console() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        stdin = kernel32.GetStdHandle(-10)
        stdout = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(stdin, ctypes.byref(mode)):
            return

        enable_extended_flags = 0x0080
        enable_quick_edit_mode = 0x0040
        enable_mouse_input = 0x0010
        new_mode = mode.value
        new_mode |= enable_extended_flags
        new_mode &= ~enable_quick_edit_mode
        new_mode &= ~enable_mouse_input
        kernel32.SetConsoleMode(stdin, new_mode)
        out_mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(stdout, ctypes.byref(out_mode)):
            enable_virtual_terminal_processing = 0x0004
            kernel32.SetConsoleMode(stdout, out_mode.value | enable_virtual_terminal_processing)
        try:
            os.system("mode con: cols=200 lines=45 > nul")
        except Exception:
            pass
    except Exception:
        pass


def main() -> None:
    global ENABLE_MDNS, ENABLE_SSDP, ENABLE_TCP_PROBE, ENABLE_VENDOR_API, OUI_DB_PATH, ENABLE_OUI_DOWNLOAD
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if os.name == "nt":
        os.system("chcp 65001 > nul")
        configure_windows_console()
    args = parse_args()
    apply_profile(args)
    ENABLE_MDNS = not args.no_mdns
    ENABLE_SSDP = not args.no_ssdp
    ENABLE_TCP_PROBE = not args.no_tcp_probe
    ENABLE_VENDOR_API = not args.no_vendor_api
    OUI_DB_PATH = args.oui_db
    ENABLE_OUI_DOWNLOAD = not args.no_oui_download
    install_signal_handlers()
    startup_warning()

    if not is_admin():
        die_setup("Administrator/root permission required for reliable Scapy sniffing and ARP sweep.")

    interface = args.iface or get_default_interface()
    subnet = args.subnet or args.range_cidr
    try:
        network = detect_network(interface, subnet)
    except Exception as exc:
        print("[-] Could not detect subnet:", exc)
        sys.exit(1)

    state_file = args.state_file or subnet_state_file(network, args.state_dir)
    oui_records = 0
    if ENABLE_VENDOR_API:
        try:
            oui_records = len(ensure_oui_db(args.oui_db, refresh=args.refresh_oui_db, allow_download=ENABLE_OUI_DOWNLOAD, timeout=10.0))
        except Exception:
            oui_records = 0
    initial_devices = load_state(state_file)
    aliases = load_aliases(args.alias_file)
    gateway_ip = get_default_gateway_ip()
    manager = StateManager(
        initial_devices,
        args.offline_after,
        args.offline_fail_threshold,
        state_file,
        args.event_log,
        gateway_ip=gateway_ip,
        traffic_window=args.traffic_window,
        traffic_enabled=not args.no_traffic,
        network=network,
        aliases=aliases,
        sort_mode=args.sort,
        only_active_traffic=args.only_active_traffic,
        hide_unknown=args.hide_unknown,
        min_confidence=args.min_confidence,
        show_events=args.show_events,
        show_legend=args.show_legend,
    )

    print(f"[+] Interface: {interface}")
    print(f"[+] Subnet:    {network}")
    print(f"[+] Gateway:   {gateway_ip or 'unknown'}")
    print(f"[+] Profile:   {args.profile}")
    print(f"[+] State:     {state_file} ({len(initial_devices)} loaded; realtime rows only)")
    if ENABLE_VENDOR_API:
        mode = "download off" if args.no_oui_download else "auto-download"
        print(f"[+] OUI DB:    {args.oui_db} ({oui_records} prefixes; {mode})")
    else:
        print("[+] OUI DB:    disabled")
    print(f"[+] Aliases:   {args.alias_file} ({len(aliases)} loaded)")
    time.sleep(1.0)

    ui_target = ui_loop
    ui_args = (interface, network, args.ui_interval, args.ui_mode, not args.no_color)

    # KHÔNG chạy UI trong luồng phụ (daemon) nữa vì luồng phụ không bắt được Ctrl+C chuẩn xác
    threads: List[threading.Thread] = [
        threading.Thread(target=manager.run, name="state-manager"),
        threading.Thread(target=packet_sniffer_loop, args=(interface, network, not args.no_traffic), daemon=True, name="packet-sniffer"),
    ]

    if args.profile != "passive":
        threads.append(
            threading.Thread(
                target=active_discovery_loop,
                args=(interface, network, args.sweep_interval, max(1, args.tcp_workers), ENABLE_TCP_PROBE, not args.no_icmp),
                daemon=True,
                name="active-discovery",
            )
        )
    if not args.no_mdns:
        threads.append(threading.Thread(target=mdns_loop, args=(network,), daemon=True, name="mdns-zeroconf"))
    for _ in range(FAST_WORKER_COUNT):
        threads.append(threading.Thread(target=fast_fingerprint_worker, daemon=True, name="fast-fingerprint"))
    for _ in range(max(1, args.slow_workers)):
        threads.append(threading.Thread(target=slow_fingerprint_worker, daemon=True, name="slow-fingerprint"))

    for thread in threads:
        thread.start()

    try:
        # Chạy UI ở luồng chính (Main Thread) để tự do xử lý Ctrl+C
        ui_target(*ui_args)
    except KeyboardInterrupt:
        STOP_EVENT.set()
    finally:
        STOP_EVENT.set()
        for thread in threads:
            if thread.name == "state-manager":
                thread.join(timeout=SHUTDOWN_DRAIN_SECONDS + 2.0)
        if args.export_json:
            manager.export_json(args.export_json)
        if args.export_csv:
            manager.export_csv(args.export_csv)
        clear_screen()
        print("[+] LAN Watcher Pro stopped.")
        print(f"[+] State saved: {state_file}")
        if args.export_json:
            print(f"[+] JSON exported: {args.export_json}")
        if args.export_csv:
            print(f"[+] CSV exported: {args.export_csv}")


if __name__ == "__main__":
    main()
