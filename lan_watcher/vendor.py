"""Offline OUI vendor lookup for LAN Watcher.

The scanner should not depend on a live per-MAC API while fingerprint workers
are running. This module keeps a small in-memory dict loaded from a cached CSV
and downloads that CSV at most once when allowed.
"""

from __future__ import annotations

import csv
import os
import re
import threading
from typing import Dict, Optional

OUI_DB_URL = "https://maclookup.app/downloads/csv-database/get-db"
UNKNOWN_VENDOR = "Unknown/Private MAC"

_LOCK = threading.Lock()
_DB: Dict[str, str] = {}
_LOADED_PATH: Optional[str] = None
_DOWNLOAD_FAILED = False


def normalize_oui(value: str) -> str:
    """Return the 6-hex OUI prefix from a MAC/prefix string."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    return cleaned[:6]


def _first_value(row: Dict[str, str], names: list[str]) -> str:
    lowered = {str(key).strip().lower(): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value:
            return str(value).strip()
    return ""


def parse_oui_csv(path: str) -> Dict[str, str]:
    """Parse common OUI CSV layouts into prefix -> vendor."""
    db: Dict[str, str] = {}
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            prefix = normalize_oui(
                _first_value(
                    row,
                    [
                        "mac prefix",
                        "macPrefix",
                        "mac_prefix",
                        "prefix",
                        "assignment",
                        "Assignment",
                        "oui",
                    ],
                )
            )
            vendor = _first_value(
                row,
                [
                    "vendor name",
                    "vendorName",
                    "vendor_name",
                    "vendor",
                    "organization",
                    "Organization Name",
                    "company",
                ],
            )
            if prefix and vendor:
                db[prefix] = vendor[:120]
    return db


def download_oui_db(path: str, timeout: float = 10.0) -> bool:
    import requests

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp_path = f"{path}.tmp"
    response = requests.get(OUI_DB_URL, timeout=timeout)
    if response.status_code != 200 or not response.content:
        return False
    with open(tmp_path, "wb") as handle:
        handle.write(response.content)
    os.replace(tmp_path, path)
    return True


def ensure_oui_db(path: str, refresh: bool = False, allow_download: bool = True, timeout: float = 10.0) -> Dict[str, str]:
    """Load the local OUI DB, optionally downloading it once if missing."""
    global _DB, _LOADED_PATH, _DOWNLOAD_FAILED
    with _LOCK:
        if _LOADED_PATH == path and _DB and not refresh:
            return _DB

        if (refresh or not os.path.exists(path)) and allow_download and not _DOWNLOAD_FAILED:
            try:
                if not download_oui_db(path, timeout=timeout):
                    _DOWNLOAD_FAILED = True
            except Exception:
                _DOWNLOAD_FAILED = True

        try:
            _DB = parse_oui_csv(path) if os.path.exists(path) else {}
            _LOADED_PATH = path
        except Exception:
            _DB = {}
            _LOADED_PATH = path
        return _DB


def lookup_vendor_local(mac: str, path: str, allow_download: bool = True) -> str:
    db = ensure_oui_db(path, refresh=False, allow_download=allow_download)
    prefix = normalize_oui(mac)
    if not prefix:
        return UNKNOWN_VENDOR
    return db.get(prefix, UNKNOWN_VENDOR)


def reset_oui_cache() -> None:
    global _DB, _LOADED_PATH, _DOWNLOAD_FAILED
    with _LOCK:
        _DB = {}
        _LOADED_PATH = None
        _DOWNLOAD_FAILED = False
