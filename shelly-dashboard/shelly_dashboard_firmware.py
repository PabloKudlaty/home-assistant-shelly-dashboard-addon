#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shelly Dashboard – refactored v2
=================================
Flask‑based web dashboard for discovering, monitoring, and controlling
Shelly smart‑home devices on the local network.

Changes from v1
----------------
* PEP 8 formatting & descriptive variable names
* Proper thread‑safety (lock discipline, deep copies)
* Per‐thread ``requests.Session`` for connection reuse
* ``gen()`` now sends authentication credentials
* Generation caching to avoid redundant HTTP roundtrips
* ``query()`` split into ``_query_gen1`` / ``_query_gen2``
* SSRF protection in ``api_add`` (IP validation)
* CIDR scan guard (max 1024 hosts)
* Health‑score constants extracted to module level
* Structured logging instead of silent ``except: pass``
* Optional API‑key authentication on mutating endpoints
* Type hints and docstrings throughout
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, render_template_string
import requests
import requests.auth

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

    HAS_ZEROCONF = True
except Exception:
    HAS_ZEROCONF = False

# ── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)

# ── Flask app ────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Health‑score constants ───────────────────────────────────────────
HEALTH_WEIGHT_ONLINE = 35
HEALTH_WEIGHT_WEB_OK = 15
HEALTH_WEIGHT_WEB_AUTH = 10
HEALTH_WEIGHT_FW_LATEST = 15
HEALTH_WEIGHT_FW_UPDATE = 7
HEALTH_WEIGHT_RSSI_GOOD = 10
HEALTH_WEIGHT_RSSI_FAIR = 7
HEALTH_WEIGHT_RSSI_WEAK = 3
HEALTH_WEIGHT_CONNECTIVITY = 10
HEALTH_WEIGHT_NO_ERROR = 5
HEALTH_WEIGHT_UPTIME_OK = 5
HEALTH_WEIGHT_LATENCY_FAST = 5
HEALTH_WEIGHT_LATENCY_MED = 3
HEALTH_WEIGHT_LATENCY_SLOW = 1

RSSI_GOOD = -60
RSSI_FAIR = -70
RSSI_WEAK = -80

UPTIME_MIN_SECONDS = 300
LATENCY_FAST_MS = 500
LATENCY_MED_MS = 1000
LATENCY_SLOW_MS = 2000

HEALTH_LEVEL_GOOD = 85
HEALTH_LEVEL_WARN = 60

MAX_SCAN_HOSTS = 1024

# ── Global application state ────────────────────────────────────────

@dataclass
class Config:
    """Runtime configuration populated from CLI arguments."""

    timeout: float = 3.0
    refresh: int = 15
    mdns_timeout: float = 5.0
    user: Optional[str] = None
    password: Optional[str] = None
    devices: List[str] = field(default_factory=list)
    network: Optional[str] = None
    use_mdns: bool = True
    api_key: Optional[str] = None


class State:
    """Thread‑safe container for device data and status flags."""

    def __init__(self) -> None:
        self.devices: Dict[str, dict] = {}
        self.lock: threading.Lock = threading.Lock()
        self.refreshing: bool = False
        self.firmware_checking: bool = False
        self.last_refresh: Optional[str] = None
        self.last_firmware_check: Optional[str] = None
        self.cfg: Config = Config()


state = State()

# ── Per‑thread requests.Session ──────────────────────────────────────
_thread_local = threading.local()


def _get_session() -> requests.Session:
    """Return a ``requests.Session`` local to the current thread."""
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
    return _thread_local.session


# ── Utility helpers ──────────────────────────────────────────────────

def _now() -> str:
    """ISO‑8601 timestamp truncated to seconds."""
    return datetime.now().isoformat(timespec="seconds")


def _auth_gen1() -> Optional[Tuple[str, str]]:
    """HTTP Basic‑Auth tuple for Gen 1 devices (or ``None``)."""
    if state.cfg.user and state.cfg.password:
        return (state.cfg.user, state.cfg.password)
    return None


def _auth_gen2() -> Optional[requests.auth.HTTPDigestAuth]:
    """HTTP Digest‑Auth object for Gen 2+ devices (or ``None``)."""
    if state.cfg.password:
        username = state.cfg.user or "admin"
        return requests.auth.HTTPDigestAuth(username, state.cfg.password)
    return None


def _get_cached_generation(ip: str) -> int:
    """Return generation from cache, or 0 if unknown."""
    with state.lock:
        return int(state.devices.get(ip, {}).get("generation", 0))


def detect_generation(ip: str) -> int:
    """
    Detect the Shelly generation by querying ``/shelly``.

    Returns 1 or 2+ on success, 0 on failure.  Uses cached value first.
    """
    cached = _get_cached_generation(ip)
    if cached:
        return cached

    session = _get_session()
    for auth in (_auth_gen1(), _auth_gen2(), None):
        try:
            resp = session.get(
                f"http://{ip}/shelly",
                timeout=state.cfg.timeout,
                auth=auth,
            )
            if resp.status_code == 200:
                generation = int(resp.json().get("gen", 1))
                # cache it
                with state.lock:
                    state.devices.setdefault(ip, {"ip": ip})["generation"] = generation
                return generation
        except requests.RequestException as exc:
            log.debug("gen() auth attempt failed for %s: %s", ip, exc)
        except (ValueError, KeyError) as exc:
            log.debug("gen() parse error for %s: %s", ip, exc)
    return 0


# ── mDNS discovery ──────────────────────────────────────────────────

if HAS_ZEROCONF:
    class ShellyListener(ServiceListener):
        """Zeroconf listener that collects Shelly device IPs."""

        def __init__(self) -> None:
            self.found: Dict[str, dict] = {}

        def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            info = zc.get_service_info(service_type, name)
            if info and info.parsed_scoped_addresses():
                ip = info.parsed_scoped_addresses()[0]
                self.found[ip] = {"ip": ip}

        def remove_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            pass

        def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            pass


def discover_mdns() -> Dict[str, dict]:
    """Discover Shelly devices via mDNS.  Returns ``{}`` if unavailable."""
    if not HAS_ZEROCONF:
        return {}
    zc = Zeroconf()
    listener = ShellyListener()
    browser = ServiceBrowser(zc, "_shelly._tcp.local.", listener)
    time.sleep(state.cfg.mdns_timeout)
    browser.cancel()
    zc.close()
    return listener.found


# ── Network scanning ────────────────────────────────────────────────

def scan_network(cidr: str) -> Dict[str, dict]:
    """
    Scan a CIDR range for Shelly devices.

    Raises ``ValueError`` if the network contains more than ``MAX_SCAN_HOSTS`` hosts.
    """
    network = ipaddress.IPv4Network(cidr, strict=False)
    if network.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(
            f"Network too large ({network.num_addresses} hosts, max {MAX_SCAN_HOSTS}). "
            f"Use a smaller subnet."
        )

    found: Dict[str, dict] = {}
    scan_timeout = min(float(state.cfg.timeout), 1.5)

    def _probe(ip_str: str) -> Tuple[Optional[str], Optional[dict]]:
        session = _get_session()
        try:
            resp = session.get(f"http://{ip_str}/shelly", timeout=scan_timeout)
            if resp.status_code == 200:
                return ip_str, {"ip": ip_str}
        except requests.RequestException:
            pass
        return None, None

    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = [
            executor.submit(_probe, str(host))
            for host in network.hosts()
        ]
        for future in as_completed(futures):
            ip_str, device_stub = future.result()
            if ip_str:
                found[ip_str] = device_stub

    return found


# ── Firmware helpers ────────────────────────────────────────────────

def _firmware_status(
    current: Optional[str] = None,
    latest: Optional[str] = None,
    error: Optional[str] = None,
    has_update: Optional[bool] = None,
) -> dict:
    """Build a normalised firmware‑status dict."""
    result: Dict[str, Any] = {
        "firmware_current": current,
        "firmware_latest": latest,
        "firmware_checked_at": _now(),
    }
    if error:
        result.update({"firmware_status": "error", "firmware_error": error, "has_update": None})
    elif has_update is True or (latest and current and str(latest) != str(current)):
        result.update({"firmware_status": "update_available", "has_update": True})
    elif has_update is False or current:
        result.update({"firmware_status": "latest", "has_update": False})
    else:
        result.update({"firmware_status": "unknown", "has_update": None})
    return result


def check_firmware(ip: str, device: Optional[dict] = None) -> dict:
    """Check whether a firmware update is available for *ip*."""
    device = device or {}
    generation = int(device.get("generation") or detect_generation(ip) or 1)
    current_fw = device.get("firmware_current") or device.get("firmware")
    session = _get_session()

    if generation >= 2:
        return _check_firmware_gen2(ip, current_fw, session)
    return _check_firmware_gen1(ip, current_fw, session)


def _check_firmware_gen2(ip: str, current_fw: Optional[str], session: requests.Session) -> dict:
    """Check firmware for Gen 2+ devices via RPC."""
    try:
        resp = session.get(
            f"http://{ip}/rpc/Shelly.CheckForUpdate",
            timeout=state.cfg.timeout,
            auth=_auth_gen2(),
        )
        if resp.status_code != 200:
            return _firmware_status(current_fw, error=f"HTTP {resp.status_code}")
        stable = resp.json().get("stable") or {}
        latest = stable.get("version") or stable.get("ver") or stable.get("fw_id")
        has = True if latest and str(latest) != str(current_fw) else False
        return _firmware_status(current_fw, latest, has_update=has)
    except requests.RequestException as exc:
        return _firmware_status(current_fw, error=str(exc))
    except (ValueError, KeyError) as exc:
        return _firmware_status(current_fw, error=str(exc))


def _check_firmware_gen1(ip: str, current_fw: Optional[str], session: requests.Session) -> dict:
    """Check firmware for Gen 1 devices via ``/ota`` and ``/status``."""
    latest: Optional[str] = None
    has_update: Optional[bool] = None
    cur = current_fw
    try:
        # trigger update check
        try:
            session.get(
                f"http://{ip}/ota/check",
                timeout=state.cfg.timeout,
                auth=_auth_gen1(),
            )
        except requests.RequestException:
            pass

        for url in (f"http://{ip}/ota", f"http://{ip}/status"):
            try:
                resp = session.get(url, timeout=state.cfg.timeout, auth=_auth_gen1())
                if resp.status_code == 200:
                    data = resp.json()
                    upd = data.get("update", data) if isinstance(data, dict) else {}
                    latest = upd.get("new_version") or upd.get("version") or latest
                    cur = upd.get("old_version") or upd.get("current_version") or cur
                    if "has_update" in upd:
                        has_update = bool(upd["has_update"])
            except (requests.RequestException, ValueError, KeyError) as exc:
                log.debug("Gen1 firmware check url %s failed: %s", url, exc)

        return _firmware_status(cur, latest, has_update=has_update)
    except Exception as exc:
        log.warning("Unexpected error during Gen1 fw check for %s: %s", ip, exc)
        return _firmware_status(cur, error=str(exc))


# ── Health scoring ──────────────────────────────────────────────────

def compute_health(device: dict) -> dict:
    """
    Return a health‑score dict (0–100) with a level and issue list.

    The score is an additive composite of several weighted factors.
    """
    score = 0
    issues: List[str] = []

    # Online
    if device.get("online"):
        score += HEALTH_WEIGHT_ONLINE
    else:
        issues.append("offline")

    # Web UI
    web = device.get("web_status")
    if web == "ok" and not device.get("web_auth_required"):
        score += HEALTH_WEIGHT_WEB_OK
    elif web == "ok" and device.get("web_auth_required"):
        score += HEALTH_WEIGHT_WEB_AUTH
        issues.append("web_auth")
    elif web == "timeout":
        issues.append("web_timeout")
    elif web == "error":
        issues.append("web_error")

    # Firmware
    fw_status = device.get("firmware_status")
    if fw_status == "latest":
        score += HEALTH_WEIGHT_FW_LATEST
    elif fw_status == "update_available":
        score += HEALTH_WEIGHT_FW_UPDATE
        issues.append("fw_update")
    elif fw_status == "error":
        issues.append("fw_check_error")

    # WiFi RSSI
    rssi = device.get("wifi_rssi")
    if rssi is not None:
        if rssi > RSSI_GOOD:
            score += HEALTH_WEIGHT_RSSI_GOOD
        elif rssi > RSSI_FAIR:
            score += HEALTH_WEIGHT_RSSI_FAIR
        elif rssi > RSSI_WEAK:
            score += HEALTH_WEIGHT_RSSI_WEAK
            issues.append("wifi_weak")
        else:
            issues.append("wifi_poor")

    # Connectivity (WiFi or Ethernet)
    has_wifi = rssi is not None
    has_eth = bool(device.get("eth_connected"))
    if has_wifi or has_eth:
        score += HEALTH_WEIGHT_CONNECTIVITY
    else:
        issues.append("no_connectivity")

    # API errors
    if device.get("error"):
        issues.append("api_error")
    else:
        score += HEALTH_WEIGHT_NO_ERROR

    # Uptime
    uptime_val = device.get("uptime")
    if uptime_val is not None:
        if uptime_val >= UPTIME_MIN_SECONDS:
            score += HEALTH_WEIGHT_UPTIME_OK
        else:
            issues.append("recent_reboot")

    # Web latency
    latency = device.get("web_latency_ms")
    if latency is not None:
        if latency < LATENCY_FAST_MS:
            score += HEALTH_WEIGHT_LATENCY_FAST
        elif latency < LATENCY_MED_MS:
            score += HEALTH_WEIGHT_LATENCY_MED
        elif latency < LATENCY_SLOW_MS:
            score += HEALTH_WEIGHT_LATENCY_SLOW
            issues.append("web_slow")
        else:
            issues.append("web_slow")

    score = max(0, min(100, score))
    if score >= HEALTH_LEVEL_GOOD:
        level = "good"
    elif score >= HEALTH_LEVEL_WARN:
        level = "warn"
    else:
        level = "bad"

    return {"health_score": score, "health_level": level, "health_issues": issues}


# ── Web‑UI check ────────────────────────────────────────────────────

def check_web(ip: str) -> dict:
    """Probe the device's Web UI and return status, latency, auth info."""
    session = _get_session()
    t0 = time.time()
    try:
        resp = session.get(
            f"http://{ip}/",
            timeout=state.cfg.timeout,
            auth=_auth_gen1(),
            allow_redirects=True,
        )
        latency_ms = int((time.time() - t0) * 1000)
        ok = 200 <= resp.status_code < 400 or resp.status_code == 401
        return {
            "web_status": "ok" if ok else "error",
            "web_code": resp.status_code,
            "web_latency_ms": latency_ms,
            "web_auth_required": resp.status_code == 401,
            "web_checked_at": _now(),
        }
    except requests.exceptions.Timeout:
        return {
            "web_status": "timeout",
            "web_code": None,
            "web_latency_ms": int((time.time() - t0) * 1000),
            "web_checked_at": _now(),
        }
    except requests.RequestException as exc:
        return {
            "web_status": "error",
            "web_code": None,
            "web_error": str(exc)[:120],
            "web_latency_ms": int((time.time() - t0) * 1000),
            "web_checked_at": _now(),
        }


# ── Device query (split by generation) ──────────────────────────────

def query_device(ip: str) -> dict:
    """
    Query a single Shelly device and return a complete status dict.

    Dispatches to ``_query_gen1`` or ``_query_gen2`` based on detected
    generation, then appends firmware, web, and health data.
    """
    generation = detect_generation(ip)
    device: Dict[str, Any] = {"ip": ip, "generation": generation or 1, "online": False}

    try:
        if generation >= 2:
            device = _query_gen2(ip, device)
        else:
            device = _query_gen1(ip, device)

        device.update(check_firmware(ip, device))
        device.update(check_web(ip))
        device.update(compute_health(device))
        return device

    except Exception as exc:
        log.warning("query_device(%s) failed: %s", ip, exc)
        device["error"] = str(exc)
        device.update(check_web(ip))
        device.update(compute_health(device))
        return device


def _query_gen2(ip: str, device: dict) -> dict:
    """Populate *device* dict using Gen 2+ RPC endpoints."""
    session = _get_session()
    auth = _auth_gen2()

    # ── Device info ──────────────────────────────────────────────────
    info = session.get(
        f"http://{ip}/rpc/Shelly.GetDeviceInfo",
        timeout=state.cfg.timeout,
        auth=auth,
    ).json()
    device.update({
        "online": True,
        "model": info.get("model") or info.get("app"),
        "firmware": info.get("ver") or info.get("fw_id"),
        "firmware_current": info.get("ver") or info.get("fw_id"),
        "generation": info.get("gen", 2),
        "hostname": info.get("id") or info.get("hostname"),
    })

    # ── Status (WiFi, switches, eth) ─────────────────────────────────
    try:
        status = session.get(
            f"http://{ip}/rpc/Shelly.GetStatus",
            timeout=state.cfg.timeout,
            auth=auth,
        ).json()
        wifi = status.get("wifi", {})
        sys_info = status.get("sys", {})
        eth = status.get("eth") or {}

        device.update({
            "wifi_rssi": wifi.get("rssi"),
            "wifi_ssid": wifi.get("ssid"),
            "uptime": sys_info.get("uptime"),
            "switches": [],
            "total_power_w": 0,
            "eth_ip": eth.get("ip"),
            "eth_connected": bool(eth.get("ip")),
            "eth_supported": "eth" in status,
        })
        for key, val in status.items():
            if key.startswith("switch:"):
                power = val.get("apower", 0) or 0
                device["switches"].append({
                    "id": key.split(":")[1],
                    "is_on": val.get("output", False),
                    "power_w": power,
                })
                device["total_power_w"] += power
        device["total_power_w"] = round(device["total_power_w"], 2)
    except (requests.RequestException, ValueError, KeyError) as exc:
        log.debug("Gen2 status for %s: %s", ip, exc)

    # ── Config (device name, channel names) ──────────────────────────
    try:
        cfg = session.get(
            f"http://{ip}/rpc/Shelly.GetConfig",
            timeout=state.cfg.timeout,
            auth=auth,
        ).json()
        dev_section = ((cfg.get("sys") or {}).get("device") or {})
        device["device_name"] = dev_section.get("name")
        device["hostname"] = device.get("hostname") or dev_section.get("hostname") or dev_section.get("mac")

        channel_names: Dict[str, Optional[str]] = {}
        for key, val in cfg.items():
            if key.startswith(("switch:", "input:", "cover:", "light:")) and isinstance(val, dict):
                channel_names[key] = val.get("name")

        for switch in device.get("switches", []):
            name = channel_names.get(f"switch:{switch['id']}")
            if name:
                switch["name"] = name

        device["channel_names"] = {k: v for k, v in channel_names.items() if v}
    except (requests.RequestException, ValueError, KeyError) as exc:
        log.debug("Gen2 config for %s: %s", ip, exc)

    # ── Fallback device name ─────────────────────────────────────────
    if not device.get("device_name"):
        try:
            sys_cfg = session.get(
                f"http://{ip}/rpc/Sys.GetConfig",
                timeout=state.cfg.timeout,
                auth=auth,
            ).json()
            device["device_name"] = ((sys_cfg.get("device") or {}).get("name"))
        except (requests.RequestException, ValueError, KeyError) as exc:
            log.debug("Gen2 Sys.GetConfig fallback for %s: %s", ip, exc)

    if not device.get("device_name"):
        device["device_name"] = device.get("hostname") or device.get("model")

    return device


def _query_gen1(ip: str, device: dict) -> dict:
    """Populate *device* dict using Gen 1 REST endpoints."""
    session = _get_session()
    auth = _auth_gen1()

    # ── /shelly ──────────────────────────────────────────────────────
    info = session.get(
        f"http://{ip}/shelly",
        timeout=state.cfg.timeout,
        auth=auth,
    ).json()
    device.update({
        "online": True,
        "model": info.get("type"),
        "firmware": info.get("fw"),
        "firmware_current": info.get("fw"),
        "hostname": info.get("hostname") or info.get("mac"),
    })

    # ── /status ──────────────────────────────────────────────────────
    try:
        status = session.get(
            f"http://{ip}/status",
            timeout=state.cfg.timeout,
            auth=auth,
        ).json()
        wifi = status.get("wifi_sta", {})
        device.update({
            "wifi_rssi": wifi.get("rssi"),
            "switches": [
                {"id": idx, "is_on": relay.get("ison", False)}
                for idx, relay in enumerate(status.get("relays", []))
            ],
        })
        meters = status.get("meters", [])
        device["total_power_w"] = round(
            sum(m.get("power", 0) or 0 for m in meters), 2
        )
    except (requests.RequestException, ValueError, KeyError) as exc:
        log.debug("Gen1 status for %s: %s", ip, exc)

    # ── /settings ────────────────────────────────────────────────────
    try:
        settings = session.get(
            f"http://{ip}/settings",
            timeout=state.cfg.timeout,
            auth=auth,
        ).json()
        device["device_name"] = settings.get("name")
        device["hostname"] = (
            ((settings.get("device") or {}).get("hostname")) or device.get("hostname")
        )
        relay_names: Dict[int, Optional[str]] = {
            idx: (r.get("name") if isinstance(r, dict) else None)
            for idx, r in enumerate(settings.get("relays") or [])
        }
        for switch in device.get("switches", []):
            sid = switch["id"]
            name = relay_names.get(int(sid)) if str(sid).isdigit() else None
            if name:
                switch["name"] = name
        device["channel_names"] = {
            f"switch:{idx}": name for idx, name in relay_names.items() if name
        }
    except (requests.RequestException, ValueError, KeyError) as exc:
        log.debug("Gen1 settings for %s: %s", ip, exc)

    if not device.get("device_name"):
        device["device_name"] = device.get("hostname") or device.get("model")

    return device


# ── Batch operations ────────────────────────────────────────────────

def refresh_devices() -> None:
    """Re‑query all known devices."""
    with state.lock:
        state.refreshing = True
        ips = list(state.devices.keys())

    results: Dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=24) as executor:
        futures = [executor.submit(query_device, ip) for ip in ips]
        for future in as_completed(futures):
            device = future.result()
            results[device["ip"]] = device

    with state.lock:
        state.devices.update(results)
        state.last_refresh = _now()
        state.refreshing = False


def discover_devices() -> None:
    """Discover new Shelly devices, then refresh all."""
    found: Dict[str, dict] = {
        ip: {"ip": ip} for ip in state.cfg.devices
    }
    if state.cfg.use_mdns:
        found.update(discover_mdns())
    if state.cfg.network:
        try:
            found.update(scan_network(state.cfg.network))
        except ValueError as exc:
            log.error("Network scan aborted: %s", exc)

    with state.lock:
        for ip in found:
            state.devices.setdefault(ip, {"ip": ip, "online": False, "error": "waiting"})

    refresh_devices()


def check_all_firmware() -> None:
    """Run a firmware check across all known devices."""
    with state.lock:
        state.firmware_checking = True
        snapshot = copy.deepcopy(state.devices)

    with ThreadPoolExecutor(max_workers=24) as executor:
        future_to_ip = {
            executor.submit(check_firmware, ip, dev): ip
            for ip, dev in snapshot.items()
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            fw_result = future.result()
            with state.lock:
                state.devices.setdefault(ip, {"ip": ip}).update(fw_result)
                state.devices[ip].update(compute_health(state.devices[ip]))

    with state.lock:
        state.last_firmware_check = _now()
        state.firmware_checking = False


# ── Relay control ────────────────────────────────────────────────────

def toggle_relay(ip: str, relay_id: str, action: str) -> Tuple[bool, str]:
    """Send an on/off/toggle command to a relay."""
    session = _get_session()
    generation = detect_generation(ip)
    try:
        if generation >= 2:
            if action == "toggle":
                url = f"http://{ip}/rpc/Switch.Toggle?id={relay_id}"
            else:
                on_value = "true" if action == "on" else "false"
                url = f"http://{ip}/rpc/Switch.Set?id={relay_id}&on={on_value}"
            resp = session.get(url, timeout=state.cfg.timeout, auth=_auth_gen2())
        else:
            resp = session.get(
                f"http://{ip}/relay/{relay_id}?turn={action}",
                timeout=state.cfg.timeout,
                auth=_auth_gen1(),
            )
        return resp.status_code == 200, resp.text
    except requests.RequestException as exc:
        return False, str(exc)


# ── Optional API‑key authentication decorator ───────────────────────

def require_api_key(func):
    """Decorator: reject POST requests when an API key is configured but missing/wrong."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if state.cfg.api_key:
            provided = request.headers.get("X-API-Key", "")
            if provided != state.cfg.api_key:
                return jsonify(error="unauthorized"), 401
        return func(*args, **kwargs)

    return wrapper


# ── IP validation helper ────────────────────────────────────────────

def _validate_ip(ip_str: str) -> Tuple[bool, str]:
    """Return ``(True, '')`` if *ip_str* is a safe unicast IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except (ipaddress.AddressValueError, ValueError):
        return False, "invalid IPv4 address"
    if addr.is_loopback:
        return False, "loopback address not allowed"
    if addr.is_link_local:
        return False, "link‑local address not allowed"
    if addr.is_multicast:
        return False, "multicast address not allowed"
    if addr.is_reserved:
        return False, "reserved address not allowed"
    return True, ""


# ── Flask routes ─────────────────────────────────────────────────────

@app.route("/")
def home():
    """Serve the single‑page dashboard."""
    return render_template_string(HTML, refresh=state.cfg.refresh)


@app.get("/api/devices")
def api_devices():
    """Return the full device list and status flags."""
    with state.lock:
        devices_copy = copy.deepcopy(list(state.devices.values()))
        return jsonify({
            "devices": devices_copy,
            "last_refresh": state.last_refresh,
            "last_firmware_check": state.last_firmware_check,
            "refreshing": state.refreshing,
            "firmware_checking": state.firmware_checking,
        })


@app.get("/api/summary")
def api_summary():
    """Return aggregate statistics about all devices."""
    with state.lock:
        devices = copy.deepcopy(list(state.devices.values()))

    total = len(devices)
    online = sum(1 for d in devices if d.get("online"))
    return jsonify({
        "total": total,
        "online": online,
        "offline": total - online,
        "power": round(sum(d.get("total_power_w", 0) or 0 for d in devices), 2),
        "updates": sum(1 for d in devices if d.get("has_update") is True),
        "latest": sum(1 for d in devices if d.get("firmware_status") == "latest"),
        "web_ok": sum(1 for d in devices if d.get("web_status") == "ok"),
        "web_bad": sum(1 for d in devices if d.get("web_status") in ("error", "timeout")),
        "health_avg": round(
            sum(d.get("health_score", 0) or 0 for d in devices) / total, 1
        ) if total else 0,
        "health_issues": sum(1 for d in devices if d.get("health_level") != "good"),
    })


@app.post("/api/refresh")
@require_api_key
def api_refresh():
    """Trigger a background refresh of all devices."""
    threading.Thread(target=refresh_devices, daemon=True).start()
    return jsonify(ok=True)


@app.post("/api/discover")
@require_api_key
def api_discover():
    """Trigger background device discovery + refresh."""
    threading.Thread(target=discover_devices, daemon=True).start()
    return jsonify(ok=True)


@app.post("/api/firmware/check")
@require_api_key
def api_firmware_check_all():
    """Trigger a background firmware check for all devices."""
    threading.Thread(target=check_all_firmware, daemon=True).start()
    return jsonify(ok=True)


@app.post("/api/device/<ip>/firmware/check")
@require_api_key
def api_firmware_check_one(ip: str):
    """Check firmware for a single device (synchronous)."""
    with state.lock:
        device = copy.deepcopy(state.devices.get(ip, {"ip": ip}))

    fw_result = check_firmware(ip, device)

    with state.lock:
        state.devices.setdefault(ip, {"ip": ip}).update(fw_result)
        state.devices[ip].update(compute_health(state.devices[ip]))

    return jsonify(fw_result)


@app.post("/api/device/<ip>/web/check")
@require_api_key
def api_web_check_one(ip: str):
    """Check web UI reachability for a single device (synchronous)."""
    web_result = check_web(ip)

    with state.lock:
        state.devices.setdefault(ip, {"ip": ip}).update(web_result)
        state.devices[ip].update(compute_health(state.devices[ip]))

    return jsonify(web_result)


@app.post("/api/devices/add")
@require_api_key
def api_add_device():
    """Manually add a device by IP address."""
    ip = (request.json or {}).get("ip", "").strip()
    if not ip:
        return jsonify(error="missing ip"), 400

    valid, reason = _validate_ip(ip)
    if not valid:
        return jsonify(error=reason), 400

    with state.lock:
        state.devices[ip] = {"ip": ip, "online": False, "error": "waiting"}

    def _background_add() -> None:
        result = query_device(ip)
        with state.lock:
            state.devices[ip] = result

    threading.Thread(target=_background_add, daemon=True).start()
    return jsonify(ok=True)


@app.post("/api/device/<ip>/relay/<rid>/<act>")
@require_api_key
def api_relay(ip: str, rid: str, act: str):
    """Toggle a relay on a device."""
    ok, msg = toggle_relay(ip, rid, act)
    if ok:
        # Re‑query outside the lock, then update under the lock
        refreshed = query_device(ip)
        with state.lock:
            state.devices[ip] = refreshed
    return jsonify(success=ok, message=msg)


# ── Background refresh loop ─────────────────────────────────────────

def _refresh_loop() -> None:
    """Periodically refresh device data in the background."""
    while True:
        time.sleep(state.cfg.refresh)
        try:
            refresh_devices()
        except Exception as exc:
            log.error("Background refresh failed: %s", exc)



# ── HTML template (preserved from original) ────────────────────────
HTML = r"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shelly Dashboard</title>
<style>
:root{
  --bg:#0b1020; --panel:#151b2e; --panel2:#111a31; --border:#26314f;
  --text:#e8eefc; --mut:#93a4c7; --accent:#3b82f6; --ok:#22c55e;
  --warn:#f59e0b; --bad:#ef4444; --shadow:0 6px 24px rgba(0,0,0,.25);
}
html[data-theme="light"]{
  --bg:#f4f6fb; --panel:#ffffff; --panel2:#ffffff; --border:#e2e8f0;
  --text:#0f172a; --mut:#64748b; --shadow:0 6px 24px rgba(15,23,42,.08);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,Arial,sans-serif;min-height:100vh}
.top{position:sticky;top:0;z-index:10;padding:14px 22px;background:var(--panel2);
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px;flex-wrap:wrap;box-shadow:var(--shadow)}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:1.1rem}
.brand .logo{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,#3b82f6,#22c55e);
  display:grid;place-items:center;color:white;font-weight:900}
.spacer{flex:1}
.btn{cursor:pointer;border:0;border-radius:10px;padding:9px 14px;background:var(--accent);color:#fff;
  font-weight:700;display:inline-flex;align-items:center;gap:6px;transition:transform .08s,opacity .15s}
.btn:hover{opacity:.9} .btn:active{transform:scale(.97)}
.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
.btn.warn{background:var(--warn)} .btn.ok{background:var(--ok)} .btn.bad{background:var(--bad)}
.btn.sm{padding:6px 10px;font-size:.8rem;border-radius:8px}
.wrap{padding:22px;max-width:1400px;margin:0 auto}
.stats{display:flex;flex-wrap:nowrap;gap:8px;margin-bottom:14px;overflow-x:auto;padding-bottom:4px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px 12px;box-shadow:var(--shadow);
  display:flex;align-items:center;gap:8px;flex:1 1 0;min-width:120px;white-space:nowrap}
.stat .v{font-size:1.15rem;font-weight:800;line-height:1}
.stat .l{color:var(--mut);font-size:.7rem;margin:0;text-transform:uppercase;letter-spacing:.03em}
.stat .ico{float:none;font-size:1.05rem;opacity:.7;margin:0}
.stat .col{display:flex;flex-direction:column;min-width:0}
@media (max-width:900px){.stats{flex-wrap:wrap}.stat{flex:1 1 calc(33% - 8px);min-width:0}}
.bar{display:flex;gap:10px;margin:8px 0 18px;flex-wrap:wrap;align-items:center}
.inp{padding:10px 12px;border-radius:10px;background:var(--panel);color:var(--text);
  border:1px solid var(--border);min-width:160px;outline:none;transition:border-color .15s}
.inp:focus{border-color:var(--accent)}
.search{flex:1;min-width:220px}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{cursor:pointer;padding:6px 12px;border-radius:999px;border:1px solid var(--border);
  background:transparent;color:var(--mut);font-size:.85rem;font-weight:600}
.chip.active{background:var(--accent);color:#fff;border-color:transparent}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}
.grid.view-small{grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.grid.view-small .card{padding:12px;gap:6px;font-size:.85rem}
.grid.view-small .card h3{font-size:.95rem}
.grid.view-small .row{padding:3px 0;font-size:.78rem}
.grid.view-small .actions{margin-top:2px}
.grid.view-small .btn.sm{padding:4px 8px;font-size:.72rem}
.grid.view-list{display:flex;flex-direction:column;gap:6px}
.grid.view-list .card{flex-direction:row;align-items:center;gap:14px;padding:10px 14px;flex-wrap:wrap}
.grid.view-list .card:hover{transform:none}
.grid.view-list .head{flex:1 1 220px;min-width:200px}
.grid.view-list .row{border:0;padding:0;font-size:.82rem;display:flex;gap:4px}
.grid.view-list .row .k{display:none}
.grid.view-list .switches{flex:0 0 auto;flex-direction:row;gap:8px;margin:0}
.grid.view-list .actions{margin:0}
.grid.view-list .l-cell{display:flex;flex-direction:column;min-width:80px}
.grid.view-list .l-cell .lbl{color:var(--mut);font-size:.65rem;text-transform:uppercase;letter-spacing:.04em}
.grid.view-list .l-cell .val{font-weight:600;font-size:.85rem}
.view-btns{display:inline-flex;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.view-btns button{background:transparent;border:0;color:var(--mut);padding:7px 10px;cursor:pointer;font-size:1rem}
.view-btns button.active{background:var(--accent);color:#fff}
.health{display:flex;align-items:center;gap:8px;margin:2px 0 4px}
.health .hbar{flex:1;height:8px;border-radius:6px;background:rgba(148,163,184,.25);overflow:hidden;position:relative}
.health .hfill{height:100%;border-radius:6px;transition:width .4s}
.health.good .hfill{background:var(--ok)}
.health.warn .hfill{background:var(--warn)}
.health.bad .hfill{background:var(--bad)}
.health .hval{font-weight:800;font-size:.85rem;min-width:48px;text-align:right}
.health.good .hval{color:var(--ok)} .health.warn .hval{color:var(--warn)} .health.bad .hval{color:var(--bad)}
.issues{display:flex;gap:4px;flex-wrap:wrap;margin-top:-2px}
.issues .pill{font-size:.66rem;padding:2px 7px;border-radius:999px;background:rgba(245,158,11,.15);color:var(--warn);font-weight:700}
.issues .pill.bad{background:rgba(239,68,68,.15);color:var(--bad)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px;
  box-shadow:var(--shadow);display:flex;flex-direction:column;gap:10px;transition:transform .12s}
.card:hover{transform:translateY(-2px)}
.card h3{margin:0;font-size:1.05rem;display:flex;align-items:center;gap:8px}
.card .ip{color:var(--mut);font-size:.8rem;font-family:ui-monospace,Consolas,monospace}
.head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.badge{display:inline-block;border-radius:999px;padding:3px 9px;font-size:.7rem;font-weight:800;letter-spacing:.02em}
.b-ok{background:rgba(34,197,94,.15);color:var(--ok)}
.b-bad{background:rgba(239,68,68,.15);color:var(--bad)}
.b-warn{background:rgba(245,158,11,.15);color:var(--warn)}
.b-info{background:rgba(59,130,246,.15);color:var(--accent)}
.row{display:flex;justify-content:space-between;gap:8px;padding:6px 0;border-bottom:1px dashed var(--border);font-size:.88rem}
.row:last-child{border-bottom:0}
.row .k{color:var(--mut)} .row .vv{font-weight:600}
.switches{display:flex;flex-direction:column;gap:6px;margin-top:4px}
.sw-row{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;
  background:rgba(0,0,0,.15);border-radius:8px}
html[data-theme="light"] .sw-row{background:rgba(15,23,42,.04)}
.toggle{width:44px;height:24px;border-radius:20px;background:#475569;position:relative;cursor:pointer;
  transition:background .2s;flex-shrink:0}
.toggle:before{content:'';position:absolute;width:18px;height:18px;border-radius:50%;background:#fff;
  top:3px;left:3px;transition:left .2s}
.toggle.on{background:var(--ok)} .toggle.on:before{left:23px}
.actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.empty{text-align:center;padding:60px 20px;color:var(--mut)}
.empty .big{font-size:3rem;margin-bottom:10px}
.foot{margin-top:18px;color:var(--mut);font-size:.8rem;text-align:center}
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.3);
  border-top-color:#fff;border-radius:50%;animation:sp 1s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--panel);
  border:1px solid var(--border);color:var(--text);padding:10px 16px;border-radius:10px;
  box-shadow:var(--shadow);opacity:0;pointer-events:none;transition:opacity .2s;z-index:50}
.toast.show{opacity:1}
</style>
</head>
<body>
<div class="top">
  <div class="brand"><div class="logo">S</div>Shelly Dashboard</div>
  <div class="spacer"></div>
  <select class="inp" id="langSel" onchange="setLang(this.value)" style="padding:6px 8px;min-width:auto">
    <option value="auto">🌐 Auto</option>
    <option value="pl">🇵🇱 Polski</option>
    <option value="en">🇬🇧 English</option>
  </select>
  <span class="view-btns" role="group" aria-label="View">
    <button id="vw-large" onclick="setView('large')" title="Large">▣</button>
    <button id="vw-small" onclick="setView('small')" title="Small">▦</button>
    <button id="vw-list" onclick="setView('list')" title="List">☰</button>
  </span>
  <button class="btn ghost sm" id="themeBtn" onclick="toggleTheme()">🌓 <span data-i18n="theme">Motyw</span></button>
  <button class="btn" onclick="call('api/discover','msg_discovering')">🔍 <span data-i18n="discover">Odkryj</span></button>
  <button class="btn ghost" onclick="call('api/refresh','msg_refreshing')">🔄 <span data-i18n="refresh">Odśwież</span></button>
  <button class="btn warn" onclick="call('api/firmware/check','msg_checking_fw')">⬆ <span data-i18n="firmware">Firmware</span></button>
</div>

<div class="wrap">
  <div class="stats">
    <div class="stat"><span class="ico">📦</span><span class="col"><span class="v" id="total">-</span><span class="l" data-i18n="devices">Urządzenia</span></span></div>
    <div class="stat"><span class="ico">🟢</span><span class="col"><span class="v" id="online">-</span><span class="l" data-i18n="online">Online</span></span></div>
    <div class="stat"><span class="ico">🔴</span><span class="col"><span class="v" id="offline">-</span><span class="l" data-i18n="offline">Offline</span></span></div>
    <div class="stat"><span class="ico">⚡</span><span class="col"><span class="v" id="power">-</span><span class="l" data-i18n="total_power">Moc (W)</span></span></div>
    <div class="stat"><span class="ico">⬆</span><span class="col"><span class="v" id="updates">-</span><span class="l" data-i18n="updates">Aktualizacje</span></span></div>
    <div class="stat"><span class="ico">✅</span><span class="col"><span class="v" id="latest">-</span><span class="l" data-i18n="up_to_date">Aktualne</span></span></div>
    <div class="stat"><span class="ico">🌐</span><span class="col"><span class="v" id="web_ok">-</span><span class="l" data-i18n="web_ok_stat">Web OK</span></span></div>
    <div class="stat"><span class="ico">⚠️</span><span class="col"><span class="v" id="web_bad">-</span><span class="l" data-i18n="web_bad_stat">Web błąd</span></span></div>
    <div class="stat"><span class="ico">❤️</span><span class="col"><span class="v" id="health_avg">-</span><span class="l" data-i18n="health_avg">Kondycja</span></span></div>
    <div class="stat"><span class="ico">🚨</span><span class="col"><span class="v" id="health_issues">-</span><span class="l" data-i18n="health_issues_stat">Problemy</span></span></div>
  </div>

  <div class="bar">
    <input class="inp search" id="q" data-i18n-ph="search_ph" placeholder="🔎 Szukaj po nazwie / IP / modelu..." oninput="render()">
    <input class="inp" id="ip" data-i18n-ph="ip_ph" placeholder="np. 192.168.1.50" style="max-width:180px">
    <button class="btn ok" onclick="add()">＋ <span data-i18n="add">Dodaj</span></button>
    <div class="chips">
      <span class="chip active" data-f="all" onclick="setFilter('all')" data-i18n="all">Wszystkie</span>
      <span class="chip" data-f="online" onclick="setFilter('online')" data-i18n="online">Online</span>
      <span class="chip" data-f="offline" onclick="setFilter('offline')" data-i18n="offline">Offline</span>
      <span class="chip" data-f="update" onclick="setFilter('update')">⬆ <span data-i18n="updates">Aktualizacje</span></span>
      <span class="chip" data-f="issues" onclick="setFilter('issues')">🚨 <span data-i18n="issues_filter">Problemy</span></span>
    </div>
  </div>

  <div id="grid" class="grid"></div>
  <div class="foot" id="foot" data-i18n="loading">Ładowanie...</div>
</div>

<div class="toast" id="toast"></div>

<script>
const I18N={
  pl:{theme:'Motyw',discover:'Odkryj',refresh:'Odśwież',firmware:'Firmware',devices:'Urządzenia',online:'Online',offline:'Offline',
     total_power:'Moc (W)',updates:'Aktualizacje',up_to_date:'Aktualne',all:'Wszystkie',add:'Dodaj',
     search_ph:'🔎 Szukaj po nazwie / IP / modelu...',ip_ph:'np. 192.168.1.50',loading:'Ładowanie...',
     last_refresh:'Ostatnie odświeżenie',refreshing_status:'⏳ odświeżanie...',
     model:'Model',hostname:'Hostname',fw:'Firmware',wifi:'WiFi',eth:'Ethernet',uptime:'Czas pracy',power:'Moc',channel:'Kanał',
     check_fw:'⬆ Sprawdź FW',web:'🔗 Panel',check_web:'🌐 Test Web',no_devices:'Brak urządzeń pasujących do filtra',
     eth_na:'N/A',eth_none:'brak',eth_disc:'odłączony',eth_conn:'połączony',
     web_label:'Web UI',web_ok:'OK',web_timeout:'timeout',web_error:'błąd',web_auth:'wymaga logowania',web_never:'nie sprawdzano',
     web_ok_stat:'Web OK',web_bad_stat:'Web błąd',
     health:'Kondycja',health_avg:'Kondycja',health_issues_stat:'Problemy',issues_filter:'Problemy',
     iss_offline:'Offline',iss_web_auth:'Web: wymaga logowania',iss_web_timeout:'Web: timeout',iss_web_error:'Web: błąd',
     iss_fw_update:'Dostępna aktualizacja FW',iss_fw_check_error:'Błąd sprawdzania FW',iss_wifi_weak:'Słaby sygnał WiFi',iss_wifi_poor:'Bardzo słaby sygnał WiFi',
     iss_no_connectivity:'Brak łączności',iss_api_error:'Błąd API',iss_recent_reboot:'Niedawny restart',iss_web_slow:'Wolny Web UI',
     b_offline:'Offline',b_update:'⬆ Aktualizacja',b_latest:'Aktualne',b_online:'Online',
     msg_discovering:'Skanowanie sieci...',msg_refreshing:'Odświeżanie...',msg_checking_fw:'Sprawdzanie firmware...',
     msg_check_one:'Sprawdzam FW...',msg_check_web:'Sprawdzam Web UI...',msg_on:'Włączanie...',msg_off:'Wyłączanie...',msg_add:'Dodano',msg_need_ip:'Podaj IP'},
  en:{theme:'Theme',discover:'Discover',refresh:'Refresh',firmware:'Firmware',devices:'Devices',online:'Online',offline:'Offline',
     total_power:'Power (W)',updates:'Updates',up_to_date:'Up to date',all:'All',add:'Add',
     search_ph:'🔎 Search by name / IP / model...',ip_ph:'e.g. 192.168.1.50',loading:'Loading...',
     last_refresh:'Last refresh',refreshing_status:'⏳ refreshing...',
     model:'Model',hostname:'Hostname',fw:'Firmware',wifi:'WiFi',eth:'Ethernet',uptime:'Uptime',power:'Power',channel:'Channel',
     check_fw:'⬆ Check FW',web:'🔗 Panel',check_web:'🌐 Test Web',no_devices:'No devices matching filter',
     eth_na:'N/A',eth_none:'none',eth_disc:'disconnected',eth_conn:'connected',
     web_label:'Web UI',web_ok:'OK',web_timeout:'timeout',web_error:'error',web_auth:'auth required',web_never:'not checked',
     web_ok_stat:'Web OK',web_bad_stat:'Web error',
     health:'Health',health_avg:'Health',health_issues_stat:'Issues',issues_filter:'Issues',
     iss_offline:'Offline',iss_web_auth:'Web: auth required',iss_web_timeout:'Web: timeout',iss_web_error:'Web: error',
     iss_fw_update:'Firmware update available',iss_fw_check_error:'Firmware check failed',iss_wifi_weak:'Weak WiFi signal',iss_wifi_poor:'Very poor WiFi signal',
     iss_no_connectivity:'No connectivity',iss_api_error:'API error',iss_recent_reboot:'Recently rebooted',iss_web_slow:'Slow Web UI',
     b_offline:'Offline',b_update:'⬆ Update',b_latest:'Up to date',b_online:'Online',
     msg_discovering:'Scanning network...',msg_refreshing:'Refreshing...',msg_checking_fw:'Checking firmware...',
     msg_check_one:'Checking FW...',msg_check_web:'Checking Web UI...',msg_on:'Turning on...',msg_off:'Turning off...',msg_add:'Added',msg_need_ip:'Enter IP'}
};
let LANG='pl';
function detectLang(){const s=localStorage.getItem('lang')||'auto';if(s==='pl'||s==='en')return s;const n=(navigator.language||'pl').toLowerCase();return n.startsWith('pl')?'pl':'en'}
function t(k){return (I18N[LANG]&&I18N[LANG][k])||I18N.pl[k]||k}
function applyI18n(){document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=t(el.dataset.i18n)});document.querySelectorAll('[data-i18n-ph]').forEach(el=>{el.placeholder=t(el.dataset.i18nPh)});document.documentElement.lang=LANG}
function setLang(v){localStorage.setItem('lang',v);LANG=v==='auto'?detectLang():v;applyI18n();render()}
(function(){const s=localStorage.getItem('lang')||'auto';LANG=s==='auto'?detectLang():s})();
let DEVS=[], FILTER='all', VIEW=(localStorage.getItem('view')||'large');
const BASE=(location.pathname.endsWith('/')?location.pathname:location.pathname+'/').replace(/\/+$/,'/');
const api=p=>BASE+p.replace(/^\/+/,'');
const $=id=>document.getElementById(id);
const j=(u,o)=>fetch(u,o).then(r=>r.json()).catch(()=>({}));
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');clearTimeout(toast._t);toast._t=setTimeout(()=>t.classList.remove('show'),2200)}
function toggleTheme(){const h=document.documentElement;const cur=h.getAttribute('data-theme')==='light'?'dark':'light';h.setAttribute('data-theme',cur);localStorage.setItem('theme',cur)}
(function(){const t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)})();
function setFilter(f){FILTER=f;document.querySelectorAll('.chip').forEach(c=>c.classList.toggle('active',c.dataset.f===f));render()}
function setView(v){VIEW=v;localStorage.setItem('view',v);applyView();render()}
function applyView(){const g=$('grid');if(!g)return;g.classList.remove('view-large','view-small','view-list');g.classList.add('view-'+VIEW);['large','small','list'].forEach(k=>{const b=$('vw-'+k);if(b)b.classList.toggle('active',k===VIEW)})}
async function load(){
  const sum=await j(api('api/summary'));
  $('total').textContent=sum.total??'-'; $('online').textContent=sum.online??'-';
  $('offline').textContent=sum.offline??'-'; $('power').textContent=(sum.power??0).toFixed(1);
  $('updates').textContent=sum.updates??'-'; $('latest').textContent=sum.latest??'-';
  $('web_ok').textContent=sum.web_ok??'-'; $('web_bad').textContent=sum.web_bad??'-';
  $('health_avg').textContent=sum.health_avg!=null?sum.health_avg+'%':'-';
  $('health_issues').textContent=sum.health_issues??'-';
  const d=await j(api('api/devices')); DEVS=d.devices||[];
  $('foot').textContent=`${t('last_refresh')}: ${d.last_refresh||'-'} · ${t('fw')}: ${d.last_firmware_check||'-'}${d.refreshing?' · '+t('refreshing_status'):''}`;
  render();
}
function statusBadge(d){
  if(!d.online) return `<span class="badge b-bad">${t('b_offline')}</span>`;
  if(d.has_update===true) return `<span class="badge b-warn">${t('b_update')}</span>`;
  if(d.firmware_status==='latest') return `<span class="badge b-ok">${t('b_latest')}</span>`;
  return `<span class="badge b-info">${t('b_online')}</span>`;
}
function rssiIcon(r){if(!r) return '📶';if(r>-60)return '📶 ●●●';if(r>-75)return '📶 ●●○';return '📶 ●○○'}
function ethStatus(d){if(d.generation&&d.generation<2) return `<span class="badge b-info">${t('eth_na')}</span>`;if(d.eth_supported===false) return `<span class="badge b-info">${t('eth_none')}</span>`;if(d.eth_connected) return `<span class="badge b-ok">🔌 ${d.eth_ip||t('eth_conn')}</span>`;if(d.eth_supported) return `<span class="badge b-bad">${t('eth_disc')}</span>`;return '<span class="badge b-info">-</span>'}
function webStatus(d){
  if(!d.web_status) return `<span class="badge b-info">${t('web_never')}</span>`;
  const lat=d.web_latency_ms!=null?` · ${d.web_latency_ms} ms`:'';
  const code=d.web_code?` (${d.web_code})`:'';
  if(d.web_status==='ok'&&d.web_auth_required) return `<span class="badge b-warn">🔐 ${t('web_auth')}${lat}</span>`;
  if(d.web_status==='ok') return `<span class="badge b-ok">✅ ${t('web_ok')}${code}${lat}</span>`;
  if(d.web_status==='timeout') return `<span class="badge b-bad">⏱ ${t('web_timeout')}${lat}</span>`;
  return `<span class="badge b-bad">❌ ${t('web_error')}${code}</span>`;
}
function uptime(s){if(!s) return '-';s=+s;const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);return (d?d+'d ':'')+(h?h+'h ':'')+m+'m'}
function row(k,v){return `<div class="row"><span class="k">${k}</span><span class="vv">${v??'-'}</span></div>`}
function matches(d,q){if(!q) return true;q=q.toLowerCase();return (d.ip||'').toLowerCase().includes(q)||(d.device_name||'').toLowerCase().includes(q)||(d.model||'').toLowerCase().includes(q)||(d.hostname||'').toLowerCase().includes(q)}
function passFilter(d){if(FILTER==='online')return d.online;if(FILTER==='offline')return !d.online;if(FILTER==='update')return d.has_update===true;if(FILTER==='issues')return d.health_level&&d.health_level!=='good';return true}
function healthBar(d){
  if(d.health_score==null) return '';
  const lvl=d.health_level||'good';
  const iss=(d.health_issues||[]).map(k=>{const bad=['offline','web_timeout','web_error','no_connectivity','api_error','wifi_poor'].includes(k);return `<span class="pill ${bad?'bad':''}">${t('iss_'+k)||k}</span>`}).join('');
  return `<div class="health ${lvl}" title="${t('health')}: ${d.health_score}%">
    <div class="hbar"><div class="hfill" style="width:${d.health_score}%"></div></div>
    <div class="hval">${d.health_score}%</div>
  </div>${iss?`<div class="issues">${iss}</div>`:''}`;
}
function render(){
  const q=$('q').value.trim();
  const list=DEVS.filter(d=>passFilter(d)&&matches(d,q)).sort((a,b)=>(a.device_name||a.hostname||a.ip).localeCompare(b.device_name||b.hostname||b.ip));
  const g=$('grid');
  if(!list.length){g.innerHTML=`<div class="empty" style="grid-column:1/-1"><div class="big">📬</div><div>${t('no_devices')}</div></div>`;applyView();return}
  if(VIEW==='list'){
    g.innerHTML=list.map(d=>{
      const fw=(d.firmware_current||d.firmware||'?')+(d.firmware_latest&&d.firmware_latest!=d.firmware_current?` <span class="badge b-warn">→ ${d.firmware_latest}</span>`:'');
      return `<div class="card">
        <div class="head">
          <div><h3>${d.device_name||d.hostname||d.model||'Shelly'}</h3><div class="ip">${d.ip} · ${d.hostname||d.model||'-'} · Gen ${d.generation||1}</div></div>
          ${statusBadge(d)}
        </div>
        <div class="l-cell"><span class="lbl">${t('health')}</span><span class="val" style="color:var(--${d.health_level==='good'?'ok':d.health_level==='warn'?'warn':'bad'})">${d.health_score!=null?d.health_score+'%':'-'}</span></div>
        <div class="l-cell"><span class="lbl">${t('fw')}</span><span class="val">${fw}</span></div>
        <div class="l-cell"><span class="lbl">${t('wifi')}</span><span class="val">${d.wifi_rssi?d.wifi_rssi+' dBm':'-'}</span></div>
        <div class="l-cell"><span class="lbl">${t('eth')}</span><span class="val">${ethStatus(d)}</span></div>
        <div class="l-cell"><span class="lbl">${t('web_label')}</span><span class="val">${webStatus(d)}</span></div>
        <div class="l-cell"><span class="lbl">${t('power')}</span><span class="val">${d.total_power_w!=null?d.total_power_w+' W':'-'}</span></div>
        <div class="l-cell"><span class="lbl">${t('uptime')}</span><span class="val">${uptime(d.uptime)}</span></div>
        <div class="actions">
          <button class="btn sm ghost" onclick="call('api/device/${d.ip}/firmware/check','msg_check_one')">⬆</button>
          <button class="btn sm ghost" onclick="call('api/device/${d.ip}/web/check','msg_check_web')">🌐</button>
          <a class="btn sm ghost" href="http://${d.ip}" target="_blank" rel="noopener">🔗</a>
        </div>
      </div>`;
    }).join('');
    applyView();return;
  }
  g.innerHTML=list.map(d=>{
    const fw=(d.firmware_current||d.firmware||'?')+(d.firmware_latest&&d.firmware_latest!=d.firmware_current?` <span class="badge b-warn">→ ${d.firmware_latest}</span>`:'');
    const sw=(d.switches||[]).map(x=>`<div class="sw-row"><span>${x.name?x.name+' <span style="color:var(--mut)">('+t('channel')+' '+x.id+')</span>':t('channel')+' '+x.id}${x.power_w!=null?` · <span style="color:var(--mut)">${x.power_w} W</span>`:''}</span>
      <span class="toggle ${x.is_on?'on':''}" onclick="tog('${d.ip}','${x.id}',${x.is_on})"></span></div>`).join('');
    return `<div class="card">
      <div class="head">
        <div><h3>${d.device_name||d.hostname||d.model||'Shelly'}</h3><div class="ip">${d.ip} · ${d.hostname||d.model||'-'} · Gen ${d.generation||1}</div></div>
        ${statusBadge(d)}
      </div>
      ${healthBar(d)}
      ${row(t('model'),d.model||'-')}
      ${row(t('hostname'),d.hostname?`<span style="font-family:ui-monospace,Consolas,monospace">${d.hostname}</span>`:'-')}
      ${row(t('fw'),fw)}
      ${row(t('wifi'),d.wifi_rssi?`${rssiIcon(d.wifi_rssi)} ${d.wifi_rssi} dBm`:'-')}
      ${row(t('eth'), ethStatus(d))}
      ${row(t('web_label'), webStatus(d))}
      ${row(t('uptime'),uptime(d.uptime))}
      ${row(t('power'),d.total_power_w!=null?d.total_power_w+' W':'-')}
      ${sw?`<div class="switches">${sw}</div>`:''}
      <div class="actions">
        <button class="btn sm ghost" onclick="call('api/device/${d.ip}/firmware/check','msg_check_one')">${t('check_fw')}</button>
        <button class="btn sm ghost" onclick="call('api/device/${d.ip}/web/check','msg_check_web')">${t('check_web')}</button>
        <a class="btn sm ghost" href="http://${d.ip}" target="_blank" rel="noopener">${t('web')}</a>
      </div>
    </div>`;
  }).join('');
  applyView();
}
async function call(u,msgKey){if(msgKey)toast(t(msgKey)||msgKey);await j(api(u),{method:'POST'});setTimeout(load,1500)}
async function tog(ip,id,on){await call(`api/device/${ip}/relay/${id}/${on?'off':'on'}`, on?'msg_off':'msg_on')}
async function add(){const ip=$('ip').value.trim();if(!ip){toast(t('msg_need_ip'));return}
  await j(api('api/devices/add'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  $('ip').value='';toast(`${t('msg_add')} ${ip}`);setTimeout(load,1200)}
$('ip').addEventListener('keydown',e=>{if(e.key==='Enter')add()});
$('langSel').value=localStorage.getItem('lang')||'auto';
applyI18n();
applyView();
load();setInterval(load,{{refresh}}*1000);
</script>
</body>
</html>"""


# ── CLI entry point ──────────────────────────────────────────────────

def main() -> None:
    """Parse arguments and start the dashboard."""
    parser = argparse.ArgumentParser(description="Shelly Dashboard Add‑on")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5000, help="Bind port")
    parser.add_argument("--devices", default="", help="Comma‑separated list of device IPs")
    parser.add_argument("--network", help="CIDR range to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--no-mdns", action="store_true", help="Disable mDNS discovery")
    parser.add_argument("--timeout", type=float, default=3, help="HTTP timeout in seconds")
    parser.add_argument("--mdns-timeout", type=float, default=5, help="mDNS browse time")
    parser.add_argument("--refresh", type=int, default=15, help="Auto‑refresh interval (s)")
    parser.add_argument("--user", help="Username for device auth")
    parser.add_argument("--password", help="Password for device auth")
    parser.add_argument("--api-key", help="Optional API key for mutating endpoints")

    args = parser.parse_args()

    state.cfg = Config(
        timeout=args.timeout,
        refresh=args.refresh,
        mdns_timeout=args.mdns_timeout,
        user=args.user,
        password=args.password,
        devices=[x.strip() for x in args.devices.split(",") if x.strip()],
        network=args.network,
        use_mdns=not args.no_mdns,
        api_key=args.api_key,
    )

    log.info("Shelly Dashboard listening on %s:%d", args.host, args.port)

    threading.Thread(target=discover_devices, daemon=True).start()
    threading.Thread(target=_refresh_loop, daemon=True).start()
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
