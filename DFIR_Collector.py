#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================================
 DFIR Portable Evidence Collector (RegHiveTool Suite)
 Version : 1.3.0
 Author  : Senior DFIR Engineering
 Target  : Windows 10 / Windows 11  (and Server 2016+)
 Runtime : Python 3.10+ (standard library only — no third-party deps)
 License : Internal / IR use

 NOTE ON WIN10/11 CLIENT EDITIONS
     Microsoft restricts `vssadmin create shadow` to Server SKUs. On client
     Windows 10 / 11 it returns "Error: Invalid command". This tool therefore
     creates and removes shadow copies via the Win32_ShadowCopy WMI class
     (called through PowerShell), which works identically on every edition.

 NOTE ON HASH COMPUTATION
     SHA-256 is computed by the host computer's native cryptographic engine:
     Windows CNG (bcrypt.dll), called directly via ctypes. This is the same
     OS-validated, hardware-accelerated (SHA-NI / ARMv8 Crypto) code path
     used by Get-FileHash, certutil, and BitLocker. Hashes are byte-identical
     to those produced by `Get-FileHash <file> -Algorithm SHA256`, so an
     examiner can independently re-verify any artifact without this tool.

 NOTE ON WRITE-BLOCKING (EVIDENCE PROTECTION)
     Once an artifact is acquired and its two-pass integrity check passes,
     the file is immediately set read-only using POSIX permission bits:
         stat.S_IRUSR (0o400) — owner  : read
         stat.S_IRGRP (0o040) — group  : read
         stat.S_IROTH (0o004) — others : read
         Combined     (0o444) — r--r--r--
     On NTFS this maps to FILE_ATTRIBUTE_READONLY. Failed/error artifacts
     are also write-blocked — their state is evidence. A final hardening
     sweep locks the manifest, report, log, and all directories after the
     acquisition phase closes.
================================================================================

PURPOSE
    Single-execution, USB-portable forensic acquisition of:
        * HKLM registry hives   : SYSTEM, SAM, SOFTWARE, SECURITY, DEFAULT
        * HKU per-user hives    : NTUSER.DAT for every real user profile
        * Windows event logs    : System.evtx, Security.evtx, Application.evtx

    All artifacts are pulled through a Volume Shadow Copy snapshot so the
    sources are read-only and point-in-time consistent. Each file is
    SHA-256 hashed in-flight during the copy AND re-hashed after fsync on
    the USB, and the two digests must agree for the artifact to be marked
    integrity=PASS. A chain-of-custody log (append-only, UTC) and a
    structured JSON report are written alongside the evidence.

USAGE
    # On the target, from an elevated cmd / PowerShell:
    python DFIR_Collector.py

    # Or, after building with PyInstaller (see end of file for build cmd):
    DFIR_Collector.exe          # UAC prompt fires automatically

OUTPUT LAYOUT  (created next to this script / EXE — i.e. on the USB)
    DFIR_Evidence\
      CASE_<HOSTNAME>_<UTC>\
        registry_hives\       SYSTEM, SAM, SOFTWARE, SECURITY, DEFAULT
        user_hives_ntuser\    NTUSER_<user>.DAT  (one per profile)
        evtx_logs\            System.evtx, Security.evtx, Application.evtx
        hashes\
          SHA256SUMS.txt      master manifest (sha256sum -c compatible)
          *.sha256            per-artifact sidecars
        logs\
          chain_of_custody.log
        report.json           full structured report

EXIT CODES
    0   success                                     4   VSS lifecycle error
    1   unhandled exception                         5   report generation failed
    2   not Windows                                 130 operator interrupted (Ctrl+C)
    3   not elevated (admin required)

FORENSIC POSTURE
    * Read-only against the live volume; reads happen only inside the VSS shadow.
    * No registry writes. No services installed. No persistence.
    * The single shadow we create is torn down on exit (success or failure).
    * Every state-changing action is recorded in chain_of_custody.log.
================================================================================
"""

from __future__ import annotations

import ctypes
import getpass
import hashlib
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional


# =============================================================================
# SECTION 1 — CONFIGURATION
# =============================================================================

TOOL_NAME    = "DFIR Portable Evidence Collector"
TOOL_SUITE   = "RegHiveTool Suite"
TOOL_VERSION = "1.3.0"

# HKLM hives — locked while Windows runs; acquired through VSS.
REGISTRY_HIVES = {
    "SYSTEM":   r"Windows\System32\config\SYSTEM",
    "SAM":      r"Windows\System32\config\SAM",
    "SOFTWARE": r"Windows\System32\config\SOFTWARE",
    "SECURITY": r"Windows\System32\config\SECURITY",
    "DEFAULT":  r"Windows\System32\config\DEFAULT",
}

# Core EVTX set (extend by appending to this list).
EVTX_DIR_REL = r"Windows\System32\winevt\Logs"
EVTX_LOGS    = ["System.evtx", "Security.evtx", "Application.evtx"]

# User profiles
USERS_DIR_REL   = "Users"
NTUSER_FILENAME = "NTUSER.DAT"
EXCLUDED_USER_DIRS = {
    "All Users", "Default", "Default User", "Public",
    "desktop.ini", "WDAGUtilityAccount",
}

# Evidence package layout
EVIDENCE_ROOT_NAME = "DFIR_Evidence"
SUBDIR_REGISTRY    = "registry_hives"
SUBDIR_NTUSER      = "user_hives_ntuser"
SUBDIR_EVTX        = "evtx_logs"
SUBDIR_HASHES      = "hashes"
SUBDIR_LOGS        = "logs"
EVIDENCE_SUBDIRS   = (
    SUBDIR_REGISTRY, SUBDIR_NTUSER, SUBDIR_EVTX,
    SUBDIR_HASHES,   SUBDIR_LOGS,
)

REPORT_FILENAME   = "report.json"
COC_LOG_FILENAME  = "chain_of_custody.log"
MANIFEST_FILENAME = "SHA256SUMS.txt"

# Operational
HASH_ALGORITHM       = "sha256"
CHUNK_SIZE           = 1024 * 1024     # 1 MiB streaming reads
VSSADMIN_TIMEOUT_SEC = 180              # also used as PowerShell timeout

# System drive (defaults to "C:" but honours environment)
SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:")


def windows_edition_info() -> dict:
    """Return a small dict describing the host Windows edition / build.
    Used purely for the report — never gates execution."""
    info = {
        "release":     "",
        "version":     "",
        "build":       "",
        "is_server":   False,
        "win10_or_11": False,
    }
    if not sys.platform.startswith("win"):
        return info
    try:
        info["release"] = platform.release()        # '10' or '11'
        info["version"] = platform.version()        # e.g. '10.0.22631'
        info["build"]   = info["version"].split(".")[-1]
        try:
            edition = platform.win32_edition() or ""
        except AttributeError:
            edition = ""
        info["is_server"]   = "Server" in edition
        info["win10_or_11"] = info["release"] in ("10", "11")
    except Exception:
        pass
    return info


def get_base_dir() -> Path:
    """Return the directory of this script / frozen EXE — i.e. the USB root."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def generate_case_id() -> str:
    host = socket.gethostname().upper().replace(" ", "_")
    # Local time stamp — matches what the operator sees on the target clock
    ts   = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S")
    return f"CASE_{host}_{ts}"


def evidence_root_for(case_id: str) -> Path:
    return get_base_dir() / EVIDENCE_ROOT_NAME / case_id


def local_now_iso() -> str:
    """
    Return the current LOCAL time of the host computer as ISO-8601 with
    explicit UTC offset embedded, e.g.:

        EAT (UTC+3):  2026-06-14T06:30:01.123456+03:00
        EST (UTC-5):  2026-06-13T22:30:01.123456-05:00
        UTC (UTC+0):  2026-06-14T03:30:01.123456+00:00

    Uses datetime.now().astimezone() which reads the OS-configured timezone.
    On Windows this comes from the registry key:
        HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation
    — the same source Windows uses for Explorer, Task Scheduler, and the
    system clock displayed to the user.

    The UTC offset is always present in the string, so every timestamp is
    globally unambiguous — an examiner can convert to UTC by subtracting
    the offset, or any ISO-8601 parser handles it automatically.

    Replaces the previous implementation which always returned UTC regardless
    of the host clock, causing timestamps 3 hours behind the actual computer
    clock on UTC+3 (EAT) machines.
    """
    return datetime.now().astimezone().isoformat()


def local_tz_info() -> dict:
    """
    Return a dict describing the host's configured timezone at runtime.
    Recorded in both the chain-of-custody log and report.json so an
    examiner can unambiguously convert any local timestamp to UTC.

        {
            "tzname":          "EAT",        # OS timezone abbreviation
            "utc_offset":      "+03:00",      # hours:minutes east of UTC
            "utc_offset_secs": 10800          # seconds east of UTC (signed)
        }
    """
    dt     = datetime.now().astimezone()
    offset = dt.utcoffset()
    secs   = int(offset.total_seconds()) if offset else 0
    h, rem = divmod(abs(secs), 3600)
    sign   = "+" if secs >= 0 else "-"
    return {
        "tzname":          dt.tzname() or "Unknown",
        "utc_offset":      f"{sign}{h:02d}:{rem // 60:02d}",
        "utc_offset_secs": secs,
    }


# =============================================================================
# SECTION 2 — FORENSIC LOGGER (append-only, UTC, thread-safe)
# =============================================================================

class ForensicLogger:
    """Append-only chain-of-custody log.
    All entries timestamped in local time with UTC offset (ISO-8601)."""

    LEVELS = ("INFO", "ACTION", "WARN", "ERROR")

    def __init__(self, log_dir: Path, case_id: str,
                 log_filename: str = COC_LOG_FILENAME):
        self.case_id  = case_id
        self.log_dir  = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / log_filename
        self._lock    = threading.Lock()
        self._banner()

    def _emit(self, level: str, message: str) -> None:
        if level not in self.LEVELS:
            level = "INFO"
        line = f"[{local_now_iso()}] [{level:<6}] {message}\n"
        with self._lock:
            with open(self.log_file, "a", encoding="utf-8", newline="") as fh:
                fh.write(line)
            print(line, end="")  # mirror to operator console

    def _banner(self) -> None:
        sep = "=" * 72
        self._emit("INFO", sep)
        self._emit("INFO", f"Chain of Custody opened — case_id={self.case_id}")
        self._emit("INFO", sep)

    def info(self,   msg: str) -> None: self._emit("INFO",   msg)
    def action(self, msg: str) -> None: self._emit("ACTION", msg)
    def warn(self,   msg: str) -> None: self._emit("WARN",   msg)
    def error(self,  msg: str) -> None: self._emit("ERROR",  msg)

    def close(self) -> None:
        self._emit("INFO", f"Chain of Custody closed — case_id={self.case_id}")


# =============================================================================
# SECTION 3 — HASHING
# -----------------------------------------------------------------------------
# SHA-256 is computed by the host computer's *native* cryptographic engine,
# not a userland Python implementation:
#
#     Windows  →  CNG (bcrypt.dll), called directly via ctypes.
#                 Hardware-accelerated when the CPU exposes SHA-NI (Intel/AMD)
#                 or ARMv8 Crypto Extensions. FIPS-validated when the host
#                 is in FIPS mode. Same code path as Get-FileHash and
#                 certutil -hashfile.
#
#     Non-Win  →  hashlib (libcrypto/OpenSSL).
#                 Only used for off-target development testing; production
#                 acquisition only runs on Windows.
#
# Output digests are byte-identical between the two paths — SHA-256 is a
# standard algorithm; what differs is *who* computes it.
# =============================================================================

# ---- Windows CNG (bcrypt.dll) binding ----------------------------------------
_BCRYPT_AVAILABLE = False
_BCRYPT = None

if sys.platform.startswith("win"):
    try:
        _BCRYPT = ctypes.WinDLL("bcrypt.dll")

        # NTSTATUS BCryptOpenAlgorithmProvider(
        #     BCRYPT_ALG_HANDLE *phAlgorithm,
        #     LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
        _BCRYPT.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong,
        ]
        _BCRYPT.BCryptOpenAlgorithmProvider.restype = ctypes.c_long

        # NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
        _BCRYPT.BCryptCloseAlgorithmProvider.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong,
        ]
        _BCRYPT.BCryptCloseAlgorithmProvider.restype = ctypes.c_long

        # NTSTATUS BCryptCreateHash(
        #     BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*,
        #     PUCHAR pbHashObject, ULONG cbHashObject,
        #     PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
        _BCRYPT.BCryptCreateHash.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_char_p, ctypes.c_ulong,
            ctypes.c_char_p, ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        _BCRYPT.BCryptCreateHash.restype = ctypes.c_long

        # NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        _BCRYPT.BCryptHashData.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong,
        ]
        _BCRYPT.BCryptHashData.restype = ctypes.c_long

        # NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
        _BCRYPT.BCryptFinishHash.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong,
        ]
        _BCRYPT.BCryptFinishHash.restype = ctypes.c_long

        # NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE);
        _BCRYPT.BCryptDestroyHash.argtypes = [ctypes.c_void_p]
        _BCRYPT.BCryptDestroyHash.restype  = ctypes.c_long

        _BCRYPT_AVAILABLE = True
    except (OSError, AttributeError):
        _BCRYPT = None
        _BCRYPT_AVAILABLE = False


class BCryptSHA256:
    """
    SHA-256 hasher backed by Windows CNG (bcrypt.dll).

    Interface mirrors hashlib.sha256() — `update(bytes)`, `digest()`,
    `hexdigest()` — so it is drop-in compatible. Internally each
    operation translates to a single NTSTATUS-returning kernel call
    that routes to the CPU's SHA-NI / ARMv8 Crypto unit when present.
    """

    DIGEST_SIZE = 32  # bytes (SHA-256)

    def __init__(self):
        if not _BCRYPT_AVAILABLE:
            raise OSError("CNG (bcrypt.dll) is not available on this host.")
        self._alg  = ctypes.c_void_p()
        self._hash = ctypes.c_void_p()

        status = _BCRYPT.BCryptOpenAlgorithmProvider(
            ctypes.byref(self._alg), "SHA256", None, 0,
        )
        if status != 0:
            raise OSError(
                f"BCryptOpenAlgorithmProvider failed: NTSTATUS 0x{status & 0xFFFFFFFF:08x}"
            )

        status = _BCRYPT.BCryptCreateHash(
            self._alg, ctypes.byref(self._hash),
            None, 0,   # pbHashObject, cbHashObject — CNG allocates internally
            None, 0,   # pbSecret, cbSecret — not HMAC
            0,
        )
        if status != 0:
            _BCRYPT.BCryptCloseAlgorithmProvider(self._alg, 0)
            self._alg = ctypes.c_void_p()
            raise OSError(
                f"BCryptCreateHash failed: NTSTATUS 0x{status & 0xFFFFFFFF:08x}"
            )

    def update(self, data: bytes) -> None:
        if not data:
            return
        # Passing bytes to a c_char_p parameter is a pointer-pass, not a
        # NUL-terminated copy — the explicit cbInput length governs.
        status = _BCRYPT.BCryptHashData(self._hash, data, len(data), 0)
        if status != 0:
            raise OSError(
                f"BCryptHashData failed: NTSTATUS 0x{status & 0xFFFFFFFF:08x}"
            )

    def digest(self) -> bytes:
        out = ctypes.create_string_buffer(self.DIGEST_SIZE)
        status = _BCRYPT.BCryptFinishHash(
            self._hash, out, self.DIGEST_SIZE, 0,
        )
        if status != 0:
            raise OSError(
                f"BCryptFinishHash failed: NTSTATUS 0x{status & 0xFFFFFFFF:08x}"
            )
        # .raw returns exactly DIGEST_SIZE bytes (no NUL trimming).
        return bytes(out.raw)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def close(self) -> None:
        if self._hash:
            _BCRYPT.BCryptDestroyHash(self._hash)
            self._hash = ctypes.c_void_p()
        if self._alg:
            _BCRYPT.BCryptCloseAlgorithmProvider(self._alg, 0)
            self._alg = ctypes.c_void_p()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def new_sha256():
    """
    Return a fresh SHA-256 hasher.

    Preference order:
        1. Windows CNG (BCryptSHA256) — native, OS-validated, HW-accelerated.
        2. hashlib.sha256()           — only when CNG is not available.

    The returned object exposes `.update(bytes)`, `.digest()`, `.hexdigest()`,
    matching hashlib's contract.
    """
    if _BCRYPT_AVAILABLE:
        try:
            return BCryptSHA256()
        except OSError:
            pass  # fall through to hashlib
    return hashlib.sha256()


def hash_provider_name() -> str:
    """One-line identifier of the active SHA-256 provider, for logs / report."""
    return "Windows CNG (bcrypt.dll)" if _BCRYPT_AVAILABLE \
        else "hashlib (libcrypto/OpenSSL)"


# ---- File-level helpers (use the native provider transparently) -------------
def sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    """Streaming SHA-256 of *path*. Constant memory, identical chunk size
    to the copy-and-hash pipeline so verification is byte-for-byte parallel.
    Uses CNG on Windows; hashlib elsewhere."""
    h = new_sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sidecar(target_file: Path, digest: str, hashes_dir: Path) -> Path:
    """Write `<filename>.sha256` in `sha256sum -c` compatible format."""
    hashes_dir.mkdir(parents=True, exist_ok=True)
    sidecar = hashes_dir / (target_file.name + ".sha256")
    sidecar.write_text(f"{digest}  {target_file.name}\n", encoding="utf-8")
    return sidecar


def append_manifest(manifest_path: Path, digest: str, relative_name: str) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "a", encoding="utf-8", newline="") as fh:
        fh.write(f"{digest}  {relative_name}\n")


# =============================================================================
# SECTION 3.5 — EVIDENCE WRITE-BLOCKER
# -----------------------------------------------------------------------------
# Once a file leaves the acquisition pipeline its bytes must not change.
# We enforce this immediately by applying read-only POSIX permission bits:
#
#   stat.S_IRUSR  0o400   owner  : read
#   stat.S_IRGRP  0o040   group  : read
#   stat.S_IROTH  0o004   others : read
#   ──────────────────────────────────
#   combined      0o444   r--r--r--
#
# Platform notes:
#   Windows (NTFS)  os.chmod respects only the owner-write bit; 0o444 clears
#                   FILE_ATTRIBUTE_READONLY, which prevents modification by
#                   Explorer, cmd, and most user-mode tools. ACL-level access
#                   by SYSTEM/Administrators is not blocked — this is by design
#                   (the examiner workstation may need to archive the evidence).
#   Linux / macOS   Standard UGO semantics apply; 0o444 removes all write bits.
#
# Sequencing:
#   Per-artifact  : artifact file + its sidecar → blocked immediately after
#                   the two-pass integrity check (PASS, FAIL, or ERROR alike —
#                   all states are evidence and must be frozen).
#   Final sweep   : manifest → report.json → CoC log → directories (bottom-up).
#                   Directories are blocked last so the pipeline can still
#                   write into them during acquisition.
# =============================================================================

# The canonical read-only mode (owner | group | others = r--r--r--)
_EVIDENCE_MODE     = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH   # 0o444
_EVIDENCE_MODE_STR = f"{oct(_EVIDENCE_MODE)} (r--r--r--)"


def write_block(path: Path, logger: Optional["ForensicLogger"] = None) -> str:
    """
    Apply read-only permissions to *path* (file or directory).

    Returns a human-readable description such as "0o444 (r--r--r--)".
    Never raises — a failure is logged as WARN and a failure string returned
    so it never interrupts acquisition.
    """
    try:
        os.chmod(path, _EVIDENCE_MODE)
        desc = _EVIDENCE_MODE_STR
        if logger:
            logger.action(
                f"WRITE-BLOCKED {desc} "
                f"[{'DIR' if path.is_dir() else 'FILE'}] {path.name}"
            )
        return desc
    except OSError as e:
        msg = f"write-block failed on {path.name}: {e}"
        if logger:
            logger.warn(msg)
        return f"FAILED ({e})"


def write_block_tree(root: Path, logger: "ForensicLogger") -> int:
    """
    Recursively write-block every file and directory under *root*.

    Ordering:
        1. All files first (deepest first for neatness — order doesn't matter).
        2. All directories bottom-up (deepest first) so a parent dir is not
           locked before we finish writing child dirs into it.
        3. The root directory itself last.

    Returns the number of paths successfully blocked.
    """
    blocked = 0
    # Files (any order)
    for p in root.rglob("*"):
        if p.is_file():
            result = write_block(p, logger)
            if not result.startswith("FAILED"):
                blocked += 1
    # Directories — sort by depth (most-nested first)
    dirs = sorted(
        (p for p in root.rglob("*") if p.is_dir()),
        key=lambda p: len(p.parts),
        reverse=True,
    )
    for d in dirs:
        result = write_block(d, logger)
        if not result.startswith("FAILED"):
            blocked += 1
    # Root last
    result = write_block(root, logger)
    if not result.startswith("FAILED"):
        blocked += 1
    return blocked


# =============================================================================
# SECTION 4 — PRIVILEGE / PLATFORM CHECKS
# =============================================================================

def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    """True if the current process holds an elevated token."""
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# =============================================================================
# SECTION 5 — VOLUME SHADOW COPY LIFECYCLE
# =============================================================================

class VSSError(RuntimeError):
    """Raised when shadow-copy creation, parsing, or teardown fails."""


# Win32_ShadowCopy.Create() return codes (MSDN). Mapping them gives
# the operator an actionable message instead of a bare number.
_WMI_CREATE_ERRORS = {
    0:  "Success",
    1:  "Access denied",
    2:  "Invalid argument",
    3:  "Specified volume not found",
    4:  "Specified volume not supported",
    5:  "Unsupported shadow copy context",
    6:  "Insufficient storage",
    7:  "Volume is in use",
    8:  "Maximum number of shadow copies reached",
    9:  "Another shadow copy operation is already in progress",
    10: "Shadow copy provider had an error",
    11: "Shadow copy is currently transient",
    12: "Shadow copy not supported by the provider",
}


class ShadowCopy:
    r"""
    Create / expose / clean up a single VSS snapshot of a target volume on
    Windows 10 / 11 (and Server 2016+).

    Uses the Win32_ShadowCopy WMI class invoked through PowerShell. This is
    the same mechanism KAPE, CyLR, and Velociraptor use, and the only
    supported way to create on-demand shadow copies on client editions of
    Windows — `vssadmin create shadow` is gated to Server SKUs by Microsoft.

    Use as a context manager:

        with ShadowCopy("C:", logger) as vss:
            src = vss.path_for(r"Windows\System32\config\SYSTEM")

    The shadow we create is *always* deleted on exit (success or exception),
    leaving zero persistent change on the target.
    """

    # PowerShell prints two labelled lines: SHADOW_ID=... and DEVICE=...
    _RE_SHADOW_ID  = re.compile(r"SHADOW_ID=(\{[0-9A-Fa-f-]+\})")
    _RE_SHADOW_DEV = re.compile(
        r"DEVICE=(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)"
    )

    def __init__(self, drive: str, logger: ForensicLogger):
        d = drive.strip().rstrip("\\").rstrip(":")
        self.drive: str = f"{d}:"
        self.logger     = logger
        self.shadow_id:     Optional[str] = None
        self.shadow_device: Optional[str] = None

    # ---- PowerShell invoker -------------------------------------------------
    def _run_powershell(self, script: str) -> subprocess.CompletedProcess:
        """
        Run a PowerShell script in a clean, non-interactive process.

        Flags:
            -NoProfile           : don't load $PROFILE (faster, predictable)
            -NonInteractive      : never prompt the operator
            -ExecutionPolicy Bypass : ignore signed-script policy for this run
            -Command             : inline script (no temp file on the target)
        """
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script,
        ]
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True, check=False,
                timeout=VSSADMIN_TIMEOUT_SEC,
            )
        except FileNotFoundError as e:
            raise VSSError("powershell.exe not found — Windows-only tool.") from e
        except subprocess.TimeoutExpired as e:
            raise VSSError(
                f"PowerShell timed out after {VSSADMIN_TIMEOUT_SEC}s"
            ) from e

    # ---- Create -------------------------------------------------------------
    def create(self) -> str:
        if not is_admin():
            raise VSSError("Administrator privileges required for VSS.")

        self.logger.action(
            f"Creating Volume Shadow Copy for {self.drive}\\ "
            f"(Win32_ShadowCopy WMI — Win10/11 compatible)"
        )

        # PowerShell payload: create the shadow, query it back, print its
        # ID and device path on two labelled lines. ReturnValue != 0 is
        # mapped to a non-zero exit so subprocess.returncode surfaces it.
        ps = (
            "$ErrorActionPreference = 'Stop'; "
            f"$r = (Get-WmiObject -List Win32_ShadowCopy).Create('{self.drive}\\','ClientAccessible'); "
            "if ($r.ReturnValue -ne 0) { "
            "  Write-Output \"RETURN_VALUE=$($r.ReturnValue)\"; exit 10; "
            "} "
            "$sc = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $r.ShadowID }; "
            "if (-not $sc) { Write-Output 'QUERY_BACK_FAILED'; exit 11; } "
            "Write-Output \"SHADOW_ID=$($sc.ID)\"; "
            "Write-Output \"DEVICE=$($sc.DeviceObject)\""
        )

        proc = self._run_powershell(ps)
        out  = (proc.stdout or "") + (proc.stderr or "")

        # Decode WMI ReturnValue if Create() refused
        rv_match = re.search(r"RETURN_VALUE=(\d+)", out)
        if rv_match:
            rv = int(rv_match.group(1))
            human = _WMI_CREATE_ERRORS.get(rv, f"Unknown WMI error {rv}")
            raise VSSError(
                f"Win32_ShadowCopy.Create returned {rv} ({human})."
            )

        if proc.returncode != 0:
            raise VSSError(
                f"PowerShell shadow create failed (rc={proc.returncode}):\n"
                f"{out.strip() or '<no output>'}"
            )

        m_id  = self._RE_SHADOW_ID.search(out)
        m_dev = self._RE_SHADOW_DEV.search(out)
        if not (m_id and m_dev):
            raise VSSError(
                "Could not parse shadow info from PowerShell output.\n"
                f"--- output ---\n{out}"
            )

        self.shadow_id     = m_id.group(1)
        self.shadow_device = m_dev.group(1)
        self.logger.info(f"Shadow created — device = {self.shadow_device}")
        self.logger.info(f"Shadow ID = {self.shadow_id}")
        return self.shadow_device

    # ---- Read access helpers ------------------------------------------------
    def path_for(self, relative_path: str) -> str:
        """Build an absolute path inside the shadow copy namespace.
        Trailing backslash on the device path is required."""
        if not self.shadow_device:
            raise VSSError("Shadow copy has not been created yet.")
        rel = relative_path.lstrip("\\").lstrip("/")
        return f"{self.shadow_device}\\{rel}"

    def list_directory(self, relative_path: str) -> list[str]:
        target = self.path_for(relative_path)
        try:
            return os.listdir(target)
        except OSError as e:
            raise VSSError(f"Cannot list {target}: {e}") from e

    # ---- Delete -------------------------------------------------------------
    def delete(self) -> None:
        if not self.shadow_id:
            self.logger.warn(
                "No shadow ID captured — skipping delete to avoid "
                "removing unrelated shadows."
            )
            return
        self.logger.action(f"Deleting shadow copy {self.shadow_id}")
        ps = (
            "$ErrorActionPreference = 'Stop'; "
            f"$sc = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{self.shadow_id}' }}; "
            "if ($sc) { $sc.Delete() } else { Write-Output 'NOT_FOUND'; exit 1 }"
        )
        proc = self._run_powershell(ps)
        if proc.returncode == 0:
            self.logger.info("Shadow copy deleted.")
        else:
            # Don't raise — we don't want cleanup failure to mask an
            # otherwise-successful acquisition. Just log loudly so an
            # examiner can manually `vssadmin delete shadows` later.
            self.logger.warn(
                f"Shadow delete via WMI failed (rc={proc.returncode}): "
                f"{(proc.stderr or proc.stdout).strip()}"
            )

    # ---- Context manager ----------------------------------------------------
    def __enter__(self) -> "ShadowCopy":
        self.create()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            self.delete()
        except Exception as e:
            self.logger.error(f"Exception during shadow cleanup: {e!r}")


# =============================================================================
# SECTION 6 — DISCOVERY (user profiles, EVTX targets)
# =============================================================================

@dataclass(frozen=True)
class UserProfile:
    username:    str   # profile folder name
    profile_rel: str   # e.g. "Users\\Alice"
    ntuser_rel:  str   # e.g. "Users\\Alice\\NTUSER.DAT"


def discover_user_profiles(vss: ShadowCopy) -> Iterator[UserProfile]:
    """Yield UserProfile for every Users\\* dir containing a non-empty NTUSER.DAT."""
    try:
        entries = vss.list_directory(USERS_DIR_REL)
    except Exception:
        return
    for name in sorted(entries):
        if name in EXCLUDED_USER_DIRS or name.startswith("."):
            continue
        profile_rel = os.path.join(USERS_DIR_REL, name)
        ntuser_rel  = os.path.join(profile_rel, NTUSER_FILENAME)
        full = vss.path_for(ntuser_rel)
        try:
            st = os.stat(full)
        except OSError:
            continue
        if st.st_size <= 0:
            continue
        yield UserProfile(username=name, profile_rel=profile_rel, ntuser_rel=ntuser_rel)


@dataclass(frozen=True)
class EvtxTarget:
    name:     str   # e.g. "System.evtx"
    rel_path: str   # e.g. "Windows\\System32\\winevt\\Logs\\System.evtx"


def enumerate_evtx(vss: ShadowCopy) -> Iterator[EvtxTarget]:
    for filename in EVTX_LOGS:
        rel  = os.path.join(EVTX_DIR_REL, filename)
        full = vss.path_for(rel)
        try:
            if os.path.getsize(full) > 0:
                yield EvtxTarget(name=filename, rel_path=rel)
        except OSError:
            continue


# =============================================================================
# SECTION 7 — EXTRACTION ENGINE (two-pass integrity)
# =============================================================================
#
# Each artifact runs through this pipeline:
#
#   Pass 1 — STREAM-COPY:
#       Read from VSS in CHUNK_SIZE chunks → write to USB → update SHA-256.
#       Produces (digest_inflight, bytes_copied).
#
#   Pass 2 — VERIFY:
#       Re-open the destination after fsync and re-hash.
#       Produces digest_persisted.
#
#   integrity = PASS iff  digest_inflight == digest_persisted
#                   AND   persisted_size == bytes_copied
#
# Why two passes? Catches USB write errors, AV mid-flight mutation, silent
# corruption — all things a one-pass hash misses.
# =============================================================================

@dataclass
class ArtifactRecord:
    artifact_type:    str
    logical_name:     str
    source_path:      str
    destination_path: str
    size_bytes:       int
    sha256_inflight:  Optional[str]
    sha256_persisted: Optional[str]
    integrity:        str            # 'PASS' | 'FAIL' | 'ERROR'
    acquired_at:      str            # local time with UTC offset, e.g. 2026-06-14T06:30:01+03:00
    error:            Optional[str] = None
    write_blocked:    bool           = False
    permissions:      str            = ""    # e.g. "0o444 (r--r--r--)"

    def to_dict(self) -> dict:
        return asdict(self)


class Extractor:
    """Performs all artifact acquisition for one case."""

    def __init__(self, vss: ShadowCopy, evidence_dir: Path,
                 hashes_dir: Path, logger: ForensicLogger):
        self.vss          = vss
        self.evidence_dir = Path(evidence_dir)
        self.hashes_dir   = Path(hashes_dir)
        self.logger       = logger
        self.manifest     = self.hashes_dir / MANIFEST_FILENAME

    # --- Pass 1: stream-copy + in-flight hash --------------------------------
    def _copy_with_hash(self, src_vss_path: str, dst_path: Path) -> tuple[str, int]:
        sha   = new_sha256()                # CNG on Windows, hashlib off-Win
        total = 0
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        with open(src_vss_path, "rb") as fin, open(dst_path, "wb") as fout:
            for chunk in iter(lambda: fin.read(CHUNK_SIZE), b""):
                fout.write(chunk)
                sha.update(chunk)
                total += len(chunk)
            fout.flush()
            try:
                os.fsync(fout.fileno())
            except OSError:
                pass  # not all USB drivers support fsync — non-fatal
        return sha.hexdigest(), total

    # --- Combined pass-1 + pass-2 + write-block for a single artifact --------
    def _acquire_one(self, artifact_type: str, logical_name: str,
                     src_rel: str, dst_path: Path) -> ArtifactRecord:
        src         = self.vss.path_for(src_rel)
        acquired_at = local_now_iso()

        # Pass 1
        try:
            digest_inflight, size = self._copy_with_hash(src, dst_path)
        except Exception as e:
            self.logger.error(f"COPY FAIL [{logical_name}] {src} → {dst_path}: {e!r}")
            # Write-block even a partial/failed file — its state is evidence.
            perm = write_block(dst_path, self.logger) if dst_path.exists() else ""
            return ArtifactRecord(
                artifact_type, logical_name, src, str(dst_path),
                0, None, None, "ERROR", acquired_at, repr(e),
                write_blocked=bool(perm and not perm.startswith("FAILED")),
                permissions=perm,
            )

        # Pass 2
        try:
            digest_persisted = sha256_file(dst_path)
            persisted_size   = dst_path.stat().st_size
        except Exception as e:
            self.logger.error(f"VERIFY FAIL [{logical_name}]: {e!r}")
            perm = write_block(dst_path, self.logger)
            return ArtifactRecord(
                artifact_type, logical_name, src, str(dst_path),
                size, digest_inflight, None, "ERROR", acquired_at, repr(e),
                write_blocked=not perm.startswith("FAILED"),
                permissions=perm,
            )

        ok = (digest_inflight == digest_persisted) and (persisted_size == size)
        integrity = "PASS" if ok else "FAIL"

        # Manifest + sidecar
        sidecar = write_sidecar(dst_path, digest_persisted, self.hashes_dir)
        append_manifest(
            self.manifest, digest_persisted,
            str(dst_path.relative_to(self.evidence_dir)).replace("\\", "/"),
        )

        # Write-block the artifact file
        perm = write_block(dst_path, self.logger)
        # Write-block the sidecar immediately too
        write_block(sidecar, self.logger)

        self.logger.action(
            f"ACQUIRED [{artifact_type}] {logical_name} "
            f"size={size} sha256={digest_persisted[:16]}... "
            f"integrity={integrity} perm={perm}"
        )
        return ArtifactRecord(
            artifact_type, logical_name, src, str(dst_path),
            size, digest_inflight, digest_persisted, integrity, acquired_at,
            write_blocked=not perm.startswith("FAILED"),
            permissions=perm,
        )

    # --- Per-category drivers ------------------------------------------------
    def acquire_registry_hives(self) -> list[ArtifactRecord]:
        out_dir = self.evidence_dir / SUBDIR_REGISTRY
        results = []
        for name, rel in REGISTRY_HIVES.items():
            self.logger.action(f"Acquiring HKLM hive: {name}")
            results.append(self._acquire_one("registry_hive", name, rel, out_dir / name))
        return results

    def acquire_user_hives(self) -> list[ArtifactRecord]:
        out_dir = self.evidence_dir / SUBDIR_NTUSER
        results = []
        profiles = list(discover_user_profiles(self.vss))
        if not profiles:
            self.logger.warn("No user profiles with NTUSER.DAT discovered.")
            return results
        self.logger.info(
            f"Discovered {len(profiles)} user profile(s): "
            f"{', '.join(p.username for p in profiles)}"
        )
        for prof in profiles:
            self.logger.action(f"Acquiring NTUSER.DAT — user={prof.username}")
            safe = prof.username.replace(" ", "_").replace("\\", "_")
            dst  = out_dir / f"NTUSER_{safe}.DAT"
            results.append(self._acquire_one(
                "ntuser_hive", f"{prof.username}/NTUSER.DAT",
                prof.ntuser_rel, dst,
            ))
        return results

    def acquire_evtx(self) -> list[ArtifactRecord]:
        out_dir = self.evidence_dir / SUBDIR_EVTX
        results = []
        targets = list(enumerate_evtx(self.vss))
        present = {t.name for t in targets}
        for missing in (set(EVTX_LOGS) - present):
            self.logger.warn(f"EVTX missing from snapshot: {missing}")
        for tgt in targets:
            self.logger.action(f"Acquiring EVTX: {tgt.name}")
            results.append(self._acquire_one(
                "evtx", tgt.name, tgt.rel_path, out_dir / tgt.name,
            ))
        return results


# =============================================================================
# SECTION 8 — REPORT GENERATOR
# =============================================================================

def build_report(case_id: str, started_at: str,
                 vss_shadow_id: Optional[str], vss_shadow_device: Optional[str],
                 registry_records: list[ArtifactRecord],
                 user_records:     list[ArtifactRecord],
                 evtx_records:     list[ArtifactRecord],
                 elevated:         bool) -> dict:
    all_records = registry_records + user_records + evtx_records
    n_pass     = sum(1 for r in all_records if r.integrity == "PASS")
    n_fail     = sum(1 for r in all_records if r.integrity == "FAIL")
    n_err      = sum(1 for r in all_records if r.integrity == "ERROR")
    n_blocked  = sum(1 for r in all_records if r.write_blocked)
    bytes_total = sum(r.size_bytes for r in all_records)

    if all_records and n_pass == len(all_records):
        overall = "PASS"
    elif n_pass == 0:
        overall = "FAIL"
    else:
        overall = "PARTIAL"

    tz = local_tz_info()

    return {
        "case_id": case_id,
        "tool": {
            "name":    TOOL_NAME,
            "suite":   TOOL_SUITE,
            "version": TOOL_VERSION,
        },
        "timestamps": {
            # Both timestamps are LOCAL time with UTC offset embedded.
            # Example on EAT (UTC+3): "2026-06-14T06:30:01.123456+03:00"
            # Subtract the offset to get UTC; add it to get local time.
            "started_at":    started_at,
            "completed_at":  local_now_iso(),
        },
        "source_machine": {
            "hostname":        socket.gethostname(),
            "os":              platform.platform(),
            "platform":        platform.system(),
            "windows_edition": windows_edition_info(),
            "timezone":        tz,
            "user_running":    getpass.getuser(),
            "elevated":        bool(elevated),
            "system_drive":    SYSTEM_DRIVE,
        },
        "vss": {
            "shadow_id":     vss_shadow_id,
            "shadow_device": vss_shadow_device,
        },
        "hashing": {
            "algorithm":       "SHA-256",
            "provider":        hash_provider_name(),
            "hardware_native": _BCRYPT_AVAILABLE,
        },
        "evidence_protection": {
            "write_block_mode":        _EVIDENCE_MODE_STR,
            "owner_read":              bool(_EVIDENCE_MODE & stat.S_IRUSR),
            "group_read":              bool(_EVIDENCE_MODE & stat.S_IRGRP),
            "others_read":             bool(_EVIDENCE_MODE & stat.S_IROTH),
            "artifacts_write_blocked": n_blocked,
        },
        "artifacts": {
            "registry_hives": [r.to_dict() for r in registry_records],
            "user_hives":     [r.to_dict() for r in user_records],
            "evtx_logs":      [r.to_dict() for r in evtx_records],
        },
        "summary": {
            "total_artifacts":    len(all_records),
            "pass":               n_pass,
            "fail":               n_fail,
            "error":              n_err,
            "write_blocked":      n_blocked,
            "bytes_acquired":     bytes_total,
        },
        "integrity": overall,
    }


def write_report(report: dict, evidence_dir: Path) -> Path:
    out = Path(evidence_dir) / REPORT_FILENAME
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out


# =============================================================================
# SECTION 9 — ORCHESTRATION (single entry point)
# =============================================================================

def _build_evidence_tree(case_id: str) -> dict:
    root = evidence_root_for(case_id)
    root.mkdir(parents=True, exist_ok=True)
    paths = {"root": root}
    for sub in EVIDENCE_SUBDIRS:
        p = root / sub
        p.mkdir(parents=True, exist_ok=True)
        paths[sub] = p
    return paths


def main() -> int:
    started = local_now_iso()
    case_id = generate_case_id()

    # ---- Preflight ----------------------------------------------------------
    if not is_windows():
        print("[FATAL] This tool only runs on Windows.", file=sys.stderr)
        return 2

    elevated = is_admin()
    if not elevated:
        print(
            "[FATAL] Administrator privileges are required.\n"
            "        Right-click → Run as administrator, or invoke from an\n"
            "        elevated cmd / PowerShell session.",
            file=sys.stderr,
        )
        return 3

    # ---- Evidence layout + logger ------------------------------------------
    paths = _build_evidence_tree(case_id)
    log = ForensicLogger(paths[SUBDIR_LOGS], case_id)
    log.info(f"{TOOL_NAME} v{TOOL_VERSION} — {TOOL_SUITE}")
    log.info(f"Evidence root  : {paths['root']}")
    log.info(f"Started at     : {started}")

    tz = local_tz_info()
    log.info(
        f"Timezone       : {tz['tzname']}  "
        f"(UTC{tz['utc_offset']} = {tz['utc_offset_secs']:+d}s)"
    )
    log.info(f"Target volume  : {SYSTEM_DRIVE}")
    log.info(f"Hash provider  : {hash_provider_name()}  (SHA-256)")

    win = windows_edition_info()
    log.info(
        f"Windows edition: release={win['release']!r} "
        f"build={win['build']!r} server={win['is_server']}"
    )
    if not win["win10_or_11"] and not win["is_server"]:
        log.warn(
            "Host does not self-report as Windows 10/11 or Server — "
            "WMI shadow creation may still work but is unvalidated here."
        )

    # ---- Acquisition --------------------------------------------------------
    registry_records: list[ArtifactRecord] = []
    user_records:     list[ArtifactRecord] = []
    evtx_records:     list[ArtifactRecord] = []
    shadow_id = shadow_device = None
    exit_code = 0

    try:
        with ShadowCopy(SYSTEM_DRIVE, log) as vss:
            shadow_id     = vss.shadow_id
            shadow_device = vss.shadow_device

            ext = Extractor(
                vss          = vss,
                evidence_dir = paths["root"],
                hashes_dir   = paths[SUBDIR_HASHES],
                logger       = log,
            )

            log.info("--- Phase 1: HKLM registry hives ---")
            registry_records = ext.acquire_registry_hives()

            log.info("--- Phase 2: User NTUSER.DAT hives ---")
            user_records = ext.acquire_user_hives()

            log.info("--- Phase 3: Windows event logs (EVTX) ---")
            evtx_records = ext.acquire_evtx()

    except VSSError as e:
        log.error(f"VSS lifecycle error: {e}")
        exit_code = 4
    except KeyboardInterrupt:
        log.warn("Acquisition interrupted by operator (Ctrl+C).")
        exit_code = 130
    except Exception as e:
        log.error(f"UNHANDLED EXCEPTION: {e!r}")
        exit_code = 1

    # ---- Reporting ----------------------------------------------------------
    report_path: Optional[Path] = None
    try:
        report = build_report(
            case_id           = case_id,
            started_at        = started,
            vss_shadow_id     = shadow_id,
            vss_shadow_device = shadow_device,
            registry_records  = registry_records,
            user_records      = user_records,
            evtx_records      = evtx_records,
            elevated          = elevated,
        )
        report_path = write_report(report, paths["root"])
        log.info(f"Report written : {report_path}")
        log.info(f"Overall result : {report['integrity']} "
                 f"({report['summary']['pass']}/"
                 f"{report['summary']['total_artifacts']} artifacts PASS, "
                 f"{report['summary']['write_blocked']} write-blocked)")
    except Exception as e:
        log.error(f"Report generation failed: {e!r}")
        exit_code = exit_code or 5

    # ---- Final evidence hardening -------------------------------------------
    # Applies 0o444 (r--r--r--) to EVERY path in the evidence package.
    #
    # Why 0o444 rather than 0o555?
    #   Directories need execute to be traversable on Unix.
    #   We deliberately remove execute too — the examiner archives the
    #   package as-is; nobody should be cd'ing into live evidence.
    #   On NTFS the execute bit is irrelevant; only write matters.
    #
    # Permission bit breakdown:
    #   stat.S_IRUSR  0o400   owner  : r--
    #   stat.S_IRGRP  0o040   group  :  r--
    #   stat.S_IROTH  0o004   others :   r--
    #   ─────────────────────────────────────
    #   combined      0o444             r--r--r--
    #
    # Sequencing (order is mandatory):
    #   Step 1 — all files under the case root  (except the live CoC log)
    #   Step 2 — all directories bottom-up      (except logs/)
    #   Step 3 — log.close(), then seal the log file
    #   Step 4 — seal logs/ directory
    #   Step 5 — seal the case root  (DFIR_Evidence/CASE_xxx/)
    #   Step 6 — seal the parent     (DFIR_Evidence/)   ← was missing before
    # ---------------------------------------------------------------------- #
    log.info("--- Final hardening: write-blocking entire evidence package ---")
    log.info(
        f"Permission mode : {_EVIDENCE_MODE_STR}  "
        f"(owner={bool(_EVIDENCE_MODE & stat.S_IRUSR)}  "
        f"group={bool(_EVIDENCE_MODE & stat.S_IRGRP)}  "
        f"others={bool(_EVIDENCE_MODE & stat.S_IROTH)})"
    )

    live_log = paths[SUBDIR_LOGS] / COC_LOG_FILENAME

    # Step 1 — every file under the case root, deepest first, skipping live log
    for p in sorted(paths["root"].rglob("*"), key=lambda x: -len(x.parts)):
        if p.is_file() and p != live_log:
            write_block(p, log)

    # Step 2 — every directory bottom-up, skipping logs/ (live log still open)
    for d in sorted(
        (p for p in paths["root"].rglob("*")
         if p.is_dir() and p != paths[SUBDIR_LOGS]),
        key=lambda p: -len(p.parts),
    ):
        write_block(d, log)

    log.info("Evidence package hardening complete.")
    log.close()                          # <<< last write to the log

    # Steps 3-6: seal in bottom-up order after log is closed
    write_block(live_log)                # chain_of_custody.log
    write_block(paths[SUBDIR_LOGS])      # logs/
    write_block(paths["root"])           # DFIR_Evidence/CASE_xxx/
    write_block(paths["root"].parent)    # DFIR_Evidence/

    return exit_code


if __name__ == "__main__":
    sys.exit(main())


# =============================================================================
# BUILD INSTRUCTIONS (PyInstaller, optional)
# =============================================================================
#
#   pip install pyinstaller
#   pyinstaller --onefile --console --uac-admin --clean ^
#               --name DFIR_Collector DFIR_Collector.py
#
#   Output:  dist\DFIR_Collector.exe   (copy to the root of the forensic USB)
#
#   The --uac-admin flag bakes elevation into the manifest, so launching the
#   EXE normally fires a UAC prompt automatically (required for vssadmin).
# =============================================================================
