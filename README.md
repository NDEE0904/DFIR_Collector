## DFIR Portable Evidence Collector
### RegHiveTool Suite · v1.4.0

> Single-file, USB-portable Windows forensic acquisition tool.  
> No installation. No persistence. No third-party dependencies.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Requirements](#requirements)
4. [Quick Start](#quick-start)
5. [Evidence Package Structure](#evidence-package-structure)
6. [Acquisition Workflow](#acquisition-workflow)
7. [Forensic Integrity Model](#forensic-integrity-model)
8. [Timestamp Handling](#timestamp-handling)
9. [Write-Blocking](#write-blocking)
10. [Native Hash Engine (Windows CNG)](#native-hash-engine-windows-cng)
11. [Building a Portable EXE](#building-a-portable-exe)
12. [Output Reference](#output-reference)
13. [Forensic Principles](#forensic-principles)
14. [Standards Alignment](#standards-alignment)
15. [Compatibility](#compatibility)
16. [Known Limitations](#known-limitations)
17. [Changelog](#changelog)

---

## Overview

**DFIR Portable Evidence Collector** is an enterprise-grade Windows forensic acquisition tool built for incident response teams who need to collect registry hives, user artefacts, and event logs from a live Windows 10 or Windows 11 system — quickly, defensibly, and without leaving any trace on the target.

The tool is a single Python script (`DFIR_Collector.py`) that can be deployed as a standalone `.exe` via PyInstaller. It runs entirely from a forensic USB drive and writes all evidence back to that same drive. No software is installed on the target. No registry keys are written. No services are created. The only state change on the target is the creation and immediate deletion of one Volume Shadow Copy.

The design is inspired by industry-standard tools such as **KAPE**, **FTK Imager**, and **CyLR**, with a focus on code transparency: every acquisition step, hash computation, and integrity decision is visible in the source.

---

## Key Features

| Capability | Detail |
|---|---|
| **VSS-based acquisition** | All locked files (hives, EVTX) are read through a Volume Shadow Copy snapshot — never from the live volume |
| **Two-pass SHA-256 integrity** | Hash computed in-flight during copy (Pass 1) and re-verified after `fsync` (Pass 2); both must agree for `PASS` |
| **Native OS hash engine** | SHA-256 routed through Windows CNG (`bcrypt.dll`) via ctypes — the same FIPS-validated, hardware-accelerated provider used by `Get-FileHash` and BitLocker |
| **Write-blocking (0o444)** | Every acquired file is immediately set `r--r--r--` (owner, group, others) after integrity verification; a final sweep seals all directories and the package root |
| **Local-time timestamps** | All timestamps reflect the host computer's configured timezone with explicit UTC offset (e.g. `+03:00`), not UTC, so chain-of-custody entries match what the operator sees on the machine's clock |
| **Chain-of-custody log** | Append-only, human-readable log with ISO-8601 local timestamps and UTC offset on every entry |
| **Structured JSON report** | Single `report.json` covering tool metadata, source machine, VSS info, hash provider, write-block status, and per-artifact integrity |
| **sha256sum-compatible manifest** | `SHA256SUMS.txt` can be verified on any platform with `sha256sum -c SHA256SUMS.txt` |
| **Win10 / Win11 client support** | Uses `Win32_ShadowCopy` WMI (via PowerShell) instead of `vssadmin create shadow`, which is restricted to Server SKUs on client editions |
| **Zero dependencies** | Standard library only (`hashlib`, `ctypes`, `subprocess`, `json`, `os`, `stat`, `re`, `socket`, `threading`) |
| **Portable USB execution** | Evidence tree always created next to the script / EXE — on the USB, never on the target |

---

## Requirements

### Target Machine (the system being acquired)

| Requirement | Notes |
|---|---|
| Windows 10 or Windows 11 | Also works on Windows Server 2016 and newer |
| PowerShell 5.1 or newer | Ships with every Win10/11 installation |
| Administrator privileges | Required for VSS snapshot creation |
| Volume Shadow Copy service running | `vss` service — enabled by default |

### Analyst Workstation (build machine, one-time)

| Requirement | Notes |
|---|---|
| Python 3.10 or newer | For running from source or building the EXE |
| PyInstaller 6.x | Required only to build the portable EXE |

### Runtime Dependencies

**None.** The tool uses Python's standard library exclusively. No `pip install` is needed on either machine when running from source.

---

## Quick Start

### Option A — Run from source (elevated `cmd` or PowerShell on the target)

```cmd
:: 1. Copy DFIR_Collector.py to the root of your forensic USB
:: 2. On the target machine, open an elevated cmd prompt:

python DFIR_Collector.py
```

### Option B — Run as a standalone EXE (recommended for field deployment)

**Step 1:** On your analyst workstation, build the EXE once:

```cmd
pip install pyinstaller
pyinstaller --onefile --console --uac-admin --clean --name DFIR_Collector DFIR_Collector.py
```

**Step 2:** Copy `dist\DFIR_Collector.exe` to the root of your forensic USB.

**Step 3:** On the target machine, launch the EXE. The `--uac-admin` manifest flag triggers a UAC elevation prompt automatically — no need to right-click manually.

```cmd
E:\DFIR_Collector.exe
```

**Step 4:** Wait for the console to print `Overall result : PASS`. Remove the USB. All evidence is under `E:\DFIR_Evidence\`.

### Verifying the evidence package after acquisition

```bash
# On any Linux / macOS / Windows (with Git Bash or WSL) workstation:
cd DFIR_Evidence/CASE_<hostname>_<timestamp>/
sha256sum -c hashes/SHA256SUMS.txt
```

Every artifact should print `OK`. Any `FAILED` line requires investigation before the evidence is used.

---

## Evidence Package Structure

The tool creates the following directory tree **next to the EXE on the USB drive** — never on the target system:

```
<USB>:\
└── DFIR_Evidence\                          ← write-blocked (0o444) after acquisition
    └── CASE_<HOSTNAME>_<YYYYMMDDTHHMMSS>\  ← case root, one per run
        │
        ├── registry_hives\                 ← HKLM system hives
        │   ├── SYSTEM
        │   ├── SAM
        │   ├── SOFTWARE
        │   ├── SECURITY
        │   └── DEFAULT
        │
        ├── user_hives_ntuser\              ← per-user NTUSER.DAT files
        │   ├── NTUSER_Alice.DAT
        │   ├── NTUSER_Bob.DAT
        │   └── ...
        │
        ├── evtx_logs\                      ← Windows event logs
        │   ├── System.evtx
        │   ├── Security.evtx
        │   └── Application.evtx
        │
        ├── hashes\                         ← integrity artefacts
        │   ├── SHA256SUMS.txt              ← master manifest (sha256sum -c compatible)
        │   ├── SYSTEM.sha256               ← per-artifact sidecar
        │   ├── SAM.sha256
        │   └── ...
        │
        ├── logs\
        │   └── chain_of_custody.log        ← append-only, local time + UTC offset
        │
        └── report.json                     ← structured forensic report
```

All files and directories — including `DFIR_Evidence\` itself — are set to `r--r--r--` (0o444) by the tool's final hardening sweep before it exits.

---

## Acquisition Workflow

```
START
  │
  ├─ Preflight checks
  │    ├─ Is this Windows?          (exits code 2 if not)
  │    └─ Is process elevated?      (exits code 3 if not)
  │
  ├─ Create evidence directory tree on USB
  ├─ Open chain-of-custody log
  ├─ Log host timezone (tzname + UTC offset)
  │
  ├─ Create Volume Shadow Copy (Win32_ShadowCopy WMI via PowerShell)
  │
  ├─ PHASE 1 ── HKLM Registry Hives ─────────────────────────────────
  │    For each of: SYSTEM, SAM, SOFTWARE, SECURITY, DEFAULT
  │      ├─ Copy from VSS shadow namespace → USB  (Pass 1 hash)
  │      ├─ fsync destination
  │      ├─ Re-hash destination                   (Pass 2 hash)
  │      ├─ Compare digests + sizes → PASS / FAIL / ERROR
  │      ├─ Write .sha256 sidecar
  │      ├─ Append to SHA256SUMS.txt
  │      └─ Apply 0o444 write-block to artifact + sidecar
  │
  ├─ PHASE 2 ── User NTUSER.DAT Hives ────────────────────────────────
  │    Enumerate C:\Users\* (skip Default, Public, system accounts)
  │    For each real user profile with a readable NTUSER.DAT:
  │      └─ [same copy → hash → verify → write-block pipeline]
  │
  ├─ PHASE 3 ── Windows Event Logs ───────────────────────────────────
  │    For each of: System.evtx, Security.evtx, Application.evtx
  │      └─ [same copy → hash → verify → write-block pipeline]
  │
  ├─ Delete Volume Shadow Copy (always, even on failure)
  │
  ├─ Generate report.json
  │
  ├─ FINAL HARDENING SWEEP ───────────────────────────────────────────
  │    Step 1: All files under case root (deepest-first)   → 0o444
  │    Step 2: All subdirectories (bottom-up, skip logs/)  → 0o444
  │    Step 3: Close chain-of-custody log
  │    Step 4: logs/chain_of_custody.log                   → 0o444
  │    Step 5: logs/ directory                             → 0o444
  │    Step 6: CASE_xxx/ (case root)                       → 0o444
  │    Step 7: DFIR_Evidence/ (package root)               → 0o444
  │
EXIT (code 0 = success)
```

---

## Forensic Integrity Model

Every artifact undergoes a **two-pass SHA-256 verification**:

### Pass 1 — In-flight hash (during copy)

Bytes are read from the VSS shadow in 1 MiB chunks, written to the USB destination, and fed into a SHA-256 accumulator simultaneously. On completion: `digest_inflight` and `bytes_copied`.

### Pass 2 — Persisted hash (after fsync)

The destination file is re-opened and hashed from scratch after `os.fsync()` forces a kernel-level flush. Result: `digest_persisted` and `persisted_size`.

### Integrity verdict

```
PASS   ←  digest_inflight == digest_persisted
           AND persisted_size == bytes_copied

FAIL   ←  digests or sizes disagree (write error, AV mutation, corruption)

ERROR  ←  I/O exception during copy or verification
```

Only `PASS` artifacts should be admitted as forensic evidence without qualification. `FAIL` and `ERROR` artifacts are still write-blocked and recorded — their state is itself evidence.

### Why two passes?

A single hash during copy cannot detect:
- USB write errors (bytes written to cache but not flushed)
- Antivirus software that intercepts and mutates the file in transit
- Silent filesystem corruption between write and close
- Partial writes on USB disconnection

The two-pass model catches all of these because the second hash reads bytes that are physically on the USB, not from a write buffer.

---

## Timestamp Handling

All timestamps in the chain-of-custody log and `report.json` reflect the **local time of the target computer** with the UTC offset explicitly embedded.

| Format | Example (EAT, UTC+3) | Example (EST, UTC-5) |
|---|---|---|
| ISO-8601 with offset | `2026-06-14T06:30:01.123456+03:00` | `2026-06-13T22:30:01.123456-05:00` |

### Why local time?

The UTC offset is always present, so any timestamp is globally unambiguous — subtract the offset to get UTC. Local time is used because:

- It matches what the operator sees on the target machine's clock at the moment of acquisition
- Registry artefacts (Last Write Times, MRU entries, shellbag timestamps) are often stored relative to local time — examiner correlation is more natural
- Chain-of-custody records are typically read in the context of the timezone where the investigation occurred

### Timezone source on Windows

The timezone is read from `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` via the C runtime (`datetime.now().astimezone()`), the same key Windows uses for the taskbar clock.

The timezone name and offset are recorded in both the CoC log and `report.json`:

```json
"timezone": {
  "tzname":          "EAT",
  "utc_offset":      "+03:00",
  "utc_offset_secs": 10800
}
```

---

## Write-Blocking

Once a file is acquired and verified, it is immediately made read-only using POSIX permission bits:

```
stat.S_IRUSR  0o400   owner  : r--
stat.S_IRGRP  0o040   group  :  r--
stat.S_IROTH  0o004   others :   r--
─────────────────────────────────────
combined      0o444             r--r--r--
```

### Platform behaviour

| Platform | Effect of 0o444 |
|---|---|
| NTFS (Windows) | Sets `FILE_ATTRIBUTE_READONLY`. Prevents modification by Explorer, `cmd`, PowerShell, and most user-mode tools. SYSTEM/Administrators can still copy the evidence to archive it. |
| ext4 / APFS (Linux / macOS) | Removes all write bits for all principals. Write attempts by non-root users raise `PermissionError`. |

### Blocking sequence

Files are blocked immediately in `_acquire_one()`. The final hardening sweep (after report generation) applies write-blocking in this order:

1. All remaining files (manifest, report, sidecars not yet blocked)
2. All subdirectories — bottom-up (deepest first)
3. `chain_of_custody.log` — after the logger is closed
4. `logs/` directory
5. Case root directory (`DFIR_Evidence/CASE_xxx/`)
6. `DFIR_Evidence/` parent — **the entire package root**

Every directory is blocked bottom-up so the tool can still write into parent directories while processing child ones.

---

## Native Hash Engine (Windows CNG)

SHA-256 computation is routed through **Windows Cryptography: Next Generation (CNG)** via a direct `ctypes` binding to `bcrypt.dll`. This is the same code path used by:

- `Get-FileHash` (PowerShell)
- `certutil -hashfile`
- BitLocker
- Windows Code Integrity

### Why this matters forensically

| Property | CNG (bcrypt.dll) | Python hashlib |
|---|---|---|
| FIPS 140-2 / 140-3 validated | Yes (when host is in FIPS mode) | Not guaranteed |
| Hardware acceleration | Auto (Intel SHA-NI / ARMv8 Crypto) | Depends on build |
| Cross-tool verifiable | Byte-identical to `Get-FileHash` | Should match, but different pipeline |
| Defensibility | "OS-validated provider" | "Bundled OpenSSL" |

### Independent verification

Any artifact in the package can be re-verified without this tool:

```powershell
Get-FileHash .\registry_hives\SYSTEM -Algorithm SHA256
```

The resulting hash must match the `.sha256` sidecar and `SHA256SUMS.txt` line exactly.

The tool falls back to `hashlib` automatically if `bcrypt.dll` cannot be loaded (this should never happen on a Windows system but is provided as a fail-safe for off-target testing).

---

## Building a Portable EXE

### Prerequisites

```cmd
pip install pyinstaller
```

### Build command

```cmd
pyinstaller ^
    --onefile ^
    --console ^
    --uac-admin ^
    --clean ^
    --name DFIR_Collector ^
    DFIR_Collector.py
```

| Flag | Purpose |
|---|---|
| `--onefile` | Bundle interpreter + script into a single `.exe` |
| `--console` | Keep stdout visible so the operator can monitor progress |
| `--uac-admin` | Embed UAC elevation manifest — launching the EXE automatically prompts for admin rights |
| `--clean` | Wipe PyInstaller cache before building to prevent stale artefacts |

### Output

```
dist\DFIR_Collector.exe      ← the only file you copy to the USB
```

### Windows SmartScreen

SmartScreen will warn about unsigned executables on removable media. Options:

- Click **More info → Run anyway** for one-time bypass (acceptable in controlled environments)
- Code-sign the EXE with an Authenticode certificate for production deployment
- Deploy via SCCM or endpoint management tools that bypass SmartScreen for trusted binaries

### Cross-compilation note

PyInstaller bundles the Python interpreter for the platform it runs on. Building on Ubuntu produces a Linux ELF binary, not a Windows `.exe`. The EXE **must be built on a Windows machine**. Use a dedicated analyst workstation or a Windows VM with Python 3.10+ and PyInstaller installed.

---

## Output Reference

### chain_of_custody.log

Append-only plain text. Every line follows the format:

```
[<ISO-8601 local timestamp with UTC offset>] [<LEVEL >] <message>
```

Example (EAT timezone):

```
[2026-06-14T06:30:00.001234+03:00] [INFO  ] ========================================================================
[2026-06-14T06:30:00.001987+03:00] [INFO  ] Chain of Custody opened — case_id=CASE_PHILENIUS_20260614T063000
[2026-06-14T06:30:00.002100+03:00] [INFO  ] ========================================================================
[2026-06-14T06:30:00.003000+03:00] [INFO  ] DFIR Portable Evidence Collector v1.4.0 — RegHiveTool Suite
[2026-06-14T06:30:00.003200+03:00] [INFO  ] Timezone       : EAT  (UTC+03:00 = +10800s)
[2026-06-14T06:30:00.005000+03:00] [ACTION] Creating Volume Shadow Copy for C:\
[2026-06-14T06:30:04.120000+03:00] [INFO  ] Shadow created — device = \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
[2026-06-14T06:30:04.121000+03:00] [ACTION] Acquiring HKLM hive: SYSTEM
[2026-06-14T06:30:06.880000+03:00] [ACTION] WRITE-BLOCKED 0o444 (r--r--r--) [FILE] SYSTEM
[2026-06-14T06:30:06.881000+03:00] [ACTION] ACQUIRED [registry_hive] SYSTEM size=14680064 sha256=3a7f9c1e... integrity=PASS perm=0o444 (r--r--r--)
```

Log levels:

| Level | Meaning |
|---|---|
| `INFO` | Informational status update |
| `ACTION` | A state-changing operation (copy, hash, write-block, VSS create/delete) |
| `WARN` | Non-fatal anomaly (missing EVTX file, no user profiles found) |
| `ERROR` | Acquisition or verification failure for a specific artifact |

### report.json

```jsonc
{
  "case_id": "CASE_PHILENIUS_20260614T063000",
  "tool": {
    "name":    "DFIR Portable Evidence Collector",
    "suite":   "RegHiveTool Suite",
    "version": "1.4.0"
  },
  "timestamps": {
    "started_at":   "2026-06-14T06:30:00.001234+03:00",   // local time + UTC offset
    "completed_at": "2026-06-14T06:31:45.998000+03:00"
  },
  "source_machine": {
    "hostname":   "PHILENIUS",
    "os":         "Windows-11-10.0.22631-SP0",
    "platform":   "Windows",
    "timezone": {
      "tzname":          "EAT",
      "utc_offset":      "+03:00",
      "utc_offset_secs": 10800
    },
    "windows_edition": {
      "release":     "11",
      "version":     "10.0.22631",
      "build":       "22631",
      "is_server":   false,
      "win10_or_11": true
    },
    "user_running": "Investigator",
    "elevated":     true,
    "system_drive": "C:"
  },
  "vss": {
    "shadow_id":     "{A1B2C3D4-5678-90AB-CDEF-1234567890AB}",
    "shadow_device": "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3"
  },
  "hashing": {
    "algorithm":       "SHA-256",
    "provider":        "Windows CNG (bcrypt.dll)",
    "hardware_native": true
  },
  "evidence_protection": {
    "write_block_mode":        "0o444 (r--r--r--)",
    "owner_read":              true,
    "group_read":              true,
    "others_read":             true,
    "artifacts_write_blocked": 9
  },
  "artifacts": {
    "registry_hives": [
      {
        "artifact_type":    "registry_hive",
        "logical_name":     "SYSTEM",
        "source_path":      "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3\\Windows\\System32\\config\\SYSTEM",
        "destination_path": "E:\\DFIR_Evidence\\CASE_...\\registry_hives\\SYSTEM",
        "size_bytes":       14680064,
        "sha256_inflight":  "3a7f9c1e...",
        "sha256_persisted": "3a7f9c1e...",
        "integrity":        "PASS",
        "acquired_at":      "2026-06-14T06:30:04.882000+03:00",
        "error":            null,
        "write_blocked":    true,
        "permissions":      "0o444 (r--r--r--)"
      }
      // ... SAM, SOFTWARE, SECURITY, DEFAULT
    ],
    "user_hives":     [ /* NTUSER_<user>.DAT entries */ ],
    "evtx_logs":      [ /* System.evtx, Security.evtx, Application.evtx entries */ ]
  },
  "summary": {
    "total_artifacts": 9,
    "pass":            9,
    "fail":            0,
    "error":           0,
    "write_blocked":   9,
    "bytes_acquired":  104857600
  },
  "integrity": "PASS"   // "PASS" | "PARTIAL" | "FAIL"
}
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Acquisition complete, all phases succeeded |
| `1` | Unhandled exception — check `chain_of_custody.log` |
| `2` | Not running on Windows |
| `3` | Process is not elevated (Administrator required) |
| `4` | VSS lifecycle error (create, parse, or delete failed) |
| `5` | Report generation failed |
| `130` | Operator interrupted with `Ctrl+C` |

A non-zero exit code does **not** mean no evidence was collected. The chain-of-custody log and partial `report.json` are always written (and write-blocked) even when the tool exits with an error.

---

## Forensic Principles

The tool is designed around the following non-negotiable principles:

### Read-only acquisition

All artifact bytes are read exclusively from the Volume Shadow Copy namespace (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...`), never from the live volume. The live filesystem is not opened for reading at any point.

### No modification of the target system

The tool does not:
- Write to the Windows Registry
- Install services or scheduled tasks
- Create files outside the VSS snapshot namespace on the target volume
- Leave any trace after the VSS snapshot is deleted

The only state changes on the target are:
1. One VSS snapshot created at the start (recorded with its ID in the CoC log)
2. That same snapshot deleted at exit (recorded in the CoC log)

### Evidence immutability

Every acquired file is write-blocked immediately after its integrity check completes. Failed and errored artifacts are also blocked — their partial state is evidence of what went wrong.

### Reproducibility

Given the same target machine at the same point in time, the tool should produce the same SHA-256 digests. Case IDs are deterministic (hostname + local timestamp). All decisions are logged.

### Chain of custody

Every action — including VSS creation/deletion, file copy, hash computation, integrity result, write-block, and directory seal — is recorded in the append-only `chain_of_custody.log` with a timestamped, levelled entry. The log is sealed last, after its own final entry is written.

---

## Standards Alignment

| Standard | Relevant section | How the tool aligns |
|---|---|---|
| **NIST SP 800-86** (Guide to Integrating Forensic Techniques) | §4.2 — Collection | VSS acquisition preserves original media; two-pass hash verifies no modification during transfer |
| **NIST SP 800-86** | §4.3 — Examination | SHA-256 sidecar files and `SHA256SUMS.txt` enable independent re-verification without the tool |
| **ISO/IEC 27037:2012** | §8.3.3 — Acquisition | Evidence integrity checked at acquisition time; chain-of-custody log maintained |
| **ACPO Good Practice Guide** | Principle 2 — No alteration | VSS read-only access; no writes to target; shadow deleted after acquisition |
| **RFC 3161** | Timestamping | Timestamps carry ISO-8601 format with explicit UTC offset for unambiguous global interpretation |

---

## Compatibility

| Component | Supported versions |
|---|---|
| Target OS | Windows 10 (all editions), Windows 11 (all editions), Windows Server 2016+ |
| Python (source mode) | 3.10, 3.11, 3.12, 3.13 |
| PowerShell | 5.1 (built-in), 7.x |
| WMI provider | Win32_ShadowCopy (available on all supported Windows editions) |
| Hash verification tools | `sha256sum` (Linux/macOS/WSL), `Get-FileHash` (PowerShell), `certutil -hashfile` (cmd) |
| Forensic suites | Hive files loadable by Registry Explorer, RegRipper, Autopsy, FTK, X-Ways |

---

## Known Limitations

**Windows client restriction on VSS creation via `vssadmin`**
This tool deliberately uses WMI (`Win32_ShadowCopy`) to bypass the client-edition restriction. If the WMI service (`winmgmt`) is stopped or corrupted on the target, acquisition will fail with exit code 4.

**VSS provider dependency**
The Microsoft Software Shadow Copy Provider service (`swprv`) must be running. On heavily locked-down systems this may be disabled.

**Volume Shadow Copy storage**
VSS requires available disk space on the target volume (typically 10–15% free space minimum). On near-full volumes, `Win32_ShadowCopy.Create()` may return error code 6 (`Insufficient storage`).

**No support for BitLocker-encrypted offline volumes**
The tool acquires from the running, decrypted volume via VSS. Offline acquisition of BitLocker-encrypted drives is out of scope.

**Directory write-blocking on NTFS**
`os.chmod` with 0o444 on an NTFS directory sets `FILE_ATTRIBUTE_READONLY` but does not apply ACL-level restrictions. An Administrator process on the target can still create files in those directories. File-level write-blocking is the primary protection.

**Single-drive acquisition**
The tool acquires from `%SystemDrive%` (default: `C:`) only. Evidence on secondary volumes requires a separate run with the `SYSTEM_DRIVE` environment variable overridden.

**No network capture or memory acquisition**
The scope is limited to registry hives and event logs. Live memory, network traffic, and process artefacts are not collected.

---

## Changelog

### v1.4.0 — Local-time timestamps
- All timestamps now use `datetime.now().astimezone()` — reflects the host computer's OS-configured timezone with explicit UTC offset (e.g. `2026-06-14T06:30:01+03:00`)
- Adds `timezone` block to `report.json → source_machine` (tzname, utc_offset, utc_offset_secs)
- Logs timezone name and offset at startup in chain-of-custody log
- Renames `ArtifactRecord.acquired_at_utc` → `acquired_at`; report keys `started_utc`/`completed_utc` → `started_at`/`completed_at`
- Fixes 3-hour offset symptom on UTC+3 (EAT) and equivalent discrepancies in all non-UTC timezones

### v1.3.0 — Write-blocking and package clean-up
- Adds evidence write-blocker (`stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH = 0o444`) applied per-artifact and in a final hardening sweep
- Removes unused `metadata/` directory from evidence package structure
- Adds `write_blocked` and `permissions` fields to `ArtifactRecord` and `report.json`
- Adds `evidence_protection` block to `report.json`
- Fixes final hardening sweep to cover all files, all directories, and `DFIR_Evidence/` parent directory

### v1.2.0 — Native CNG hash engine
- SHA-256 routed through Windows CNG (`bcrypt.dll`) via ctypes — FIPS-validated, hardware-accelerated
- Adds `hashing` block to `report.json` (algorithm, provider, hardware_native)
- Falls back to `hashlib` on non-Windows (testing only)

### v1.1.0 — Windows 10/11 client edition support
- Replaces `vssadmin create shadow` (Server-only) with `Win32_ShadowCopy` WMI via PowerShell
- Adds WMI ReturnValue → human-readable error message mapping
- Adds `windows_edition` block to `report.json`

### v1.0.0 — Initial release
- VSS-based acquisition of SYSTEM, SAM, SOFTWARE, SECURITY, DEFAULT, NTUSER.DAT (all users), System.evtx, Security.evtx, Application.evtx
- Two-pass SHA-256 integrity model (in-flight + persisted)
- Append-only chain-of-custody log
- sha256sum-compatible manifest + per-artifact sidecar files
- Structured JSON report
- UAC-aware portable EXE build via PyInstaller

---

## Legal Notice

This tool is intended for use by authorised digital forensic investigators, incident response teams, and security professionals operating under appropriate legal authority (search warrant, written consent, corporate policy, or equivalent). Unauthorised acquisition of computer evidence may be a criminal offence under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), or equivalent legislation in your jurisdiction. The authors accept no liability for misuse.

---

*DFIR Portable Evidence Collector — RegHiveTool Suite*  
