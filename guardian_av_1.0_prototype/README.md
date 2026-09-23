# Guardian AV 1.0 — Windows Endpoint Security Prototype

Guardian AV is an educational/portfolio-grade Windows endpoint-security prototype. It is designed to demonstrate how a layered defensive security product can be structured without disabling or replacing Microsoft Defender.

## What is included

### File protection
- Full recursive system scanning (`C:\`)
- User-selected folder scans
- SHA-256 exact-match signatures
- EICAR test-file detection
- Suspicious script and LOLBin command-pattern rules
- Entropy-based executable heuristic
- Large-file safety limits
- Permission/error handling
- SQLite detection and scan history

### Threat engine
- Detection scores
- Explicit reasons for every alert
- Persistent detection history
- Conservative auto-remediation policy
- No automatic deletion

### Quarantine
- Moves confirmed malicious/EICAR files to a dedicated directory
- Saves original-path and hash metadata
- Includes restore functionality in the Python API
- Uses restrictive permissions when supported

### Process monitoring
- Uses `psutil`
- Watches running process command lines
- Detects examples such as encoded PowerShell and suspicious script-host patterns

### Network monitoring
- Uses `psutil.net_connections()`
- Records suspicious connections to a small set of unusual test/remote-shell ports
- Does not pretend to be an IDS or cloud reputation service
- Does not automatically block network traffic

### Real-time monitoring
- Uses `watchdog` when installed
- Watches configured directories for file create/modify/move events
- Immediately rescans changed files
- Only auto-quarantines exact signatures/EICAR

### GUI
- Tkinter dashboard
- Quick scan of Downloads
- Full system scan
- Folder selection
- Progress
- Detection history
- Basic counters

### Windows service
- Optional `pywin32` ServiceFramework wrapper is included.
- The service starts real-time, process, and network monitors.
- It never disables Microsoft Defender.

## Installation

Open PowerShell in this directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, you can run Python directly from:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Use

Open the GUI:

```powershell
python .\main.py gui
```

Scan Downloads:

```powershell
python .\main.py scan "$HOME\Downloads"
```

Scan the whole C: drive:

```powershell
python .\main.py scan "C:\"
```

Run the background monitors from a terminal:

```powershell
python .\main.py service
```

## EICAR test

Create a harmless EICAR test file from a local text editor or another safe test method using the standard EICAR anti-malware test content. Guardian AV recognizes the test signature without executing it.

Do not use real malware as a test sample on a normal Windows system.

## Important engineering limitations

This is not a replacement for Defender or commercial endpoint protection. A production AV would need substantially more validation and Windows-specific engineering, including kernel/file-system integration, signed drivers where required, tamper protection, update infrastructure, cloud reputation, memory scanning, exploit mitigation, robust PE parsing, archive inspection, credential protection, rollback, code-signature verification, secure IPC, privileged-service hardening, and large-scale false-positive testing.

The included rules are intentionally transparent and conservative. They can produce false positives. Network monitoring is visibility-only. Process rules are examples rather than behavioral malware detection.

## Suggested next upgrades

- PE parser and Authenticode verification
- Local YARA integration with a rule directory
- Microsoft Defender integration/read-only status checks
- Scheduled scans via Windows Task Scheduler
- Secure allowlist and exclusions UI
- Signed update packages
- Better installer/uninstaller
- Unit/integration tests
- Test corpus and benchmark reporting
