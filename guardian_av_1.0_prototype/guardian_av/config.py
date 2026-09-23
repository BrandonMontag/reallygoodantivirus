from __future__ import annotations
import json
import os
from pathlib import Path

APP_DIR = Path(os.environ.get("PROGRAMDATA", Path.home())) / "GuardianAV"
QUARANTINE_DIR = APP_DIR / "Quarantine"
LOG_DIR = APP_DIR / "Logs"
DB_FILE = APP_DIR / "guardian.db"
CONFIG_FILE = APP_DIR / "config.json"

DEFAULT_CONFIG = {
    "scan_paths": ["C:\\"],
    "excluded_prefixes": [
        str(QUARANTINE_DIR),
        r"C:\System Volume Information",
        r"C:\$Recycle.Bin",
    ],
    "max_file_size_mb": 2048,
    "worker_count": 4,
    "realtime_interval_seconds": 3,
    "process_interval_seconds": 5,
    "network_interval_seconds": 10,
    "enable_process_monitor": True,
    "enable_network_monitor": True,
    "enable_realtime_monitor": True,
}

def ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def load_config() -> dict:
    ensure_dirs()
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        return DEFAULT_CONFIG.copy()
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return DEFAULT_CONFIG.copy()
    merged = DEFAULT_CONFIG.copy()
    merged.update(data)
    return merged
