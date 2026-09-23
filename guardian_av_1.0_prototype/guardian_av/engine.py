from __future__ import annotations
import threading
from datetime import datetime, timezone
from pathlib import Path
from .config import load_config
from .database import Database
from .logger import get_logger
from .models import Detection
from .quarantine import Quarantine
from .scanner import FileScanner

class DetectionEngine:
    def __init__(self):
        self.config = load_config()
        self.db = Database()
        self.scanner = FileScanner()
        self.quarantine = Quarantine()
        self.log = get_logger("engine")
        self.lock = threading.Lock()
        self.recent = []

    def handle_detection(self, detection: Detection, auto_quarantine: bool = False):
        with self.lock:
            self.db.add_detection(detection)
            self.recent.append(detection)
            self.recent = self.recent[-200:]
        self.log.warning(
            "%s %s %s %s",
            detection.kind, detection.verdict, detection.path or detection.process_name,
            "; ".join(detection.reasons)
        )

        # Only exact signatures/EICAR are considered strong enough for automatic quarantine.
        if auto_quarantine and detection.verdict == "MALICIOUS" and detection.path:
            try:
                original = Path(detection.path)
                if original.exists() and detection.sha256:
                    destination = self.quarantine.quarantine(original, detection.sha256)
                    self.log.warning("Quarantined %s -> %s", original, destination)
            except OSError as e:
                self.log.error("Quarantine failed for %s: %s", detection.path, e)

    def scan(self, target: Path, callback=None) -> dict:
        started = datetime.now(timezone.utc).isoformat()
        scan_id = self.db.start_scan(str(target), started)
        stats = {"scanned": 0, "malicious": 0, "suspicious": 0, "errors": 0}

        for result in self.scanner.scan(target):
            stats["scanned"] += 1
            if result.verdict == "MALICIOUS":
                stats["malicious"] += 1
                self.handle_detection(result, auto_quarantine=False)
            elif result.verdict == "SUSPICIOUS":
                stats["suspicious"] += 1
                self.handle_detection(result, auto_quarantine=False)
            elif result.verdict == "ERROR":
                stats["errors"] += 1

            if callback:
                callback(result, stats)

        self.db.finish_scan(
            scan_id, datetime.now(timezone.utc).isoformat(),
            stats["scanned"], stats["malicious"], stats["suspicious"], stats["errors"]
        )
        return stats
