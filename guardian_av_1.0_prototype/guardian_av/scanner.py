from __future__ import annotations
import hashlib
import os
from pathlib import Path
from .config import load_config
from .heuristics import heuristic_score
from .models import Detection
from .rules import inspect_content
from .signatures import contains_eicar, is_known_bad
from .logger import get_logger

class FileScanner:
    def __init__(self):
        self.config = load_config()
        self.log = get_logger("scanner")

    def excluded(self, path: Path) -> bool:
        text = str(path).lower()
        for prefix in self.config["excluded_prefixes"]:
            if text.startswith(str(prefix).lower()):
                return True
        return False

    def iter_files(self, target: Path):
        if target.is_file():
            if not self.excluded(target):
                yield target
            return

        def onerror(_):
            return

        for current, dirs, names in os.walk(target, topdown=True, onerror=onerror, followlinks=False):
            dirs[:] = [d for d in dirs if not self.excluded(Path(current) / d)]
            for name in names:
                p = Path(current) / name
                if not self.excluded(p):
                    yield p

    def scan_file(self, path: Path) -> Detection:
        try:
            st = path.stat()
            max_bytes = int(self.config["max_file_size_mb"]) * 1024 * 1024
            if st.st_size > max_bytes:
                return Detection(
                    path=str(path), verdict="SUSPICIOUS", score=5, size=st.st_size,
                    reasons=[f"skipped content analysis because file exceeds {self.config['max_file_size_mb']} MB limit"]
                )

            h = hashlib.sha256()
            with path.open("rb") as f:
                data = f.read(1024 * 1024)
                if data:
                    h.update(data)
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)

            digest = h.hexdigest()
            reasons = []
            score = 0
            if is_known_bad(digest):
                reasons.append("SHA-256 matches a configured malicious signature")
                score = 100

            if contains_eicar(data):
                reasons.append("EICAR anti-malware test signature detected")
                score = max(score, 100)

            rule_score, rule_reasons = inspect_content(path, data)
            heuristic, heuristic_reasons = heuristic_score(path, data)
            score += rule_score + heuristic
            reasons.extend(rule_reasons)
            reasons.extend(heuristic_reasons)

            if score >= 100:
                verdict = "MALICIOUS"
            elif score >= 25:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"

            return Detection(
                path=str(path), verdict=verdict, score=min(score, 100),
                sha256=digest, size=st.st_size, reasons=reasons
            )
        except (OSError, PermissionError) as e:
            return Detection(path=str(path), verdict="ERROR", reasons=[str(e)])

    def scan(self, target: Path, callback=None):
        for path in self.iter_files(target):
            result = self.scan_file(path)
            if callback:
                callback(result)
            yield result
