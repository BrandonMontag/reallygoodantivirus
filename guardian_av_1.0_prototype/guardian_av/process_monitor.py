from __future__ import annotations
import os
import time
from .models import Detection
from .logger import get_logger

try:
    import psutil
except ImportError:
    psutil = None

class ProcessMonitor:
    def __init__(self, engine, interval: int = 5):
        self.engine = engine
        self.interval = interval
        self.log = get_logger("process")
        self.running = False
        self.seen = set()

    def _score_process(self, proc) -> Detection | None:
        try:
            info = proc.info
            pid = info["pid"]
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            cmd = info.get("cmdline") or []
            cmd_text = " ".join(cmd)

            reasons = []
            score = 0

            if "-enc" in cmd_text.lower() and "powershell" in cmd_text.lower():
                reasons.append("PowerShell encoded command-line")
                score += 45
            if "downloadstring(" in cmd_text.lower():
                reasons.append("PowerShell DownloadString command-line")
                score += 35
            if "frombase64string" in cmd_text.lower():
                reasons.append("PowerShell Base64 decode command-line")
                score += 30
            if name.lower() in {"wscript.exe", "cscript.exe", "mshta.exe"}:
                if cmd_text:
                    score += 10
                    reasons.append(f"script host running: {name}")

            if score:
                return Detection(
                    kind="process", path=exe, verdict="MALICIOUS" if score >= 100 else "SUSPICIOUS",
                    score=min(score, 100), reasons=reasons, pid=pid, process_name=name
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        return None

    def scan_once(self):
        if psutil is None:
            return []
        detections = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            if proc.info["pid"] == os.getpid():
                continue
            d = self._score_process(proc)
            if d:
                key = (d.pid, tuple(d.reasons))
                if key not in self.seen:
                    self.seen.add(key)
                    detections.append(d)
                    self.engine.handle_detection(d, auto_quarantine=False)
        return detections

    def run(self):
        if psutil is None:
            self.log.warning("psutil is not installed; process monitoring disabled.")
            return
        self.running = True
        while self.running:
            self.scan_once()
            time.sleep(self.interval)

    def stop(self):
        self.running = False
