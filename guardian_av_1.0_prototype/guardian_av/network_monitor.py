from __future__ import annotations
import time
from .models import Detection
from .logger import get_logger

try:
    import psutil
except ImportError:
    psutil = None

class NetworkMonitor:
    def __init__(self, engine, interval: int = 10):
        self.engine = engine
        self.interval = interval
        self.log = get_logger("network")
        self.running = False
        self.seen = set()

    def scan_once(self):
        if psutil is None:
            return []
        detections = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return detections

        for conn in connections:
            if not conn.raddr:
                continue
            remote = f"{conn.raddr.ip}:{conn.raddr.port}"
            status = conn.status or ""
            if status not in {"ESTABLISHED", "SYN_SENT"}:
                continue

            # This is a visibility layer, not a reputation service.
            # Flag only unusual high-risk local process states; do not block automatically.
            if conn.pid is None:
                continue
            key = (conn.pid, remote)
            if key in self.seen:
                continue
            self.seen.add(key)

            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "unknown"

            if conn.raddr.port in {4444, 5555, 1337}:
                d = Detection(
                    kind="network", verdict="SUSPICIOUS", score=35,
                    reasons=[f"connection to uncommon test/remote-shell port {conn.raddr.port}"],
                    pid=conn.pid, process_name=name, remote=remote
                )
                detections.append(d)
                self.engine.handle_detection(d, auto_quarantine=False)
        return detections

    def run(self):
        if psutil is None:
            self.log.warning("psutil is not installed; network monitoring disabled.")
            return
        self.running = True
        while self.running:
            self.scan_once()
            time.sleep(self.interval)

    def stop(self):
        self.running = False
