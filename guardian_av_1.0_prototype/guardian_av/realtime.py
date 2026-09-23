from __future__ import annotations
import threading
import time
from pathlib import Path
from .logger import get_logger

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = None
    Observer = None

class _Handler(FileSystemEventHandler if FileSystemEventHandler else object):
    def __init__(self, manager):
        if FileSystemEventHandler:
            super().__init__()
        self.manager = manager

    def _scan(self, path: str):
        p = Path(path)
        if p.is_file():
            self.manager.scan_path(p)

    def on_created(self, event):
        if not event.is_directory:
            self._scan(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._scan(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._scan(event.dest_path)

class RealtimeMonitor:
    def __init__(self, engine, paths, interval=3):
        self.engine = engine
        self.paths = [Path(p) for p in paths]
        self.interval = interval
        self.log = get_logger("realtime")
        self.observer = None
        self.running = False

    def scan_path(self, path: Path):
        try:
            result = self.engine.scanner.scan_file(path)
            if result.verdict != "CLEAN":
                self.engine.handle_detection(result, auto_quarantine=(result.verdict == "MALICIOUS"))
        except OSError as e:
            self.log.warning("Realtime scan failed for %s: %s", path, e)

    def start(self):
        if Observer is None:
            self.log.warning("watchdog is not installed; realtime monitoring disabled.")
            return
        self.observer = Observer()
        handler = _Handler(self)
        for path in self.paths:
            if path.exists():
                try:
                    self.observer.schedule(handler, str(path), recursive=True)
                except OSError as e:
                    self.log.warning("Could not monitor %s: %s", path, e)
        self.observer.start()
        self.running = True

    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
