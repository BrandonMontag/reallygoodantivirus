from __future__ import annotations
import threading
import time
from .config import load_config
from .engine import DetectionEngine
from .logger import get_logger
from .network_monitor import NetworkMonitor
from .process_monitor import ProcessMonitor
from .realtime import RealtimeMonitor

class GuardianService:
    def __init__(self):
        self.config = load_config()
        self.engine = DetectionEngine()
        self.log = get_logger("service")
        self.process_monitor = ProcessMonitor(
            self.engine, self.config["process_interval_seconds"]
        )
        self.network_monitor = NetworkMonitor(
            self.engine, self.config["network_interval_seconds"]
        )
        self.realtime_monitor = RealtimeMonitor(
            self.engine, self.config["scan_paths"],
            self.config["realtime_interval_seconds"]
        )
        self.threads = []
        self.running = False

    def start(self):
        self.running = True
        if self.config.get("enable_realtime_monitor", True):
            self.realtime_monitor.start()
        if self.config.get("enable_process_monitor", True):
            t = threading.Thread(target=self.process_monitor.run, daemon=True)
            t.start()
            self.threads.append(t)
        if self.config.get("enable_network_monitor", True):
            t = threading.Thread(target=self.network_monitor.run, daemon=True)
            t.start()
            self.threads.append(t)
        self.log.info("Guardian background monitors started.")

    def stop(self):
        self.running = False
        self.realtime_monitor.stop()
        self.process_monitor.stop()
        self.network_monitor.stop()
        self.log.info("Guardian background monitors stopped.")

def console_service():
    service = GuardianService()
    service.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop()

# Optional Windows Service wrapper. Install pywin32 and register it yourself
# in an elevated shell if you want SCM integration.
try:
    import win32serviceutil
    import win32service
    import win32event

    class GuardianWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "GuardianAV"
        _svc_display_name_ = "Guardian AV"
        _svc_description_ = "Guardian AV endpoint security prototype"

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.service = GuardianService()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.service.stop()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            self.service.start()
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
except ImportError:
    GuardianWindowsService = None

if __name__ == "__main__":
    if GuardianWindowsService is None:
        console_service()
    else:
        import win32serviceutil
        win32serviceutil.HandleCommandLine(GuardianWindowsService)
