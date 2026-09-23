from __future__ import annotations
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from .config import load_config
from .engine import DetectionEngine

class GuardianGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Guardian AV")
        self.root.geometry("1050x700")
        self.engine = DetectionEngine()
        self._build()
        self.refresh()

    def _build(self):
        header = ttk.Frame(self.root, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text="Guardian AV", font=("Segoe UI", 22, "bold")).pack(side="left")
        ttk.Label(header, text="Endpoint Security Prototype", font=("Segoe UI", 10)).pack(side="left", padx=12)

        controls = ttk.Frame(self.root, padding=(12, 0, 12, 10))
        controls.pack(fill="x")
        ttk.Button(controls, text="Quick Scan (Downloads)", command=self.quick_scan).pack(side="left", padx=4)
        ttk.Button(controls, text="Full System Scan", command=self.full_scan).pack(side="left", padx=4)
        ttk.Button(controls, text="Choose Folder", command=self.choose_folder).pack(side="left", padx=4)
        ttk.Button(controls, text="Refresh", command=self.refresh).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(controls, textvariable=self.status).pack(side="right")

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=12)

        cards = ttk.Frame(self.root, padding=12)
        cards.pack(fill="x")
        self.scanned_var = tk.StringVar(value="Scanned: 0")
        self.susp_var = tk.StringVar(value="Suspicious: 0")
        self.mal_var = tk.StringVar(value="Malicious: 0")
        self.err_var = tk.StringVar(value="Errors: 0")
        for var in (self.scanned_var, self.susp_var, self.mal_var, self.err_var):
            ttk.Label(cards, textvariable=var, relief="groove", padding=12).pack(side="left", padx=5)

        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill="both", expand=True)
        columns = ("time", "kind", "verdict", "score", "path", "reasons")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings")
        widths = {"time": 165, "kind": 90, "verdict": 95, "score": 55, "path": 300, "reasons": 300}
        for col in columns:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=widths[col], anchor="w")
        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        footer = ttk.Frame(self.root, padding=12)
        footer.pack(fill="x")
        ttk.Label(
            footer,
            text="Guardian AV never disables Microsoft Defender and only auto-quarantines exact-signature/EICAR matches.",
            foreground="#666"
        ).pack(side="left")

    def run_scan(self, target: Path):
        self.status.set(f"Scanning {target} ...")
        self.progress.start(12)

        def worker():
            last_stats = {}
            def callback(result, stats):
                nonlocal last_stats
                last_stats = stats.copy()
                self.root.after(0, self.update_stats, stats)
                if result.verdict in {"MALICIOUS", "SUSPICIOUS"}:
                    self.root.after(0, self.refresh)

            stats = self.engine.scan(target, callback)
            self.root.after(0, self.scan_finished, stats)

        threading.Thread(target=worker, daemon=True).start()

    def update_stats(self, stats):
        self.scanned_var.set(f"Scanned: {stats['scanned']}")
        self.susp_var.set(f"Suspicious: {stats['suspicious']}")
        self.mal_var.set(f"Malicious: {stats['malicious']}")
        self.err_var.set(f"Errors: {stats['errors']}")

    def scan_finished(self, stats):
        self.progress.stop()
        self.update_stats(stats)
        self.status.set("Scan complete")
        messagebox.showinfo("Guardian AV", f"Scan complete.\n\nFiles scanned: {stats['scanned']}\nMalicious: {stats['malicious']}\nSuspicious: {stats['suspicious']}\nErrors: {stats['errors']}")

    def quick_scan(self):
        target = Path.home() / "Downloads"
        self.run_scan(target)

    def full_scan(self):
        self.run_scan(Path("C:\\"))

    def choose_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.run_scan(Path(folder))

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for d in self.engine.db.recent_detections(100):
            self.tree.insert("", "end", values=(
                d["detected_at"], d["kind"], d["verdict"], d["score"],
                d["path"] or d["process_name"] or d["remote"],
                "; ".join(d["reasons"])
            ))

    def run(self):
        self.root.mainloop()

def main():
    GuardianGUI().run()
