from __future__ import annotations
import argparse
from pathlib import Path
from guardian_av.engine import DetectionEngine
from guardian_av.gui import main as gui_main
from guardian_av.service import console_service

def cli_scan(target: str):
    engine = DetectionEngine()
    path = Path(target).expanduser().resolve()

    if not path.exists():
        raise SystemExit(f"Target does not exist: {path}")

    print(f"Guardian AV scanning: {path}")
    print("Press Ctrl+C to stop.\n")

    def callback(result, stats):
        if result.verdict != "CLEAN":
            print(f"[{result.verdict:9}] score={result.score:3} {result.path}")
            for reason in result.reasons:
                print(f"           - {reason}")
        if stats["scanned"] % 500 == 0:
            print(f"Progress: {stats['scanned']} files")

    stats = engine.scan(path, callback)
    print("\nScan complete")
    print(f"Files scanned : {stats['scanned']}")
    print(f"Malicious     : {stats['malicious']}")
    print(f"Suspicious    : {stats['suspicious']}")
    print(f"Errors        : {stats['errors']}")

def main():
    parser = argparse.ArgumentParser(description="Guardian AV endpoint security prototype")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a file or folder")
    scan.add_argument("target", nargs="?", default="C:\\")

    sub.add_parser("gui", help="Open the Guardian AV dashboard")
    sub.add_parser("service", help="Run background process/network/realtime monitors")

    args = parser.parse_args()

    if args.command == "gui":
        gui_main()
    elif args.command == "service":
        console_service()
    else:
        cli_scan(getattr(args, "target", "C:\\"))

if __name__ == "__main__":
    main()
