from __future__ import annotations
import hashlib
import json
import os
import shutil
from pathlib import Path
from datetime import datetime, timezone
from .config import QUARANTINE_DIR, ensure_dirs

class Quarantine:
    def __init__(self, directory: Path = QUARANTINE_DIR):
        ensure_dirs()
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def _metadata_path(self, stored: Path) -> Path:
        return stored.with_suffix(stored.suffix + ".json")

    def quarantine(self, file_path: Path, sha256: str) -> Path:
        destination_name = hashlib.sha256(str(file_path).encode("utf-8")).hexdigest()[:20] + "_" + file_path.name
        destination = self.directory / destination_name
        counter = 1
        while destination.exists():
            destination = self.directory / f"{counter}_{destination_name}"
            counter += 1

        # Best-effort Windows hardening: remove user write/execute inheritance after moving.
        shutil.move(str(file_path), str(destination))
        try:
            os.chmod(destination, 0o400)
        except OSError:
            pass

        metadata = self._metadata_path(destination)
        metadata.write_text(json.dumps({
            "original_path": str(file_path),
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "sha256": sha256,
        }, indent=2), encoding="utf-8")
        return destination

    def list_items(self) -> list[dict]:
        out = []
        for meta in self.directory.glob("*.json"):
            try:
                out.append(json.loads(meta.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                pass
        return out

    def restore(self, stored_name: str, destination: Path | None = None) -> Path:
        stored = self.directory / stored_name
        meta = self._metadata_path(stored)
        if not stored.exists() or not meta.exists():
            raise FileNotFoundError("Quarantine item or metadata not found")
        info = json.loads(meta.read_text(encoding="utf-8"))
        target = destination or Path(info["original_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(stored, 0o600)
        except OSError:
            pass
        shutil.move(str(stored), str(target))
        meta.unlink(missing_ok=True)
        return target
