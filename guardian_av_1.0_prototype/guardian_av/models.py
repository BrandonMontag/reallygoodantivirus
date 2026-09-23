from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass
class Detection:
    path: str = ""
    kind: str = "file"
    verdict: str = "CLEAN"  # CLEAN, SUSPICIOUS, MALICIOUS, ERROR
    score: int = 0
    sha256: str = ""
    size: int = 0
    reasons: list[str] = field(default_factory=list)
    pid: Optional[int] = None
    process_name: str = ""
    remote: str = ""
    detected_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "verdict": self.verdict,
            "score": self.score,
            "sha256": self.sha256,
            "size": self.size,
            "reasons": self.reasons,
            "pid": self.pid,
            "process_name": self.process_name,
            "remote": self.remote,
            "detected_at": self.detected_at,
        }
