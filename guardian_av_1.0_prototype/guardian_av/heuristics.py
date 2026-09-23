from __future__ import annotations
import math
from pathlib import Path

EXECUTABLES = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com"}

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)

def heuristic_score(path: Path, sample: bytes) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    ext = path.suffix.lower()

    if ext in EXECUTABLES and len(sample) >= 4096:
        e = entropy(sample)
        if e >= 7.7:
            score += 20
            reasons.append(f"very high entropy ({e:.2f} bits/byte)")
        elif e >= 7.4:
            score += 10
            reasons.append(f"high entropy ({e:.2f} bits/byte)")

    if path.name.lower() in {"invoice.exe", "update.exe", "patch.exe", "document.exe"}:
        score += 8
        reasons.append("deceptive executable filename pattern")

    return score, reasons
