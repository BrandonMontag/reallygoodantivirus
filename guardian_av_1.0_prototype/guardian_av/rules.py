from __future__ import annotations
import re
from pathlib import Path

# Transparent, educational rules. They add suspicion but do not quarantine by themselves.
TEXT_RULES = [
    (re.compile(rb"powershell(?:\.exe)?\s+-enc(?:odedcommand)?\b", re.I), 35, "PowerShell encoded command pattern"),
    (re.compile(rb"frombase64string", re.I), 20, "Base64 decode pattern in file"),
    (re.compile(rb"downloadstring\s*\(", re.I), 30, "PowerShell DownloadString pattern"),
    (re.compile(rb"invoke-expression", re.I), 25, "PowerShell Invoke-Expression pattern"),
    (re.compile(rb"certutil(?:\.exe)?\s+-decode", re.I), 25, "certutil decode pattern"),
    (re.compile(rb"rundll32(?:\.exe)?\b", re.I), 10, "rundll32 execution pattern"),
    (re.compile(rb"regsvr32(?:\.exe)?\b", re.I), 10, "regsvr32 execution pattern"),
]

EXTENSION_RULES = {
    ".hta": 25,
    ".scr": 15,
    ".vbs": 15,
    ".js": 10,
    ".jse": 15,
    ".ps1": 8,
    ".bat": 8,
    ".cmd": 8,
}

def inspect_content(path: Path, sample: bytes) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    for pattern, points, reason in TEXT_RULES:
        if pattern.search(sample):
            score += points
            reasons.append(reason)

    points = EXTENSION_RULES.get(path.suffix.lower(), 0)
    if points:
        score += points
        reasons.append(f"script/high-risk extension: {path.suffix.lower()}")
    return score, reasons
