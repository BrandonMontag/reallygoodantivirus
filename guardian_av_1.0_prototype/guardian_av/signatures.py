from __future__ import annotations
import hashlib

# Exact SHA-256 signatures for files you have independently verified as malicious.
# Keep this list empty unless you trust the source of the signature.
KNOWN_BAD_HASHES: set[str] = set()

# EICAR is a harmless anti-malware test string. We detect the standard test string
# by byte content so you can safely validate the detection engine.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7dbd1d5c4f0d6f2c6f9f0d9d3b6f4b8f8c6c0c8"

def contains_eicar(data: bytes) -> bool:
    marker = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    return marker in data

def is_known_bad(digest: str) -> bool:
    return digest.lower() in KNOWN_BAD_HASHES
