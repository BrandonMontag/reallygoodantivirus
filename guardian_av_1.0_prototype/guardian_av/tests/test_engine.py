from pathlib import Path
from tempfile import TemporaryDirectory
from guardian_av.scanner import FileScanner
from guardian_av.signatures import contains_eicar

EICAR = rb'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

def test_eicar_marker():
    assert contains_eicar(EICAR)

def test_clean_file():
    with TemporaryDirectory() as td:
        p = Path(td) / "hello.txt"
        p.write_text("hello guardian", encoding="utf-8")
        d = FileScanner().scan_file(p)
        assert d.verdict == "CLEAN"
        assert len(d.sha256) == 64
