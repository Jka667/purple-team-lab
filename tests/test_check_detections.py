import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from check_detections import epoch, report  # noqa: E402


def test_epoch_parses_powershell_utc_format():
    assert epoch("1970-01-01T00:01:00Z") == 60


def test_report_marks_missed_techniques():
    rows = [{"detection_id": "DET-0001", "technique": "T1059.001", "test_name": "a", "host": "WIN10"},
            {"detection_id": "DET-0002", "technique": "T1003.001", "test_name": "b", "host": "WIN10"}]
    md = report(rows, [3, 0])
    assert "Detected 1/2" in md
    assert "| DET-0002 | T1003.001 | b | WIN10 | **MISSED** | 0 |" in md
