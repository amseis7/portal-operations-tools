import enum
from dataclasses import dataclass
from flask import current_app


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    CLEAN = "clean"
    INFECTED = "infected"
    NOT_SCANNED = "not_scanned"
    SCAN_ERROR = "scan_error"


@dataclass
class ScanResult:
    status: ScanStatus
    detail: str | None = None


class Scanner:
    def scan_file(self, path: str) -> ScanResult:
        raise NotImplementedError


class NullScanner(Scanner):
    """Default when no real engine is configured. Never claims a file is
    clean — see Global Constraints: scan_status must only reach "clean"
    through an actual scan."""

    def scan_file(self, path: str) -> ScanResult:
        return ScanResult(status=ScanStatus.NOT_SCANNED)


_SCANNERS = {"null": NullScanner}


def get_scanner() -> Scanner:
    name = current_app.config.get("KB_SCANNER", "null")
    return _SCANNERS.get(name, NullScanner)()
