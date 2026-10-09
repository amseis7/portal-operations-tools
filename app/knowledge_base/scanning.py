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


class DevAllowScanner(Scanner):
    """Deliberately insecure: marks every file clean without scanning it.
    Local development only — never the default, and only ever selected
    when BOTH KB_SCANNER=dev_allow and KB_ALLOW_INSECURE_DEV_SCANNER=true
    are explicitly set (enforced by validate_scanner_config() at startup,
    not here)."""

    def scan_file(self, path: str) -> ScanResult:
        return ScanResult(status=ScanStatus.CLEAN, detail="dev-allow: file was NOT malware-scanned")


_SCANNERS = {"null": NullScanner, "dev_allow": DevAllowScanner}


def _require_dev_allow_gate(config, name):
    """Shared by validate_scanner_config() (startup) and get_scanner()
    (every call) — one rule, one message, checked in both places so a
    future change to the gating condition can't silently apply to only
    one of them. Strict `is True` identity, not plain truthiness: the
    shipped Config always coerces this to a real bool via
    .strip().lower() == 'true', but the gate itself must not trust an
    arbitrary config source where a non-empty string like "false" would
    otherwise be truthy."""
    if name == "dev_allow" and config.get("KB_ALLOW_INSECURE_DEV_SCANNER") is not True:
        raise RuntimeError(
            "KB_SCANNER=dev_allow requiere KB_ALLOW_INSECURE_DEV_SCANNER=true explícito. "
            "DevAllowScanner NO escanea archivos reales — solo para desarrollo local."
        )


def validate_scanner_config(app):
    """Fail fast at startup — never silently downgrade to NullScanner for
    an unrecognized KB_SCANNER, and never allow dev_allow without its
    explicit opt-in flag."""
    name = app.config.get("KB_SCANNER", "null")
    if name not in _SCANNERS:
        raise RuntimeError(
            f"KB_SCANNER={name!r} no es un scanner reconocido. Valores válidos: {sorted(_SCANNERS)}."
        )
    _require_dev_allow_gate(app.config, name)


def get_scanner() -> Scanner:
    # Re-runs the exact same checks as create_app()'s one-time startup
    # call — not just KB_SCANNER but also the dev_allow opt-in flag — so
    # mutating config after create_app() returned (e.g. clearing the
    # insecure-dev flag at runtime) is caught here too, on every call, via
    # one shared validation path instead of a second hand-rolled copy of
    # it.
    validate_scanner_config(current_app)
    name = current_app.config.get("KB_SCANNER", "null")
    return _SCANNERS[name]()
