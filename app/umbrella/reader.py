import logging
from pathlib import Path
from typing import IO, Union

_log = logging.getLogger(__name__)


def _fix_mojibake(s: str) -> str:
    if s.isascii():
        return s
    try:
        fixed = s.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s
    if fixed == s or max(ord(c) for c in fixed) >= max(ord(c) for c in s):
        return s
    _log.debug("Mojibake corrected: %r → %r", s, fixed)
    return fixed


def read_apps(file_source: Union[str, Path, IO], column: str) -> list:
    """Read unique app names from an Excel file.

    file_source can be a file path string/Path or a file-like object (e.g. Flask's request.files stream).
    Raises ValueError on any validation error instead of calling sys.exit.
    """
    try:
        import pandas as pd
    except ImportError:
        raise RuntimeError("pandas is required. Install with: pip install pandas openpyxl")

    try:
        df = pd.read_excel(file_source, engine="openpyxl")
    except Exception as exc:
        raise ValueError(f"No se pudo leer el archivo Excel: {exc}")

    if column not in df.columns:
        available = ", ".join(str(c) for c in df.columns)
        raise ValueError(f'Columna "{column}" no encontrada. Columnas disponibles: {available}')

    values = df[column].dropna().astype(str).str.strip()
    values = values[values != ""]

    if values.empty:
        raise ValueError(f'No se encontraron nombres de apps en la columna "{column}"')

    seen: set = set()
    result: list = []
    for v in values:
        v = _fix_mojibake(v)
        key = v.lower()
        if key not in seen:
            seen.add(key)
            result.append(v)

    return result


def get_excel_columns(file_source: Union[str, Path, IO]) -> list:
    """Return column names from an Excel file without loading all data."""
    try:
        import pandas as pd
    except ImportError:
        raise RuntimeError("pandas is required. Install with: pip install pandas openpyxl")

    try:
        df = pd.read_excel(file_source, engine="openpyxl", nrows=0)
        return list(df.columns)
    except Exception as exc:
        raise ValueError(f"No se pudo leer el archivo Excel: {exc}")
