import hashlib
import io
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass

_SIGNATURES = {
    "png":  (b"\x89PNG\r\n\x1a\n", "image/png"),
    "jpg":  (b"\xff\xd8\xff", "image/jpeg"),
    "jpeg": (b"\xff\xd8\xff", "image/jpeg"),
    "pdf":  (b"%PDF-", "application/pdf"),
    "xls":  (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/vnd.ms-excel"),
}
_ZIP_OFFICE_MIME = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
_MACRO_CONTENT_TYPES = (
    "vnd.ms-word.document.macroEnabled",
    "vnd.ms-excel.sheet.macroEnabled",
    "vnd.ms-excel.template.macroEnabled",
    "vnd.ms-powerpoint.presentation.macroEnabled",
)
_REQUIRED_OFFICE_PART = {
    "docx": "word/document.xml",
    "xlsx": "xl/workbook.xml",
}
# A genuine [Content_Types].xml is a few KB even for a complex document.
# Capping its declared (uncompressed) size before reading it blocks a
# zip-bomb-style amplification (a tiny compressed entry that declares a
# huge uncompressed size) from being decompressed into memory at all.
_MAX_CONTENT_TYPES_SIZE = 1 * 1024 * 1024


class AttachmentValidationError(Exception):
    pass


@dataclass
class ValidatedFile:
    extension: str
    mime_type: str
    is_image: bool
    sha256: str
    size_bytes: int


def validate_upload(data: bytes, declared_extension: str) -> ValidatedFile:
    ext = declared_extension.lower().lstrip(".")

    if ext == "webp":
        if len(data) < 12 or data[0:4] != b"RIFF" or data[8:12] != b"WEBP":
            raise AttachmentValidationError("El contenido no corresponde a una imagen WEBP válida.")
        mime = "image/webp"

    elif ext in _SIGNATURES:
        signature, mime = _SIGNATURES[ext]
        if not data.startswith(signature):
            raise AttachmentValidationError(f"El contenido no corresponde a un archivo .{ext} válido.")
        if ext == "xls":
            _reject_xls_vba_project(data)

    elif ext in _ZIP_OFFICE_MIME:
        if not data.startswith(b"PK\x03\x04"):
            raise AttachmentValidationError(f"El contenido no corresponde a un archivo .{ext} válido.")
        mime = _ZIP_OFFICE_MIME[ext]
        _validate_office_zip(data, ext)

    elif ext in ("csv", "txt"):
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                data.decode("latin-1")
            except UnicodeDecodeError:
                raise AttachmentValidationError(f"El archivo .{ext} no es texto válido.")
        if b"\x00" in data:
            raise AttachmentValidationError(f"El archivo .{ext} contiene bytes binarios inesperados.")
        mime = "text/csv" if ext == "csv" else "text/plain"

    else:
        raise AttachmentValidationError(f"Extensión no soportada: .{ext}")

    return ValidatedFile(
        extension=ext,
        mime_type=mime,
        is_image=ext in ("png", "jpg", "jpeg", "webp"),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


_XLS_VBA_MARKER = "VBA".encode("utf-16-le")


def _reject_xls_vba_project(data: bytes) -> None:
    """Legacy (pre-2007) .xls is a single OLE2 compound file, unlike
    .docx/.xlsx's ZIP container, so it has no [Content_Types].xml to
    inspect. A macro-enabled .xls stores its VBA project in an OLE2
    directory entry conventionally named with "VBA" (e.g. a "Macros"
    storage containing a "VBA" sub-storage), and OLE2 directory entry
    names are encoded UTF-16LE in the compound file itself. Searching the
    raw bytes for that marker — without parsing the OLE2 directory sector
    structure, and without a new dependency — catches the common case,
    consistent with this module's existing signature-based approach."""
    if _XLS_VBA_MARKER in data:
        raise AttachmentValidationError(
            "Los documentos de Excel con macros (VBA) no están permitidos."
        )


def _validate_office_zip(data: bytes, ext: str) -> None:
    """.docx/.xlsx are ZIPs sharing the same PK\\x03\\x04 signature as any
    arbitrary ZIP. The signature alone proves nothing — validate the
    internal container structure, entirely in memory (zipfile.ZipFile
    over io.BytesIO; nothing is ever extracted to the filesystem):

    1. The expected core document part for this format must actually be
       present in the archive's namelist — catches a minimal/arbitrary
       ZIP that is not a real Office container at all.
    2. [Content_Types].xml must exist and be well-formed XML — catches a
       forged/truncated entry, not just "a file with this name exists".
    3. The declared content type must not be a macro-enabled one —
       catches a .docm/.xlsm renamed to .docx/.xlsx, which otherwise has
       an identical signature AND a genuine internal structure, differing
       only in this declaration.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if _REQUIRED_OFFICE_PART[ext] not in zf.namelist():
                raise AttachmentValidationError(
                    f"El archivo .{ext} no contiene la estructura interna esperada de un documento Office."
                )
            try:
                content_types_info = zf.getinfo("[Content_Types].xml")
            except KeyError:
                raise AttachmentValidationError(f"El archivo .{ext} no contiene [Content_Types].xml.")
            if content_types_info.file_size > _MAX_CONTENT_TYPES_SIZE:
                raise AttachmentValidationError(
                    f"El archivo .{ext} tiene un [Content_Types].xml demasiado grande."
                )
            content_types = zf.read(content_types_info).decode("utf-8", errors="replace")
    except zipfile.BadZipFile:
        raise AttachmentValidationError(f"El archivo .{ext} no es un documento Office válido.")

    try:
        ET.fromstring(content_types)
    except ET.ParseError:
        raise AttachmentValidationError(f"El archivo .{ext} tiene un [Content_Types].xml malformado.")

    if any(marker in content_types for marker in _MACRO_CONTENT_TYPES):
        raise AttachmentValidationError(
            "Los documentos de Office con macros no están permitidos."
        )
