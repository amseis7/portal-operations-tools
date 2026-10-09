# Knowledge Base Secure Attachments — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add secure file attachments (pasted images + uploaded documents) to Knowledge Base articles: validated, quarantined-by-default, never served until a malware scanner marks them `clean`, never trusting client-supplied filename/MIME, and isolated per-user while an article is still being drafted.

**Architecture:** One new model (`KnowledgeAttachment`) sharing `app/models/knowledge.py`; a pure-Python validation chain (`app/knowledge_base/attachment_validation.py`) with no new dependency; a decoupled scanner interface (`app/knowledge_base/scanning.py`) defaulting to a safe `NullScanner`; attachment routes in a new `app/knowledge_base/attachment_routes.py` on the existing `bp`; files stored under `instance/kb_attachments/` (single directory — see Task 2 for why there is no separate "clean" directory); cleanup via lazy purge + a daily APScheduler job, both calling the same idempotent function.

**Tech Stack:** Flask / SQLAlchemy / Alembic (existing). No new third-party dependency (see "Dependencies" below — `python-magic` was evaluated and rejected). `unittest` + Flask test client (existing harness, `tests/base.py`).

**Spec:** This conversation's confirmed design — draft_token with per-uploader isolation, 24h TTL, author/admin upload+delete, tool-read view/download, strict `scan_status == "clean"` gate with no "serve with warning" exception, images-inline-only vs documents-always-`attachment`, no Office macros, storage outside `static/`.

## Global Constraints

- **No new dependency.** Magic-byte detection is a fixed signature table in stdlib Python, not `python-magic`/`libmagic` — see "Dependencies" section for the full comparison the task required before any library choice.
- **Single storage directory**, not separate quarantine/clean directories. "Quarantine" is enforced by the `scan_status` **database** gate checked on every serve, not by filesystem location. Moving a file between directories on a status transition would add a second place for a missing-file race with no real security benefit, since access control already happens at the application layer before any file is opened.
- **`scan_status == "clean"` is the only state that may ever be served** — via `/view`, `/download`, or rendered inline in Markdown. `pending`, `not_scanned`, `scan_error`, and `infected` are all blocked identically, with no exception. No "serve with a warning" path exists anywhere in this plan.
- **`draft_token` + `uploaded_by` together define draft ownership.** No route may let a user read, promote, or discard a draft attachment whose `uploaded_by` is not `current_user.id`, even if they know the token.
- Upload and delete require the same permission as editing the article (author or admin). View and download require only `knowledge_base` tool access (same as reading the article).
- Documents (`pdf`, `docx`, `xlsx`, `xls`, `csv`, `txt`) are **always** served with `Content-Disposition: attachment`. Only images (`png`, `jpg`, `jpeg`, `webp`) may be served `inline`, and only once `clean`.
- No Office macro-enabled file may pass validation even if renamed to a non-macro extension (`.docx`/`.xlsx` are ZIPs — validated by inspecting `[Content_Types].xml`, not by extension alone).
- `.env` is not read or modified. No migration is generated or applied in this planning pass — Task 1 specifies the exact migration body for the implementation pass to generate and verify against.
- Cleanup (lazy and scheduled) must be idempotent and safe under duplicate/concurrent execution — see Task 10. This does **not** fix the existing APScheduler-under-Werkzeug-reloader duplication (already known, out of scope); it means the cleanup logic itself must not care if it runs twice.

## Review Focus

- **A disguised `.docm` renamed to `.docx` gets uploaded.** Expected: rejected at validation (Task 3's ZIP content-types check), never reaches `clean`. Most likely bypass a naive extension-only check would miss.
- **An attachment referenced by `![alt](/kb/attachments/<id>/view)` in already-saved Markdown is still `pending` (or becomes `infected` later).** Expected: `/view` blocks it on **every** request, regardless of what the stored Markdown text says — the gate is re-evaluated live, never baked into the rendered page.
- **User B uploads to the same open `/kb/nuevo` form tab as User A would, or guesses User A's `draft_token`.** Expected: User B's `draft-upload` creates its own row under B's `uploaded_by`; and a request against A's draft token/attachment id fails ownership regardless of who guesses what, because the check is `draft_token == token AND uploaded_by == current_user.id`, not token alone.
- **Two cleanup executions (manual trigger + scheduled job, or the reloader's duplicate scheduler) run concurrently against the same expired draft.** Expected: no unhandled exception, no double-delete error, exactly one outcome (row + file gone), not a partially-deleted/partially-errored state.
- **An article is deleted while it still has attachments.** Expected: the physical files are removed, not just the DB rows (SQLAlchemy cascade only deletes rows — it has no idea the row pointed at a file on disk).

---

## Task 1: Model and migration design

**Files:**
- Modify: `app/models/knowledge.py` (add `KnowledgeAttachment`, add `attachments` relationship to `KnowledgeArticle`)
- Create (implementation pass only — **not generated in this plan**): `migrations/versions/<rev>_add_knowledge_attachment_table.py`
- Test: `tests/knowledge_base/test_attachment_model.py`

**Interfaces:**
- Produces: `app.models.knowledge.KnowledgeAttachment` with columns `id, article_id, draft_token, original_filename, stored_filename, mime_type, extension, size_bytes, sha256, is_image, uploaded_by, created_at, scan_status, scan_checked_at`. `KnowledgeArticle.attachments` (relationship, `cascade="all, delete-orphan"`).
- Consumed by: every later task.

### Final model

```python
class KnowledgeAttachment(db.Model):
    __tablename__ = "knowledge_attachment"
    __table_args__ = (
        db.CheckConstraint(
            "(article_id IS NOT NULL AND draft_token IS NULL) "
            "OR (article_id IS NULL AND draft_token IS NOT NULL)",
            name="ck_knowledge_attachment_exactly_one_owner",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(
        db.Integer, db.ForeignKey("knowledge_article.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    draft_token = db.Column(db.String(36), nullable=True, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(64), nullable=False, unique=True)
    mime_type = db.Column(db.String(100), nullable=False)
    extension = db.Column(db.String(10), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    is_image = db.Column(db.Boolean, default=False, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    scan_status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    scan_checked_at = db.Column(db.DateTime, nullable=True)

    article = db.relationship("KnowledgeArticle", back_populates="attachments")
    uploader = db.relationship("User", backref=db.backref("knowledge_attachments", lazy="dynamic"))

    def __repr__(self):
        return f"<KnowledgeAttachment {self.id}: {self.original_filename}>"
```

Add to `KnowledgeArticle`:
```python
    attachments = db.relationship(
        "KnowledgeAttachment", back_populates="article",
        cascade="all, delete-orphan", order_by="KnowledgeAttachment.created_at",
    )
```

### DB invariant: exactly one owner

The `CheckConstraint` enforces at the DB level that a row has **either** `article_id` **or** `draft_token` set, never both, never neither. The promotion transition (Task 5) assigns both fields (`article_id = new_id`, `draft_token = None`) on the same Python object inside the **same transaction** as the article's own `INSERT`, committed together in one `db.session.commit()` — there is never a committed intermediate state with both or neither set; the constraint is never actually at risk of being violated by normal application code, it exists as a backstop against a future bug.

### Why no separate "clean" directory (answering the brief)

Already stated in Global Constraints — repeated here because Task 1 is where the schema would otherwise imply two paths. There is exactly one `stored_filename`, resolved against exactly one configured directory (Task 2). "Quarantine" is a DB-state concept (`scan_status != clean`), not a filesystem location.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_model.py
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401
from sqlalchemy.exc import IntegrityError


class TestKnowledgeAttachmentModel(PortalTestCase):
    def _make_article(self):
        author = self.make_user("kb_author")
        article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=author)
        db.session.add(article)
        db.session.flush()
        return article, author

    def test_attachment_belongs_to_article(self):
        article, author = self._make_article()
        att = KnowledgeAttachment(
            article_id=article.id, original_filename="shot.png",
            stored_filename="abc123.png", mime_type="image/png", extension="png",
            size_bytes=100, sha256="x" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        db.session.commit()
        self.assertEqual(KnowledgeArticle.query.get(article.id).attachments[0].original_filename, "shot.png")

    def test_attachment_belongs_to_draft_token(self):
        author = self.make_user("kb_author2")
        att = KnowledgeAttachment(
            draft_token="tok-1", original_filename="shot.png",
            stored_filename="def456.png", mime_type="image/png", extension="png",
            size_bytes=100, sha256="y" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        db.session.commit()
        self.assertEqual(KnowledgeAttachment.query.filter_by(draft_token="tok-1").count(), 1)

    def test_neither_article_nor_draft_token_violates_constraint(self):
        author = self.make_user("kb_author3")
        att = KnowledgeAttachment(
            original_filename="shot.png", stored_filename="ghi789.png",
            mime_type="image/png", extension="png", size_bytes=100,
            sha256="z" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_both_article_and_draft_token_violates_constraint(self):
        article, author = self._make_article()
        att = KnowledgeAttachment(
            article_id=article.id, draft_token="tok-2",
            original_filename="shot.png", stored_filename="jkl012.png",
            mime_type="image/png", extension="png", size_bytes=100,
            sha256="w" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_deleting_article_cascades_attachment_rows(self):
        article, author = self._make_article()
        att = KnowledgeAttachment(
            article_id=article.id, original_filename="shot.png",
            stored_filename="mno345.png", mime_type="image/png", extension="png",
            size_bytes=100, sha256="v" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        db.session.commit()
        att_id = att.id

        db.session.delete(article)
        db.session.commit()

        self.assertIsNone(db.session.get(KnowledgeAttachment, att_id))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_attachment_model -v`
Expected: `ModuleNotFoundError`/`ImportError` — `KnowledgeAttachment` does not exist yet.

- [ ] **Step 3: Implement the model** (code above), register it the same way `KnowledgeArticle`/`KnowledgeTag` already are in `app/models/__init__.py` (required for Alembic autogenerate to see it — same lesson learned building the original Knowledge Base module).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_attachment_model -v`
Expected: PASS (5/5). SQLite enforces `CHECK` constraints by default — confirm `test_neither_...`/`test_both_...` actually raise (SQLite silently ignoring a CHECK would be a false green; if either test fails to raise, that's a real finding to stop on, not a reason to drop the constraint).

- [ ] **Step 5: Generate and review the migration** (implementation pass only)

```bash
flask db migrate -m "add knowledge attachment table"
```
Current head is `38fd8516d488` (`add_knowledge_base_tables`) — the new migration's `down_revision` must be that. Expected body (verify autogenerate matches, adjust if not):

```python
def upgrade():
    op.create_table(
        'knowledge_attachment',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('article_id', sa.Integer(), nullable=True),
        sa.Column('draft_token', sa.String(length=36), nullable=True),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('stored_filename', sa.String(length=64), nullable=False),
        sa.Column('mime_type', sa.String(length=100), nullable=False),
        sa.Column('extension', sa.String(length=10), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('is_image', sa.Boolean(), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('scan_status', sa.String(length=20), nullable=False),
        sa.Column('scan_checked_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "(article_id IS NOT NULL AND draft_token IS NULL) "
            "OR (article_id IS NULL AND draft_token IS NOT NULL)",
            name='ck_knowledge_attachment_exactly_one_owner',
        ),
        sa.ForeignKeyConstraint(['article_id'], ['knowledge_article.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['uploaded_by'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('stored_filename'),
    )
    with op.batch_alter_table('knowledge_attachment', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_knowledge_attachment_article_id'), ['article_id'])
        batch_op.create_index(batch_op.f('ix_knowledge_attachment_draft_token'), ['draft_token'])
        batch_op.create_index(batch_op.f('ix_knowledge_attachment_sha256'), ['sha256'])
        batch_op.create_index(batch_op.f('ix_knowledge_attachment_created_at'), ['created_at'])
        batch_op.create_index(batch_op.f('ix_knowledge_attachment_scan_status'), ['scan_status'])


def downgrade():
    with op.batch_alter_table('knowledge_attachment', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_knowledge_attachment_scan_status'))
        batch_op.drop_index(batch_op.f('ix_knowledge_attachment_created_at'))
        batch_op.drop_index(batch_op.f('ix_knowledge_attachment_sha256'))
        batch_op.drop_index(batch_op.f('ix_knowledge_attachment_draft_token'))
        batch_op.drop_index(batch_op.f('ix_knowledge_attachment_article_id'))
    op.drop_table('knowledge_attachment')
```

Existing-data impact: new table only, no change to any existing table — safe on a populated database.

- [ ] **Step 6: Commit**

### Shared storage helper (new deliverable of this task — needed by Tasks 5, 8, 9, 10)

A tiny module, created now because the physical-file-vs-DB-row relationship this whole feature is built around starts here, and four later tasks (5, 8, 9, 10) all need the exact same "delete this file, tolerate it already being gone" primitive — defining it once now avoids four divergent copies.

```python
# app/knowledge_base/attachment_storage.py
import os
import logging

logger = logging.getLogger(__name__)


def attachment_path(app, stored_filename):
    return os.path.join(app.config["KB_ATTACHMENTS_DIR"], stored_filename)


def safe_unlink(path):
    """Delete a file, tolerant of it already being gone (a concurrent
    cleanup run, or a prior partial run, must not raise)."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning("No se pudo eliminar archivo de adjunto: %s", e)
```

**Interfaces produced**: `attachment_path(app, stored_filename) -> str`, `safe_unlink(path) -> None`. Every later task that touches a physical attachment file imports from here instead of redefining either function.

---

## Task 2: Configuration

**Files:**
- Modify: `config.py`
- Test: `tests/knowledge_base/test_attachment_config.py`

**Interfaces:**
- Produces: `Config.KB_ATTACHMENTS_DIR`, `KB_ATTACHMENT_MAX_SIZE_BYTES`, `KB_ATTACHMENT_MAX_TOTAL_BYTES`, `KB_ATTACHMENT_ALLOWED_EXTENSIONS`, `KB_ATTACHMENT_IMAGE_EXTENSIONS`, `KB_ATTACHMENT_DRAFT_TTL_HOURS`, `KB_SCANNER`.

All of these are **optional** with safe defaults — per AGENTS.md §7, a config value should only be fatal if the app cannot safely run without it. None of these are global invariants (unlike `SECRET_KEY`/`VAULT_KEY`), so none raise `RuntimeError` if unset; `.env` is not read or modified by this task, only `os.environ.get(..., default)` with fallbacks is added.

```python
    # --- Knowledge Base attachments ---
    KB_ATTACHMENTS_DIR = os.path.join(_instance_path, 'kb_attachments')
    KB_ATTACHMENT_MAX_SIZE_BYTES = int(os.environ.get('KB_ATTACHMENT_MAX_SIZE_BYTES', 10 * 1024 * 1024))   # 10 MB/file
    KB_ATTACHMENT_MAX_TOTAL_BYTES = int(os.environ.get('KB_ATTACHMENT_MAX_TOTAL_BYTES', 50 * 1024 * 1024))  # 50 MB/article
    KB_ATTACHMENT_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'pdf', 'docx', 'xlsx', 'xls', 'csv', 'txt'}
    KB_ATTACHMENT_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
    KB_ATTACHMENT_DRAFT_TTL_HOURS = int(os.environ.get('KB_ATTACHMENT_DRAFT_TTL_HOURS', 24))
    KB_SCANNER = os.environ.get('KB_SCANNER', 'null')  # 'null' today; 'clamav'/'defender'/'trellix' are future values
```

`KB_ATTACHMENTS_DIR` must be created (`os.makedirs(..., exist_ok=True)`) the same way `app.instance_path` already is in `create_app()` — add that one line to `app/__init__.py` alongside the existing `os.makedirs(app.instance_path)` try/except, not a new mechanism.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_config.py
import unittest
from tests.base import TestConfig


class TestAttachmentConfig(unittest.TestCase):
    def test_defaults_present(self):
        self.assertTrue(TestConfig.KB_ATTACHMENTS_DIR.endswith("kb_attachments"))
        self.assertEqual(TestConfig.KB_ATTACHMENT_MAX_SIZE_BYTES, 10 * 1024 * 1024)
        self.assertEqual(TestConfig.KB_ATTACHMENT_MAX_TOTAL_BYTES, 50 * 1024 * 1024)
        self.assertEqual(
            TestConfig.KB_ATTACHMENT_ALLOWED_EXTENSIONS,
            {"png", "jpg", "jpeg", "webp", "pdf", "docx", "xlsx", "xls", "csv", "txt"},
        )
        self.assertEqual(TestConfig.KB_ATTACHMENT_IMAGE_EXTENSIONS, {"png", "jpg", "jpeg", "webp"})
        self.assertEqual(TestConfig.KB_ATTACHMENT_DRAFT_TTL_HOURS, 24)
        self.assertEqual(TestConfig.KB_SCANNER, "null")
```

Note: `tests/base.py`'s `TestConfig` is a plain class, not a subclass of the real `Config` — these new attributes must be added to **both** `config.py`'s `Config` and `tests/base.py`'s `TestConfig` (mirroring how `VAULT_KDBX_PATH` etc. are already duplicated there today). `TestConfig.KB_ATTACHMENTS_DIR` should point at the harness's isolated `instance_path` temp dir (`cls._instance_dir`), not the real project path — set it in `setUpClass` after `tempfile.mkdtemp()`, e.g. `TestConfig.KB_ATTACHMENTS_DIR = os.path.join(cls._instance_dir, "kb_attachments")`, assigned before `create_app()` is called.

- [ ] **Step 2: Run test to verify it fails** — `AttributeError`, config values don't exist yet.
- [ ] **Step 3: Implement** the config additions in both `config.py` and `tests/base.py`.
- [ ] **Step 4: Run test to verify it passes.**
- [ ] **Step 5: Commit.**

---

## Task 3: File validation chain

**Files:**
- Create: `app/knowledge_base/attachment_validation.py`
- Test: `tests/knowledge_base/test_attachment_validation.py`

**Interfaces:**
- Produces: `app.knowledge_base.attachment_validation.validate_upload(stream_bytes: bytes, declared_extension: str) -> ValidatedFile` (raises `AttachmentValidationError(message)` on any failure); `ValidatedFile` is a small dataclass with `extension, mime_type, is_image, sha256, size_bytes`.
- Pure function — no Flask, no disk I/O, no DB. Takes raw bytes + the extension the client claims, returns a validated/normalized result or raises. The caller (Task 5/7) is responsible for size-limit checks (those need the configured limits, which this module doesn't own) and for actually writing the file to disk.

### Exact chain (per the brief: nombre seguro → tamaño → extensión → MIME por contenido → magic bytes → SHA-256)

1. **Never trust the client filename** — the caller never passes `original_filename` into this function at all; it's stored as metadata only, never used to decide anything security-relevant.
2. **Size** — checked by the caller before even reading the full stream into memory where practical (Task 5/7), not by this module.
3. **Extension** — must be in `KB_ATTACHMENT_ALLOWED_EXTENSIONS`, checked by the caller before calling this (this module receives `declared_extension` already lower-cased/validated-as-in-allowlist by the caller — kept as a parameter rather than re-deriving it from a filename here, since "never trust filename" applies everywhere, including inside this module).
4. **Magic bytes / signature** — this module's core job:

```python
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
            content_types = zf.read("[Content_Types].xml").decode("utf-8", errors="replace")
    except zipfile.BadZipFile:
        raise AttachmentValidationError(f"El archivo .{ext} no es un documento Office válido.")
    except KeyError:
        raise AttachmentValidationError(f"El archivo .{ext} no contiene [Content_Types].xml.")

    try:
        ET.fromstring(content_types)
    except ET.ParseError:
        raise AttachmentValidationError(f"El archivo .{ext} tiene un [Content_Types].xml malformado.")

    if any(marker in content_types for marker in _MACRO_CONTENT_TYPES):
        raise AttachmentValidationError(
            "Los documentos de Office con macros no están permitidos."
        )
```

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_validation.py
import io
import unittest
import zipfile

from app.knowledge_base.attachment_validation import validate_upload, AttachmentValidationError


def _make_office_zip(main_content_type: str, ext: str = "docx", include_main_part: bool = True) -> bytes:
    part_name = "word/document.xml" if ext == "docx" else "xl/workbook.xml"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            f'<?xml version="1.0"?><Types><Override PartName="/{part_name}" '
            f'ContentType="{main_content_type}"/></Types>',
        )
        if include_main_part:
            zf.writestr(part_name, "<fake-but-present/>")
    return buf.getvalue()


class TestValidateUpload(unittest.TestCase):
    def test_valid_png(self):
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        result = validate_upload(data, "png")
        self.assertEqual(result.mime_type, "image/png")
        self.assertTrue(result.is_image)
        self.assertEqual(len(result.sha256), 64)

    def test_valid_webp(self):
        data = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"\x00" * 10
        result = validate_upload(data, "webp")
        self.assertEqual(result.mime_type, "image/webp")

    def test_png_extension_with_executable_content_rejected(self):
        data = b"MZ" + b"\x00" * 100  # PE executable header
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "png")

    def test_valid_pdf(self):
        data = b"%PDF-1.7\n" + b"\x00" * 20
        result = validate_upload(data, "pdf")
        self.assertEqual(result.mime_type, "application/pdf")
        self.assertFalse(result.is_image)

    def test_valid_docx(self):
        data = _make_office_zip("application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
        result = validate_upload(data, "docx")
        self.assertEqual(result.extension, "docx")

    def test_valid_xlsx(self):
        data = _make_office_zip(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", ext="xlsx"
        )
        result = validate_upload(data, "xlsx")
        self.assertEqual(result.extension, "xlsx")

    def test_zip_without_real_office_part_is_rejected(self):
        # Forges a plausible [Content_Types].xml but never includes the
        # actual word/document.xml part — an arbitrary ZIP renamed to
        # .docx with a fake manifest, not a real Office container.
        data = _make_office_zip(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            include_main_part=False,
        )
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "docx")

    def test_arbitrary_zip_without_content_types_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("whatever.txt", "not an office document")
        with self.assertRaises(AttachmentValidationError):
            validate_upload(buf.getvalue(), "docx")

    def test_docm_renamed_to_docx_is_rejected(self):
        data = _make_office_zip("application/vnd.ms-word.document.macroEnabled.main+xml")
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "docx")

    def test_valid_xls_ole2(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 20
        result = validate_upload(data, "xls")
        self.assertEqual(result.mime_type, "application/vnd.ms-excel")

    def test_valid_csv_text(self):
        data = "col1,col2\nval1,val2\n".encode("utf-8")
        result = validate_upload(data, "csv")
        self.assertEqual(result.mime_type, "text/csv")

    def test_csv_with_binary_content_rejected(self):
        data = b"col1,col2\n\x00\x01\x02binary"
        with self.assertRaises(AttachmentValidationError):
            validate_upload(data, "csv")

    def test_unsupported_extension_rejected(self):
        with self.assertRaises(AttachmentValidationError):
            validate_upload(b"anything", "exe")

    def test_sha256_is_deterministic(self):
        data = b"%PDF-1.7\n" + b"same content"
        r1 = validate_upload(data, "pdf")
        r2 = validate_upload(data, "pdf")
        self.assertEqual(r1.sha256, r2.sha256)
```

- [ ] **Step 2: Run test to verify it fails** — `ModuleNotFoundError`.
- [ ] **Step 3: Implement** (code above).
- [ ] **Step 4: Run test to verify it passes** — all 14 green, especially `test_docm_renamed_to_docx_is_rejected` and `test_zip_without_real_office_part_is_rejected` (Review Focus items: a disguised macro file, and an arbitrary ZIP with only a forged manifest and no real internal document part).
- [ ] **Step 5: Commit.**

---

## Task 4: Scanner abstraction

**Files:**
- Create: `app/knowledge_base/scanning.py`
- Test: `tests/knowledge_base/test_scanning.py`

**Interfaces:**
- Produces: `ScanStatus` (str enum: `PENDING`, `CLEAN`, `INFECTED`, `NOT_SCANNED`, `SCAN_ERROR`), `ScanResult` (dataclass: `status`, `detail: str | None`), `Scanner` (ABC with `scan_file(path: str) -> ScanResult`), `NullScanner`, `get_scanner() -> Scanner` (factory reading `current_app.config["KB_SCANNER"]`, returns `NullScanner()` for `"null"` or any unrecognized value — unrecognized falls back to the safe default rather than raising, since a typo in config must not crash uploads).

```python
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
```

Future `ClamAVScanner`/`DefenderScanner`/`TrellixScanner` register themselves into `_SCANNERS` and are selected purely by the `KB_SCANNER` config value — `knowledge_base`'s callers (Task 5/7) only ever call `get_scanner().scan_file(path)` and never know which implementation answered.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_scanning.py
import unittest
from app.knowledge_base.scanning import ScanStatus, NullScanner


class TestNullScanner(unittest.TestCase):
    def test_null_scanner_never_returns_clean(self):
        result = NullScanner().scan_file("/any/path")
        self.assertEqual(result.status, ScanStatus.NOT_SCANNED)
        self.assertNotEqual(result.status, ScanStatus.CLEAN)
```

```python
# appended to tests/knowledge_base/test_scanning.py — needs app context for current_app.config
from tests.base import PortalTestCase
from app.knowledge_base.scanning import get_scanner, NullScanner


class TestGetScanner(PortalTestCase):
    def test_default_config_returns_null_scanner(self):
        self.assertIsInstance(get_scanner(), NullScanner)

    def test_unknown_scanner_name_falls_back_to_null(self):
        self.app.config["KB_SCANNER"] = "something-not-registered"
        self.assertIsInstance(get_scanner(), NullScanner)
        self.app.config["KB_SCANNER"] = "null"  # restore
```

- [ ] **Step 2: RED** — `ModuleNotFoundError`.
- [ ] **Step 3: Implement** (code above).
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Commit.**

---

## Task 5: Draft attachment lifecycle (upload, ownership, promotion)

**Files:**
- Create: `app/knowledge_base/attachment_routes.py` (draft-upload route only in this task)
- Modify: `app/knowledge_base/__init__.py` (import the new routes module)
- Modify: `app/knowledge_base/routes.py` (`crear()` — promote drafts on success)
- Modify: `app/templates/knowledge_base/form.html` (hidden `draft_token` field, preserved across re-render)
- Test: `tests/knowledge_base/test_attachment_draft.py`

**Interfaces:**
- Consumes: `app.knowledge_base.attachment_validation.validate_upload`, `app.knowledge_base.scanning.get_scanner`.
- Produces: `POST /kb/attachments/draft-upload` (multipart, fields `file`, `draft_token`, `csrf_token`); promotion logic inside `crear()`.

### Draft token lifecycle

1. **`crear()` generates the token server-side on GET, and preserves the client-submitted one on any POST (success or validation failure) — never regenerates on failure.** Concrete diff to the existing route:

   ```python
   # app/knowledge_base/routes.py — add `import uuid as uuid_mod` and
   # `from app.models.knowledge import KnowledgeAttachment` to the existing
   # imports, then change crear() to:
   @bp.route("/nuevo", methods=["GET", "POST"])
   @login_required
   def crear():
       form = KnowledgeArticleForm()

       if request.method == "GET":
           draft_token = uuid_mod.uuid4().hex
       else:
           # Preserve exactly what the client submitted — including on a
           # validation failure below, where this same value is re-rendered
           # back into the hidden field. Only falls back to a fresh uuid if
           # the hidden field was somehow stripped (defensive, not the
           # normal path), so a draft is never silently orphaned by a typo
           # in the rest of the form.
           draft_token = request.form.get("draft_token", "").strip() or uuid_mod.uuid4().hex

       if form.validate_on_submit():
           article = KnowledgeArticle(
               title=form.title.data,
               problem_md=form.problem_md.data,
               solution_md=form.solution_md.data,
               client=(form.client.data or "").strip() or None,
               platform=(form.platform.data or "").strip() or None,
               author_id=current_user.id,
           )
           db.session.add(article)
           db.session.flush()
           sync_tags(article, form.tags_raw.data)

           KnowledgeAttachment.query.filter_by(
               draft_token=draft_token, uploaded_by=current_user.id
           ).update({"article_id": article.id, "draft_token": None})

           log_audit("knowledge_base", "create", "article", article.id, article.title)
           db.session.commit()
           flash("Artículo creado.", "success")
           return redirect(url_for("knowledge_base.detalle", id=article.id))

       return render_template(
           "knowledge_base/form.html",
           form=form,
           heading="Nuevo artículo",
           draft_token=draft_token,
           clients=distinct_values(KnowledgeArticle.client),
           platforms=distinct_values(KnowledgeArticle.platform),
       )
   ```

   `form.html`'s hidden field, added only for the creation case (`editar()` keeps rendering the same template but never passes/needs `draft_token` — an existing article has no draft state):
   ```html
   {% if draft_token %}
   <input type="hidden" name="draft_token" id="draft_token" value="{{ draft_token }}">
   {% endif %}
   ```

2. `draft-upload` route: validates the file (Task 3), checks the scanner (Task 4 — new rows always start `pending`, flip to whatever `get_scanner().scan_file()` returns immediately, since the scan happens synchronously at upload time in this design — see Task 7 for why async scanning is explicitly out of MVP scope), writes it to `KB_ATTACHMENTS_DIR/<uuid>.<ext>`, creates the `KnowledgeAttachment` row with `draft_token=<submitted token>, article_id=None, uploaded_by=current_user.id`.
3. **Ownership check on every draft operation.** Deleting a draft attachment before the article is ever saved is in scope (confirmed): Task 8's `attachment_delete` route already branches on `att.article_id is None` → requires `att.uploaded_by == current_user.id`, with no `_can_edit()` involved (there is no article yet to check edit-permission against) — that single route serves both "delete a promoted attachment" (author-or-admin) and "discard a draft" (uploader-only) without a separate endpoint.

### Shared upload handler and the draft route itself (concrete code, not just description)

```python
# app/knowledge_base/attachment_routes.py
import os
import uuid as uuid_mod
from datetime import datetime

from flask import current_app, jsonify, request, abort, send_file
from flask_login import current_user, login_required

from app.extensions import db
from app.knowledge_base import bp
from app.knowledge_base.attachment_storage import attachment_path, safe_unlink
from app.knowledge_base.attachment_validation import validate_upload, AttachmentValidationError
from app.knowledge_base.attachment_cleanup import purge_expired_drafts
from app.knowledge_base.scanning import get_scanner, ScanStatus
from app.models.knowledge import KnowledgeAttachment
from app.models.audit import log_audit


def _handle_attachment_upload(article_id, draft_token):
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "No se recibió ningún archivo."}), 400

    declared_ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if declared_ext not in current_app.config["KB_ATTACHMENT_ALLOWED_EXTENSIONS"]:
        return jsonify({"error": "Extensión no permitida."}), 400

    data = file.read()
    if len(data) > current_app.config["KB_ATTACHMENT_MAX_SIZE_BYTES"]:
        return jsonify({"error": "El archivo excede el tamaño máximo permitido."}), 400

    if article_id is not None:
        total = db.session.query(
            db.func.coalesce(db.func.sum(KnowledgeAttachment.size_bytes), 0)
        ).filter_by(article_id=article_id).scalar()
        if total + len(data) > current_app.config["KB_ATTACHMENT_MAX_TOTAL_BYTES"]:
            return jsonify({"error": "El artículo alcanzó el límite total de adjuntos."}), 400

    try:
        validated = validate_upload(data, declared_ext)
    except AttachmentValidationError as e:
        return jsonify({"error": str(e)}), 400

    stored_filename = f"{uuid_mod.uuid4().hex}.{validated.extension}"
    os.makedirs(current_app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
    path = attachment_path(current_app, stored_filename)
    with open(path, "wb") as f:
        f.write(data)

    scan_result = get_scanner().scan_file(path)

    attachment = KnowledgeAttachment(
        article_id=article_id,
        draft_token=draft_token,
        original_filename=file.filename[:255],
        stored_filename=stored_filename,
        mime_type=validated.mime_type,
        extension=validated.extension,
        size_bytes=validated.size_bytes,
        sha256=validated.sha256,
        is_image=validated.is_image,
        uploaded_by=current_user.id,
        scan_status=scan_result.status.value,
        scan_checked_at=datetime.utcnow(),
    )
    db.session.add(attachment)
    db.session.flush()

    log_audit("knowledge_base", "attachment_upload", "attachment", attachment.id, attachment.original_filename)

    if scan_result.status == ScanStatus.INFECTED:
        # Confirmed policy: never store malware just to keep evidence.
        # The row (for traceability) stays; the physical file does not.
        log_audit("knowledge_base", "malware_detected", "attachment", attachment.id, attachment.original_filename)
        safe_unlink(path)

    db.session.commit()

    return jsonify({
        "id": attachment.id,
        "view_url": f"/kb/attachments/{attachment.id}/view",
        "download_url": f"/kb/attachments/{attachment.id}/download",
        "is_image": attachment.is_image,
        "scan_status": attachment.scan_status,
    })


@bp.route("/attachments/draft-upload", methods=["POST"])
@login_required
def attachment_draft_upload():
    purge_expired_drafts(current_app._get_current_object())  # lazy purge, cheap, opportunistic
    draft_token = request.form.get("draft_token", "").strip()
    if not draft_token:
        return jsonify({"error": "Falta draft_token."}), 400
    return _handle_attachment_upload(article_id=None, draft_token=draft_token)
```

Note the infected-at-upload-time branch here is the **synchronous** path (today's only path, since `NullScanner`/any MVP scanner call is synchronous — see Task 4). An async scanner integrated later would instead leave the row `pending`, scan out-of-band, and flip `scan_status` (and run this same immediate-unlink-on-infected step) from whatever background mechanism calls the scanner — that mechanism is explicitly not designed here (Task 4's interface doesn't change either way, only who calls `scan_file()` and when).

4. **Promotion** inside `crear()`, right where the article is created and `db.session.flush()` already happens:
   ```python
   draft_token = request.form.get("draft_token", "")
   if draft_token:
       KnowledgeAttachment.query.filter_by(
           draft_token=draft_token, uploaded_by=current_user.id
       ).update({"article_id": article.id, "draft_token": None})
   ```
   This single `UPDATE` (via SQLAlchemy's bulk `.update()`) runs inside the same session as the article `INSERT`, committed together by the existing `db.session.commit()` a few lines later — one transaction, matching Task 1's invariant discussion.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_draft.py
import io
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestAttachmentDraftLifecycle(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.login("kb_author")

    def _csrf(self, url="/kb/nuevo"):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def _draft_upload(self, token, csrf, filename="shot.png", data=PNG_BYTES):
        return self.client.post(
            "/kb/attachments/draft-upload",
            data={
                "file": (io.BytesIO(data), filename),
                "draft_token": token,
                "csrf_token": csrf,
            },
            content_type="multipart/form-data",
        )

    def test_draft_upload_creates_attachment_owned_by_uploader(self):
        resp = self._draft_upload("tok-A", self._csrf())
        self.assertEqual(resp.status_code, 200)
        att = KnowledgeAttachment.query.filter_by(draft_token="tok-A").first()
        self.assertIsNotNone(att)
        self.assertEqual(att.uploaded_by, self.author.id)

    def test_other_user_draft_upload_gets_independent_token_ownership(self):
        self._draft_upload("tok-A", self._csrf())
        self.make_user("other_user", tools=["knowledge_base"])
        self.login("other_user")
        self._draft_upload("tok-A", self._csrf())  # same token string, different user

        rows = KnowledgeAttachment.query.filter_by(draft_token="tok-A").all()
        self.assertEqual(len(rows), 2)
        uploaders = {r.uploaded_by for r in rows}
        self.assertEqual(len(uploaders), 2)  # each row owned by its own uploader, not shared

    def test_promotion_on_successful_article_creation(self):
        token = "tok-promote"
        self._draft_upload(token, self._csrf())

        csrf = self._csrf()
        self.client.post(
            "/kb/nuevo",
            data={
                "title": "Articulo con adjunto",
                "problem_md": "p", "solution_md": "s",
                "draft_token": token, "csrf_token": csrf,
            },
            follow_redirects=True,
        )

        article = KnowledgeArticle.query.filter_by(title="Articulo con adjunto").first()
        self.assertIsNotNone(article)
        att = KnowledgeAttachment.query.filter_by(stored_filename=KnowledgeAttachment.query.filter_by(draft_token=None).first().stored_filename).first()
        self.assertEqual(att.article_id, article.id)
        self.assertIsNone(att.draft_token)

    def test_failed_article_creation_leaves_draft_untouched(self):
        token = "tok-fail"
        self._draft_upload(token, self._csrf())

        csrf = self._csrf()
        self.client.post(  # missing title -> validation failure
            "/kb/nuevo",
            data={"problem_md": "p", "solution_md": "s", "draft_token": token, "csrf_token": csrf},
        )

        att = KnowledgeAttachment.query.filter_by(draft_token=token).first()
        self.assertIsNotNone(att)
        self.assertIsNone(att.article_id)
```

- [ ] **Step 2: RED** — 404 on the new route, `ModuleNotFoundError` on imports.
- [ ] **Step 3: Implement** the route, blueprint wiring, and `crear()` promotion diff.
- [ ] **Step 4: GREEN** (4/4, especially `test_other_user_draft_upload_gets_independent_token_ownership` — the Review Focus item).
- [ ] **Step 5: Commit.**

---

## Task 6: Upload to an existing article (manual + paste share one endpoint)

**Files:**
- Modify: `app/knowledge_base/attachment_routes.py` (add `POST /kb/<article_id>/attachments/upload`)
- Test: `tests/knowledge_base/test_attachment_upload.py`

**Interfaces:**
- Produces: `POST /kb/<article_id>/attachments/upload` — identical validation path to draft-upload, difference is only `article_id` instead of `draft_token`, and the permission check reuses the **already-existing** `_can_edit(article)` from `app/knowledge_base/routes.py:90-91` (`current_user.is_admin or article.author_id == current_user.id` — this is exactly the author-or-admin rule confirmed for attachment upload; it already exists from the Knowledge Base edit-authorization work, nothing new to define here).
- Response: `{"id": <attachment_id>, "view_url": "/kb/attachments/<id>/view", "download_url": "/kb/attachments/<id>/download", "is_image": bool, "scan_status": "..."}` — the frontend (Task 11) uses `is_image` to decide whether to insert `![...]()` or `[...]()` Markdown, and `scan_status` to show the right badge immediately without a second request.

```python
from app.knowledge_base.routes import _can_edit  # already exists, author-or-admin


@bp.route("/<int:article_id>/attachments/upload", methods=["POST"])
@login_required
def attachment_upload(article_id):
    article = KnowledgeArticle.query.get_or_404(article_id)
    if not _can_edit(article):
        abort(403)
    return _handle_attachment_upload(article_id=article_id, draft_token=None)
```
The shared body is the same `_handle_attachment_upload(article_id, draft_token)` already written in Task 5 (one real implementation, two thin wrappers that only differ in their permission check and which FK column they set) — this is the mechanism that satisfies the Review Focus requirement that paste and manual upload (and draft vs. direct) never diverge in validation strictness.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_upload.py
import io
from tests.base import PortalTestCase
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401
from app.extensions import db

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestAttachmentUploadToExistingArticle(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.login("kb_author")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()

    def _csrf(self):
        page = self.client.get(f"/kb/{self.article.id}/editar")
        return self.extract_csrf(page.get_data(as_text=True))

    def test_author_can_upload_to_own_article(self):
        resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": self._csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(KnowledgeAttachment.query.filter_by(article_id=self.article.id).count(), 1)

    def test_non_owner_non_admin_cannot_upload(self):
        self.make_user("other_user", tools=["knowledge_base"])
        self.login("other_user")
        csrf = self._csrf() if False else self.extract_csrf(
            self.client.get("/kb/").get_data(as_text=True)
        )
        resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": csrf},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(KnowledgeAttachment.query.filter_by(article_id=self.article.id).count(), 0)

    def test_oversized_file_rejected(self):
        self.app.config["KB_ATTACHMENT_MAX_SIZE_BYTES"] = 10  # force a tiny limit for this test
        resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": self._csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)
        self.app.config["KB_ATTACHMENT_MAX_SIZE_BYTES"] = 10 * 1024 * 1024  # restore
```

- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement** the route, importing the already-existing `_can_edit()` and reusing Task 5's `_handle_attachment_upload()`.
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Commit.**

---

## Task 7: Serving — `/view` and `/download`

**Files:**
- Modify: `app/knowledge_base/attachment_routes.py`
- Test: `tests/knowledge_base/test_attachment_serving.py`

**Interfaces:**
- Produces: `GET /kb/attachments/<id>/view` (images only, `clean` only, `inline`), `GET /kb/attachments/<id>/download` (any clean attachment, always `attachment`).

```python
@bp.route("/attachments/<int:attachment_id>/view")
@login_required
def attachment_view(attachment_id):
    att = KnowledgeAttachment.query.get_or_404(attachment_id)
    _require_article_read_access(att)
    if not att.is_image or att.scan_status != "clean":
        abort(404)
    path = attachment_path(current_app, att.stored_filename)
    resp = send_file(path, mimetype=att.mime_type, as_attachment=False)
    resp.headers["Content-Disposition"] = f'inline; filename="{att.stored_filename}"'
    return resp


@bp.route("/attachments/<int:attachment_id>/download")
@login_required
def attachment_download(attachment_id):
    att = KnowledgeAttachment.query.get_or_404(attachment_id)
    _require_article_read_access(att)
    if att.scan_status != "clean":
        abort(404)
    path = attachment_path(current_app, att.stored_filename)
    return send_file(
        path, mimetype=att.mime_type, as_attachment=True,
        download_name=f"{att.original_filename}",
    )


def _require_article_read_access(att):
    """Tool access is enough to read — Knowledge Base has no per-article
    ownership restriction on reading, same as detalle(). A draft attachment
    (no article_id yet) can only be read by its own uploader — there is no
    "article" to check permission against yet."""
    if att.article_id is None:
        if att.uploaded_by != current_user.id:
            abort(404)
    # else: knowledge_base tool access (already enforced by proteger_blueprint
    # at the blueprint level) is sufficient — no further object check, matching
    # detalle()'s own policy.
```

Note `download_name=att.original_filename` — this is the **one** place the untrusted original filename is used, and only as the suggested filename in the `Content-Disposition` header value, which Werkzeug's `send_file` already escapes/quotes safely; it is never used to construct a filesystem path (`stored_filename` is what touches the filesystem, always a UUID the app generated).

Explicitly **not** doing here: a `scan_status != clean` row returns a plain `404`, not a custom "pending/infected" JSON/HTML page from this route — Task 11 handles showing that status in the article/edit page's attachment list (where the status is already known from the DB, no need to hit `/view` just to find out), so `/view`/`/download` themselves stay simple and never need to branch on *why* it's not servable.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_serving.py
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401


class TestAttachmentServing(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.reader = self.make_user("kb_reader", tools=["knowledge_base"])
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.flush()

    def _make_attachment(self, scan_status, is_image=True, article_id=None, draft_token=None, uploaded_by=None):
        import hashlib, os
        content = b"fake-content"
        stored = "test-" + hashlib.sha1(os.urandom(8)).hexdigest() + (".png" if is_image else ".pdf")
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], stored)
        os.makedirs(self.app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        att = KnowledgeAttachment(
            article_id=article_id, draft_token=draft_token,
            original_filename="x.png" if is_image else "x.pdf",
            stored_filename=stored,
            mime_type="image/png" if is_image else "application/pdf",
            extension="png" if is_image else "pdf",
            size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest(),
            is_image=is_image, uploaded_by=uploaded_by or self.author.id,
            scan_status=scan_status,
        )
        db.session.add(att)
        db.session.commit()
        return att

    def test_clean_image_view_succeeds_for_any_tool_user(self):
        att = self._make_attachment("clean", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        resp = self.client.get(f"/kb/attachments/{att.id}/view")
        self.assertEqual(resp.status_code, 200)

    def test_pending_image_view_blocked(self):
        att = self._make_attachment("pending", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)

    def test_not_scanned_image_view_blocked(self):
        att = self._make_attachment("not_scanned", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)

    def test_infected_blocked_on_both_routes(self):
        att = self._make_attachment("infected", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/download").status_code, 404)

    def test_scan_error_blocked(self):
        att = self._make_attachment("scan_error", is_image=False, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/download").status_code, 404)

    def test_clean_document_download_is_attachment_not_inline(self):
        att = self._make_attachment("clean", is_image=False, article_id=self.article.id)
        self.login("kb_reader")
        resp = self.client.get(f"/kb/attachments/{att.id}/download")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))

    def test_clean_document_has_no_view_route_access(self):
        att = self._make_attachment("clean", is_image=False, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)

    def test_draft_attachment_readable_only_by_its_uploader(self):
        att = self._make_attachment("clean", is_image=True, draft_token="tok-x", uploaded_by=self.author.id)
        self.login("kb_reader")  # different user than uploader
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)
        self.login("kb_author")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 200)
```

- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: GREEN** (9/9 — this task covers 3 of the 5 Review Focus items by itself).
- [ ] **Step 5: Commit.**

---

## Task 8: Delete

**Files:**
- Modify: `app/knowledge_base/attachment_routes.py`
- Test: `tests/knowledge_base/test_attachment_delete.py`

```python
@bp.route("/attachments/<int:attachment_id>/delete", methods=["POST"])
@login_required
def attachment_delete(attachment_id):
    att = KnowledgeAttachment.query.get_or_404(attachment_id)
    if att.article_id is not None:
        if not _can_edit(att.article):
            abort(403)
    else:
        if att.uploaded_by != current_user.id:
            abort(403)

    path = attachment_path(current_app, att.stored_filename)  # from app.knowledge_base.attachment_storage (Task 1)
    safe_unlink(path)
    log_audit("knowledge_base", "attachment_delete", "attachment", att.id, att.original_filename)
    db.session.delete(att)
    db.session.commit()
    return jsonify({"deleted": True})
```

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_delete.py
import io
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestAttachmentDelete(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.login("kb_author")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()
        upload_resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"),
                  "csrf_token": self.extract_csrf(self.client.get(f"/kb/{self.article.id}/editar").get_data(as_text=True))},
            content_type="multipart/form-data",
        )
        self.att_id = upload_resp.get_json()["id"]

    def _csrf(self):
        return self.extract_csrf(self.client.get(f"/kb/{self.article.id}/editar").get_data(as_text=True))

    def test_author_can_delete(self):
        import os
        att = db.session.get(KnowledgeAttachment, self.att_id)
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], att.stored_filename)
        self.assertTrue(os.path.exists(path))

        resp = self.client.post(
            f"/kb/attachments/{self.att_id}/delete", data={"csrf_token": self._csrf()}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(db.session.get(KnowledgeAttachment, self.att_id))
        self.assertFalse(os.path.exists(path))

    def test_non_owner_non_admin_cannot_delete(self):
        self.make_user("other_user", tools=["knowledge_base"])
        self.login("other_user")
        csrf = self.extract_csrf(self.client.get("/kb/").get_data(as_text=True))
        resp = self.client.post(
            f"/kb/attachments/{self.att_id}/delete", data={"csrf_token": csrf}
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, self.att_id))
```

- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Commit.**

---

## Task 9: Delete article → delete its attachments' physical files

**Files:**
- Modify: `app/knowledge_base/routes.py` (`eliminar()`)
- Test: `tests/knowledge_base/test_article_delete_cleans_attachments.py`

SQLAlchemy's `cascade="all, delete-orphan"` (Task 1) already deletes the **rows** when an article is deleted. It has no concept of the physical file. `eliminar()` must unlink files **before** `db.session.delete(article)`:

Add to `routes.py`'s existing top-level imports: `from app.knowledge_base.attachment_storage import attachment_path, safe_unlink`.

```python
@bp.route("/<int:id>/eliminar", methods=["POST"])
@login_required
def eliminar(id):
    article = KnowledgeArticle.query.get_or_404(id)
    if not _can_delete(article):
        abort(403)
    for att in article.attachments:
        safe_unlink(attachment_path(current_app, att.stored_filename))  # from attachment_storage (Task 1)
    log_audit("knowledge_base", "delete", "article", article.id, article.title)
    db.session.delete(article)
    db.session.commit()
    ...
```

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_article_delete_cleans_attachments.py
import io, os
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestArticleDeleteCleansAttachments(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("kb_admin", is_admin=True)
        self.login("kb_admin")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.admin)
        db.session.add(self.article)
        db.session.commit()
        csrf = self.extract_csrf(self.client.get(f"/kb/{self.article.id}/editar").get_data(as_text=True))
        self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": csrf},
            content_type="multipart/form-data",
        )

    def test_deleting_article_removes_attachment_file_from_disk(self):
        att = KnowledgeAttachment.query.filter_by(article_id=self.article.id).first()
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], att.stored_filename)
        self.assertTrue(os.path.exists(path))

        csrf = self.extract_csrf(self.client.get(f"/kb/{self.article.id}").get_data(as_text=True))
        self.client.post(f"/kb/{self.article.id}/eliminar", data={"csrf_token": csrf}, follow_redirects=True)

        self.assertFalse(os.path.exists(path))
        self.assertIsNone(db.session.get(KnowledgeAttachment, att.id))
```

- [ ] **Step 2: RED** (file survives today, since `eliminar()` has no attachment-aware code yet).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Commit.**

---

## Task 10: Cleanup — lazy purge + daily scheduled job, idempotent and concurrency-safe

**Files:**
- Create: `app/knowledge_base/attachment_cleanup.py`
- Modify: `app/__init__.py` (register the daily job)
- Modify: `app/knowledge_base/attachment_routes.py` (call lazy purge from draft-upload)
- Test: `tests/knowledge_base/test_attachment_cleanup.py`

**Interfaces:**
- Produces: `purge_expired_drafts(app) -> int` (returns count actually deleted — used by both the lazy call-site and the scheduled job; same function, same guarantees).

### Idempotency and concurrency design (this task's core requirement)

```python
# app/knowledge_base/attachment_cleanup.py
import logging
from datetime import datetime, timedelta

from app.knowledge_base.attachment_storage import attachment_path, safe_unlink

logger = logging.getLogger(__name__)


def purge_expired_drafts(app) -> int:
    from app.extensions import db
    from app.models.knowledge import KnowledgeAttachment

    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(hours=app.config["KB_ATTACHMENT_DRAFT_TTL_HOURS"])
        expired = KnowledgeAttachment.query.filter(
            KnowledgeAttachment.article_id.is_(None),
            KnowledgeAttachment.draft_token.isnot(None),
            KnowledgeAttachment.created_at < cutoff,
        ).all()

        deleted = 0
        for att in expired:
            # Re-check it is STILL a draft right before deleting: a concurrent
            # request may have promoted it (Task 5) between the query above
            # and this loop iteration. Never delete a promoted attachment.
            db.session.refresh(att)
            if att.article_id is not None:
                continue  # promoted since the query ran — leave it alone

            path = attachment_path(app, att.stored_filename)
            safe_unlink(path)

            # delete() + commit() per row, not one giant transaction: if a
            # second concurrent purge run (duplicate scheduler fire, or a
            # manual trigger overlapping the daily job) already deleted this
            # same row, this commit is a no-op, not an error — the row is
            # simply gone, matched zero rows, nothing raises.
            db.session.delete(att)
            try:
                db.session.commit()
                deleted += 1
            except Exception:
                db.session.rollback()
                logger.warning("Fila de adjunto huérfano ya no existía al purgar (concurrencia esperada).")

        return deleted
```

This satisfies every requirement from the brief:
- tolerant file removal (`_safe_unlink`);
- row deleted only if still a draft at the moment of deletion (`db.session.refresh` re-check, not the staleness of the original query);
- no unhandled exception under duplicate/concurrent execution (per-row commit + narrow `except`);
- never touches a promoted attachment (the re-check);
- never touches a draft still inside its TTL (the `cutoff` filter).

### Wiring

```python
# app/__init__.py, alongside the existing vigilante_csirt job:
from app.knowledge_base.attachment_cleanup import purge_expired_drafts
scheduler.add_job(
    id='kb_attachment_cleanup',
    func=purge_expired_drafts,
    args=[app],
    trigger='interval',
    hours=24,
)
```

```python
# attachment_routes.py draft-upload, before creating the new row:
from app.knowledge_base.attachment_cleanup import purge_expired_drafts
purge_expired_drafts(current_app._get_current_object())
```

The brief explicitly says not to fix the known APScheduler-duplicates-under-the-reloader issue — this design doesn't need that fix: if the job fires twice, `purge_expired_drafts` running twice concurrently is exactly the scenario the per-row commit + re-check handles.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_cleanup.py
import os
from datetime import datetime, timedelta
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401
from app.knowledge_base.attachment_cleanup import purge_expired_drafts


class TestAttachmentCleanup(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author")

    def _make_attachment(self, created_at, article_id=None, draft_token=None):
        import hashlib
        stored = "cleanup-" + hashlib.sha1(os.urandom(8)).hexdigest() + ".png"
        os.makedirs(self.app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], stored)
        with open(path, "wb") as f:
            f.write(b"x")
        att = KnowledgeAttachment(
            article_id=article_id, draft_token=draft_token,
            original_filename="x.png", stored_filename=stored,
            mime_type="image/png", extension="png", size_bytes=1,
            sha256="a" * 64, is_image=True, uploaded_by=self.author.id,
            scan_status="pending", created_at=created_at,
        )
        db.session.add(att)
        db.session.commit()
        return att, path

    def test_expired_draft_is_purged(self):
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=25), draft_token="tok-old"
        )
        deleted = purge_expired_drafts(self.app)
        self.assertEqual(deleted, 1)
        self.assertIsNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertFalse(os.path.exists(path))

    def test_draft_within_ttl_is_not_purged(self):
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=1), draft_token="tok-fresh"
        )
        purge_expired_drafts(self.app)
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertTrue(os.path.exists(path))

    def test_promoted_attachment_is_never_purged_even_if_old(self):
        article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(article)
        db.session.flush()
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=48), article_id=article.id
        )
        purge_expired_drafts(self.app)
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertTrue(os.path.exists(path))

    def test_purge_already_missing_file_does_not_raise(self):
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=25), draft_token="tok-nofile"
        )
        os.remove(path)  # simulate a prior/concurrent run already having removed it
        deleted = purge_expired_drafts(self.app)  # must not raise
        self.assertEqual(deleted, 1)

    def test_running_purge_twice_concurrently_is_safe(self):
        self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=25), draft_token="tok-dup"
        )
        first = purge_expired_drafts(self.app)
        second = purge_expired_drafts(self.app)  # same expired row, run again
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)  # nothing left to purge, no error
```

- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: GREEN** (5/5 — covers the duplicate-execution Review Focus item directly).
- [ ] **Step 5: Commit.**

---

## Task 11: UI/UX

**Files:**
- Modify: `app/templates/knowledge_base/form.html` (paste listener, upload button, attachment list with status badges, hidden `draft_token`)
- Modify: `app/templates/knowledge_base/detail.html` (attachment list with status, download links)
- Modify: `app/knowledge_base/markdown_render.py` (allow `<img>` with `src`/`alt` only, restricted to internal attachment URLs)
- Test: `tests/knowledge_base/test_markdown_img_allowlist.py`

**No general redesign** — same card/Bootstrap language already used everywhere else in Knowledge Base and the rest of the portal.

### Markdown allowlist change

```python
_ALLOWED_TAGS = [
    ... ,  # existing list unchanged
    "img",
]
_ALLOWED_ATTRIBUTES = {
    ... ,  # existing dict unchanged
    "img": ["src", "alt"],
}
```
`bleach` alone does not restrict `src` to a path prefix — add a second pass after `bleach.clean()` that drops (or neutralizes) any `<img>` whose `src` does not start with `/kb/attachments/`, so an attacker can't smuggle `<img src="https://evil/track.gif">` (or `src="javascript:..."`, already blocked by `_ALLOWED_PROTOCOLS` not including `javascript`, but external image tracking/exfiltration is a separate concern `bleach`'s protocol allowlist doesn't cover). Concretely: parse with `bleach`'s underlying `html5lib` tree or a light regex pass restricted to the already-sanitized output, stripping `src` values that don't match `^/kb/attachments/\d+/view$`.

### Status badges (states from the brief)

```text
analizando   -> scan_status in (pending)                -> badge bg-secondary, spinner icon
limpio       -> scan_status == clean                     -> badge bg-success
sin scanner  -> scan_status == not_scanned                -> badge bg-warning text-dark
error        -> scan_status == scan_error                 -> badge bg-danger
infectado    -> scan_status == infected                   -> badge bg-danger, no link at all (not even a dead one)
```
Rendered in a small attachment list below the editor in `form.html` and in `detail.html` — not inside the Markdown body itself (the Markdown only ever contains the `/view` or `/download` reference once inserted; the status badge lives in the surrounding template, which already has the live `scan_status` from the DB on every render, so it's always accurate without re-querying `/view`).

### Paste JS (sketch, scoped to `problem_md`/`solution_md` textareas)

```javascript
textarea.addEventListener('paste', function (e) {
  const item = Array.from(e.clipboardData.items).find(i => i.type.startsWith('image/'));
  if (!item) return;
  e.preventDefault();
  const blob = item.getAsFile();
  const formData = new FormData();
  formData.append('file', blob, 'pasted-image.png');
  formData.append('draft_token', document.getElementById('draft_token').value);
  formData.append('csrf_token', CSRF_TOKEN);
  fetch(UPLOAD_URL, { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      insertAtCursor(textarea, `![captura](${data.view_url})`);
      renderAttachmentBadge(data);  // shows "analizando"/"sin scanner" immediately
    });
});
```

- [ ] **Step 1: Write the failing test** (backend piece only — the Markdown `<img>` allowlist; JS/template rendering is validated manually per `portal-testing-and-validation`, not unit-tested)

```python
# tests/knowledge_base/test_markdown_img_allowlist.py
import unittest
from app.knowledge_base.markdown_render import render_markdown


class TestMarkdownImgAllowlist(unittest.TestCase):
    def test_internal_attachment_image_renders(self):
        html = render_markdown("![captura](/kb/attachments/5/view)")
        self.assertIn('<img', html)
        self.assertIn('/kb/attachments/5/view', html)

    def test_external_image_src_is_stripped(self):
        html = render_markdown("![tracker](https://evil.example/track.gif)")
        self.assertNotIn("evil.example", html)

    def test_javascript_protocol_image_src_is_stripped(self):
        html = render_markdown('<img src="javascript:alert(1)">')
        self.assertNotIn("javascript:", html)
```

- [ ] **Step 2: RED** — `<img>` currently stripped entirely (not in today's allowlist), so `test_internal_attachment_image_renders` fails.
- [ ] **Step 3: Implement** the allowlist change + `src`-prefix enforcement pass.
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Manual validation** (per `portal-testing-and-validation` — paste/upload JS, badges, layout): start the app, paste a screenshot into a new article's `problem_md`, confirm the badge shows "sin scanner" (no real engine configured) and the image does **not** render inline (expected — nothing is `clean` without a real scanner, exactly the confirmed policy). State this limitation in the manual test notes, not as a bug.
- [ ] **Step 6: Commit.**

---

## Task 12: Audit events

**Files:**
- Modify: `app/knowledge_base/attachment_routes.py` (already calls `log_audit` for delete in Task 8; add create + malware-detected events here)
- Test: `tests/knowledge_base/test_attachment_audit.py`

**Events** (reusing the existing global `AuditLog`/`log_audit()` — no new audit table, consistent with how the rest of Knowledge Base already works):

```text
module="knowledge_base", action="attachment_upload", object_type="attachment", object_id=<id>, object_name=<original_filename>
module="knowledge_base", action="attachment_delete", object_type="attachment", object_id=<id>, object_name=<original_filename>
module="knowledge_base", action="malware_detected",  object_type="attachment", object_id=<id>, object_name=<original_filename>
```

`scan_error`/`not_scanned` get **logged** (Python `logger.warning`, operational visibility) but are **not** audited as security events — they are not an attacker action, they are an operational/configuration state (no scanner reachable, or the scan itself failed), which is exactly the distinction `AGENTS.md`/`portal-security-change` draws between "what happened" (log) and "a security-relevant action by someone" (audit). `malware_detected` **is** audited, because a real infected upload is exactly the kind of event `portal-security-change` §24 says should be auditable.

Audit content, per §25 of that skill: never the file content, never the full filesystem path — `object_name` is the **original** (untrusted) filename, already length-capped to 200 chars by `log_audit()` itself (existing behavior, confirmed in `app/models/audit.py`), which is acceptable as a human-readable label, not a secret.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_attachment_audit.py
import io
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401
from app.models.audit import AuditLog

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestAttachmentAudit(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.login("kb_author")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()

    def test_upload_creates_audit_record(self):
        csrf = self.extract_csrf(self.client.get(f"/kb/{self.article.id}/editar").get_data(as_text=True))
        self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": csrf},
            content_type="multipart/form-data",
        )
        audit = AuditLog.query.filter_by(module="knowledge_base", action="attachment_upload").first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.object_name, "shot.png")

    def test_audit_never_contains_stored_path_or_file_content(self):
        csrf = self.extract_csrf(self.client.get(f"/kb/{self.article.id}/editar").get_data(as_text=True))
        self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": csrf},
            content_type="multipart/form-data",
        )
        audit = AuditLog.query.filter_by(module="knowledge_base", action="attachment_upload").first()
        self.assertNotIn("kb_attachments", audit.details or "")
        self.assertNotIn(str(PNG_BYTES), audit.details or "")
```

- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement** the `log_audit()` calls.
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Commit.**

---

## Task 13: Documentation

**Files:**
- Modify: `docs/systems/knowledge_base.md` (new section: attachments — model, validation chain, scanner abstraction, draft lifecycle, serving policy)
- Modify: `docs/PROJECT_MAP.md` (file list for the Knowledge Base section)
- Modify: `docs/technical-debt/current.md` (new deliberate-limitation entries — no real scanner integrated yet; attachments unusable end-to-end until one is; async scanning not implemented, scan runs synchronously at upload time)

No ADR — this is an ordinary feature addition inside the existing modular-monolith architecture, not a departure from any accepted decision.

- [ ] **Step 1: Write the documentation updates.**
- [ ] **Step 2: Commit.**

---

## Dependencies — required analysis before choosing (or not choosing) a library

**Recommendation: no new dependency.** Task 3's fixed signature table covers the entire allowlist (8 extensions) in about 60 lines of stdlib Python (`hashlib`, `zipfile`, `io`) — exactly the "a few lines" threshold past which AGENTS.md §11 would require justifying a new dependency, and this plan stays under it.

**`python-magic` (the standard choice for "real" MIME detection) was evaluated and rejected**, for packaging reasons specific to this project, not general preference:

| | `python-magic` | This plan's fixed-table approach |
|---|---|---|
| Detection breadth | Any of thousands of formats `libmagic` recognizes | Exactly the 8 allowed extensions — sufficient, since anything else is rejected by the extension whitelist before magic-byte checking even runs |
| Native dependency | Requires the `libmagic` C library installed on the host | None — pure Python |
| **Windows** | `libmagic` is not bundled with Python on Windows; requires `python-magic-bin` (an unofficial, unmaintained-pace wheel bundling a prebuilt DLL) or manually installing `libmagic` via something like MSYS2/Cygwin | Works identically to every other pure-Python module already in this project |
| **PyInstaller** | The runtime-loaded native `.dll`/`.so` must be explicitly added to the `.spec`'s `binaries`, and PyInstaller's static analysis cannot discover it automatically — this is exactly the class of packaging miss already flagged in this week's runtime audit (knowledge_base's own `markdown` extensions were missed by the `.spec` for the same underlying reason: dynamic/non-import-based loading) | No `.spec` changes needed at all |
| **Docker** | Needs `apt-get install libmagic1` (or equivalent) added to the `Dockerfile` | No `Dockerfile` change needed |
| **macOS** | Usually available via Homebrew's `file` package, but not guaranteed on a bare `python:3.11-slim`-style environment | No macOS-specific concern |

Given the project already ships a Windows PyInstaller EXE and a slim Docker image, `python-magic` would add real, recurring packaging risk for a benefit (broader format detection) this feature doesn't need, since the extension whitelist already narrows the field to 8 known types before any signature check runs.

**If a real malware scanner is integrated later** (ClamAV, Defender, Trellix — all explicitly out of this plan's scope per Task 4), each would likely need its own narrow dependency (e.g. a `clamd` socket client for ClamAV) — that is a separate, later decision, isolated behind the `Scanner` interface so it never touches `knowledge_base`'s own code.

---

## Implementation order

Tasks 1→4 are pure, dependency-free foundations (model, config, validation, scanner) and should land first, in order, since every later task imports from them. Tasks 5→9 are the request/response surface, in the order a real user flow would exercise them (draft → upload-to-article → serve → delete → article-delete-cascade). Task 10 (cleanup) depends on Task 5 existing (nothing to clean up otherwise) but is otherwise independent of 6-9 — it could run in parallel with them if using `subagent-driven-development`. Task 11 (UI) depends on 5-8 existing (the JS calls real endpoints). Tasks 12-13 are wrap-up and can trail.

## TDD strategy

Every task follows the same RED→GREEN→COMMIT discipline already used for this week's Vault hardening tasks: write the test first, watch it fail for the stated reason, implement the minimum, watch it pass, run the **whole** `tests/knowledge_base/` suite (not just the new file) before moving to the next task, and the full project suite before considering the plan done.

## Risks

- **The feature is end-to-end untestable-by-humans without a real scanner** (every upload stays `not_scanned` forever under `NullScanner`) — confirmed intentional by the approved policy, not a defect to work around; flagged again here so it's not mistaken for a bug during manual QA.
- **`send_file`/`Content-Disposition` header-injection via `original_filename`** — mitigated by relying on Werkzeug's own `send_file(download_name=...)` quoting rather than hand-building the header string; must be verified during implementation that this Werkzeug version actually does that quoting (it does, as of the Werkzeug version already pinned in `requirements.txt`, but worth a one-line confirmation test).
- **`<img>` allowlist change in `markdown_render.py` is shared global infrastructure** for the whole module — a mistake in the `src`-prefix enforcement pass could reopen external-image exfiltration; Task 11's tests are the regression guard, and this is exactly the kind of change that would benefit from `/codex review` before merging, given it touches the one security chokepoint (`render_markdown()`) the whole Knowledge Base module relies on.
- **Disk space**: no quota enforcement beyond per-file and per-article size limits — an admin could still accumulate many large `clean` attachments over time with no global disk-usage cap. Explicitly out of MVP scope (not in the brief), noting it as a known limitation for Task 13's documentation.

## Decisions still requiring your approval

1. **Exact numeric defaults** for `KB_ATTACHMENT_MAX_SIZE_BYTES` (proposed 10 MB) and `KB_ATTACHMENT_MAX_TOTAL_BYTES` (proposed 50 MB/article) — reasonable guesses, not something I can derive from requirements.
2. **Whether a user can remove a pasted/uploaded draft attachment *before* saving the article** (e.g. pasted the wrong screenshot) — Task 5 designs the ownership-check helper needed for this but does not add a dedicated "discard single draft attachment" route, since it wasn't in the brief; flagging as a likely near-term follow-up, not building it speculatively now.
3. **Whether `/download` should also be offered for images** (today only `/view` is designed for images, no `/download` path for them) — minor, easy to add either way, confirm if wanted.
