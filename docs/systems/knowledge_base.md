# Knowledge Base System

## Purpose

Lets the team document ticket solutions as Markdown articles and find them
later by text search, client, platform, or tag.

It describes the **current implementation**, not a future design.

Primary files:

```text
app/knowledge_base/__init__.py
app/knowledge_base/routes.py
app/knowledge_base/forms.py
app/knowledge_base/logic.py
app/knowledge_base/markdown_render.py
app/knowledge_base/attachment_routes.py
app/knowledge_base/attachment_validation.py
app/knowledge_base/attachment_storage.py
app/knowledge_base/attachment_cleanup.py
app/knowledge_base/scanning.py
app/models/knowledge.py
```

Primary templates:

```text
app/templates/knowledge_base/list.html
app/templates/knowledge_base/form.html
app/templates/knowledge_base/detail.html
```

Relevant migrations:

```text
migrations/versions/38fd8516d488_add_knowledge_base_tables.py
migrations/versions/36c6bc7ea6fa_add_knowledge_attachment_table.py
```

---

# 1. Blueprint

Tool identifier: `knowledge_base`. URL prefix: `/kb`. Protected with
`proteger_blueprint(bp, "knowledge_base")`, called at module level in
`app/knowledge_base/routes.py` (same convention as CSIRT/VirusTotal/Umbrella —
the call must happen before the blueprint is registered in `app/__init__.py`,
not after, or Flask raises `AssertionError` at startup). Unlike Vault, this
module uses the standard server-side tool guard from day one.

---

# 2. Models

`KnowledgeArticle`: `title, problem_md, solution_md, client, platform,
author_id, created_at, updated_at`, plus a many-to-many `tags` relationship
to `KnowledgeTag` through the `knowledge_article_tag` association table.

Both models are also re-exported from `app/models/__init__.py` (the same
aggregator used by CSIRT/VirusTotal/Umbrella/Notification/Audit) — this is
required for Alembic autogenerate to detect them, not just a style choice.

`client` and `platform` are plain indexed strings, not master tables —
the filter dropdowns and form autocomplete are populated from
`SELECT DISTINCT` over existing rows. This is a deliberate MVP decision
(see `docs/technical-debt/current.md`), not an oversight.

---

# 3. Markdown Rendering and Sanitization

Both `problem_md` and `solution_md` are stored as raw Markdown, never as
HTML. The only path from Markdown to HTML is
`app.knowledge_base.markdown_render.render_markdown()`, exposed to templates
as the `|markdown` Jinja filter (registered in
`app/knowledge_base/__init__.py`). It converts with `python-markdown`
(`tables`, `fenced_code`, `nl2br` extensions) and then sanitizes the
resulting HTML with `bleach` against a fixed tag/attribute/protocol
allowlist before returning `Markup`.

No template must ever call `markdown.markdown()` directly or apply `|safe`
to `problem_md`/`solution_md` without going through this filter — that
would reintroduce stored XSS.

Note on `bleach.clean(strip=True)`: it removes the disallowed *tag* but
keeps its inner text as inert, non-executable content. A `<script>alert(1)
</script>` payload becomes the literal visible text `alert(1)` — harmless
but technically still present as text. The security boundary is "no tag
survives", not "no substring of the payload survives anywhere in the
rendered output".

---

# 4. Authorization Model

Tool access: `UserTool("knowledge_base")` + `User.has_tool()`, same as
every other tool. Admins get access automatically.

Object-level (permission model C, a deliberate product decision, not
inferred):

```text
read    → any user with the tool
create  → any user with the tool
edit    → the article's author, or an admin
delete  → admin only (not even the author)
```

Enforced in `_can_edit()`/`_can_delete()` in `routes.py`, checked
server-side on every `editar`/`eliminar` request — not just hidden in the
UI.

---

# 5. Search, Filters, Pagination

Text search is a `LIKE`-based match (escaped via
`app.knowledge_base.logic.escape_like`) over `title`, `problem_md`,
`solution_md`, combined with exact-match filters on `client`, `platform`,
and `tag`. Results are paginated server-side (`per_page=20`) using
Flask-SQLAlchemy's built-in `.paginate()`.

There is no full-text search engine (SQLite FTS5) in this version — see
`docs/technical-debt/current.md`.

---

# 6. Audit Logging

Create, edit, and delete all call the shared `log_audit("knowledge_base",
...)` — no dedicated audit table was created for this module.

---

# 7. Tests

Automated coverage lives under `tests/knowledge_base/`, using Python's
stdlib `unittest` plus Flask's test client — this repository had no test
framework at all before this module, so no existing suite was replaced or
reused. The shared harness is `tests/base.py` (`PortalTestCase`).

Covered: model persistence, Markdown sanitization (including XSS
payloads), tag normalization/dedup, blueprint tool-level authorization,
search/filter/pagination, object-level authorization for edit (author or
admin) and delete (admin only), and audit record creation.

Not covered by automated tests: visual layout, flash message styling,
`<datalist>` autocomplete UX — verified manually instead.

---

# 8. Attachments

Articles support file attachments: pasted images (inline-rendered once
`clean`) and uploaded documents (PDF/Word/Excel/CSV/TXT, always served as
a download). The design is quarantine-by-default — nothing is servable
until a malware scanner marks it `clean` — and isolated per uploader while
an article is still being drafted.

## 8.1 Model

`KnowledgeAttachment` (`app/models/knowledge.py`): `article_id` (nullable,
FK, cascade delete), `draft_token` (nullable), `original_filename`,
`stored_filename` (the only thing that ever touches the filesystem — a
generated UUID, never the client-supplied name), `mime_type`, `extension`,
`size_bytes`, `sha256`, `is_image`, `uploaded_by`, `created_at`,
`scan_status`, `scan_checked_at`. A `CHECK` constraint enforces exactly one
of `article_id`/`draft_token` set, never both, never neither — the
promotion transition (draft → real article) sets both fields on the same
object inside the article's own transaction, so a committed row with both
or neither is never actually reachable; the constraint is a backstop.

`KnowledgeArticle.attachments` uses `cascade="all, delete-orphan"` —
SQLAlchemy only removes the **rows** when an article is deleted; the
physical files are unlinked explicitly in `eliminar()` before the delete
commits (see 8.6).

## 8.2 Validation (`attachment_validation.py`)

Pure function, no Flask/disk/DB access: `validate_upload(data: bytes,
declared_extension: str) -> ValidatedFile`. The caller (never this module)
is responsible for the extension allowlist and size-limit checks, since
those need config this module deliberately doesn't import (kept pure and
independently testable).

Chain: magic-byte/signature check against a fixed table (`png`, `jpg`,
`webp`, `pdf`, `xls`) — no `python-magic`/`libmagic` dependency (see the
plan's own "Dependencies" analysis: Windows/PyInstaller/Docker packaging
risk for a benefit the 8-extension allowlist doesn't need). `.docx`/`.xlsx`
are ZIPs sharing the same signature as any arbitrary ZIP, so they get an
additional **in-memory** structural check (`zipfile`/`io.BytesIO`, nothing
ever extracted to disk): the expected core document part must be present,
`[Content_Types].xml` must exist, be well-formed, under a declared-size
cap (zip-bomb guard — a genuine manifest is a few KB; anything claiming
more is rejected before being decompressed), and must not declare a
macro-enabled content type. Legacy `.xls` (OLE2, not a ZIP) gets its own
check: the raw bytes are searched for the UTF-16LE `"VBA"` marker an OLE2
macro project's directory entry name would contain — not a full OLE2
parse, but enough to catch a macro-enabled `.xls` without a new
dependency.

## 8.3 Scanner Abstraction (`scanning.py`)

`Scanner` ABC + `get_scanner()` factory reading `KB_SCANNER` config
(`"null"` today; unrecognized values fall back to `NullScanner` rather
than raising). `NullScanner` **never** returns `clean` — it returns
`not_scanned`. **No real scanner is integrated in this version** — see
`docs/technical-debt/current.md`. Until one is, every attachment is
permanently unservable (`/view`/`/download` both 404, and `<img>` never
renders inline) — this is the confirmed policy, not a defect.

## 8.4 Draft Lifecycle

`crear()`'s `GET /kb/nuevo` generates a `draft_token` (secure UUID)
server-side and renders it into a hidden form field. A validation-failure
re-render preserves the **client-submitted** token exactly (never
regenerates it), so attachments uploaded before the failed submit are
never orphaned. `POST /kb/attachments/draft-upload` creates rows with
`article_id=None, draft_token=<token>, uploaded_by=current_user.id`. On
successful article creation, a single bulk `UPDATE` (same transaction as
the article `INSERT`) sets `article_id` and clears `draft_token` for every
row matching `(draft_token, uploaded_by=current_user.id)`.

Draft ownership is `draft_token` **and** `uploaded_by` together — knowing
someone else's token (e.g. two users on the same open `/kb/nuevo` tab
pattern) never grants access to their rows; each uploader's rows under the
same token string stay isolated.

## 8.5 Upload, Serving, Delete

`POST /<article_id>/attachments/upload` and the draft-upload route share
one implementation, `_handle_attachment_upload()`, differing only in which
FK column they set and their permission check — this is what guarantees
paste and manual upload (and draft vs. direct) never diverge in
validation strictness. Permission: author-or-admin (`_can_edit()`), same
as editing the article.

`GET /attachments/<id>/view` (images only) and `GET /attachments/<id>/
download` (any type, always `Content-Disposition: attachment`) both
re-check `scan_status == "clean"` **live, on every request** — the gate is
never baked into previously-rendered Markdown or cached. A draft
attachment (no article yet) is readable only by its own uploader. A
missing physical file (e.g. an orphaned row) degrades to a plain `404`,
never an unhandled exception.

`POST /attachments/<id>/delete` branches on ownership: a promoted
attachment requires `_can_edit()` on its article (author-or-admin); a
still-draft attachment requires `uploaded_by == current_user.id` — the
same route serves both "delete a promoted attachment" and "discard a
draft before saving".

Every delete path (this route, and `eliminar()`'s per-attachment cleanup)
commits the DB delete **before** unlinking the physical file, never the
other way around — a failed commit must never leave a `clean` row
pointing at a file that no longer exists.

## 8.6 Cleanup (`attachment_cleanup.py`)

`purge_expired_drafts(app) -> int` removes drafts (no `article_id`, past
`KB_ATTACHMENT_DRAFT_TTL_HOURS`) via a single atomic conditional
`DELETE ... WHERE id=:id AND article_id IS NULL` per row — the database
engine's own statement-level atomicity, not a `refresh()`-then-check in
application code, is what makes this safe against a draft being promoted
or purged again concurrently; it simply matches zero rows and does
nothing if the row is already gone or already promoted. Called from two
places with the identical guarantee: a 24h APScheduler job
(`app/__init__.py`), and an opportunistic, **throttled** (at most once
every 5 minutes, in-process) call at the top of the draft-upload route —
the throttle exists because the unconditional per-request version was a
full table scan on every single upload.

This does **not** fix the existing known APScheduler-under-Werkzeug-
reloader duplicate-job issue (separate, pre-existing debt) — it means the
cleanup logic itself tolerates running twice concurrently without error.

## 8.7 Markdown `<img>` Integration

`markdown_render.py`'s sanitizer allowlist includes `<img src alt>`, but
`src` is additionally validated **by value** (via `bleach`'s
attribute-callable API, not just tag/attribute presence) against
`^/kb/attachments/\d+/view\Z` — an exact match, not a prefix, and
anchored with `\Z` (not `$`, which would also match before a trailing
newline). This blocks external image tracking/exfiltration
(`<img src="https://evil/track.gif">`) that a bare tag allowlist would
otherwise let through.

## 8.8 Configuration

```text
KB_ATTACHMENTS_DIR             instance/kb_attachments (single directory
                                — "quarantine" is the scan_status DB gate,
                                not a filesystem location)
KB_ATTACHMENT_MAX_SIZE_BYTES    10 MB/file (default)
KB_ATTACHMENT_MAX_TOTAL_BYTES   50 MB/article or /draft (default)
KB_ATTACHMENT_ALLOWED_EXTENSIONS   png, jpg, jpeg, webp, pdf, docx, xlsx, xls, csv, txt
KB_ATTACHMENT_IMAGE_EXTENSIONS     png, jpg, jpeg, webp
KB_ATTACHMENT_DRAFT_TTL_HOURS   24 (default)
KB_SCANNER                      "null" (default; no real engine wired up)
```

All optional with safe defaults — none are global invariants, so none
raise at startup if unset (unlike `SECRET_KEY`/`VAULT_KEY`).

## 8.9 Known Limitations

See `docs/technical-debt/current.md` items #39-#41 for the specific
filesystem/DB-consistency and quota-TOCTOU edge cases found and
deliberately deferred (narrow windows, bounded consequences, not security
bypasses) during this feature's own review. The "no real scanner" and
"scanning is synchronous, not async" limitations are the confirmed MVP
policy, not oversights — see 8.3 above.
