# Knowledge Base Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new Portal Operations Tools module, "Base de Conocimiento" (`knowledge_base`), letting the team document and search ticket solutions as Markdown articles with client/platform/tag filters, author-or-admin edit, and admin-only delete.

**Architecture:** New Flask Blueprint `app/knowledge_base/` following the existing modular-monolith pattern (same shape as `app/umbrella/`), two new tables reached through SQLAlchemy + a new Alembic migration, server-rendered Jinja templates extending `base.html`, and a single centralized Markdown-to-HTML rendering function that always sanitizes with an allowlist before any template outputs it.

**Tech Stack:** Flask / Flask-SQLAlchemy / Flask-WTF (existing), Alembic (existing), `markdown` + `bleach` (new, justified in Task 2), Python stdlib `unittest` + Flask's built-in test client for tests (no new test dependency — confirmed no test framework exists anywhere in this repo today).

**Spec:** This conversation's confirmed design (permission model C, `problem_md` + `solution_md` both Markdown, `client`/`platform` as plain strings with autocomplete only, LIKE+filters+pagination search, single centralized sanitized renderer, explicit MVP exclusions).

## Global Constraints

- Permission model is **option C**: any user with the `knowledge_base` tool can read all articles and create articles; the author or an admin can edit; **only an admin can delete** — enforced server-side on every route, not just hidden in the UI.
- Both `problem_md` and `solution_md` are Markdown, stored raw (never pre-rendered HTML), and both go through the **same** centralized render function.
- No template may apply `|safe` directly to `problem_md`/`solution_md`/raw Markdown. The only path to HTML is the `markdown` Jinja filter defined in Task 4/7, which always sanitizes before returning `Markup`.
- `client` and `platform` stay plain indexed string columns in the MVP. No master tables. UI offers autocomplete from existing distinct values only.
- Search is `LIKE` (escaped) over title/problem/solution + exact-match filters on client/platform/tag, with server-side pagination. No FTS5.
- Explicitly out of scope for this plan: version history, attachments, comments, favorites, semantic search, FTS5, client/platform master tables, related articles, usage metrics. Do not build scaffolding for any of these.
- Reuse existing infrastructure: `proteger_blueprint()` + `UserTool` + `User.has_tool()` for module access, global `AuditLog`/`log_audit()` for auditing (no new audit table), existing Bootstrap/Jinja layout (`base.html` blocks: `title`, `breadcrumb`, `content`), existing `FlaskForm` conventions (`form.hidden_tag()`).
- Every state-changing route is POST. CSRF stays enabled everywhere, including in tests (extract the real token from the rendered form instead of disabling CSRF).

## Review Focus

- **Stored XSS via Markdown.** A user pastes `<script>...</script>` or `![x](javascript:alert(1))` into `problem_md`/`solution_md`. Expected: the rendered detail page contains neither the script tag nor a `javascript:` URL — Task 4's sanitizer test pins this before any route renders user content.
- **Cross-author edit bypass.** User B (non-admin, has the tool) opens `/kb/<id>/editar` for an article authored by User A by guessing/incrementing the ID. Expected: HTTP 403, not just a hidden "Editar" button. Task 10's negative test pins this.
- **Non-admin delete.** The article's own author (non-admin) tries `POST /kb/<id>/eliminar`. Expected: HTTP 403 — permission model C makes deletion admin-only even for the author. Task 10's negative test pins this.
- **Tool-less direct URL access.** An authenticated user without the `knowledge_base` `UserTool` row requests `/kb/` directly. Expected: redirect to the dashboard with a warning flash, not a 500 or an empty-but-visible page. Task 7/8's test pins this.
- **Search wildcard injection.** A user searches for a literal `%` or `_` (e.g. a ticket ID containing `_`). Expected: treated as a literal character, not a SQL wildcard that matches everything/unexpectedly. Task 8's test pins this.

---

### Task 1: Test harness foundation

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/base.py`

**Interfaces:**
- Consumes: `app.create_app(config_class=...)`, `app.extensions.db`, `app.models.user.User`, `app.models.user.UserTool`.
- Produces: `tests.base.PortalTestCase` with `self.client` (Flask test client), `self.make_user(username, is_admin=False, tools=None) -> User`, `self.login(username, password="Synthetic-Pass-123!") -> werkzeug.Response`, `self.extract_csrf(html: str) -> str`. Every later test file imports `from tests.base import PortalTestCase`.

No existing test infrastructure exists in this repo (verified: no `tests/` directory, no `pytest`/`unittest` in `requirements.txt`, no `conftest.py`). This task creates the minimum harness every other task's tests need. `config.py`'s `Config` class raises `RuntimeError` at import time if `SECRET_KEY`/`SECRET_KEY_DB`/`CREDENTIAL_MANAGER_KEY`/`VAULT_KEY` are missing from the environment, so those must be set **before** `app` is imported.

- [ ] **Step 1: Write the failing test**

```python
# tests/__init__.py
```
(empty file, makes `tests` a package)

```python
# tests/test_harness_smoke.py
import unittest


class TestHarnessSmoke(unittest.TestCase):
    def test_portal_test_case_importable(self):
        from tests.base import PortalTestCase  # noqa: F401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_harness_smoke -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tests.base'`

- [ ] **Step 3: Write the implementation**

```python
# tests/base.py
import os
import re
import unittest

# Must be set before `app`/`config` is imported — Config raises RuntimeError
# at import time if any of these are missing. Values are synthetic and only
# ever used inside this disposable, in-memory test database.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("SECRET_KEY_DB", "Zx3n9B9z1dY2z1y3cT9kR0pQfX6vM3bJ9eH5sA7dC0=")
os.environ.setdefault("CREDENTIAL_MANAGER_KEY", "test-only-credential-manager-key")
os.environ.setdefault("VAULT_KEY", "Zx3n9B9z1dY2z1y3cT9kR0pQfX6vM3bJ9eH5sA7dC0=")

from app import create_app
from app.extensions import db
from app.models.user import User, UserTool

SYNTHETIC_PASSWORD = "Synthetic-Pass-123!"


class TestConfig:
    SECRET_KEY = os.environ["SECRET_KEY"]
    SECRET_KEY_DB = os.environ["SECRET_KEY_DB"].encode()
    CREDENTIAL_MANAGER_KEY = os.environ["CREDENTIAL_MANAGER_KEY"]
    VAULT_KEY = os.environ["VAULT_KEY"]
    VAULT_KDBX_PATH = ""
    VAULT_KDBX_PASSWORD = ""
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCHEDULER_API_ENABLED = False
    TESTING = True
    WTF_CSRF_ENABLED = True


class PortalTestCase(unittest.TestCase):
    """Base test case: one real Flask app per test class, one clean
    in-memory schema per test method. Uses db.create_all() because this is
    a disposable test database, not schema evolution (ADR-002 governs real
    deployments, not throwaway test fixtures)."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app(config_class=TestConfig)
        cls.app_context = cls.app.app_context()
        cls.app_context.push()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()

    def setUp(self):
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def make_user(self, username, is_admin=False, tools=None):
        user = User(username=username, is_admin=is_admin, must_change_password=False)
        user.set_password(SYNTHETIC_PASSWORD)
        db.session.add(user)
        db.session.flush()
        for tool_name in (tools or []):
            db.session.add(UserTool(user_id=user.id, tool_name=tool_name))
        db.session.commit()
        return user

    def extract_csrf(self, html: str) -> str:
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        assert match, "csrf_token not found in rendered page"
        return match.group(1)

    def login(self, username, password=SYNTHETIC_PASSWORD):
        page = self.client.get("/auth/login")
        token = self.extract_csrf(page.get_data(as_text=True))
        return self.client.post(
            "/auth/login",
            data={"username": username, "password": password, "csrf_token": token},
            follow_redirects=True,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_harness_smoke -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/__init__.py tests/base.py tests/test_harness_smoke.py
git commit -m "test: add portal test harness (unittest + Flask test client)"
```

---

### Task 2: Add Markdown + sanitization dependencies

**Files:**
- Modify: `requirements.txt`

**Interfaces:**
- Produces: `markdown` and `bleach` importable in the environment. Task 4 consumes both.

Justification (per `AGENTS.md` §11): Python's stdlib has no Markdown parser and no HTML sanitizer. `MarkupSafe` (already a dependency, via Jinja2) only does autoescaping of plain text — it cannot parse Markdown or allowlist-filter already-generated HTML. Reinventing either by hand is exactly the kind of ad-hoc security code this project should avoid.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dependencies.py
import unittest


class TestNewDependencies(unittest.TestCase):
    def test_markdown_importable(self):
        import markdown  # noqa: F401

    def test_bleach_importable(self):
        import bleach  # noqa: F401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_dependencies -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'markdown'`

- [ ] **Step 3: Add dependencies and install**

Append to `requirements.txt`:

```text
markdown==3.7
bleach==6.2.0
```

Run: `pip install markdown==3.7 bleach==6.2.0`

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_dependencies -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add requirements.txt tests/test_dependencies.py
git commit -m "build: add markdown and bleach for knowledge base rendering"
```

---

### Task 3: Database model and migration

**Files:**
- Create: `app/models/knowledge.py`
- Create: `migrations/versions/d4f29b6e71a3_add_knowledge_base_tables.py`
- Test: `tests/knowledge_base/__init__.py`, `tests/knowledge_base/test_models.py`

**Interfaces:**
- Consumes: `app.extensions.db`, `app.models.user.User`.
- Produces: `app.models.knowledge.KnowledgeArticle` (fields: `id, title, problem_md, solution_md, client, platform, author_id, created_at, updated_at, tags`), `app.models.knowledge.KnowledgeTag` (fields: `id, name`), `app.models.knowledge.knowledge_article_tag` (association table). All later tasks import these from `app.models.knowledge`.

Current migration head (verified with `git log`/inspection of `migrations/versions/`): `1b639e84d474` (`add_vault_sync_config_table`). No other migration points past it, so the new migration chains from there.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/__init__.py
```
(empty file)

```python
# tests/knowledge_base/test_models.py
from tests.base import PortalTestCase
from app.extensions import db


class TestKnowledgeModels(PortalTestCase):
    def test_create_article_with_tags(self):
        from app.models.knowledge import KnowledgeArticle, KnowledgeTag

        author = self.make_user("autor1")
        tag = KnowledgeTag(name="dns")
        article = KnowledgeArticle(
            title="Resolver DNS intermitente",
            problem_md="El **DNS** falla a veces.",
            solution_md="Reiniciar el servicio `named`.",
            client="Acme Corp",
            platform="BIND9",
            author=author,
        )
        article.tags.append(tag)
        db.session.add(article)
        db.session.commit()

        fetched = KnowledgeArticle.query.first()
        self.assertEqual(fetched.title, "Resolver DNS intermitente")
        self.assertEqual(fetched.author.username, "autor1")
        self.assertEqual([t.name for t in fetched.tags], ["dns"])
        self.assertIsNotNone(fetched.created_at)
        self.assertIsNotNone(fetched.updated_at)

    def test_article_requires_title_problem_solution(self):
        from app.models.knowledge import KnowledgeArticle
        from sqlalchemy.exc import IntegrityError

        author = self.make_user("autor2")
        article = KnowledgeArticle(
            title=None,  # violates nullable=False
            problem_md="x",
            solution_md="y",
            author=author,
        )
        db.session.add(article)
        with self.assertRaises(IntegrityError):
            db.session.commit()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_models -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.models.knowledge'`

- [ ] **Step 3: Write the model**

```python
# app/models/knowledge.py
from datetime import datetime
from app.extensions import db


knowledge_article_tag = db.Table(
    "knowledge_article_tag",
    db.Column(
        "article_id",
        db.Integer,
        db.ForeignKey("knowledge_article.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "tag_id",
        db.Integer,
        db.ForeignKey("knowledge_tag.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class KnowledgeArticle(db.Model):
    __tablename__ = "knowledge_article"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    problem_md = db.Column(db.Text, nullable=False)
    solution_md = db.Column(db.Text, nullable=False)
    client = db.Column(db.String(120), nullable=True, index=True)
    platform = db.Column(db.String(120), nullable=True, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    author = db.relationship(
        "User", backref=db.backref("knowledge_articles", lazy="dynamic")
    )
    tags = db.relationship(
        "KnowledgeTag", secondary=knowledge_article_tag, back_populates="articles"
    )

    def __repr__(self):
        return f"<KnowledgeArticle {self.id}: {self.title}>"


class KnowledgeTag(db.Model):
    __tablename__ = "knowledge_tag"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)

    articles = db.relationship(
        "KnowledgeArticle", secondary=knowledge_article_tag, back_populates="tags"
    )

    def __repr__(self):
        return f"<KnowledgeTag {self.name}>"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_models -v`
Expected: PASS

- [ ] **Step 5: Create and review the migration**

Run: `flask db migrate -m "add knowledge base tables"`

Inspect the generated file under `migrations/versions/` — it must contain **only** the three new tables below and nothing else (no unrelated autogenerate noise). Replace its body to match exactly (keep whatever revision id Alembic generated; this plan uses `d4f29b6e71a3` as a placeholder for illustration):

```python
# migrations/versions/d4f29b6e71a3_add_knowledge_base_tables.py
"""add knowledge base tables

Revision ID: d4f29b6e71a3
Revises: 1b639e84d474
Create Date: 2026-10-07 19:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'd4f29b6e71a3'
down_revision = '1b639e84d474'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'knowledge_article',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('problem_md', sa.Text(), nullable=False),
        sa.Column('solution_md', sa.Text(), nullable=False),
        sa.Column('client', sa.String(length=120), nullable=True),
        sa.Column('platform', sa.String(length=120), nullable=True),
        sa.Column('author_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['author_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('knowledge_article', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_knowledge_article_title'), ['title'], unique=False)
        batch_op.create_index(batch_op.f('ix_knowledge_article_client'), ['client'], unique=False)
        batch_op.create_index(batch_op.f('ix_knowledge_article_platform'), ['platform'], unique=False)

    op.create_table(
        'knowledge_tag',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    with op.batch_alter_table('knowledge_tag', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_knowledge_tag_name'), ['name'], unique=False)

    op.create_table(
        'knowledge_article_tag',
        sa.Column('article_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['article_id'], ['knowledge_article.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tag_id'], ['knowledge_tag.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('article_id', 'tag_id'),
    )


def downgrade():
    op.drop_table('knowledge_article_tag')
    with op.batch_alter_table('knowledge_tag', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_knowledge_tag_name'))
    op.drop_table('knowledge_tag')
    with op.batch_alter_table('knowledge_article', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_knowledge_article_platform'))
        batch_op.drop_index(batch_op.f('ix_knowledge_article_client'))
        batch_op.drop_index(batch_op.f('ix_knowledge_article_title'))
    op.drop_table('knowledge_article')
```

Existing-data impact: three brand-new tables, no column added to any existing table — no migration risk to current rows. `downgrade()` is fully lossless to run (it only removes tables this migration created).

- [ ] **Step 6: Apply the migration to a disposable copy of the dev database and verify**

```bash
cp instance/app.db instance/app.db.plan-test-backup   # never test against the only copy
flask db upgrade
python -c "from app import create_app; from app.extensions import db; app=create_app(); app.app_context().push(); from app.models.knowledge import KnowledgeArticle; print(KnowledgeArticle.query.count())"
flask db downgrade
mv instance/app.db.plan-test-backup instance/app.db   # restore
```

Expected: upgrade succeeds, query prints `0`, downgrade succeeds, app still starts afterward.

- [ ] **Step 7: Commit**

```bash
git add app/models/knowledge.py migrations/versions/d4f29b6e71a3_add_knowledge_base_tables.py tests/knowledge_base/__init__.py tests/knowledge_base/test_models.py
git commit -m "feat: add KnowledgeArticle/KnowledgeTag models and migration"
```

---

### Task 4: Centralized Markdown rendering and sanitization

**Files:**
- Create: `app/knowledge_base/__init__.py` (package marker only — the Blueprint itself is created in Task 7; this task only needs the package to exist so `app.knowledge_base.markdown_render` is importable)
- Create: `app/knowledge_base/markdown_render.py`
- Test: `tests/knowledge_base/test_markdown_render.py`

**Interfaces:**
- Consumes: `markdown.markdown`, `bleach.clean`, `markupsafe.Markup` (all from Task 2's dependencies).
- Produces: `app.knowledge_base.markdown_render.render_markdown(raw_text: str) -> markupsafe.Markup`. Task 7 wires this into a Jinja filter; Task 9/10's templates are the only place it is ever called from.

This is the module the first Review Focus item (stored XSS) depends on — it must strip dangerous markup regardless of whether it arrived as literal HTML inside the Markdown or as a generated tag/attribute from a Markdown construct (e.g. an image with a `javascript:` URL).

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_markdown_render.py
import unittest


class TestRenderMarkdown(unittest.TestCase):
    def test_basic_formatting(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown("**bold** and `code`")
        self.assertIn("<strong>bold</strong>", html)
        self.assertIn("<code>code</code>", html)

    def test_table_and_fenced_code(self):
        from app.knowledge_base.markdown_render import render_markdown

        raw = "| a | b |\n|---|---|\n| 1 | 2 |\n\n```bash\nls -la\n```\n"
        html = render_markdown(raw)
        self.assertIn("<table>", html)
        self.assertIn("<pre>", html)

    def test_strips_script_tag(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown("before <script>alert(1)</script> after")
        self.assertNotIn("<script", html)
        self.assertNotIn("alert(1)", html)

    def test_strips_javascript_protocol_link(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown("[click me](javascript:alert(1))")
        self.assertNotIn("javascript:", html)

    def test_strips_event_handler_attribute(self):
        from app.knowledge_base.markdown_render import render_markdown

        html = render_markdown('<img src="x" onerror="alert(1)">')
        self.assertNotIn("onerror", html)

    def test_empty_input_returns_empty_string(self):
        from app.knowledge_base.markdown_render import render_markdown

        self.assertEqual(render_markdown(""), "")
        self.assertEqual(render_markdown(None), "")

    def test_result_is_markup_safe(self):
        from markupsafe import Markup
        from app.knowledge_base.markdown_render import render_markdown

        self.assertIsInstance(render_markdown("hi"), Markup)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_markdown_render -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.knowledge_base'`

- [ ] **Step 3: Write the implementation**

```python
# app/knowledge_base/__init__.py
```
(empty for now — populated with the Blueprint in Task 7)

```python
# app/knowledge_base/markdown_render.py
import bleach
import markdown as _markdown
from markupsafe import Markup

# This is the ONLY function allowed to turn user-authored Markdown into
# HTML in this module. Never call markdown.markdown()/`|safe` directly from
# a template or route — always go through render_markdown(), which both
# converts and sanitizes before returning Markup.

_ALLOWED_TAGS = [
    "p", "br", "hr",
    "strong", "em", "b", "i", "u", "s", "del",
    "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "code", "pre", "span",
]

_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
    "code": ["class"],
    "th": ["align"],
    "td": ["align"],
}

_ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def render_markdown(raw_text):
    if not raw_text:
        return Markup("")

    html = _markdown.markdown(
        raw_text,
        extensions=["tables", "fenced_code", "nl2br"],
        output_format="html5",
    )

    clean_html = bleach.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
    )

    return Markup(clean_html)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_markdown_render -v`
Expected: PASS (all 7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/knowledge_base/__init__.py app/knowledge_base/markdown_render.py tests/knowledge_base/test_markdown_render.py
git commit -m "feat: add centralized sanitized Markdown renderer for knowledge base"
```

---

### Task 5: Tag sync and search helpers

**Files:**
- Create: `app/knowledge_base/logic.py`
- Test: `tests/knowledge_base/test_logic.py`

**Interfaces:**
- Consumes: `app.extensions.db`, `app.models.knowledge.KnowledgeArticle`, `app.models.knowledge.KnowledgeTag`.
- Produces: `app.knowledge_base.logic.sync_tags(article, tags_raw: str) -> None`, `app.knowledge_base.logic.escape_like(term: str) -> str`, `app.knowledge_base.logic.distinct_values(column) -> list`. Task 8/9/10 routes import all three.

`sync_tags` uses the same "replace the whole collection" approach Vault already uses for `_save_custom_fields()` (delete/recreate rather than diffing) — simplest correct option for a small per-article tag set.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_logic.py
from tests.base import PortalTestCase
from app.extensions import db


class TestSyncTags(PortalTestCase):
    def test_creates_new_tags_normalized(self):
        from app.knowledge_base.logic import sync_tags
        from app.models.knowledge import KnowledgeArticle, KnowledgeTag

        author = self.make_user("autor")
        article = KnowledgeArticle(
            title="t", problem_md="p", solution_md="s", author=author
        )
        db.session.add(article)
        db.session.flush()

        sync_tags(article, "DNS, Windows ,  dns")  # dup + case + whitespace
        db.session.commit()

        names = sorted(t.name for t in article.tags)
        self.assertEqual(names, ["dns", "windows"])
        self.assertEqual(KnowledgeTag.query.count(), 2)

    def test_reuses_existing_tag_instead_of_duplicating(self):
        from app.knowledge_base.logic import sync_tags
        from app.models.knowledge import KnowledgeArticle, KnowledgeTag

        db.session.add(KnowledgeTag(name="dns"))
        db.session.commit()

        author = self.make_user("autor2")
        article = KnowledgeArticle(
            title="t2", problem_md="p", solution_md="s", author=author
        )
        db.session.add(article)
        db.session.flush()

        sync_tags(article, "dns")
        db.session.commit()

        self.assertEqual(KnowledgeTag.query.count(), 1)

    def test_removes_tags_no_longer_present(self):
        from app.knowledge_base.logic import sync_tags
        from app.models.knowledge import KnowledgeArticle

        author = self.make_user("autor3")
        article = KnowledgeArticle(
            title="t3", problem_md="p", solution_md="s", author=author
        )
        db.session.add(article)
        db.session.flush()
        sync_tags(article, "dns, windows")
        db.session.commit()

        sync_tags(article, "windows")
        db.session.commit()

        self.assertEqual([t.name for t in article.tags], ["windows"])


class TestEscapeLike(PortalTestCase):
    def test_escapes_percent_and_underscore(self):
        from app.knowledge_base.logic import escape_like

        self.assertEqual(escape_like("50%_done"), r"50\%\_done")

    def test_escapes_backslash_first(self):
        from app.knowledge_base.logic import escape_like

        self.assertEqual(escape_like("a\\b"), "a\\\\b")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_logic -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.knowledge_base.logic'`

- [ ] **Step 3: Write the implementation**

```python
# app/knowledge_base/logic.py
from app.extensions import db
from app.models.knowledge import KnowledgeTag


def sync_tags(article, tags_raw):
    """Replace article.tags with the normalized set parsed from tags_raw.
    Same 'replace the whole collection' approach as Vault's
    _save_custom_fields() — simplest correct option for a small per-article
    tag set."""
    names = sorted({t.strip().lower() for t in (tags_raw or "").split(",") if t.strip()})
    tags = []
    for name in names:
        tag = KnowledgeTag.query.filter_by(name=name).first()
        if tag is None:
            tag = KnowledgeTag(name=name)
            db.session.add(tag)
            db.session.flush()
        tags.append(tag)
    article.tags = tags


def escape_like(term):
    """Escape a user search term for safe use inside ilike(..., escape='\\\\')."""
    return term.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


def distinct_values(column):
    """Return sorted non-empty distinct values of a mapped column, for
    populating filter/autocomplete options without a master table."""
    rows = (
        db.session.query(column)
        .filter(column.isnot(None))
        .filter(column != "")
        .distinct()
        .order_by(column)
        .all()
    )
    return [row[0] for row in rows]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_logic -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add app/knowledge_base/logic.py tests/knowledge_base/test_logic.py
git commit -m "feat: add knowledge base tag sync and search helpers"
```

---

### Task 6: Article form

**Files:**
- Create: `app/knowledge_base/forms.py`
- Test: `tests/knowledge_base/test_forms.py`

**Interfaces:**
- Consumes: `flask_wtf.FlaskForm`.
- Produces: `app.knowledge_base.forms.KnowledgeArticleForm` with fields `title, problem_md, solution_md, client, platform, tags_raw, submit`. Tasks 9/10 instantiate this in routes; Task 9/10's templates render its fields.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_forms.py
from tests.base import PortalTestCase


class TestKnowledgeArticleForm(PortalTestCase):
    def test_valid_data_passes(self):
        from app.knowledge_base.forms import KnowledgeArticleForm

        with self.app.test_request_context(
            "/kb/nuevo",
            method="POST",
            data={
                "title": "Título",
                "problem_md": "Problema",
                "solution_md": "Solución",
                "client": "Acme",
                "platform": "BIND9",
                "tags_raw": "dns, windows",
            },
        ):
            form = KnowledgeArticleForm(meta={"csrf": False})
            self.assertTrue(form.validate())

    def test_missing_required_fields_fails(self):
        from app.knowledge_base.forms import KnowledgeArticleForm

        with self.app.test_request_context("/kb/nuevo", method="POST", data={}):
            form = KnowledgeArticleForm(meta={"csrf": False})
            self.assertFalse(form.validate())
            self.assertIn("title", form.errors)
            self.assertIn("problem_md", form.errors)
            self.assertIn("solution_md", form.errors)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_forms -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.knowledge_base.forms'`

- [ ] **Step 3: Write the implementation**

```python
# app/knowledge_base/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length


class KnowledgeArticleForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired(), Length(max=200)])
    problem_md = TextAreaField("Problema", validators=[DataRequired()])
    solution_md = TextAreaField("Solución / Procedimiento", validators=[DataRequired()])
    client = StringField("Cliente", validators=[Length(max=120)])
    platform = StringField("Plataforma / Producto", validators=[Length(max=120)])
    tags_raw = StringField("Tags (separados por coma)", validators=[Length(max=300)])
    submit = SubmitField("Guardar")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_forms -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/knowledge_base/forms.py tests/knowledge_base/test_forms.py
git commit -m "feat: add KnowledgeArticleForm"
```

---

### Task 7: Blueprint, registration, tool registry, markdown filter

**Files:**
- Modify: `app/knowledge_base/__init__.py`
- Modify: `app/__init__.py` (register blueprint + `proteger_blueprint`)
- Modify: `app/tools_config.py` (add `knowledge_base` entry)
- Create: `app/knowledge_base/routes.py` (stub `index` route only — full routes arrive in Tasks 8-10)
- Test: `tests/knowledge_base/test_authorization.py`

**Interfaces:**
- Consumes: `app.utils.proteger_blueprint`, `app.knowledge_base.markdown_render.render_markdown`.
- Produces: `app.knowledge_base.bp` (registered Blueprint, url_prefix `/kb`), Jinja filter `markdown` available in every template (`{{ value|markdown }}`), tool identifier `"knowledge_base"` known to `app/tools_config.py`. Tasks 8-10 add routes onto this same `bp` inside `routes.py`.

This task's test is this plan's second and fourth Review Focus items in miniature: tool-less direct access must be denied once the blueprint exists, even before the real CRUD routes are built.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_authorization.py
from tests.base import PortalTestCase


class TestBlueprintToolGuard(PortalTestCase):
    def test_user_without_tool_is_redirected_away(self):
        self.make_user("sintool", tools=[])
        self.login("sintool")

        resp = self.client.get("/kb/", follow_redirects=False)

        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard", resp.headers["Location"] or resp.location)

    def test_user_with_tool_can_reach_index(self):
        self.make_user("contool", tools=["knowledge_base"])
        self.login("contool")

        resp = self.client.get("/kb/")

        self.assertEqual(resp.status_code, 200)

    def test_admin_can_reach_index_without_explicit_usertool(self):
        self.make_user("admin1", is_admin=True)
        self.login("admin1")

        resp = self.client.get("/kb/")

        self.assertEqual(resp.status_code, 200)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_authorization -v`
Expected: FAIL with 404 (no `/kb/` route registered yet)

- [ ] **Step 3: Write the implementation**

```python
# app/knowledge_base/__init__.py
from flask import Blueprint

bp = Blueprint("knowledge_base", __name__)

from app.knowledge_base import routes  # noqa: E402,F401
from app.knowledge_base.markdown_render import render_markdown


@bp.app_template_filter("markdown")
def markdown_filter(raw_text):
    return render_markdown(raw_text)
```

```python
# app/knowledge_base/routes.py
from flask import render_template
from flask_login import login_required
from app.knowledge_base import bp


@bp.route("/")
@login_required
def index():
    return render_template("knowledge_base/list.html", articles=[])
```

```html
<!-- app/templates/knowledge_base/list.html (temporary placeholder, replaced in Task 8) -->
{% extends "base.html" %}
{% block title %}Base de Conocimiento{% endblock %}
{% block content %}
<h2>Base de Conocimiento</h2>
{% endblock %}
```

Modify `app/__init__.py` — add alongside the existing blueprint registrations (after the `vault_bp` registration, before `from app.tools_config import TOOLS`):

```python
    from app.knowledge_base import bp as knowledge_base_bp
    app.register_blueprint(knowledge_base_bp, url_prefix='/kb')

    from app.utils import proteger_blueprint
    proteger_blueprint(knowledge_base_bp, "knowledge_base")
```

Modify `app/tools_config.py` — add a new entry to the `TOOLS` dict:

```python
    'knowledge_base': {
        'titulo': 'Base de Conocimiento',
        'descripcion': 'Documentación de soluciones y procedimientos del equipo.',
        'icono': 'bi-journal-text',
        'endpoint': 'knowledge_base.index',
        'color': 'info'
    },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_authorization -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/knowledge_base/__init__.py app/knowledge_base/routes.py app/templates/knowledge_base/list.html app/__init__.py app/tools_config.py tests/knowledge_base/test_authorization.py
git commit -m "feat: register knowledge_base blueprint with tool-level protection"
```

---

### Task 8: List route — search, filters, pagination

**Files:**
- Modify: `app/knowledge_base/routes.py` (replace stub `index`)
- Modify: `app/templates/knowledge_base/list.html` (replace placeholder)
- Test: `tests/knowledge_base/test_routes_list.py`

**Interfaces:**
- Consumes: `app.knowledge_base.logic.escape_like`, `app.knowledge_base.logic.distinct_values`, `app.models.knowledge.KnowledgeArticle`, `app.models.knowledge.KnowledgeTag`.
- Produces: `GET /kb/` accepting `q`, `client`, `platform`, `tag`, `page` query params, rendering `knowledge_base/list.html` with `pagination`, `articles`, `q`, `client`, `platform`, `tag`, `clients`, `platforms`, `tags` in context. Task 9 links "Nuevo artículo" and each row's detail link from this template.

This task's test is this plan's fifth Review Focus item (LIKE wildcard injection) plus the empty-state and pagination checks from `portal-testing-and-validation` §39/§3.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_routes_list.py
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle


class TestKnowledgeListRoute(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("lector", tools=["knowledge_base"])
        self.login("lector")

    def _make_article(self, **overrides):
        defaults = dict(
            title="Artículo", problem_md="p", solution_md="s", author=self.user
        )
        defaults.update(overrides)
        article = KnowledgeArticle(**defaults)
        db.session.add(article)
        db.session.commit()
        return article

    def test_empty_state_renders(self):
        resp = self.client.get("/kb/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("No hay artículos".encode("utf-8"), resp.data)

    def test_search_literal_percent_is_not_a_wildcard(self):
        self._make_article(title="Ticket 50%_completado")
        self._make_article(title="Otro artículo totalmente distinto")

        resp = self.client.get("/kb/?q=50%25_completado")  # literal '%' and '_'

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Ticket 50", resp.data)
        self.assertNotIn(b"Otro art\xc3\xadculo totalmente distinto", resp.data)

    def test_filter_by_client(self):
        self._make_article(title="Para Acme", client="Acme")
        self._make_article(title="Para Globex", client="Globex")

        resp = self.client.get("/kb/?client=Acme")

        self.assertIn(b"Para Acme", resp.data)
        self.assertNotIn(b"Para Globex", resp.data)

    def test_pagination_second_page(self):
        for i in range(25):
            self._make_article(title=f"Articulo {i}")

        page1 = self.client.get("/kb/")
        page2 = self.client.get("/kb/?page=2")

        self.assertEqual(page1.status_code, 200)
        self.assertEqual(page2.status_code, 200)
        self.assertNotEqual(page1.data, page2.data)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_routes_list -v`
Expected: FAIL (empty-state message and filtering don't exist against the Task 7 stub template)

- [ ] **Step 3: Write the implementation**

```python
# app/knowledge_base/routes.py
from flask import render_template, request
from flask_login import login_required
from app.extensions import db
from app.knowledge_base import bp
from app.knowledge_base.logic import escape_like, distinct_values
from app.models.knowledge import KnowledgeArticle, KnowledgeTag


@bp.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()
    client = request.args.get("client", "").strip()
    platform = request.args.get("platform", "").strip()
    tag = request.args.get("tag", "").strip()
    page = request.args.get("page", 1, type=int)

    query = KnowledgeArticle.query

    if q:
        escaped = escape_like(q)
        pattern = f"%{escaped}%"
        query = query.filter(
            db.or_(
                KnowledgeArticle.title.ilike(pattern, escape="\\"),
                KnowledgeArticle.problem_md.ilike(pattern, escape="\\"),
                KnowledgeArticle.solution_md.ilike(pattern, escape="\\"),
            )
        )
    if client:
        query = query.filter(KnowledgeArticle.client == client)
    if platform:
        query = query.filter(KnowledgeArticle.platform == platform)
    if tag:
        query = query.join(KnowledgeArticle.tags).filter(KnowledgeTag.name == tag)

    pagination = query.order_by(KnowledgeArticle.updated_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template(
        "knowledge_base/list.html",
        pagination=pagination,
        articles=pagination.items,
        q=q,
        client=client,
        platform=platform,
        tag=tag,
        clients=distinct_values(KnowledgeArticle.client),
        platforms=distinct_values(KnowledgeArticle.platform),
        tags=KnowledgeTag.query.order_by(KnowledgeTag.name).all(),
    )
```

```html
<!-- app/templates/knowledge_base/list.html -->
{% extends "base.html" %}
{% block title %}Base de Conocimiento{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item active">Base de Conocimiento</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h2 class="mb-0"><i class="bi bi-journal-text text-info me-2"></i>Base de Conocimiento</h2>
  <a href="{{ url_for('knowledge_base.crear') }}" class="btn btn-primary">
    <i class="bi bi-plus-circle me-1"></i>Nuevo artículo
  </a>
</div>

<form method="GET" class="card card-body shadow-sm mb-4">
  <div class="row g-2">
    <div class="col-md-4">
      <input type="search" name="q" class="form-control" placeholder="Buscar..." value="{{ q }}">
    </div>
    <div class="col-md-3">
      <input type="text" name="client" class="form-control" list="clientList" placeholder="Cliente" value="{{ client }}">
      <datalist id="clientList">
        {% for c in clients %}<option value="{{ c }}">{% endfor %}
      </datalist>
    </div>
    <div class="col-md-3">
      <input type="text" name="platform" class="form-control" list="platformList" placeholder="Plataforma" value="{{ platform }}">
      <datalist id="platformList">
        {% for p in platforms %}<option value="{{ p }}">{% endfor %}
      </datalist>
    </div>
    <div class="col-md-2">
      <select name="tag" class="form-select">
        <option value="">Tag</option>
        {% for t in tags %}
        <option value="{{ t.name }}" {% if t.name == tag %}selected{% endif %}>{{ t.name }}</option>
        {% endfor %}
      </select>
    </div>
  </div>
  <button type="submit" class="btn btn-outline-secondary mt-2">
    <i class="bi bi-search me-1"></i>Filtrar
  </button>
</form>

{% if articles %}
<div class="list-group shadow-sm">
  {% for article in articles %}
  <a href="{{ url_for('knowledge_base.detalle', id=article.id) }}"
     class="list-group-item list-group-item-action">
    <div class="d-flex justify-content-between">
      <strong>{{ article.title }}</strong>
      <small class="text-muted">{{ article.updated_at.strftime('%Y-%m-%d') }}</small>
    </div>
    <small class="text-muted">
      {{ article.client or '—' }} · {{ article.platform or '—' }}
      {% for t in article.tags %}<span class="badge bg-secondary ms-1">{{ t.name }}</span>{% endfor %}
    </small>
  </a>
  {% endfor %}
</div>

<nav class="mt-3">
  <ul class="pagination">
    <li class="page-item {{ 'disabled' if not pagination.has_prev }}">
      <a class="page-link" href="?page={{ pagination.prev_num }}&q={{ q }}&client={{ client }}&platform={{ platform }}&tag={{ tag }}">Anterior</a>
    </li>
    <li class="page-item disabled"><span class="page-link">Página {{ pagination.page }} de {{ pagination.pages or 1 }}</span></li>
    <li class="page-item {{ 'disabled' if not pagination.has_next }}">
      <a class="page-link" href="?page={{ pagination.next_num }}&q={{ q }}&client={{ client }}&platform={{ platform }}&tag={{ tag }}">Siguiente</a>
    </li>
  </ul>
</nav>
{% else %}
<div class="alert alert-info">No hay artículos que coincidan con los filtros actuales.</div>
{% endif %}
{% endblock %}
```

Note: `list.html` links to `knowledge_base.crear` and `knowledge_base.detalle`, which do not exist until Task 9. This is expected — Task 8's own tests never follow those links, only Task 9 onward will exercise them once those endpoints exist. Running Task 8's tests in isolation still passes because Jinja only resolves `url_for()` when that template branch actually renders (here, only when `articles` is non-empty) — the empty-state test and the "no results" branch never touch `url_for('knowledge_base.detalle', ...)` for a nonexistent endpoint; the "Nuevo artículo" link at the top is unconditional, so `knowledge_base.crear` must already exist as at least a stub by the time Task 8's tests run. To avoid that ordering hazard, add the same minimal stub routes Task 9 will flesh out before writing Task 8's tests:

```python
# append to app/knowledge_base/routes.py for this task only — Task 9 replaces both bodies
@bp.route("/nuevo")
@login_required
def crear():
    return "stub", 200


@bp.route("/<int:id>")
@login_required
def detalle(id):
    return "stub", 200
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_routes_list -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/knowledge_base/routes.py app/templates/knowledge_base/list.html tests/knowledge_base/test_routes_list.py
git commit -m "feat: add knowledge base list route with search, filters, pagination"
```

---

### Task 9: Create and detail routes, with audit logging

**Files:**
- Modify: `app/knowledge_base/routes.py` (replace the `crear`/`detalle` stubs)
- Create: `app/templates/knowledge_base/form.html`
- Create: `app/templates/knowledge_base/detail.html`
- Test: `tests/knowledge_base/test_routes_create_detail.py`

**Interfaces:**
- Consumes: `app.knowledge_base.forms.KnowledgeArticleForm`, `app.knowledge_base.logic.sync_tags`, `app.models.audit.log_audit`, `app.models.knowledge.KnowledgeArticle`.
- Produces: `GET/POST /kb/nuevo` (any user with the tool), `GET /kb/<id>` (any user with the tool) passing `can_edit`/`can_delete` booleans to `detail.html` (consumed by Task 10, which adds the actual edit/delete buttons). `form.html` is reused unmodified by Task 10 for editing.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_routes_create_detail.py
from tests.base import PortalTestCase
from app.models.knowledge import KnowledgeArticle
from app.models.audit import AuditLog


class TestCreateAndDetail(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.make_user("creador", tools=["knowledge_base"])
        self.login("creador")

    def _csrf_get(self, url):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def test_create_article_persists_and_audits(self):
        token = self._csrf_get("/kb/nuevo")

        resp = self.client.post(
            "/kb/nuevo",
            data={
                "title": "Nuevo artículo",
                "problem_md": "Problema **grave**",
                "solution_md": "Reiniciar servicio",
                "client": "Acme",
                "platform": "Linux",
                "tags_raw": "linux, servicios",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        article = KnowledgeArticle.query.filter_by(title="Nuevo artículo").first()
        self.assertIsNotNone(article)
        self.assertEqual(sorted(t.name for t in article.tags), ["linux", "servicios"])

        audit = AuditLog.query.filter_by(module="knowledge_base", action="create").first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.object_name, "Nuevo artículo")

    def test_create_missing_title_shows_validation_error(self):
        token = self._csrf_get("/kb/nuevo")

        resp = self.client.post(
            "/kb/nuevo",
            data={"problem_md": "p", "solution_md": "s", "csrf_token": token},
        )

        self.assertEqual(resp.status_code, 200)  # re-renders form, does not redirect
        self.assertEqual(KnowledgeArticle.query.count(), 0)

    def test_detail_renders_sanitized_markdown(self):
        token = self._csrf_get("/kb/nuevo")
        self.client.post(
            "/kb/nuevo",
            data={
                "title": "Con XSS",
                "problem_md": "before <script>alert(1)</script> after",
                "solution_md": "**ok**",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        article = KnowledgeArticle.query.filter_by(title="Con XSS").first()

        resp = self.client.get(f"/kb/{article.id}")

        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b"<script", resp.data)
        self.assertIn(b"<strong>ok</strong>", resp.data)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_routes_create_detail -v`
Expected: FAIL (stub routes return `"stub", 200` and never persist anything)

- [ ] **Step 3: Write the implementation**

```python
# app/knowledge_base/routes.py — replace the two stub routes with:
from flask import abort, flash, redirect, url_for
from flask_login import current_user
from app.knowledge_base.forms import KnowledgeArticleForm
from app.knowledge_base.logic import sync_tags
from app.models.audit import log_audit


@bp.route("/nuevo", methods=["GET", "POST"])
@login_required
def crear():
    form = KnowledgeArticleForm()
    if form.validate_on_submit():
        article = KnowledgeArticle(
            title=form.title.data,
            problem_md=form.problem_md.data,
            solution_md=form.solution_md.data,
            client=form.client.data or None,
            platform=form.platform.data or None,
            author_id=current_user.id,
        )
        db.session.add(article)
        db.session.flush()
        sync_tags(article, form.tags_raw.data)
        log_audit("knowledge_base", "create", "article", article.id, article.title)
        db.session.commit()
        flash("Artículo creado.", "success")
        return redirect(url_for("knowledge_base.detalle", id=article.id))

    return render_template(
        "knowledge_base/form.html",
        form=form,
        heading="Nuevo artículo",
        clients=distinct_values(KnowledgeArticle.client),
        platforms=distinct_values(KnowledgeArticle.platform),
    )


@bp.route("/<int:id>")
@login_required
def detalle(id):
    article = KnowledgeArticle.query.get_or_404(id)
    # Task 10 replaces these two lines with calls to _can_edit()/_can_delete()
    # once those helpers exist, to avoid duplicating this logic.
    can_edit = current_user.is_admin or article.author_id == current_user.id
    can_delete = current_user.is_admin
    return render_template(
        "knowledge_base/detail.html",
        article=article,
        can_edit=can_edit,
        can_delete=can_delete,
    )
```

```html
<!-- app/templates/knowledge_base/form.html -->
{% extends "base.html" %}
{% block title %}{{ heading }} — Base de Conocimiento{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('knowledge_base.index') }}">Base de Conocimiento</a></li>
    <li class="breadcrumb-item active">{{ heading }}</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<div class="row justify-content-center">
  <div class="col-md-10 col-lg-8">
    <h2 class="mb-3"><i class="bi bi-journal-plus me-2"></i>{{ heading }}</h2>
    <div class="card shadow-sm">
      <div class="card-body">
        <form method="POST" novalidate>
          {{ form.hidden_tag() }}

          <div class="mb-3">
            {{ form.title.label(class="form-label fw-bold") }}
            {{ form.title(class="form-control" + (" is-invalid" if form.title.errors else "")) }}
            {% for e in form.title.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
          </div>

          <div class="row g-3 mb-3">
            <div class="col-md-6">
              {{ form.client.label(class="form-label fw-bold") }}
              {{ form.client(class="form-control", list="clientList") }}
              <datalist id="clientList">
                {% for c in clients %}<option value="{{ c }}">{% endfor %}
              </datalist>
            </div>
            <div class="col-md-6">
              {{ form.platform.label(class="form-label fw-bold") }}
              {{ form.platform(class="form-control", list="platformList") }}
              <datalist id="platformList">
                {% for p in platforms %}<option value="{{ p }}">{% endfor %}
              </datalist>
            </div>
          </div>

          <div class="mb-3">
            {{ form.problem_md.label(class="form-label fw-bold") }}
            {{ form.problem_md(class="form-control" + (" is-invalid" if form.problem_md.errors else ""), rows=4, placeholder="Markdown soportado: **negrita**, listas, tablas, bloques de código...") }}
            {% for e in form.problem_md.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
          </div>

          <div class="mb-3">
            {{ form.solution_md.label(class="form-label fw-bold") }}
            {{ form.solution_md(class="form-control" + (" is-invalid" if form.solution_md.errors else ""), rows=8, placeholder="Markdown soportado: **negrita**, listas, tablas, bloques de código...") }}
            {% for e in form.solution_md.errors %}<div class="invalid-feedback">{{ e }}</div>{% endfor %}
          </div>

          <div class="mb-4">
            {{ form.tags_raw.label(class="form-label fw-bold") }}
            {{ form.tags_raw(class="form-control", placeholder="dns, windows, red") }}
            <div class="form-text">Separados por coma.</div>
          </div>

          <div class="d-flex justify-content-end gap-2">
            <a href="{{ url_for('knowledge_base.index') }}" class="btn btn-secondary">Cancelar</a>
            {{ form.submit(class="btn btn-primary") }}
          </div>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

```html
<!-- app/templates/knowledge_base/detail.html -->
{% extends "base.html" %}
{% block title %}{{ article.title }} — Base de Conocimiento{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="mb-3">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('knowledge_base.index') }}">Base de Conocimiento</a></li>
    <li class="breadcrumb-item active">{{ article.title }}</li>
  </ol>
</nav>
{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-start mb-3">
  <div>
    <h2 class="mb-1">{{ article.title }}</h2>
    <small class="text-muted">
      {{ article.client or '—' }} · {{ article.platform or '—' }} ·
      por {{ article.author.username }} · actualizado {{ article.updated_at.strftime('%Y-%m-%d %H:%M') }}
    </small>
    <div class="mt-1">
      {% for t in article.tags %}<span class="badge bg-secondary me-1">{{ t.name }}</span>{% endfor %}
    </div>
  </div>
</div>

<div class="card shadow-sm mb-3">
  <div class="card-header bg-light fw-bold">Problema</div>
  <div class="card-body">{{ article.problem_md|markdown }}</div>
</div>

<div class="card shadow-sm">
  <div class="card-header bg-light fw-bold">Solución / Procedimiento</div>
  <div class="card-body">{{ article.solution_md|markdown }}</div>
</div>
{% endblock %}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_routes_create_detail -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/knowledge_base/routes.py app/templates/knowledge_base/form.html app/templates/knowledge_base/detail.html tests/knowledge_base/test_routes_create_detail.py
git commit -m "feat: add knowledge base create and detail routes"
```

---

### Task 10: Edit and delete routes — permission model C enforcement

**Files:**
- Modify: `app/knowledge_base/routes.py` (add `editar`, `eliminar`)
- Modify: `app/templates/knowledge_base/detail.html` (add conditional edit/delete buttons)
- Test: `tests/knowledge_base/test_routes_edit_delete.py`

**Interfaces:**
- Consumes: everything from Task 9 (`form.html`, `KnowledgeArticleForm`, `sync_tags`, `log_audit`) plus `can_edit`/`can_delete` already computed in Task 9's `detalle` route.
- Produces: `GET/POST /kb/<id>/editar` (author or admin only, else 403), `POST /kb/<id>/eliminar` (admin only, else 403).

This task's tests are this plan's second and third Review Focus items — the two must-not-regress authorization checks.

- [ ] **Step 1: Write the failing test**

```python
# tests/knowledge_base/test_routes_edit_delete.py
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle


class TestEditDeleteAuthorization(PortalTestCase):
    def _create_article_as(self, username):
        token = self.extract_csrf(self.client.get("/kb/nuevo").get_data(as_text=True))
        self.client.post(
            "/kb/nuevo",
            data={
                "title": f"Articulo de {username}",
                "problem_md": "p",
                "solution_md": "s",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        return KnowledgeArticle.query.filter_by(title=f"Articulo de {username}").first()

    def test_author_can_edit_own_article(self):
        self.make_user("autorA", tools=["knowledge_base"])
        self.login("autorA")
        article = self._create_article_as("autorA")

        token = self.extract_csrf(
            self.client.get(f"/kb/{article.id}/editar").get_data(as_text=True)
        )
        resp = self.client.post(
            f"/kb/{article.id}/editar",
            data={
                "title": "Titulo editado",
                "problem_md": "p2",
                "solution_md": "s2",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(db.session.get(KnowledgeArticle, article.id).title, "Titulo editado")

    def test_non_author_non_admin_cannot_edit(self):
        self.make_user("autorB", tools=["knowledge_base"])
        self.login("autorB")
        article = self._create_article_as("autorB")

        self.make_user("otroUsuario", tools=["knowledge_base"])
        self.login("otroUsuario")

        resp_get = self.client.get(f"/kb/{article.id}/editar")
        self.assertEqual(resp_get.status_code, 403)

        resp_post = self.client.post(
            f"/kb/{article.id}/editar",
            data={"title": "hackeado", "problem_md": "x", "solution_md": "y"},
        )
        self.assertEqual(resp_post.status_code, 403)
        self.assertEqual(
            db.session.get(KnowledgeArticle, article.id).title, f"Articulo de autorB"
        )

    def test_admin_can_edit_any_article(self):
        self.make_user("autorC", tools=["knowledge_base"])
        self.login("autorC")
        article = self._create_article_as("autorC")

        self.make_user("admin2", is_admin=True)
        self.login("admin2")

        token = self.extract_csrf(
            self.client.get(f"/kb/{article.id}/editar").get_data(as_text=True)
        )
        resp = self.client.post(
            f"/kb/{article.id}/editar",
            data={
                "title": "Editado por admin",
                "problem_md": "p",
                "solution_md": "s",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            db.session.get(KnowledgeArticle, article.id).title, "Editado por admin"
        )

    def test_author_cannot_delete_own_article(self):
        self.make_user("autorD", tools=["knowledge_base"])
        self.login("autorD")
        article = self._create_article_as("autorD")

        resp = self.client.post(f"/kb/{article.id}/eliminar")

        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(KnowledgeArticle, article.id))

    def test_admin_can_delete_any_article(self):
        self.make_user("autorE", tools=["knowledge_base"])
        self.login("autorE")
        article = self._create_article_as("autorE")
        article_id = article.id

        self.make_user("admin3", is_admin=True)
        self.login("admin3")

        resp = self.client.post(f"/kb/{article_id}/eliminar", follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(db.session.get(KnowledgeArticle, article_id))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.knowledge_base.test_routes_edit_delete -v`
Expected: FAIL with 404 (`/kb/<id>/editar` and `/kb/<id>/eliminar` do not exist yet)

- [ ] **Step 3: Write the implementation**

```python
# app/knowledge_base/routes.py — append:
def _can_edit(article):
    return current_user.is_admin or article.author_id == current_user.id


def _can_delete(article):
    return current_user.is_admin


# Replace detalle()'s two inline boolean lines (added in Task 9) with:
#     can_edit=_can_edit(article),
#     can_delete=_can_delete(article),
# directly in the render_template(...) call, and delete the now-redundant
# can_edit/can_delete local variables. This removes the duplicated
# permission logic now that the real helpers exist.


@bp.route("/<int:id>/editar", methods=["GET", "POST"])
@login_required
def editar(id):
    article = KnowledgeArticle.query.get_or_404(id)
    if not _can_edit(article):
        abort(403)

    form = KnowledgeArticleForm(obj=article)
    if form.validate_on_submit():
        article.title = form.title.data
        article.problem_md = form.problem_md.data
        article.solution_md = form.solution_md.data
        article.client = form.client.data or None
        article.platform = form.platform.data or None
        sync_tags(article, form.tags_raw.data)
        log_audit("knowledge_base", "edit", "article", article.id, article.title)
        db.session.commit()
        flash("Artículo actualizado.", "success")
        return redirect(url_for("knowledge_base.detalle", id=article.id))

    if request.method == "GET":
        form.tags_raw.data = ", ".join(t.name for t in article.tags)

    return render_template(
        "knowledge_base/form.html",
        form=form,
        heading="Editar artículo",
        clients=distinct_values(KnowledgeArticle.client),
        platforms=distinct_values(KnowledgeArticle.platform),
    )


@bp.route("/<int:id>/eliminar", methods=["POST"])
@login_required
def eliminar(id):
    article = KnowledgeArticle.query.get_or_404(id)
    if not _can_delete(article):
        abort(403)

    log_audit("knowledge_base", "delete", "article", article.id, article.title)
    db.session.delete(article)
    db.session.commit()
    flash("Artículo eliminado.", "success")
    return redirect(url_for("knowledge_base.index"))
```

Modify `app/templates/knowledge_base/detail.html` — add inside the header `<div>` block, after the tags block:

```html
    <div class="mt-3 d-flex gap-2">
      {% if can_edit %}
      <a href="{{ url_for('knowledge_base.editar', id=article.id) }}" class="btn btn-outline-secondary btn-sm">
        <i class="bi bi-pencil me-1"></i>Editar
      </a>
      {% endif %}
      {% if can_delete %}
      <form method="POST" action="{{ url_for('knowledge_base.eliminar', id=article.id) }}"
            onsubmit="return confirm('¿Eliminar este artículo? Esta acción no se puede deshacer.');">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit" class="btn btn-outline-danger btn-sm">
          <i class="bi bi-trash me-1"></i>Eliminar
        </button>
      </form>
      {% endif %}
    </div>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.knowledge_base.test_routes_edit_delete -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Run the full knowledge_base test suite together**

Run: `python -m unittest discover -s tests/knowledge_base -v`
Expected: all tests across Tasks 3-10 pass together (catches cross-task regressions, e.g. a later task accidentally breaking an earlier route).

- [ ] **Step 6: Commit**

```bash
git add app/knowledge_base/routes.py app/templates/knowledge_base/detail.html tests/knowledge_base/test_routes_edit_delete.py
git commit -m "feat: add knowledge base edit/delete routes enforcing permission model C"
```

---

### Task 11: Documentation

**Files:**
- Create: `docs/systems/knowledge_base.md`
- Modify: `docs/PROJECT_MAP.md`
- Modify: `docs/technical-debt/current.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: documentation reflecting the implementation from Tasks 1-10. No code.

- [ ] **Step 1: Write `docs/systems/knowledge_base.md`**

```markdown
# Knowledge Base System

## Purpose

Lets the team document ticket solutions as Markdown articles and find them
later by text search, client, platform, or tag.

It describes the **current implementation**, not a future design.

Primary files:

\`\`\`text
app/knowledge_base/__init__.py
app/knowledge_base/routes.py
app/knowledge_base/forms.py
app/knowledge_base/logic.py
app/knowledge_base/markdown_render.py
app/models/knowledge.py
\`\`\`

Primary templates:

\`\`\`text
app/templates/knowledge_base/list.html
app/templates/knowledge_base/form.html
app/templates/knowledge_base/detail.html
\`\`\`

Relevant migration:

\`\`\`text
migrations/versions/d4f29b6e71a3_add_knowledge_base_tables.py
\`\`\`

---

# 1. Blueprint

Tool identifier: \`knowledge_base\`. URL prefix: \`/kb\`. Protected with
\`proteger_blueprint(bp, "knowledge_base")\` — unlike Vault, this module uses
the standard server-side tool guard from day one.

---

# 2. Models

\`KnowledgeArticle\`: \`title, problem_md, solution_md, client, platform,
author_id, created_at, updated_at\`, plus a many-to-many \`tags\` relationship
to \`KnowledgeTag\` through the \`knowledge_article_tag\` association table.

\`client\` and \`platform\` are plain indexed strings, not master tables —
the filter dropdowns and form autocomplete are populated from
\`SELECT DISTINCT\` over existing rows. This is a deliberate MVP decision
(see \`docs/technical-debt/current.md\`), not an oversight.

---

# 3. Markdown Rendering and Sanitization

Both \`problem_md\` and \`solution_md\` are stored as raw Markdown, never as
HTML. The only path from Markdown to HTML is
\`app.knowledge_base.markdown_render.render_markdown()\`, exposed to templates
as the \`|markdown\` Jinja filter. It converts with \`python-markdown\`
(\`tables\`, \`fenced_code\`, \`nl2br\` extensions) and then sanitizes the
resulting HTML with \`bleach\` against a fixed tag/attribute/protocol
allowlist before returning \`Markup\`.

No template must ever call \`markdown.markdown()\` directly or apply \`|safe\`
to \`problem_md\`/\`solution_md\` without going through this filter — that
would reintroduce stored XSS.

---

# 4. Authorization Model

Tool access: \`UserTool("knowledge_base")\` + \`User.has_tool()\`, same as
every other tool. Admins get access automatically.

Object-level (permission model C, a deliberate product decision, not
inferred):

\`\`\`text
read    → any user with the tool
create  → any user with the tool
edit    → the article's author, or an admin
delete  → admin only (not even the author)
\`\`\`

Enforced in \`_can_edit()\`/\`_can_delete()\` in \`routes.py\`, checked
server-side on every \`editar\`/\`eliminar\` request — not just hidden in the
UI.

---

# 5. Search, Filters, Pagination

Text search is a \`LIKE\`-based match (escaped via
\`app.knowledge_base.logic.escape_like\`) over \`title\`, \`problem_md\`,
\`solution_md\`, combined with exact-match filters on \`client\`, \`platform\`,
and \`tag\`. Results are paginated server-side (\`per_page=20\`) using
Flask-SQLAlchemy's built-in \`.paginate()\`.

There is no full-text search engine (SQLite FTS5) in this version — see
\`docs/technical-debt/current.md\`.

---

# 6. Audit Logging

Create, edit, and delete all call the shared \`log_audit("knowledge_base",
...)\` — no dedicated audit table was created for this module.
```

- [ ] **Step 2: Add a section to `docs/PROJECT_MAP.md`**

Insert a new numbered section after the existing "9. Vault / Credential Management" section (renumber subsequent sections if your editor doesn't do it automatically):

```markdown
# 9.5 Knowledge Base

Subsystem:

\`\`\`text
KNOWLEDGE_BASE
\`\`\`

Primary source:

\`\`\`text
app/knowledge_base/__init__.py
app/knowledge_base/routes.py
app/knowledge_base/forms.py
app/knowledge_base/logic.py
app/knowledge_base/markdown_render.py
app/models/knowledge.py
\`\`\`

Templates:

\`\`\`text
app/templates/knowledge_base/list.html
app/templates/knowledge_base/form.html
app/templates/knowledge_base/detail.html
\`\`\`

Responsibilities include:

\`\`\`text
documenting ticket solutions as Markdown articles
searching/filtering by client, platform, tag
author-or-admin edit, admin-only delete
\`\`\`

Important routes:

\`\`\`text
/kb/
/kb/nuevo
/kb/<id>
/kb/<id>/editar
/kb/<id>/eliminar
\`\`\`

Security sensitivity: \`MEDIUM\` — the main risk is stored XSS through
Markdown; all rendering goes through the single sanitized
\`render_markdown()\` function. See \`docs/systems/knowledge_base.md\`.
```

Also update the "Documentation Status" table near the top of `docs/PROJECT_MAP.md`, adding a row:

```markdown
| Knowledge Base | `docs/systems/knowledge_base.md` | VERIFIED |
```

- [ ] **Step 3: Add deliberate MVP-limitation entries to `docs/technical-debt/current.md`**

Append (reusing the existing numbering/format convention — pick the next free numbers in sequence):

```markdown
# 36. Knowledge Base Has No Full-Text Search

Priority:

\`\`\`text
P3
\`\`\`

Area:

\`\`\`text
Knowledge Base
Search
\`\`\`

Current behavior:

Search uses an escaped \`LIKE\` match over title/problem/solution. No SQLite
FTS5 or external search index exists.

Risk:

Relevance degrades as the number of articles grows; no ranking, only
substring matching.

Expected remediation only if volume/usability actually requires it — this
was deliberately deferred in the MVP, not an oversight.

---

# 37. Knowledge Base Client/Platform Are Free Text

Priority:

\`\`\`text
P3
\`\`\`

Area:

\`\`\`text
Knowledge Base
Data quality
\`\`\`

Current behavior:

\`client\` and \`platform\` are plain strings with UI autocomplete from
existing distinct values, not managed master tables. Inconsistent casing or
near-duplicate values (e.g. "Acme" vs "ACME Corp") are possible and will
fragment filter results.

Expected remediation only if fragmentation becomes a real problem in
practice — deliberately deferred, per the confirmed MVP scope.
```

- [ ] **Step 4: Commit**

```bash
git add docs/systems/knowledge_base.md docs/PROJECT_MAP.md docs/technical-debt/current.md
git commit -m "docs: document the knowledge base subsystem"
```

---

## Final Validation (run once, after Task 11)

- [ ] Run the entire new suite: `python -m unittest discover -s tests -v` — expect every test from Tasks 1-10 passing together.
- [ ] Start the app normally (`flask run` or the project's usual entry point) and confirm: the portal still boots, the dashboard still shows the existing four tools plus "Base de Conocimiento", and an admin account can open `/kb/` and create/edit/delete an article through the browser.
- [ ] `git diff` the full branch before opening a PR — confirm no unrelated files changed, no debug prints, no secrets.
- [ ] Explicitly note in the PR description: automated coverage is `unittest` + Flask test client (new to this repo — no existing suite was touched or replaced); manual browser check covers the parts automated tests don't (visual layout, flash messages, autocomplete `<datalist>` behavior).

