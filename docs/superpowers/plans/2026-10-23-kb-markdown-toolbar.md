# KB Markdown Toolbar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single, sticky, self-contained Markdown formatting toolbar in the right-hand column of the Knowledge Base create/edit form, acting on whichever of the two Markdown textareas (`problem_md`, `solution_md`) currently has focus — editing `textarea.value` directly, no WYSIWYG, no new JS dependency.

**Architecture:** One toolbar block in `form.html`, rendered once in a right-hand sticky column beside the form card. One new vanilla-JS file (`app/static/js/kb-markdown-toolbar.js`) tracks which of the two textareas last had focus (defaulting to `problem_md` before any focus event), shows a small "Editando: Problema"/"Editando: Solución" indicator in the toolbar, and applies every button action to that current textarea via `selectionStart`/`selectionEnd`/`setSelectionRange`. Backend stays untouched — `problem_md`/`solution_md` keep storing raw Markdown text, rendering/sanitization still goes exclusively through `render_markdown()`.

**Tech Stack:** Flask/Jinja, Bootstrap 5 (existing), Bootstrap Icons (existing), vanilla JS (no new dependency).

**Spec:** the user's pasted 22-phase spec (this conversation) — not a separate file; this plan is the executable form of it.

## Global Constraints

- Branch: `feature/kb-markdown-toolbar` (already current). No commit, no push (per user instruction) until the user asks.
- No new JS/CSS framework or library; no npm dependency.
- Do not replace the `<textarea>` with a WYSIWYG editor.
- Do not modify `app/knowledge_base/markdown_render.py` (no bug found that requires it).
- Do not modify `app/knowledge_base/forms.py` or any model/migration.
- Only expose toolbar actions for Markdown syntax `render_markdown()` actually renders: no raw HTML, no strikethrough (`tables`/`fenced_code`/`nl2br` are the only extensions loaded), no generic image-URL button (see rationale above — `img[src]` only survives sanitization for the exact `/kb/attachments/<id>/view` pattern, which users cannot hand-type).
- Every toolbar control is `<button type="button">` (never a bare `div onclick`), with `title`/`aria-label`, and must call `textarea.focus()` after acting so keyboard/AT users land back in the field.
- No `eval`, no `innerHTML` with user-controlled content, no new `|safe` filter usage.

## Review Focus

- **Selection spanning multiple paragraphs for line-prefix actions (list/quote/heading):** must prefix every selected line, not just the first or last — tested with a 3-line selection for bullet, numbered, and quote.
- **Numbered list must increment (`1.`, `2.`, `3.`), never repeat `1.` on every line** — explicit spec requirement, easy to get wrong with a naive per-line regex replace.
- **Code-block wrapping when the selection itself contains newlines** — fences must still land on their own line (no `` ```apt update ``` `` glued onto one line) — this is the one case the spec calls out as a concrete failure mode to avoid.
- **Empty-selection ("cursor only") case for every wrap/line action** — bold with nothing selected must produce `**|**` with the cursor literally between the markers, not at the end of the string; same shape for heading/list/quote/link/codeblock with no selection.
- **Toolbar button accidentally submitting the form** — every button needs `type="button"`; a missing one silently turns "click Negrita" into "submit the article" on whichever browser treats default `<button>` type as `submit` inside a `<form>`.
- **Shared toolbar's "current field" tracking before any textarea has been focused** — a user who lands on `/kb/nuevo` and clicks a toolbar button *before* ever clicking into a textarea must still get a sane result (default to `problem_md`, indicator already reads "Editando: Problema" on load), not a null-target exception.

---

### Task 1: Toolbar markup + styling in `form.html` (template-level, no JS yet)

**Files:**
- Modify: `app/templates/knowledge_base/form.html`
- Modify: `app/static/css/custom.css`
- Test: `tests/knowledge_base/test_markdown_toolbar.py` (new)

**Interfaces:**
- Produces: a single toolbar block rendered once per page, in a right-hand sticky column alongside the form card:
  `<div id="kb-markdown-toolbar" class="kb-markdown-toolbar card shadow-sm" data-markdown-toolbar data-markdown-targets="problem_md,solution_md">`, containing a current-field indicator `<div id="kb-md-current-field" class="kb-md-current-field">Editando: Problema</div>` and grouped `<button type="button" class="btn btn-sm btn-outline-secondary kb-md-btn" data-md-action="..." ...>` controls — the exact `data-md-action`/`data-md-level` contract Task 2's JS consumes.
- Produces: CSS classes `.kb-markdown-toolbar` (sticky on `lg+`, static otherwise), `.kb-md-current-field`, `.kb-md-btn`, `.kb-md-group`.

- [ ] **Step 1: Write failing template-structure tests**

```python
# tests/knowledge_base/test_markdown_toolbar.py
from tests.base import PortalTestCase
from app.models import KnowledgeArticle
from app import db

class TestMarkdownToolbarPresence(PortalTestCase):
    def test_create_form_has_single_toolbar_for_both_fields(self):
        self.login()
        resp = self.client.get("/kb/nuevo")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(html.count('id="kb-markdown-toolbar"'), 1)
        self.assertIn('data-markdown-targets="problem_md,solution_md"', html)
        self.assertIn("Editando: Problema", html)
        self.assertIn("kb-markdown-toolbar.js", html)

    def test_edit_form_has_single_toolbar_for_both_fields(self):
        self.login()
        article = KnowledgeArticle(title="T", problem_md="p", solution_md="s", author_id=self.user.id)
        db.session.add(article)
        db.session.commit()
        resp = self.client.get(f"/kb/{article.id}/editar")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(html.count('id="kb-markdown-toolbar"'), 1)
        self.assertIn('data-markdown-targets="problem_md,solution_md"', html)

    def test_all_toolbar_buttons_are_type_button(self):
        self.login()
        html = self.client.get("/kb/nuevo").get_data(as_text=True)
        import re
        buttons = re.findall(r'<button[^>]*class="[^"]*kb-md-btn[^"]*"[^>]*>', html)
        self.assertTrue(buttons, "expected at least one kb-md-btn button")
        for b in buttons:
            self.assertIn('type="button"', b)

    def test_no_image_button_offered(self):
        # img[src] only survives sanitization for /kb/attachments/<id>/view —
        # a hand-typed image button would produce markup that never renders.
        self.login()
        html = self.client.get("/kb/nuevo").get_data(as_text=True)
        self.assertNotIn('data-md-action="image"', html)

    def test_original_create_post_still_works(self):
        self.login()
        resp = self.client.post("/kb/nuevo", data={
            "title": "T", "problem_md": "p", "solution_md": "s",
            "platform": "", "tags_raw": "",
        }, follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
```

Adapt `self.login()`/`self.user` to whatever `tests/base.py`'s `PortalTestCase` actually exposes (read it before writing this file if the helper names differ).

- [ ] **Step 2: Run the new tests, confirm they fail**

Run: `python -m pytest tests/knowledge_base/test_markdown_toolbar.py -v`
Expected: FAIL (toolbar markup / JS include don't exist yet).

- [ ] **Step 3: Restructure `form.html` into a two-column layout and add the toolbar block**

Change the outer wrapper from `col-md-10 col-lg-8` (which centers a single narrow column) to a `row` with `col-lg-8` holding the existing form card + the existing "Adjuntos" card unchanged, and `col-lg-4` holding the new toolbar block — this stacks the toolbar below the form at `<lg` width (no horizontal overflow) and sticks it beside the form at `lg+`. The `problem_md`/`solution_md` field blocks themselves stay exactly as they are today (plain `<div class="mb-3">`, no per-field split) — only one toolbar exists on the page.

The toolbar renders 5 labelled `.kb-md-group` blocks (Títulos, Texto, Estructura, Código, Enlaces/Otros) with these exact `data-md-action` values (Task 2 implements the handler for each): `heading` (×6, with `data-md-level="1".."6"`), `bold`, `italic`, `bold-italic`, `list-bullet`, `list-number`, `quote`, `hr`, `code-inline`, `code-block`, `link`, `table`. Use Bootstrap Icons already in the project (`bi-type-h1`...`bi-type-h6`, `bi-type-bold`, `bi-type-italic`, `bi-list-ul`, `bi-list-ol`, `bi-quote`, `bi-hr`, `bi-code`, `bi-code-square`, `bi-link-45deg`, `bi-table`) with `title`/`aria-label` text in Spanish matching the rest of the form's labels.

Add `<script src="{{ url_for('static', filename='js/kb-markdown-toolbar.js') }}"></script>` near the existing inline `<script>` block at the bottom of `form.html`.

- [ ] **Step 4: Add toolbar CSS to `custom.css`**

```css
.kb-markdown-toolbar {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 1rem;
}
.kb-md-current-field {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--bs-secondary-color);
}
.kb-md-group {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
}
.kb-md-group-label {
    font-size: 0.72rem;
    text-transform: uppercase;
    color: var(--bs-secondary-color);
    margin-bottom: 0.15rem;
    width: 100%;
}
.kb-md-btn {
    line-height: 1;
}
@media (min-width: 992px) {
    .kb-markdown-toolbar {
        position: sticky;
        top: 1rem;
    }
}
```

- [ ] **Step 5: Run the tests again, confirm they pass**

Run: `python -m pytest tests/knowledge_base/test_markdown_toolbar.py -v`
Expected: PASS.

- [ ] **Step 6: Run the full existing KB suite to confirm no regression**

Run: `python -m pytest tests/knowledge_base/ -v`
Expected: all PASS (existing create/edit/list/attachment tests unaffected — only `form.html` markup changed, no field names/ids changed).

- [ ] **Step 7: Commit**

```bash
git add app/templates/knowledge_base/form.html app/static/css/custom.css tests/knowledge_base/test_markdown_toolbar.py
git commit -m "feat(kb): add markdown toolbar markup and styling to article form"
```

---

### Task 2: `kb-markdown-toolbar.js` — selection-aware formatting logic

**Files:**
- Create: `app/static/js/kb-markdown-toolbar.js`

**Interfaces:**
- Consumes: DOM produced by Task 1 — the single `[data-markdown-toolbar]` element has a `data-markdown-targets` attribute (comma-separated textarea ids, `"problem_md,solution_md"`), a child `#kb-md-current-field` indicator element, and action buttons `button[data-md-action]` (optionally `data-md-level` for headings).
- Produces: nothing read by later tasks — this is a leaf, self-initializing script (`DOMContentLoaded` listener that queries the `[data-markdown-toolbar]` block).

**Current-target tracking:** parse `data-markdown-targets` into an ordered list of textarea elements; `currentTarget` starts as the first one (`problem_md`) before any focus event, so a click with no prior focus still has a sane target and the indicator already reads "Editando: Problema" on load (matches this plan's Review Focus item on default targeting). Attach a `focus` listener to each listed textarea that sets `currentTarget` to itself and updates `#kb-md-current-field`'s text to `"Editando: " + label` (label map: `problem_md` → `"Problema"`, `solution_md` → `"Solución"`). Every action handler reads `currentTarget` at click time, not at page-load time — calling `currentTarget.focus()` at the end of an action re-fires that same textarea's `focus` listener, which is a harmless no-op re-set of the same label.

No automated JS test is added — this repository has no JS test runner (confirmed: only vendored Bootstrap under `app/static/js/`, no `package.json`/Jest/node test infra), and the spec explicitly says not to introduce one for this feature. Correctness is covered by: Task 1's Python structural tests (markup/wiring exist), and the manual browser smoke pass in Task 4. Keep every helper function short and single-purpose so a reviewer can verify it by inspection.

- [ ] **Step 1: Implement core selection helpers**

In an IIFE or module-scope object, implement:

- `wrapSelection(textarea, before, after)` — reads `selectionStart`/`selectionEnd`; if `start === end` (no selection), insert `before + after` and place the cursor at `start + before.length` (between the markers); otherwise wrap the selected text and place the cursor immediately after the inserted `after`. Always writes through `textarea.value = ...` + `textarea.setSelectionRange(...)`, then dispatches `new Event('input', { bubbles: true })` on the textarea (no existing listener consumes it yet, but Phase 15 of the spec asks for it so future dirty-state/preview logic can hook in), then `textarea.focus()`.
- `prefixLines(textarea, prefixForLine)` where `prefixForLine(lineText, index) -> string` returns the full prefixed line. Expand the current selection to the start of its first line and the end of its last line, split on `\n`, map every line through `prefixForLine`, join back with `\n`, replace that span in `textarea.value`, then select the whole replaced span (or place the cursor at its end for the empty-line/cursor-only case), dispatch `input`, focus.
- `insertBlock(textarea, builder)` where `builder(selectedText) -> { text, selectStart, selectEnd }` lets the caller fully control the replacement and the resulting selection (used by code-block, link, table — each has non-uniform cursor-placement rules). Replace the current selection with `text`, then `setSelectionRange(selectStart, selectEnd)`, dispatch `input`, focus.

- [ ] **Step 2: Implement the 12 action handlers using those three helpers**

| `data-md-action` | Implementation |
|---|---|
| `heading` | `prefixLines(ta, (line) => '#'.repeat(level) + ' ' + line.replace(/^#{1,6}\s+/, ''))` — strip any pre-existing heading marker first so re-clicking a different level doesn't stack `##### # Text`. |
| `bold` | `wrapSelection(ta, '**', '**')` |
| `italic` | `wrapSelection(ta, '*', '*')` |
| `bold-italic` | `wrapSelection(ta, '***', '***')` |
| `list-bullet` | `prefixLines(ta, (line) => '- ' + line.replace(/^-\s+/, ''))` |
| `list-number` | `prefixLines(ta, (line, i) => (i + 1) + '. ' + line.replace(/^\d+\.\s+/, ''))` |
| `quote` | `prefixLines(ta, (line) => '> ' + line.replace(/^>\s?/, ''))` |
| `hr` | `insertBlock(ta, () => ({ text: '\n\n---\n\n', selectStart: cursorAfterLen, selectEnd: cursorAfterLen }))` — always inserted as its own block regardless of selection. |
| `code-inline` | `wrapSelection(ta, '`', '`')` |
| `code-block` | `insertBlock`: if selection non-empty, `text = '```\n' + selected + '\n```'`, cursor placed right after the closing fence; if empty, `text = '```\n\n```'`, cursor placed on the blank middle line. |
| `link` | `insertBlock`: if selection non-empty, `text = '[' + selected + '](https://)'`, select the `https://` substring; if empty, `text = '[texto](https://)'`, select `texto`. |
| `table` | `insertBlock`: always `text = '| Columna 1 | Columna 2 |\n| --- | --- |\n| Valor 1 | Valor 2 |'` (selection, if any, is discarded — spec gives a fixed template), select the `Columna 1` substring so it's ready to overwrite. |

- [ ] **Step 3: Wire the shared toolbar to its current target on `DOMContentLoaded`**

```js
const toolbar = document.querySelector('[data-markdown-toolbar]');
if (toolbar) {
  const LABELS = { problem_md: 'Problema', solution_md: 'Solución' };
  const targets = toolbar.dataset.markdownTargets.split(',')
    .map(function (id) { return document.getElementById(id); })
    .filter(Boolean);
  const indicator = document.getElementById('kb-md-current-field');
  let currentTarget = targets[0] || null;

  targets.forEach(function (ta) {
    ta.addEventListener('focus', function () {
      currentTarget = ta;
      if (indicator) indicator.textContent = 'Editando: ' + (LABELS[ta.id] || ta.id);
    });
  });

  toolbar.querySelectorAll('button[data-md-action]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (!currentTarget) return;
      ACTIONS[btn.dataset.mdAction](currentTarget, btn.dataset.mdLevel);
    });
  });
}
```

- [ ] **Step 4: Manual syntax sanity pass (not automated — see Task 4 for the full smoke list)**

Open the file and trace through, by hand, the two trickiest cases from Review Focus: a 3-line selection through `list-number`, and a selection containing an embedded `\n` through `code-block`. Confirm the produced string matches the spec's examples exactly before moving to Task 3.

- [ ] **Step 5: Commit**

```bash
git add app/static/js/kb-markdown-toolbar.js
git commit -m "feat(kb): implement markdown toolbar selection logic"
```

---

### Task 3: Documentation update

**Files:**
- Modify: `docs/systems/knowledge_base.md`

- [ ] **Step 1: Add a short "Markdown authoring toolbar" subsection** under section 3 (Markdown Rendering and Sanitization), stating: it's a client-side editing helper only (`kb-markdown-toolbar.js`); it edits `textarea.value` as plain text, Markdown is still stored as-is; the backend (`render_markdown()`) remains the sole render/sanitize authority; the toolbar's button set is a subset of what `render_markdown()` actually renders (no strikethrough, no free-form image URL) and must be updated if the enabled `markdown` extensions or the bleach allowlist ever change.

- [ ] **Step 2: Commit**

```bash
git add docs/systems/knowledge_base.md
git commit -m "docs(kb): document the markdown authoring toolbar"
```

---

### Task 4: Full validation pass

- [ ] **Step 1: Run the full KB test subdirectory**

Run: `python -m pytest tests/knowledge_base/ -v`
Expected: all PASS.

- [ ] **Step 2: Run the full project test suite once**

Run: `python -m pytest`
Expected: all PASS (confirms the template/CSS/JS change didn't regress any other subsystem — none of the touched files are shared outside Knowledge Base).

- [ ] **Step 3: Manual browser smoke test** (gstack or equivalent), covering every item in the spec's Phase 19 list: H1 with/without selection, bold with/without selection, italic, multi-line bullet list, multi-line numbered list (must increment, not repeat `1.`), quote, inline code, fenced code block (including a multi-line selection), link (with/without selection, cursor lands on `https://`/`texto`), table insert, browser Ctrl+Z after a toolbar action, save the article, view its rendered HTML, re-open it for edit, confirm the stored Markdown is exactly what was typed (no silent mutation). Also confirm: no toolbar click ever submits the form, CSRF token/behavior unchanged, narrow-viewport layout has no horizontal overflow and the toolbar drops below the textarea.

- [ ] **Step 4: Report results** — go/no-go per the user's "REPORTE FINAL" checklist (rama, textarea identificado, features soportadas, toolbar final, comportamiento selection/no-selection, layouts, JS helpers, seguridad, create/edit, tests nuevos, suites, archivos modificados, git diff/status, riesgos, smoke, GO/GO WITH CHANGES/NO-GO).
