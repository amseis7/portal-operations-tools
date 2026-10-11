import io
import os

from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
PDF_BYTES = b"%PDF-1.4\n%%EOF"


class TestVisibleAttachmentsHelper(PortalTestCase):
    """The single source of truth for 'kind == attachment' filtering —
    both templates (detail.html, form.html) and crear()'s draft listing
    must all go through this, not three independent copies of the same
    Jinja condition."""

    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_visible_author", tools=["knowledge_base"])
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.flush()

    def _add(self, kind, filename):
        import hashlib

        att = KnowledgeAttachment(
            article_id=self.article.id, draft_token=None,
            original_filename=filename, stored_filename=filename + ".stored",
            mime_type="image/png", extension="png",
            size_bytes=1, sha256=hashlib.sha256(filename.encode()).hexdigest(),
            is_image=True, uploaded_by=self.author.id,
            scan_status="clean", kind=kind,
        )
        db.session.add(att)
        db.session.commit()
        return att

    def test_visible_attachments_excludes_inline(self):
        self._add("inline", "a.png")
        shown = self._add("attachment", "b.png")
        self.assertEqual(self.article.visible_attachments, [shown])


class TestAttachmentKindUpload(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_kind_author", tools=["knowledge_base"])
        self.login("kb_kind_author")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()

    def _csrf(self):
        page = self.client.get(f"/kb/{self.article.id}/editar")
        return self.extract_csrf(page.get_data(as_text=True))

    def _upload(self, content, filename, kind=None):
        data = {"file": (io.BytesIO(content), filename), "csrf_token": self._csrf()}
        if kind is not None:
            data["kind"] = kind
        return self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data=data,
            content_type="multipart/form-data",
        )

    def test_kind_omitted_defaults_to_attachment(self):
        resp = self._upload(PNG_BYTES, "shot.png")
        self.assertEqual(resp.status_code, 200)
        att = db.session.get(KnowledgeAttachment, resp.get_json()["id"])
        self.assertEqual(att.kind, "attachment")

    def test_kind_attachment_explicit_persists(self):
        resp = self._upload(PNG_BYTES, "shot.png", kind="attachment")
        self.assertEqual(resp.status_code, 200)
        att = db.session.get(KnowledgeAttachment, resp.get_json()["id"])
        self.assertEqual(att.kind, "attachment")

    def test_kind_inline_with_valid_image_persists(self):
        resp = self._upload(PNG_BYTES, "shot.png", kind="inline")
        self.assertEqual(resp.status_code, 200)
        att = db.session.get(KnowledgeAttachment, resp.get_json()["id"])
        self.assertEqual(att.kind, "inline")

    def test_invalid_kind_rejected_with_400_and_nothing_persisted(self):
        resp = self._upload(PNG_BYTES, "shot.png", kind="bogus")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(KnowledgeAttachment.query.count(), 0)

    def test_inline_with_non_image_rejected_nothing_persisted_nothing_on_disk(self):
        """is_image is taken from validate_upload()'s own signature check,
        never from anything the client claims — a PDF declaring
        kind=inline must be rejected before scanning or persistence."""
        before = set(os.listdir(self.app.config["KB_ATTACHMENTS_DIR"]))
        resp = self._upload(PDF_BYTES, "doc.pdf", kind="inline")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(KnowledgeAttachment.query.count(), 0)
        after = set(os.listdir(self.app.config["KB_ATTACHMENTS_DIR"]))
        self.assertEqual(after, before, "rejected inline-on-non-image upload must not leave a file on disk")


class TestAttachmentKindRendering(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_kind_render_author", tools=["knowledge_base"])
        self.login("kb_kind_render_author")
        self.article = KnowledgeArticle(title="Articulo Kind Test", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()

    def _make_attachment(self, kind, filename, is_image=True, scan_status="clean"):
        import hashlib

        content = b"fake-content"
        stored = "test-" + hashlib.sha1(os.urandom(8)).hexdigest() + (".png" if is_image else ".pdf")
        os.makedirs(self.app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], stored)
        with open(path, "wb") as f:
            f.write(content)
        att = KnowledgeAttachment(
            article_id=self.article.id, draft_token=None,
            original_filename=filename, stored_filename=stored,
            mime_type="image/png" if is_image else "application/pdf",
            extension="png" if is_image else "pdf",
            size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest(),
            is_image=is_image, uploaded_by=self.author.id,
            scan_status=scan_status, kind=kind,
        )
        db.session.add(att)
        db.session.commit()
        return att

    def test_inline_not_in_detail_adjuntos_list(self):
        self._make_attachment("inline", "inline-secret-name.png")
        resp = self.client.get(f"/kb/{self.article.id}")
        self.assertNotIn(b"inline-secret-name.png", resp.data)

    def test_inline_not_in_edit_form_adjuntos_list(self):
        self._make_attachment("inline", "inline-edit-name.png")
        resp = self.client.get(f"/kb/{self.article.id}/editar")
        self.assertNotIn(b"inline-edit-name.png", resp.data)

    def test_attachment_kind_shows_in_detail_adjuntos_list(self):
        self._make_attachment("attachment", "normal-attachment-name.png")
        resp = self.client.get(f"/kb/{self.article.id}")
        self.assertIn(b"normal-attachment-name.png", resp.data)

    def test_attachment_kind_shows_in_edit_form_list(self):
        self._make_attachment("attachment", "normal-edit-name.png")
        resp = self.client.get(f"/kb/{self.article.id}/editar")
        self.assertIn(b"normal-edit-name.png", resp.data)

    def test_inline_clean_still_servable_via_view(self):
        att = self._make_attachment("inline", "inline-view-name.png")
        resp = self.client.get(f"/kb/attachments/{att.id}/view")
        self.assertEqual(resp.status_code, 200)


class TestAttachmentKindDraftAndEdit(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_kind_draft_author", tools=["knowledge_base"])
        self.login("kb_kind_draft_author")

    def test_draft_inline_promotion_preserves_kind(self):
        draft_token = "kind-draft-token-1"
        new_page = self.client.get("/kb/nuevo")
        token = self.extract_csrf(new_page.get_data(as_text=True))

        draft_resp = self.client.post(
            "/kb/attachments/draft-upload",
            data={
                "file": (io.BytesIO(PNG_BYTES), "shot.png"),
                "draft_token": draft_token, "kind": "inline", "csrf_token": token,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(draft_resp.status_code, 200)
        draft_id = draft_resp.get_json()["id"]

        create_resp = self.client.post(
            "/kb/nuevo",
            data={
                "title": "Articulo con inline", "problem_md": "p", "solution_md": "s",
                "draft_token": draft_token, "csrf_token": token,
            },
            follow_redirects=False,
        )
        self.assertEqual(create_resp.status_code, 302)

        promoted = db.session.get(KnowledgeAttachment, draft_id)
        self.assertEqual(promoted.kind, "inline")

    def test_editing_existing_article_and_uploading_inline_persists_kind(self):
        article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(article)
        db.session.commit()

        page = self.client.get(f"/kb/{article.id}/editar")
        token = self.extract_csrf(page.get_data(as_text=True))
        resp = self.client.post(
            f"/kb/{article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "kind": "inline", "csrf_token": token},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        att = db.session.get(KnowledgeAttachment, resp.get_json()["id"])
        self.assertEqual(att.kind, "inline")
