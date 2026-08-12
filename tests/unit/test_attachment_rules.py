from app.detection.attachment_rules import (
    DangerousExtensionRule,
    ExecutableAttachmentRule,
    MacroEnabledDocumentRule,
)
from tests.unit.helpers import make_attachment, make_context


def test_dangerous_extension_detected():
    ctx = make_context(attachments=[make_attachment("invoice.exe")])
    result = DangerousExtensionRule().evaluate(ctx)
    assert result.matched


def test_executable_attachment_detected():
    ctx = make_context(attachments=[make_attachment("run.exe")])
    result = ExecutableAttachmentRule().evaluate(ctx)
    assert result.matched


def test_macro_enabled_document_detected():
    ctx = make_context(attachments=[make_attachment("invoice.docm")])
    result = MacroEnabledDocumentRule().evaluate(ctx)
    assert result.matched


def test_safe_pdf_not_flagged():
    ctx = make_context(attachments=[make_attachment("report.pdf")])
    assert not DangerousExtensionRule().evaluate(ctx).matched
    assert not ExecutableAttachmentRule().evaluate(ctx).matched
    assert not MacroEnabledDocumentRule().evaluate(ctx).matched
