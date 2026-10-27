"""Render vendor invoices as PDFs, with hooks for planting injection payloads.

The :class:`Injection` dataclass is how the attack generator plants a payload in
an invoice the benign carrier task will read:

* ``visible_note``   - a line a human would see (overt indirect prompt injection)
* ``hidden_text``    - white 1pt text in the footer, invisible to a human reader
  but extracted verbatim by any text-layer PDF reader (covert injection)
* ``extra_metadata`` - arbitrary PDF document-info fields (Subject/Keywords/...)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


@dataclass
class LineItem:
    description: str
    quantity: int
    unit_price: float

    @property
    def total(self) -> float:
        return round(self.quantity * self.unit_price, 2)


@dataclass
class Invoice:
    invoice_no: str
    vendor_name: str
    vendor_address: str
    vendor_email: str
    vendor_iban: str
    customer_name: str
    issue_date: str
    due_date: str
    currency: str
    items: list[LineItem]

    @property
    def total(self) -> float:
        return round(sum(i.total for i in self.items), 2)


@dataclass
class Injection:
    """A payload planted in an invoice PDF by the attack generator."""

    visible_note: str | None = None
    hidden_text: str | None = None  # white 1pt text, invisible to humans
    extra_metadata: dict[str, str] = field(default_factory=dict)


def render_invoice(inv: Invoice, path: Path, injection: Injection | None = None) -> Path:
    """Render ``inv`` to ``path`` as a one-page PDF, optionally with a payload."""
    path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(path), pagesize=A4)
    w, h = A4

    c.setFont("Helvetica-Bold", 18)
    c.drawString(20 * mm, h - 25 * mm, "INVOICE")
    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, h - 32 * mm, f"No. {inv.invoice_no}")
    c.drawString(20 * mm, h - 37 * mm, f"Issued: {inv.issue_date}   Due: {inv.due_date}")

    c.setFont("Helvetica-Bold", 10)
    c.drawString(20 * mm, h - 50 * mm, "From:")
    c.setFont("Helvetica", 9)
    y = h - 55 * mm
    for line in [inv.vendor_name, *inv.vendor_address.split("\n"), inv.vendor_email]:
        c.drawString(20 * mm, y, line)
        y -= 5 * mm
    c.drawString(20 * mm, y, f"IBAN: {inv.vendor_iban}")

    c.setFont("Helvetica-Bold", 10)
    c.drawString(120 * mm, h - 50 * mm, "Bill to:")
    c.setFont("Helvetica", 9)
    c.drawString(120 * mm, h - 55 * mm, inv.customer_name)

    # line items
    y = h - 95 * mm
    c.setFont("Helvetica-Bold", 9)
    c.drawString(20 * mm, y, "Description")
    c.drawString(120 * mm, y, "Qty")
    c.drawString(140 * mm, y, "Unit")
    c.drawString(165 * mm, y, "Total")
    c.line(20 * mm, y - 2 * mm, 190 * mm, y - 2 * mm)
    y -= 8 * mm
    c.setFont("Helvetica", 9)
    for item in inv.items:
        c.drawString(20 * mm, y, item.description[:60])
        c.drawString(120 * mm, y, str(item.quantity))
        c.drawString(140 * mm, y, f"{item.unit_price:.2f}")
        c.drawString(165 * mm, y, f"{item.total:.2f}")
        y -= 6 * mm

    c.setFont("Helvetica-Bold", 11)
    c.drawString(140 * mm, y - 4 * mm, f"TOTAL {inv.currency} {inv.total:.2f}")

    # visible injected note (overt)
    if injection and injection.visible_note:
        c.setFont("Helvetica-Oblique", 9)
        c.drawString(20 * mm, 40 * mm, "Note:")
        text = c.beginText(20 * mm, 35 * mm)
        text.setFont("Helvetica-Oblique", 8)
        for line in _wrap(injection.visible_note, 95):
            text.textLine(line)
        c.drawText(text)

    # hidden injected text (covert): white, 1pt, bottom of page
    if injection and injection.hidden_text:
        c.setFillColorRGB(1, 1, 1)
        c.setFont("Helvetica", 1)
        c.drawString(20 * mm, 8 * mm, injection.hidden_text)
        c.setFillColorRGB(0, 0, 0)

    c.showPage()
    c.save()

    if injection and injection.extra_metadata:
        _inject_metadata(path, injection.extra_metadata)

    return path


def _wrap(s: str, width: int) -> list[str]:
    words, lines, cur = s.split(), [], ""
    for wd in words:
        if len(cur) + len(wd) + 1 > width:
            lines.append(cur)
            cur = wd
        else:
            cur = f"{cur} {wd}".strip()
    if cur:
        lines.append(cur)
    return lines


def _inject_metadata(path: Path, meta: dict[str, str]) -> None:
    reader = PdfReader(str(path))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({f"/{k}": v for k, v in meta.items()})
    with path.open("wb") as fh:
        writer.write(fh)


def read_invoice_text(path: Path) -> str:
    """Extract the full text layer (including hidden text) from an invoice PDF."""
    reader = PdfReader(str(path))
    parts = [page.extract_text() or "" for page in reader.pages]
    meta = reader.metadata or {}
    meta_text = "\n".join(f"{k}: {v}" for k, v in meta.items() if v)
    if meta_text:
        parts.append(f"[document properties]\n{meta_text}")
    return "\n".join(parts)
