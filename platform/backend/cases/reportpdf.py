"""
Typesetting for case reports.

A forensic report is read by counsel, by opposing counsel and possibly by a court, so it is
laid out as a document: a title page carrying the case identity and the handling caveat, a
table of contents, running headers, numbered pages with a stated total, and ruled tables.

The section content comes from `reporting.py` as Markdown — one source for both the
readable and the printed form, so the two cannot drift.

Offline by construction: the base-14 PDF fonts need no embedding and nothing here fetches
an asset. The enclave has no egress and a report generator that wanted a CDN would not be
deployable in it.
"""
from __future__ import annotations

import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (BaseDocTemplate, Frame, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)

INK = colors.HexColor("#111418")
RULE = colors.HexColor("#9aa4ae")
SOFT = colors.HexColor("#eef1f4")
ACCENT = colors.HexColor("#1f4e79")


def _styles():
    base = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Times-Bold",
                                fontSize=24, leading=29, textColor=INK, spaceAfter=6),
        "subtitle": ParagraphStyle("st", parent=base["Normal"], fontName="Times-Roman",
                                   fontSize=13, leading=17, alignment=TA_CENTER,
                                   textColor=INK),
        "caveat": ParagraphStyle("cv", parent=base["Normal"], fontName="Helvetica-Bold",
                                 fontSize=9, leading=12, alignment=TA_CENTER,
                                 textColor=colors.HexColor("#7a2222")),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold",
                             fontSize=14, leading=18, textColor=ACCENT,
                             spaceBefore=16, spaceAfter=7),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=11, leading=14, textColor=INK,
                             spaceBefore=11, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["Normal"], fontName="Times-Roman",
                               fontSize=10, leading=14, alignment=TA_JUSTIFY,
                               textColor=INK, spaceAfter=6),
        "bullet": ParagraphStyle("bl", parent=base["Normal"], fontName="Times-Roman",
                                 fontSize=10, leading=14, leftIndent=14,
                                 bulletIndent=4, textColor=INK, spaceAfter=3),
        "quote": ParagraphStyle("q", parent=base["Normal"], fontName="Times-Italic",
                                fontSize=10, leading=14, leftIndent=18, rightIndent=18,
                                textColor=INK, spaceAfter=6),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontName="Times-Roman",
                               fontSize=8.5, leading=11, textColor=INK),
        "cellhead": ParagraphStyle("ch", parent=base["Normal"],
                                   fontName="Helvetica-Bold", fontSize=8.5, leading=11,
                                   textColor=colors.white),
        "toc": ParagraphStyle("toc", parent=base["Normal"], fontName="Times-Roman",
                              fontSize=10.5, leading=16, textColor=INK),
    }
    return s


_INLINE = [
    (re.compile(r"\*\*(.+?)\*\*"), r"<b>\1</b>"),
    (re.compile(r"(?<!\w)\*(?!\s)(.+?)(?<!\s)\*(?!\w)"), r"<i>\1</i>"),
    (re.compile(r"`(.+?)`"), r'<font face="Courier" size="8.5">\1</font>'),
]


def _inline(text):
    """Markdown emphasis to reportlab markup, after escaping the XML metacharacters."""
    out = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    for pattern, repl in _INLINE:
        out = pattern.sub(repl, out)
    return out


def _table(rows, styles, width):
    head, body = rows[0], rows[1:]
    cols = len(head)
    data = [[Paragraph(_inline(c), styles["cellhead"]) for c in head]]
    for r in body:
        data.append([Paragraph(_inline(c), styles["cell"]) for c in r])
    # Sized from what the cells will actually measure, in the face each will be set in:
    # header cells are Helvetica-Bold and code spans are Courier, both wider per glyph
    # than the body face, and estimating against the wrong one wraps identifiers mid-token.
    from reportlab.pdfbase.pdfmetrics import stringWidth

    def _measured(text, header=False):
        bare = re.sub(r"[*`]", "", text)
        font = "Helvetica-Bold" if header else ("Courier" if "`" in text
                                                else "Times-Roman")
        return stringWidth(bare, font, 8.5)

    pad = 12
    need = [max([_measured(rows[0][c], header=True)]
                + [_measured(r[c]) for r in rows[1:]]) + pad for c in range(cols)]

    # Proportional share rather than a flat scale: when the columns together want more
    # than the page, shrinking all of them equally wraps a short identifier to make room
    # for a long filename. Columns that fit their fair share are settled at what they
    # need, and only the greedy ones divide what is left.
    widths = [0.0] * cols
    pending, remaining = list(range(cols)), width
    while pending:
        fair = remaining / len(pending)
        settled = [c for c in pending if need[c] <= fair]
        if not settled:
            for c in pending:
                widths[c] = fair
            break
        for c in settled:
            widths[c] = need[c]
            remaining -= need[c]
        pending = [c for c in pending if c not in settled]
    scale = width / sum(widths)
    widths = [w * scale for w in widths]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _split_row(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def markdown_to_flowables(md, styles, width):
    """Render the section Markdown the report module already produces."""
    flow, lines, i = [], md.splitlines(), 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            i += 1
            continue
        if line.startswith("# "):
            # The title, the case line and the generation line are all on the title page
            # and in the running header; repeating them opens the body with duplication.
            i += 1
            while i < len(lines) and not lines[i].startswith("## "):
                i += 1
            continue
        if line.startswith("## "):
            flow.append(Paragraph(_inline(line[3:]), styles["h1"]))
            i += 1
            continue
        if line.startswith("### "):
            flow.append(Paragraph(_inline(line[4:]), styles["h2"]))
            i += 1
            continue
        if line.strip() in ("---", "***"):
            i += 1
            continue                       # section rules are carried by the headings
        if line.startswith("> "):
            flow.append(Paragraph(_inline(line[2:]), styles["quote"]))
            i += 1
            continue
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = _split_row(lines[i])
                if not all(set(c) <= set("-: ") for c in cells):
                    rows.append(cells)
                i += 1
            if rows:
                width_cols = max(len(r) for r in rows)
                rows = [r + [""] * (width_cols - len(r)) for r in rows]
                flow.append(Spacer(1, 3))
                flow.append(_table(rows, styles, width))
                flow.append(Spacer(1, 7))
            continue
        if re.match(r"^\s*[-*]\s+", line):
            flow.append(Paragraph(_inline(re.sub(r"^\s*[-*]\s+", "", line)),
                                  styles["bullet"], bulletText="•"))
            i += 1
            continue
        if re.match(r"^\s*\d+\.\s+", line):
            n = re.match(r"^\s*(\d+)\.\s+", line).group(1)
            flow.append(Paragraph(_inline(re.sub(r"^\s*\d+\.\s+", "", line)),
                                  styles["bullet"], bulletText=f"{n}."))
            i += 1
            continue
        para = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(
                r"^(#|\||>|\s*[-*]\s|\s*\d+\.\s|---)", lines[i]):
            para.append(lines[i].rstrip())
            i += 1
        flow.append(Paragraph(_inline(" ".join(para)), styles["body"]))
    return flow


class _Doc(BaseDocTemplate):
    """Two page templates: a bare title page, then the running body."""

    def __init__(self, buf, header, footer, **kw):
        super().__init__(buf, pagesize=LETTER, leftMargin=0.9 * inch,
                         rightMargin=0.9 * inch, topMargin=0.95 * inch,
                         bottomMargin=0.85 * inch, title=header, author="IR Platform",
                         **kw)
        self.header_text, self.footer_text = header, footer
        # Zero padding: the frame's default 6pt inset makes the usable width narrower than
        # `doc.width`, and a table built to that width is wider than its frame — which
        # reportlab cannot split across pages, so a long table raises instead of paginating.
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height,
                      id="body", leftPadding=0, rightPadding=0,
                      topPadding=0, bottomPadding=0)
        self.addPageTemplates([
            PageTemplate(id="title", frames=[frame]),
            PageTemplate(id="body", frames=[frame], onPage=self._decorate),
        ])

    def _decorate(self, canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#5a6470"))
        y = self.pagesize[1] - self.topMargin + 16
        canvas.drawString(self.leftMargin, y, self.header_text)
        canvas.drawRightString(self.pagesize[0] - self.rightMargin, y, self.footer_text)
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.4)
        canvas.line(self.leftMargin, y - 4, self.pagesize[0] - self.rightMargin, y - 4)
        # "Page 3 of 17" rather than "Page 3": a reader must be able to tell that a
        # document is complete, which is the point of paginating an evidentiary record.
        canvas.drawString(self.leftMargin, self.bottomMargin - 22,
                          "Generated by the IR Platform from case evidence")
        canvas.restoreState()

    def build_numbered(self, story):
        super().build(story, canvasmaker=_NumberedCanvas)


class _NumberedCanvas(pdfcanvas.Canvas):
    """Holds every page until the end so each can be stamped with the true total.

    A reader must be able to tell an evidentiary document is complete, and "Page 3" alone
    cannot say that.
    """

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self._pages = []

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            if self._pageNumber > 1:          # the title page carries no folio
                self.setFont("Helvetica", 7.5)
                self.setFillColor(colors.HexColor("#5a6470"))
                self.drawCentredString(LETTER[0] / 2, 0.62 * inch,
                                       f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def render(md, *, title, subtitle, meta_rows, caveat, toc_entries):
    """The whole document: title page, contents, then the body."""
    from io import BytesIO

    styles = _styles()
    buf = BytesIO()
    doc = _Doc(buf, header=title, footer=subtitle)
    width = doc.width

    story = [Spacer(1, 1.5 * inch),
             Paragraph(_inline(title), styles["title"]),
             Spacer(1, 6),
             Paragraph(_inline(subtitle), styles["subtitle"]),
             Spacer(1, 0.55 * inch)]
    if meta_rows:
        story.append(_table([["Field", "Value"]] + meta_rows, styles, width * 0.8))
    story += [Spacer(1, 0.5 * inch), Paragraph(caveat, styles["caveat"]),
              NextPageTemplate("body"), PageBreak()]

    if toc_entries:
        story.append(Paragraph("Contents", styles["h1"]))
        for n, entry in enumerate(toc_entries, 1):
            story.append(Paragraph(f"{n}. {_inline(entry)}", styles["toc"]))
        story.append(PageBreak())

    story += markdown_to_flowables(md, styles, width)
    doc.build_numbered(story)
    return buf.getvalue()
