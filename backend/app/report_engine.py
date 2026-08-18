"""
Generates a real, VAPT-style PDF static analysis report from a scan result
dict (the same shape StaticAnalyzer.analyze_apk() returns / the frontend
holds as activeFullReportObj).

Replaces the previous /api/report/pdf implementation, which wrote a plain
.txt file and relied on the frontend renaming the downloaded blob to
".pdf" — the file's actual content was never a PDF, so it failed to open
in any PDF viewer. This module produces an actual application/pdf byte
stream via reportlab.

All text pulled from the scan result can originate from an untrusted,
potentially malicious APK (class names, manifest strings, secret values,
etc.), so every dynamic value is XML-escaped before being placed into a
Paragraph — reportlab Paragraphs interpret a small HTML-like markup
subset, and unescaped attacker-controlled content could otherwise break
layout or inject unintended markup.
"""

import io
import textwrap
from datetime import datetime
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Circle, Drawing, Rect, String
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
NAVY = colors.HexColor("#0F2A4A")
NAVY_DARK = colors.HexColor("#0A1E36")
ACCENT_BLUE = colors.HexColor("#1868B7")
GOLD_HEX = "#C9A227"
GOLD = colors.HexColor(GOLD_HEX)
LIGHT_PANEL = colors.HexColor("#F2F5FA")
LIGHT_BLUE = colors.HexColor("#E4ECF7")
SLATE = colors.HexColor("#33414F")
MUTED = colors.HexColor("#5B6B7C")
GRID_LINE = colors.HexColor("#C7D2DE")

PAGE_W, PAGE_H = A4
CONTENT_W = PAGE_W - 4 * cm  # left+right margins = 2cm each
HERO_H = 8.6 * cm            # cover page's full-bleed navy header band
COVER_FOOTER_H = 1.0 * cm    # cover page's full-bleed footer band

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_HEX = {
    "CRITICAL": "#7A121E",
    "HIGH": "#D64545",
    "MEDIUM": "#E0954B",
    "LOW": "#2E8B57",
    "INFO": "#64748B",
}
SEVERITY_COLORS = {k: colors.HexColor(v) for k, v in SEVERITY_HEX.items()}

IMPACT_BY_SEVERITY = {
    "CRITICAL": "If exploited, this issue could lead to complete compromise of application data, "
                "user credentials, or backend systems the application communicates with.",
    "HIGH": "If exploited, this issue could lead to significant exposure of sensitive data or a "
            "meaningful weakening of the application's security controls.",
    "MEDIUM": "If exploited, this issue could contribute to a broader attack chain or expose "
              "limited sensitive information.",
    "LOW": "This issue represents a minor deviation from security best practice with limited "
           "standalone impact.",
    "INFO": "This is an informational observation with no direct exploitable impact on its own.",
}
LIKELIHOOD_BY_SEVERITY = {
    "CRITICAL": "High — actively exploitable with commonly available tools and minimal attacker "
                "sophistication.",
    "HIGH": "Moderate to High — exploitable by an attacker with access to the application package "
            "or a rooted/emulated device.",
    "MEDIUM": "Moderate — typically requires additional conditions or reverse-engineering effort "
              "to exploit.",
    "LOW": "Low — requires significant effort or specific conditions to exploit.",
    "INFO": "Not applicable — observational finding only.",
}

_TOC_SKIP = {"Table of Contents", "Disclaimer"}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _esc(value) -> str:
    return _xml_escape(str(value) if value is not None else "")


def _severity_rank(sev: str) -> int:
    sev = (sev or "INFO").upper()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _score_color(score) -> colors.Color:
    try:
        score = float(score)
    except (TypeError, ValueError):
        return MUTED
    if score >= 80:
        return colors.HexColor("#2E8B57")
    if score >= 50:
        return colors.HexColor("#E0954B")
    return colors.HexColor("#C0392B")


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
def _collect_observations(result: dict, include_third_party: bool = False) -> list:
    """Normalizes findings + manifest issues + certificate issues + high-severity
    secrets into one severity-sorted list of report observations."""
    obs = []

    for f in result.get("findings", []) or []:
        sev = (f.get("severity") or "INFO").upper()
        if sev == "SAFE":
            continue  # a detected defensive control, not a vulnerability
        if not include_third_party and f.get("scope") == "third_party":
            continue
        obs.append({
            "title": f.get("title") or "Static Analysis Finding",
            "severity": sev if sev in SEVERITY_ORDER else "INFO",
            "category": f.get("owasp") or f.get("category") or "Static Analysis Finding",
            "target": f.get("target") or "N/A",
            "description": f.get("description") or "",
            "remediation": f.get("remediation") or "",
            "reference": f.get("owasp"),
            "evidence": f.get("code") or "",
        })

    for m in result.get("manifest_analysis", []) or []:
        sev = (m.get("severity") or "INFO").upper()
        obs.append({
            "title": m.get("issue") or "Manifest Misconfiguration",
            "severity": sev if sev in SEVERITY_ORDER else "INFO",
            "category": "Manifest Configuration",
            "target": "AndroidManifest.xml",
            "description": m.get("description") or "",
            "remediation": m.get("remediation") or "",
            "reference": None,
            "evidence": m.get("evidence") or "",
        })

    cert = result.get("certificate", {}) or {}
    for c in cert.get("issues", []) or []:
        sev = (c.get("severity") or "INFO").upper()
        obs.append({
            "title": c.get("issue") or "Certificate Issue",
            "severity": sev if sev in SEVERITY_ORDER else "INFO",
            "category": c.get("owasp") or "Certificate / Signing",
            "target": "APK Signing Certificate",
            "description": c.get("description") or "",
            "remediation": c.get("remediation") or "",
            "reference": c.get("link"),
            "evidence": c.get("evidence") or "",
        })

    for s in result.get("secrets", []) or []:
        sev = (s.get("severity") or "INFO").upper()
        if sev not in ("HIGH", "CRITICAL"):
            continue
        if not include_third_party and s.get("scope") == "third_party":
            continue
        # Full, unredacted value shown as evidence/PoC — by design, per the
        # operator's own instruction: a VAPT report needs the actual
        # artifact to verify/triage the finding, the same way tools like
        # TruffleHog/Gitleaks surface full matched secrets. The exported
        # PDF should therefore be handled with the same sensitivity as the
        # scanned APK/source itself.
        obs.append({
            "title": f"Hardcoded Secret Detected — {s.get('type', 'Unknown Type')}",
            "severity": sev if sev in SEVERITY_ORDER else "HIGH",
            "category": "Hardcoded Secret Exposure",
            "target": s.get("file") or "N/A",
            "description": "A potential secret was found embedded in the application package. "
                           "The full matched value is included below as evidence — treat this "
                           "report as confidential.",
            "remediation": "Remove hardcoded credentials/keys from the client. Rotate any exposed "
                           "key immediately and load secrets from a secure server-side store or "
                           "runtime secret manager instead.",
            "reference": None,
            "evidence": f"{s.get('type', 'Secret')}: {s.get('value', '')}",
        })

    obs.sort(key=lambda o: _severity_rank(o["severity"]))
    for i, o in enumerate(obs, start=1):
        o["id"] = f"DO-{i}"
    return obs


def _severity_counts(observations: list) -> dict:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for o in observations:
        counts[o["severity"]] = counts.get(o["severity"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
def _build_styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="CoverKicker", fontName="Helvetica-Bold", fontSize=10,
                           textColor=ACCENT_BLUE, alignment=TA_CENTER, spaceAfter=10))
    ss.add(ParagraphStyle(name="CoverTitle", fontName="Times-Bold", fontSize=25,
                           textColor=NAVY, alignment=TA_CENTER, spaceAfter=6, leading=30))
    ss.add(ParagraphStyle(name="CoverMeta", fontName="Helvetica", fontSize=10,
                           textColor=MUTED, alignment=TA_CENTER, spaceAfter=2))
    ss.add(ParagraphStyle(name="H1", fontName="Times-Bold", fontSize=17,
                           textColor=NAVY, spaceBefore=4, spaceAfter=12))
    ss.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=12.5,
                           textColor=ACCENT_BLUE, spaceBefore=12, spaceAfter=7))
    ss.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=9.5,
                           textColor=SLATE, leading=13.5, spaceAfter=8))
    ss.add(ParagraphStyle(name="Label", fontName="Helvetica-Bold", fontSize=8.3,
                           textColor=NAVY, spaceBefore=6, spaceAfter=2))
    ss.add(ParagraphStyle(name="CellSm", fontName="Helvetica", fontSize=8.5,
                           textColor=SLATE, leading=11))
    ss.add(ParagraphStyle(name="ObsTag", fontName="Helvetica-Bold", fontSize=8,
                           textColor=ACCENT_BLUE, spaceAfter=2))
    ss.add(ParagraphStyle(name="Evidence", fontName="Courier", fontSize=8.1,
                           textColor=colors.HexColor("#D9E6F2"), leading=11.5))
    return ss


# ---------------------------------------------------------------------------
# Visual building blocks
# ---------------------------------------------------------------------------
def _hr(color_=GOLD, width_cm=6.0, thickness=1.6, centered=True):
    t = Table([[""]], colWidths=[width_cm * cm], rowHeights=[thickness])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color_),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    t.hAlign = "CENTER" if centered else "LEFT"
    return t


def _section_heading(text: str, styles) -> list:
    """A top-level (H1) section heading with a short gold accent rule beneath
    it. Kept as a plain-text Paragraph (no inline markup decoration) so
    _ReportDoc.afterFlowable()'s getPlainText() TOC/outline matching stays
    exact — decoration is a separate sibling flowable instead."""
    return [
        Paragraph(_esc(text), styles["H1"]),
        _hr(GOLD, width_cm=2.4, thickness=1.8, centered=False),
        Spacer(1, 10),
    ]


def _table_style(header_bg=ACCENT_BLUE) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_PANEL]),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_LINE),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])


def _callout(text: str, accent=NAVY, bg=LIGHT_PANEL, fg=NAVY) -> Table:
    """A left-accent-bar callout box (disclaimer banner / scope-details label)."""
    t = Table([["", text]], colWidths=[0.22 * cm, CONTENT_W - 0.22 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), accent),
        ("BACKGROUND", (1, 0), (1, -1), bg),
        ("TEXTCOLOR", (1, 0), (1, -1), fg),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (1, 0), (1, -1), 10.5),
        ("LEFTPADDING", (1, 0), (1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 0),
    ]))
    return t


def _p(text, style) -> Paragraph:
    return Paragraph(_esc(text), style)


EVIDENCE_MAX_CHARS = 600


def _evidence_block(text: str, styles) -> Table:
    """A dark, monospace 'terminal' box for Evidence / Proof of Concept —
    the raw code snippet, manifest attribute, certificate detail, or
    (deliberately, unredacted — see _collect_observations) secret value
    backing an observation."""
    text = (text or "").strip()
    if len(text) > EVIDENCE_MAX_CHARS:
        text = text[:EVIDENCE_MAX_CHARS] + " …[truncated]"
    # reportlab's Paragraph only wraps at whitespace by default — a long
    # space-less run (a secret, a hash, minified code) would otherwise
    # overflow the box instead of wrapping. Hard-wrap first so it can't.
    wrapped_lines = []
    for raw_line in text.splitlines() or [""]:
        wrapped_lines.extend(
            textwrap.wrap(raw_line, width=76, break_long_words=True, break_on_hyphens=False) or [""]
        )
    escaped = "<br/>".join(_esc(line) for line in wrapped_lines)
    p = Paragraph(escaped, styles["Evidence"])
    t = Table([[p]], colWidths=[CONTENT_W - 0.22 * cm - 12])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F1C29")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _sev_pill(sev: str) -> Drawing:
    """A small rounded 'chip' badge — used in tables and observation cards."""
    w, h = 62, 16
    d = Drawing(w, h)
    color_ = SEVERITY_COLORS.get(sev, MUTED)
    d.add(Rect(0, 0, w, h, rx=8, ry=8, fillColor=color_, strokeColor=None))
    d.add(String(w / 2, 4.6, sev, fontName="Helvetica-Bold", fontSize=7.4,
                 fillColor=colors.white, textAnchor="middle"))
    return d


def _severity_legend_rows(counts: dict, present: list) -> list:
    return [f"{s} ({counts.get(s, 0)})" for s in present]


def _executive_panel(counts: dict, security_score, highest: str) -> Drawing:
    """Composite 'dashboard' graphic: severity donut + score gauge + risk badge."""
    W, H = 480, 148
    d = Drawing(W, H)
    d.add(Rect(0, 0, W, H, rx=10, ry=10, fillColor=LIGHT_PANEL, strokeColor=GRID_LINE, strokeWidth=0.6))

    # --- severity donut (left) ---
    present = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    total = sum(counts.values())
    data = [counts[s] for s in present] if present else [1]
    if not present:
        present = ["INFO"]

    pie = Pie()
    pie.x, pie.y = 18, 14
    pie.width = pie.height = 108
    pie.data = data
    pie.labels = None
    pie.slices.strokeColor = colors.white
    pie.slices.strokeWidth = 1.6
    for i, s in enumerate(present):
        pie.slices[i].fillColor = SEVERITY_COLORS.get(s, MUTED)
    d.add(pie)
    hole = Circle(18 + 54, 14 + 54, 32, fillColor=LIGHT_PANEL, strokeColor=LIGHT_PANEL)
    d.add(hole)
    d.add(String(72, 62, str(total), fontName="Times-Bold", fontSize=18, fillColor=NAVY, textAnchor="middle"))
    d.add(String(72, 48, "FINDINGS", fontName="Helvetica", fontSize=6.2, fillColor=MUTED, textAnchor="middle"))

    legend_x = 142
    legend_labels = _severity_legend_rows(counts, present)
    for i, (s, label) in enumerate(zip(present, legend_labels)):
        y = H - 26 - i * 16
        d.add(Rect(legend_x, y, 9, 9, fillColor=SEVERITY_COLORS.get(s, MUTED), strokeColor=None))
        d.add(String(legend_x + 14, y + 1.2, label, fontName="Helvetica", fontSize=7.6, fillColor=SLATE))

    # --- security score gauge (middle) ---
    gx, gy, gw, gh = 250, 60, 108, 13
    d.add(Rect(gx, gy, gw, gh, rx=6.5, ry=6.5, fillColor=colors.HexColor("#E3E8EF"), strokeColor=None))
    try:
        score = max(0, min(100, float(security_score)))
    except (TypeError, ValueError):
        score = 0
    fill_w = max(gw * (score / 100.0), gh) if score > 0 else 0
    if fill_w > 0:
        d.add(Rect(gx, gy, min(fill_w, gw), gh, rx=6.5, ry=6.5,
                    fillColor=_score_color(score), strokeColor=None))
    d.add(String(gx + gw / 2, gy + gh + 14, f"{security_score}/100",
                 fontName="Times-Bold", fontSize=14.5, fillColor=NAVY, textAnchor="middle"))
    d.add(String(gx + gw / 2, gy - 12, "SECURITY SCORE",
                 fontName="Helvetica", fontSize=6.6, fillColor=MUTED, textAnchor="middle"))

    # --- overall risk badge (right) ---
    px, py, pw, ph = 384, 52, 78, 30
    pill_color = SEVERITY_COLORS.get(highest, MUTED)
    d.add(Rect(px, py, pw, ph, rx=15, ry=15, fillColor=pill_color, strokeColor=None))
    d.add(String(px + pw / 2, py + ph / 2 - 4, highest,
                 fontName="Helvetica-Bold", fontSize=11.5, fillColor=colors.white, textAnchor="middle"))
    d.add(String(px + pw / 2, py + ph + 10, "OVERALL RISK",
                 fontName="Helvetica", fontSize=6.6, fillColor=MUTED, textAnchor="middle"))

    return d


def _draw_badge_on_dark(canvas_obj, cx, cy):
    """Draws the Cerberus-ASF emblem (three linked rings) directly on the
    canvas — used inside the cover page's full-bleed hero band."""
    canvas_obj.saveState()
    canvas_obj.setStrokeColor(GOLD)
    canvas_obj.setLineWidth(1.3)
    canvas_obj.circle(cx, cy, 1.55 * cm, stroke=1, fill=0)
    head_fill = colors.HexColor("#EEF1F6")
    positions = [(-1.05 * cm, 0, 0.56 * cm), (0, 0.16 * cm, 0.72 * cm), (1.05 * cm, 0, 0.56 * cm)]
    for dx, dy, r in positions:
        canvas_obj.setFillColor(head_fill)
        canvas_obj.setStrokeColor(GOLD)
        canvas_obj.setLineWidth(0.8)
        canvas_obj.circle(cx + dx, cy + dy, r, stroke=1, fill=1)
    canvas_obj.restoreState()


def _draw_cover_furniture(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFillColor(NAVY)
    canvas_obj.rect(0, PAGE_H - HERO_H, PAGE_W, HERO_H, stroke=0, fill=1)
    canvas_obj.setFillColor(GOLD)
    canvas_obj.rect(0, PAGE_H - HERO_H - 0.12 * cm, PAGE_W, 0.12 * cm, stroke=0, fill=1)

    cx = PAGE_W / 2
    ring_cy = PAGE_H - HERO_H / 2 + 1.0 * cm
    _draw_badge_on_dark(canvas_obj, cx, ring_cy)

    canvas_obj.setFillColor(colors.white)
    canvas_obj.setFont("Times-Bold", 21)
    canvas_obj.drawCentredString(cx, ring_cy - 2.55 * cm, "CERBERUS-ASF")
    canvas_obj.setFillColor(colors.HexColor("#D7DEE8"))
    canvas_obj.setFont("Helvetica", 7.4)
    canvas_obj.drawCentredString(cx, ring_cy - 2.95 * cm, "S T A T I C   ·   D Y N A M I C   ·   A I - A S S I S T E D   M A S T   P L A T F O R M")

    canvas_obj.setFillColor(NAVY)
    canvas_obj.rect(0, 0, PAGE_W, COVER_FOOTER_H, stroke=0, fill=1)
    canvas_obj.setFillColor(GOLD)
    canvas_obj.rect(0, COVER_FOOTER_H, PAGE_W, 0.06 * cm, stroke=0, fill=1)
    canvas_obj.setFillColor(colors.white)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawString(2 * cm, COVER_FOOTER_H / 2 - 3, "CONFIDENTIAL")
    canvas_obj.drawRightString(PAGE_W - 2 * cm, COVER_FOOTER_H / 2 - 3, "Cerberus-ASF Security Platform")
    canvas_obj.restoreState()


def _draw_page_furniture(canvas_obj, doc):
    canvas_obj.saveState()
    band_h = 1.15 * cm
    canvas_obj.setFillColor(NAVY)
    canvas_obj.rect(0, PAGE_H - band_h, PAGE_W, band_h, stroke=0, fill=1)
    canvas_obj.setFillColor(GOLD)
    canvas_obj.rect(0, PAGE_H - band_h - 0.07 * cm, PAGE_W, 0.07 * cm, stroke=0, fill=1)
    canvas_obj.setFillColor(colors.white)
    canvas_obj.setFont("Helvetica-Bold", 9)
    canvas_obj.drawString(2 * cm, PAGE_H - band_h / 2 - 3, "CERBERUS-ASF")
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawRightString(PAGE_W - 2 * cm, PAGE_H - band_h / 2 - 3,
                                "Static Analysis Report  ·  Confidential")

    footer_h = 0.95 * cm
    canvas_obj.setFillColor(NAVY)
    canvas_obj.rect(0, 0, PAGE_W, footer_h, stroke=0, fill=1)
    canvas_obj.setFillColor(GOLD)
    canvas_obj.rect(0, footer_h, PAGE_W, 0.05 * cm, stroke=0, fill=1)
    canvas_obj.setFillColor(colors.white)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawString(2 * cm, footer_h / 2 - 3, datetime.now().strftime("%Y-%m-%d"))
    canvas_obj.drawCentredString(PAGE_W / 2, footer_h / 2 - 3, f"Page {doc.page}")
    canvas_obj.drawRightString(PAGE_W - 2 * cm, footer_h / 2 - 3, "Cerberus-ASF")
    canvas_obj.restoreState()


class _ReportDoc(BaseDocTemplate):
    """BaseDocTemplate subclass that feeds H1/H2 headings into the TOC and
    the PDF outline, resolved via multiBuild()'s two-pass layout."""

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        text = flowable.getPlainText()
        if text in _TOC_SKIP:
            return
        if style_name == "H1":
            key = f"h1-{self.page}-{id(flowable)}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=0, closed=False)
            self.notify("TOCEntry", (0, text, self.page, key))
        elif style_name == "H2":
            key = f"h2-{self.page}-{id(flowable)}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=1, closed=False)
            self.notify("TOCEntry", (1, text, self.page, key))


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------
def _build_cover(styles, app_name, package_name):
    return [
        Spacer(1, 1.3 * cm),
        Paragraph("S T A T I C&nbsp;&nbsp; A N A L Y S I S&nbsp;&nbsp; R E P O R T", styles["CoverKicker"]),
        _p(app_name, styles["CoverTitle"]),
        Spacer(1, 0.1 * cm),
        _hr(GOLD, width_cm=5.5, thickness=1.6),
        Spacer(1, 0.4 * cm),
        _p(f"Package: {package_name}", styles["CoverMeta"]),
        Paragraph(datetime.now().strftime("%d %B %Y"), styles["CoverMeta"]),
    ]


def _build_disclaimer(styles):
    text = (
        "This static analysis report was generated by Cerberus-ASF, an open-source mobile "
        "application security testing platform. Cerberus-ASF is not affiliated with any company "
        "or organization, and this report is provided as an independent, automated output of the "
        "tool.<br/><br/>"
        "This report is for informational purposes only and should not be considered a "
        "comprehensive or exhaustive security assessment. Security vulnerabilities can change over "
        "time, and new vulnerabilities may be discovered after this report was generated. Several "
        "findings in this report are produced by automated static-analysis heuristics (pattern and "
        "AST-based rules) and, where enabled, AI-assisted triage — both can produce false positives "
        "and false negatives and should be independently verified by a qualified analyst before "
        "acting on them.<br/><br/>"
        "Cerberus-ASF does not guarantee that the findings in this report are accurate or complete, "
        "and is not responsible for any damages or losses that may result from the use of this "
        "report."
    )
    return [
        *_section_heading("Disclaimer", styles),
        _callout("DISCLAIMER"),
        Spacer(1, 10),
        Paragraph(text, styles["Body"]),
    ]


def _build_toc(styles):
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name="TOC0", fontSize=11.5, leading=18, leftIndent=0,
                       fontName="Helvetica-Bold", textColor=NAVY),
        ParagraphStyle(name="TOC1", fontSize=9.5, leading=15, leftIndent=16,
                       fontName="Helvetica", textColor=SLATE),
    ]
    return [*_section_heading("Table of Contents", styles), toc]


def _build_project_summary(styles, app_name, package_name, security_score, counts, highest, ai_meta):
    story = _section_heading("Project Summary", styles)
    story.append(Paragraph(
        f"A static analysis of <b>{_esc(app_name)}</b> was performed using Cerberus-ASF to identify "
        "security weaknesses and establish the current security posture of the application, "
        "assessed against the OWASP Mobile Top 10 categories.", styles["Body"]))
    story.append(Spacer(1, 6))
    story.append(_callout("SCOPE DETAILS"))
    scope_table = Table(
        [["Target", "Description"],
         [_p(package_name, styles["CellSm"]),
          _p(f"{app_name} — Android Application Package (APK)", styles["CellSm"])]],
        colWidths=[5 * cm, CONTENT_W - 5 * cm],
    )
    scope_table.setStyle(_table_style())
    story.append(scope_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("EXECUTIVE RISK OVERVIEW", styles["H2"]))
    total = sum(counts.values())
    parts = [f"{counts[s]} {s.title()}" for s in SEVERITY_ORDER if counts[s] > 0]
    summary_line = ", ".join(parts) if parts else "no"
    story.append(Paragraph(
        f"During this assessment, {summary_line} risk observation(s) were identified "
        f"({total} total).", styles["Body"]))
    if ai_meta and ai_meta.get("performed"):
        story.append(Paragraph(
            f"AI Deep Scan was enabled for this scan using <b>{_esc(ai_meta.get('llm', 'N/A'))}</b>, "
            "adding false-positive triage and semantic source review on top of the structural "
            "findings below.", styles["Body"]))
    story.append(Spacer(1, 8))

    panel = _executive_panel(counts, security_score, highest)
    panel.hAlign = "CENTER"
    story.append(panel)
    return story


def _build_app_metadata(styles, app_info, file_info, security_score):
    story = _section_heading("Application Overview", styles)
    story.append(Paragraph("Application Metadata", styles["H2"]))
    rows = [
        ["Application Name", app_info.get("app_name", "Unknown")],
        ["Package Name", app_info.get("package_name", "Unknown")],
        ["Version", f"{app_info.get('version_name', 'Unknown')} ({app_info.get('version_code', 'Unknown')})"],
        ["Min / Target SDK", f"{app_info.get('min_sdk', 'Unknown')} / {app_info.get('target_sdk', 'Unknown')}"],
        ["Main Activity", app_info.get("main_activity", "Unknown")],
        ["Native Architectures", app_info.get("native_architectures", "Unknown")],
        ["File Size", file_info.get("size", "Unknown")],
        ["SHA-256", file_info.get("sha256", "Unknown")],
        ["Security Score", f"{security_score}/100"],
    ]
    body_rows = [[_p(name, styles["CellSm"]), _p(value, styles["CellSm"])] for name, value in rows]
    t = Table([["Name", "Value"]] + body_rows, colWidths=[5 * cm, CONTENT_W - 5 * cm])
    t.setStyle(_table_style())
    story.append(t)
    story.append(Spacer(1, 16))
    return story


def _build_app_structure(styles, components, permissions, apk_id):
    story = [Paragraph("Application Structure", styles["H2"])]
    dangerous = sum(1 for p in permissions if p.get("status") == "DANGEROUS")
    frameworks = sorted({f.get("framework", "?") for f in apk_id}) or ["None detected"]

    def comp(name):
        c = components.get(name, {}) or {}
        return f"{c.get('total', 0)} ({c.get('exported', 0)} exported)"

    rows = [
        ["Activities", comp("activities")],
        ["Services", comp("services")],
        ["Broadcast Receivers", comp("receivers")],
        ["Content Providers", comp("providers")],
        ["Declared Permissions", f"{len(permissions)} total ({dangerous} dangerous)"],
        ["Frameworks / SDKs Identified", ", ".join(frameworks)],
    ]
    body_rows = [[_p(name, styles["CellSm"]), _p(value, styles["CellSm"])] for name, value in rows]
    t = Table([["Name", "Value"]] + body_rows, colWidths=[5 * cm, CONTENT_W - 5 * cm])
    t.setStyle(_table_style())
    story.append(t)
    return story


def _build_observations_summary(styles, observations):
    story = _section_heading("Observations Summary", styles)
    if not observations:
        story.append(Paragraph(
            "No security observations were identified during this scan.", styles["Body"]))
        return story

    rows = [["ID", "Security Finding", "Area Identified", "Severity"]]
    for o in observations:
        rows.append([o["id"], _p(o["title"], styles["CellSm"]), _p(o["target"], styles["CellSm"]), _sev_pill(o["severity"])])
    t = Table(rows, colWidths=[1.5 * cm, 8.3 * cm, 4.5 * cm, CONTENT_W - 1.5 * cm - 8.3 * cm - 4.5 * cm],
               repeatRows=1)
    style = _table_style()
    style.add("VALIGN", (3, 1), (3, -1), "MIDDLE")
    style.add("ALIGN", (3, 1), (3, -1), "CENTER")
    t.setStyle(style)
    story.append(t)
    return story


def _build_detailed_observations(styles, observations):
    story = _section_heading("Detailed Observations", styles)
    if not observations:
        story.append(Paragraph(
            "No security observations were identified during this scan.", styles["Body"]))
        return story

    for o in observations:
        inner = [
            Paragraph(f"OBSERVATION&nbsp;{o['id']}", styles["ObsTag"]),
            Paragraph(_esc(o["title"]), styles["H2"]),
        ]
        meta = Table([[
            _p(f"Target: {o['target']}", styles["CellSm"]),
            _p(f"Category: {o['category']}", styles["CellSm"]),
            _sev_pill(o["severity"]),
        ]], colWidths=[7.4 * cm, 6.6 * cm, CONTENT_W - 7.4 * cm - 6.6 * cm])
        meta.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (2, 0), (2, 0), "CENTER"),
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_PANEL),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        inner.append(meta)
        inner.append(Spacer(1, 8))

        inner.append(Paragraph("DESCRIPTION", styles["Label"]))
        inner.append(_p(o["description"] or "N/A", styles["Body"]))
        if o.get("evidence"):
            inner.append(Paragraph("EVIDENCE / PROOF OF CONCEPT", styles["Label"]))
            inner.append(_evidence_block(o["evidence"], styles))
            inner.append(Spacer(1, 4))
        inner.append(Paragraph("IMPACT", styles["Label"]))
        inner.append(Paragraph(IMPACT_BY_SEVERITY.get(o["severity"], IMPACT_BY_SEVERITY["INFO"]), styles["Body"]))
        inner.append(Paragraph("LIKELIHOOD", styles["Label"]))
        inner.append(Paragraph(LIKELIHOOD_BY_SEVERITY.get(o["severity"], LIKELIHOOD_BY_SEVERITY["INFO"]), styles["Body"]))
        inner.append(Paragraph("RECOMMENDATION", styles["Label"]))
        inner.append(_p(o["remediation"] or "N/A", styles["Body"]))
        if o.get("reference"):
            inner.append(Paragraph("REFERENCE", styles["Label"]))
            inner.append(_p(o["reference"], styles["Body"]))

        card = Table([["", inner]], colWidths=[0.22 * cm, CONTENT_W - 0.22 * cm])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), SEVERITY_COLORS.get(o["severity"], MUTED)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (0, -1), 0),
            ("RIGHTPADDING", (0, 0), (0, -1), 0),
            ("LEFTPADDING", (1, 0), (1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(KeepTogether(card))
        story.append(Spacer(1, 14))
    return story


def _build_appendix(styles, ai_meta):
    story = _section_heading("Appendix", styles)

    story.append(Paragraph("Methodology", styles["H2"]))
    story.append(Paragraph(
        "Cerberus-ASF's static analysis pipeline decompiles the target APK with jadx, then runs "
        "three independent detection layers over the result: tree-sitter AST-based structural "
        "rules (covering insecure cryptography, SQL injection risk, insecure logging, clipboard "
        "exposure, insecure random number generation, and dynamic bytecode loading), a manifest "
        "and certificate/signature audit (apktool/aapt/apksigner — exported components, debug/"
        "backup/cleartext-traffic misconfigurations, signature-scheme and Janus-vulnerability "
        "checks), and multi-layer secret detection (AST field-secret queries, binary regex "
        "signatures for known API key formats, and optionally TruffleHog). Framework and SDK "
        "identification is performed via package-presence and file-level signatures.", styles["Body"]))
    if ai_meta and ai_meta.get("performed"):
        story.append(Paragraph(
            f"AI Deep Scan was additionally enabled for this scan (model: {_esc(ai_meta.get('llm', 'N/A'))}), "
            "which reviews each structural finding and secret to triage false positives, and "
            "performs a separate semantic review of exported activities for logic-level issues "
            "that pattern-based rules cannot express.", styles["Body"]))

    story.append(Paragraph("Risk Calculation &amp; Severity Rating", styles["H2"]))
    story.append(Paragraph(
        "Severity ratings in this report (Critical / High / Medium / Low / Info) are assigned per "
        "detection rule based on Cerberus-ASF's own risk model, not a per-finding calculated CVSS "
        "score. The overall Security Score (0–100, shown on the Application Metadata table) "
        "starts at 100 and is reduced by a fixed weighted penalty for each issue identified (for "
        "example, an enabled debug flag or a weakly-signed certificate carries a larger penalty "
        "than a single exported component), floored at 10.", styles["Body"]))
    sev_rows = [[
        _sev_pill(s),
        _p(IMPACT_BY_SEVERITY[s], styles["CellSm"]),
    ] for s in SEVERITY_ORDER]
    t = Table([["Severity", "General Meaning"]] + sev_rows, colWidths=[2.6 * cm, CONTENT_W - 2.6 * cm])
    style = _table_style()
    style.add("VALIGN", (0, 1), (0, -1), "MIDDLE")
    style.add("ALIGN", (0, 1), (0, -1), "CENTER")
    t.setStyle(style)
    story.append(t)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Tools Used", styles["H2"]))
    tools_rows = [
        ["jadx", "APK decompilation feeding structural analysis and AI Deep Scan"],
        ["apktool / aapt", "AndroidManifest.xml extraction and APK metadata"],
        ["apksigner", "Signing certificate and signature-scheme verification"],
        ["tree-sitter", "AST-based structural rule matching over decompiled Java source"],
        ["TruffleHog", "Independent secret-scanning signal (when installed)"],
    ]
    body_rows = [[_p(name, styles["CellSm"]), _p(purpose, styles["CellSm"])] for name, purpose in tools_rows]
    t2 = Table([["Tool", "Purpose"]] + body_rows, colWidths=[5 * cm, CONTENT_W - 5 * cm])
    t2.setStyle(_table_style())
    story.append(t2)
    return story


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def generate_pdf_report(result: dict) -> bytes:
    """Builds the full PDF report and returns it as raw bytes."""
    app_info = result.get("app_info", {}) or {}
    file_info = result.get("file_info", {}) or {}
    package_name = result.get("package_name") or "unknown.package"
    app_name = app_info.get("app_name") or package_name
    security_score = result.get("security_score", "N/A")
    components = result.get("components", {}) or {}
    permissions = result.get("permissions", []) or []
    apk_id = result.get("apk_id", []) or []
    ai_meta = result.get("ai_metadata", {}) or {}

    observations = _collect_observations(result, include_third_party=False)
    counts = _severity_counts(observations)
    highest = next((s for s in SEVERITY_ORDER if counts[s] > 0), "INFO")

    styles = _build_styles()
    buf = io.BytesIO()
    doc = _ReportDoc(buf, pagesize=A4, topMargin=2.3 * cm, bottomMargin=2.0 * cm,
                      leftMargin=2 * cm, rightMargin=2 * cm)

    # The cover's hero/footer bands are drawn full-bleed on the raw canvas
    # (see _draw_cover_furniture), outside the normal margin box — so the
    # cover's own content frame must start below the hero band and end
    # above the footer band, not reuse the standard page margins (which
    # sit well inside the 8.6cm hero band and would overlap it).
    cover_gap = 0.5 * cm
    cover_frame = Frame(
        doc.leftMargin,
        COVER_FOOTER_H + cover_gap,
        doc.width,
        PAGE_H - HERO_H - COVER_FOOTER_H - 2 * cover_gap,
        id="cover",
    )
    normal_frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=_draw_cover_furniture),
        PageTemplate(id="Normal", frames=[normal_frame], onPage=_draw_page_furniture),
    ])

    story = []
    story += _build_cover(styles, app_name, package_name)
    story.append(NextPageTemplate("Normal"))
    story.append(PageBreak())
    story += _build_disclaimer(styles)
    story.append(PageBreak())
    story += _build_toc(styles)
    story.append(PageBreak())
    story += _build_project_summary(styles, app_name, package_name, security_score, counts, highest, ai_meta)
    story.append(PageBreak())
    story += _build_app_metadata(styles, app_info, file_info, security_score)
    story += _build_app_structure(styles, components, permissions, apk_id)
    story.append(PageBreak())
    story += _build_observations_summary(styles, observations)
    story.append(PageBreak())
    story += _build_detailed_observations(styles, observations)
    story.append(PageBreak())
    story += _build_appendix(styles, ai_meta)

    doc.multiBuild(story)
    return buf.getvalue()
