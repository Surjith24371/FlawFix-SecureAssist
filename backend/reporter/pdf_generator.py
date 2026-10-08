import os
import uuid
import datetime
import html
from typing import Optional, List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

from backend.models.verification_schema import ReportRequest, ReportResponse

def escape_text(val: Any) -> str:
    """Safely escapes text for ReportLab Paragraph XML parsing."""
    if val is None:
        return ""
    return html.escape(str(val))

def extract_vulnerable_snippet(
    original_code: Optional[str],
    affected_lines: Optional[List[int]],
    function_name: Optional[str],
    file_name: Optional[str]
) -> str:
    """
    Extracts a context-aware snippet of the original vulnerable code with line numbers
    and a distinct '>' marker pointing directly to affected lines.
    """
    if not original_code or not original_code.strip():
        func_display = f"Function: @{function_name}" if function_name else "Target Function"
        lines_display = f"Lines: {', '.join(map(str, affected_lines))}" if affected_lines else "Lines: See Finding Details"
        file_display = f"File: {file_name}" if file_name else ""
        return (
            f"// {func_display} | {lines_display} | {file_display}\n"
            f"// [Vulnerable operation detected at specified source location]"
        )

    lines = original_code.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return "// Empty source file"

    # If affected lines specified
    if affected_lines and len(affected_lines) > 0:
        valid_affected = [ln for ln in affected_lines if 1 <= ln <= total_lines]
        if valid_affected:
            min_l = max(1, min(valid_affected) - 2)
            max_l = min(total_lines, max(valid_affected) + 2)
            out = []
            for i in range(min_l, max_l + 1):
                raw = lines[i - 1]
                marker = ">" if i in valid_affected else " "
                out.append(f"{marker} {i:3d} | {raw}")
            return "\n".join(out)

    # If function_name specified, locate function
    if function_name:
        clean_fn = function_name.strip()
        for idx, line in enumerate(lines):
            if clean_fn in line and any(k in line for k in ("(", "def ", "fn ")):
                min_l = max(1, idx - 1)
                max_l = min(total_lines, idx + 8)
                out = []
                for i in range(min_l, max_l + 1):
                    marker = ">" if i == idx + 1 else " "
                    out.append(f"{marker} {i:3d} | {lines[i - 1]}")
                return "\n".join(out)

    # Fallback: display first few lines
    out = [f"  {i+1:3d} | {lines[i]}" for i in range(min(8, total_lines))]
    return "\n".join(out)

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that calculates total pages and renders running header & footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Top Header
        self.drawString(36, 756, "FLAWFIX SECUREASSIST")
        self.setFont("Helvetica", 8)
        self.drawRightString(576, 756, "Security Audit & Dual-Engine Verification Report")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 750, 576, 750)

        # Running Footer
        self.line(36, 45, 576, 45)
        self.drawString(36, 32, "Confidential Security Audit Report • Automated Compiler Verification Pipeline")
        self.drawRightString(576, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()

class PDFReportGenerator:
    """
    Generates professional, publication-quality Security Audit PDF Reports using ReportLab (SRS 4.6.8).
    Includes in-depth explainable AI findings, original vulnerable code, multiple patch suggestions,
    verification statuses, and optimization insights.
    """

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), "..", "reports")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_report(self, request: ReportRequest) -> ReportResponse:
        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_name = f"FlawFix_Report_{report_id}.pdf"
        file_path = os.path.join(self.output_dir, file_name)

        doc = SimpleDocTemplate(
            file_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()

        # Custom Color Palette
        c_primary = colors.HexColor("#0F172A")       # Deep slate 900
        c_secondary = colors.HexColor("#1E293B")     # Slate 800
        c_text = colors.HexColor("#334155")          # Slate 700
        c_muted = colors.HexColor("#64748B")         # Slate 500
        c_bg_light = colors.HexColor("#F8FAFC")      # Slate 50
        c_bg_subtle = colors.HexColor("#F1F5F9")     # Slate 100
        c_border = colors.HexColor("#CBD5E1")        # Slate 300
        c_border_light = colors.HexColor("#E2E8F0")  # Slate 200
        c_accent = colors.HexColor("#2563EB")        # Blue 600
        c_accent_light = colors.HexColor("#EFF6FF")  # Blue 50

        # Severity Colors
        c_crit = colors.HexColor("#DC2626")          # Red 600
        c_crit_bg = colors.HexColor("#FEF2F2")       # Red 50
        c_high = colors.HexColor("#EA580C")          # Orange 600
        c_high_bg = colors.HexColor("#FFF7ED")       # Orange 50
        c_med = colors.HexColor("#D97706")           # Amber 600
        c_med_bg = colors.HexColor("#FFFBEB")        # Amber 50
        c_low = colors.HexColor("#2563EB")           # Blue 600
        c_low_bg = colors.HexColor("#EFF6FF")        # Blue 50

        # Success / Recommended Colors
        c_success = colors.HexColor("#16A34A")       # Green 600
        c_success_bg = colors.HexColor("#F0FDF4")    # Green 50
        c_rec = colors.HexColor("#059669")           # Emerald 600
        c_rec_bg = colors.HexColor("#ECFDF5")        # Emerald 50

        # Custom Typography Styles
        title_style = ParagraphStyle(
            'DocTitle',
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=c_primary,
            spaceAfter=2
        )
        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            fontName='Helvetica',
            fontSize=9.5,
            leading=13,
            textColor=c_muted,
            spaceAfter=8
        )
        section_heading = ParagraphStyle(
            'SectionHeading',
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=15,
            textColor=c_primary,
            spaceBefore=14,
            spaceAfter=6
        )
        h3_style = ParagraphStyle(
            'H3Heading',
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=13,
            textColor=c_secondary,
            spaceBefore=6,
            spaceAfter=3
        )
        body_style = ParagraphStyle(
            'BodyText',
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=c_text
        )
        body_bold = ParagraphStyle(
            'BodyBold',
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=12,
            textColor=c_primary
        )
        callout_label_style = ParagraphStyle(
            'CalloutLabel',
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=c_secondary,
            spaceAfter=2
        )
        code_style = ParagraphStyle(
            'CodeBlock',
            fontName='Courier',
            fontSize=7.5,
            leading=9.5,
            textColor=c_primary
        )
        code_alert_style = ParagraphStyle(
            'CodeAlertBlock',
            fontName='Courier',
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#991B1B")  # Dark Red 800
        )

        story = []

        # =========================================================================
        # 1. Header Banner & Title
        # =========================================================================
        story.append(Paragraph("FLAWFIX SECUREASSIST", title_style))
        story.append(Paragraph("Comprehensive Security Vulnerability Audit, Explainable AI & Patch Verification Report", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=0, spaceAfter=10))

        # =========================================================================
        # 2. Audit Metadata Card
        # =========================================================================
        meta_data = [
            [
                Paragraph(f"<b>Target File:</b> {escape_text(request.file_name)}", body_style),
                Paragraph(f"<b>Language:</b> {escape_text(request.language).upper()}", body_style)
            ],
            [
                Paragraph(f"<b>Project:</b> {escape_text(request.project_name)}", body_style),
                Paragraph(f"<b>Audit Date:</b> {escape_text(timestamp_str)}", body_style)
            ],
            [
                Paragraph(f"<b>Report ID:</b> {escape_text(report_id)}", body_style),
                Paragraph("<b>Analysis Engine:</b> FlawFix LLVM IR + Gemini XAI Dual-Engine", body_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[270, 270])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 3. Executive Security Assessment & Scorecard
        # =========================================================================
        story.append(Paragraph("1. Executive Security Assessment", section_heading))
        summary_text = escape_text(request.analysis_result.summary)
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 8))

        # Count Severities & Verified Patches
        crit_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "critical")
        high_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "high")
        med_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "medium")
        low_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "low")
        total_cnt = request.analysis_result.total_vulnerabilities
        verified_cnt = len(request.verified_patches or [])

        # Build map of verified patches by vulnerability_id for fast lookup
        verified_map = {}
        for vp in (request.verified_patches or []):
            vid = vp.get("vulnerability_id")
            if vid:
                verified_map[vid] = vp

        scorecard_data = [
            [
                Paragraph("<b>TOTAL FLAWS</b>", body_style),
                Paragraph("<b>CRITICAL</b>", body_style),
                Paragraph("<b>HIGH</b>", body_style),
                Paragraph("<b>MEDIUM</b>", body_style),
                Paragraph("<b>LOW</b>", body_style),
                Paragraph("<b>VERIFIED PATCHES</b>", body_style),
            ],
            [
                Paragraph(f"<font size=13><b>{total_cnt}</b></font>", body_style),
                Paragraph(f"<font size=13 color='#DC2626'><b>{crit_cnt}</b></font>", body_style),
                Paragraph(f"<font size=13 color='#EA580C'><b>{high_cnt}</b></font>", body_style),
                Paragraph(f"<font size=13 color='#D97706'><b>{med_cnt}</b></font>", body_style),
                Paragraph(f"<font size=13 color='#2563EB'><b>{low_cnt}</b></font>", body_style),
                Paragraph(f"<font size=13 color='#16A34A'><b>{verified_cnt}</b></font>", body_style),
            ]
        ]
        score_table = Table(scorecard_data, colWidths=[90, 90, 90, 90, 90, 90])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 4. Detected Vulnerability Inventory Table
        # =========================================================================
        story.append(Paragraph("2. Detected Vulnerability Inventory", section_heading))
        if request.analysis_result.vulnerabilities:
            findings_data = [
                [
                    Paragraph("<b>ID</b>", body_style),
                    Paragraph("<b>Vulnerability Title & Classification</b>", body_style),
                    Paragraph("<b>Severity</b>", body_style),
                    Paragraph("<b>Function</b>", body_style),
                    Paragraph("<b>Lines</b>", body_style),
                    Paragraph("<b>Status</b>", body_style),
                ]
            ]
            for v in request.analysis_result.vulnerabilities:
                sev_lower = v.severity.lower()
                sev_color = "#DC2626" if sev_lower == "critical" else "#EA580C" if sev_lower == "high" else "#D97706" if sev_lower == "medium" else "#2563EB"
                lines_str = ", ".join(map(str, v.affected_lines)) if v.affected_lines else "N/A"
                is_v_verified = v.vulnerability_id in verified_map
                status_html = "<font color='#16A34A'><b>✓ Verified</b></font>" if is_v_verified else "<font color='#64748B'>Pending</font>"

                findings_data.append([
                    Paragraph(f"<b>{escape_text(v.vulnerability_id)}</b>", body_style),
                    Paragraph(f"<b>{escape_text(v.title)}</b><br/><font color='#64748B'>{escape_text(v.cwe_id)}</font>", body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{escape_text(v.severity).upper()}</b></font>", body_style),
                    Paragraph(f"@{escape_text(v.function_name)}", body_style),
                    Paragraph(escape_text(lines_str), body_style),
                    Paragraph(status_html, body_style)
                ])

            findings_table = Table(findings_data, colWidths=[55, 205, 65, 95, 55, 65])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), c_bg_subtle),
                ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(findings_table)
        else:
            clean_table = Table([[Paragraph("<font color='#16A34A'><b>✓ No security vulnerabilities detected. Code successfully passed semantic audit.</b></font>", body_style)]], colWidths=[540])
            clean_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), c_success_bg),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#86EFAC")),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ]))
            story.append(clean_table)
        story.append(Spacer(1, 12))

        # =========================================================================
        # 5. In-Depth Vulnerability Diagnostics & Remediation Guide
        # =========================================================================
        if request.analysis_result.vulnerabilities:
            story.append(Paragraph("3. Detailed Vulnerability Diagnostics & Patch Alternatives", section_heading))

            for i, v in enumerate(request.analysis_result.vulnerabilities, 1):
                sev_lower = v.severity.lower()
                sev_color = "#DC2626" if sev_lower == "critical" else "#EA580C" if sev_lower == "high" else "#D97706" if sev_lower == "medium" else "#2563EB"
                sev_bg = c_crit_bg if sev_lower == "critical" else c_high_bg if sev_lower == "high" else c_med_bg if sev_lower == "medium" else c_low_bg
                lines_str = ", ".join(map(str, v.affected_lines)) if v.affected_lines else "N/A"
                is_v_verified = v.vulnerability_id in verified_map

                finding_elements = []

                # --- 5.1 Finding Header Box ---
                hdr_left = (
                    f"<b>Finding {i}: {escape_text(v.title)}</b><br/>"
                    f"<font color='#64748B'><b>Classification:</b> {escape_text(v.cwe_id)}</font><br/>"
                    f"<font color='#334155'><b>Affected Function:</b> @{escape_text(v.function_name)} | <b>Location:</b> Line(s) {escape_text(lines_str)}</font>"
                )
                hdr_right = (
                    f"<font color='{sev_color}'><b>{escape_text(v.severity).upper()} SEVERITY</b></font><br/>"
                    f"{'<font color=\"#16A34A\"><b>✓ VERIFIED PATCH</b></font>' if is_v_verified else '<font color=\"#64748B\">Pending Verification</font>'}"
                )
                header_table = Table([[Paragraph(hdr_left, body_style), Paragraph(hdr_right, body_style)]], colWidths=[400, 140])
                header_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), sev_bg),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor(sev_color)),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                finding_elements.append(header_table)
                finding_elements.append(Spacer(1, 6))

                # --- 5.2 Original Vulnerable Source Code Box ---
                vuln_snippet = extract_vulnerable_snippet(request.original_code, v.affected_lines, v.function_name, request.file_name)
                orig_code_header = Paragraph(f"<b>Original Vulnerable Code:</b> <i>(Lines marked with '>' denote the security flaw)</i>", body_style)
                orig_code_p = Preformatted(vuln_snippet, code_alert_style)
                orig_code_table = Table([[orig_code_p]], colWidths=[540])
                orig_code_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#FCA5A5")),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ]))
                finding_elements.append(orig_code_header)
                finding_elements.append(Spacer(1, 2))
                finding_elements.append(orig_code_table)
                finding_elements.append(Spacer(1, 6))

                # --- 5.3 Diagnostic Explanations (Root Cause, Impact, Remediation) ---
                diag_data = [
                    [
                        Paragraph("<b>🔍 Why This Code Is Vulnerable (Root Cause):</b>", callout_label_style),
                        Paragraph(escape_text(v.root_cause), body_style)
                    ],
                    [
                        Paragraph("<b>⚠️ Security Exploit Impact:</b>", callout_label_style),
                        Paragraph(escape_text(v.security_impact), body_style)
                    ],
                    [
                        Paragraph("<b>🛡️ Remediation Strategy & How to Solve:</b>", callout_label_style),
                        Paragraph(escape_text(v.recommendation), body_style)
                    ]
                ]
                diag_table = Table(diag_data, colWidths=[160, 380])
                diag_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
                    ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                finding_elements.append(diag_table)
                finding_elements.append(Spacer(1, 8))

                # --- 5.4 Secure Patch Alternatives & Explanations ---
                if v.patch_candidates:
                    patch_section_title = Paragraph(
                        f"<b>Secure Patch Alternatives ({len(v.patch_candidates)} Available Options):</b>",
                        h3_style
                    )
                    finding_elements.append(patch_section_title)
                    finding_elements.append(Spacer(1, 3))

                    for p_idx, p in enumerate(v.patch_candidates, 1):
                        is_rec = bool(p.is_recommended or "(recommended)" in p.title.lower())
                        rec_tag = "<font color='#059669'><b>★ RECOMMENDED FIX</b></font> &nbsp;|&nbsp; " if is_rec else ""
                        approach_tag = f"<font color='#2563EB'><b>[{escape_text(p.approach_type or 'Secure Patch')}]</b></font>"

                        patch_hdr = f"<b>Option {p_idx}: {escape_text(p.title)}</b>"
                        patch_badges = f"{rec_tag}{approach_tag}"

                        patch_meta_table = Table([[Paragraph(patch_hdr, body_style), Paragraph(patch_badges, body_style)]], colWidths=[350, 190])
                        patch_meta_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), c_rec_bg if is_rec else c_bg_subtle),
                            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#6EE7B7") if is_rec else c_border),
                            ('TOPPADDING', (0, 0), (-1, -1), 4),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                            ('LEFTPADDING', (0, 0), (-1, -1), 6),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
                        ]))
                        finding_elements.append(patch_meta_table)

                        # Description / How it fixes the vulnerability
                        fix_desc = f"<b>How This Patch Fixes the Vulnerability:</b> {escape_text(p.description)}"
                        finding_elements.append(Spacer(1, 2))
                        finding_elements.append(Paragraph(fix_desc, body_style))
                        finding_elements.append(Spacer(1, 2))

                        # Patched Code Snippet Box
                        code_p = Preformatted(p.patched_code.strip(), code_style)
                        patch_code_table = Table([[code_p]], colWidths=[540])
                        patch_code_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                            ('TOPPADDING', (0, 0), (-1, -1), 5),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ]))
                        finding_elements.append(patch_code_table)

                        # Optimization notes & verification note
                        opt_text = f"⚡ <b>Optimization Benefit:</b> {escape_text(p.optimization_notes)}" if p.optimization_notes else None
                        ver_text = (
                            f"✓ <b>Compiler Verification:</b> <font color='#16A34A'><b>VERIFIED & COMPILER-VALIDATED</b></font> (Passed syntax check and LLVM IR re-compilation with zero regressions)"
                            if is_v_verified else
                            f"ℹ <b>Compiler Verification:</b> Ready for in-editor verification via <i>Apply & Verify</i> in the FlawFix VS Code sidebar."
                        )

                        notes_data = []
                        if opt_text:
                            notes_data.append([Paragraph(opt_text, body_style)])
                        notes_data.append([Paragraph(ver_text, body_style)])

                        notes_table = Table(notes_data, colWidths=[540])
                        notes_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
                            ('BOX', (0, 0), (-1, -1), 0.5, c_border_light),
                            ('TOPPADDING', (0, 0), (-1, -1), 3),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                            ('LEFTPADDING', (0, 0), (-1, -1), 6),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                        ]))
                        finding_elements.append(Spacer(1, 2))
                        finding_elements.append(notes_table)
                        finding_elements.append(Spacer(1, 6))

                story.append(KeepTogether(finding_elements))
                story.append(Spacer(1, 10))

        # =========================================================================
        # 6. Automated Patch Verification Audit Summary
        # =========================================================================
        story.append(Paragraph("4. Automated Patch Verification Audit", section_heading))
        if request.verified_patches:
            story.append(Paragraph("The following patches have been compiled and verified through the FlawFix dual-engine pipeline:", body_style))
            story.append(Spacer(1, 4))
            v_audit_data = [
                [
                    Paragraph("<b>Vulnerability ID</b>", body_style),
                    Paragraph("<b>Verification Gate Status</b>", body_style),
                    Paragraph("<b>Compiler Audit Details</b>", body_style),
                ]
            ]
            for vp in request.verified_patches:
                vid = escape_text(vp.get("vulnerability_id", "Flaw"))
                msg = escape_text(vp.get("message", "Passed pre-flight syntax check and LLVM IR semantic verification."))
                v_audit_data.append([
                    Paragraph(f"<b>{vid}</b>", body_style),
                    Paragraph("<font color='#16A34A'><b>✓ VERIFIED & VALIDATED</b></font>", body_style),
                    Paragraph(msg, body_style)
                ])

            v_audit_table = Table(v_audit_data, colWidths=[110, 140, 290])
            v_audit_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), c_bg_subtle),
                ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(v_audit_table)
        else:
            pending_msg = (
                "<b>Status:</b> Ready for in-editor verification. "
                "Open the FlawFix sidebar in VS Code and click <b>Apply & Verify</b> on any recommended patch alternative "
                "to execute real-time syntax checking, LLVM IR re-compilation, and zero-regression semantic verification."
            )
            pending_table = Table([[Paragraph(pending_msg, body_style)]], colWidths=[540])
            pending_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
                ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(pending_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 7. AI Code Optimization Recommendations
        # =========================================================================
        if request.analysis_result.general_optimizations:
            story.append(Paragraph("5. AI Code Optimization Recommendations", section_heading))
            opt_data = [
                [
                    Paragraph("<b>Optimization Focus</b>", body_style),
                    Paragraph("<b>Description & Efficiency Advantage</b>", body_style),
                    Paragraph("<b>Expected Benefit</b>", body_style)
                ]
            ]
            for opt in request.analysis_result.general_optimizations:
                opt_data.append([
                    Paragraph(f"<b>{escape_text(opt.title)}</b>", body_style),
                    Paragraph(escape_text(opt.description), body_style),
                    Paragraph(f"<font color='#059669'><b>{escape_text(opt.impact)}</b></font>", body_style)
                ])

            opt_table = Table(opt_data, colWidths=[140, 260, 140])
            opt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), c_bg_subtle),
                ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(opt_table)
            story.append(Spacer(1, 10))

        # Build PDF using NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)

        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        return ReportResponse(
            report_id=report_id,
            file_name=file_name,
            file_path=os.path.abspath(file_path),
            download_url=f"/api/reports/{file_name}",
            file_size_bytes=file_size,
            generated_at=timestamp_str
        )

# Global singleton
pdf_report_generator = PDFReportGenerator()
