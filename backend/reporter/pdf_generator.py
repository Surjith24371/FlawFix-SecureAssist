import os
import uuid
import datetime
from typing import Optional, List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

from backend.models.verification_schema import ReportRequest, ReportResponse

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
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Top Header
        self.drawString(36, 756, "FlawFix SecureAssist • AI Vulnerability Detection & Patch Verification")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 750, 576, 750)

        # Running Footer
        self.line(36, 45, 576, 45)
        self.drawString(36, 32, "Confidential Security Audit Report • Automated Verification Pipeline")
        self.drawRightString(576, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()

class PDFReportGenerator:
    """
    Generates professional, publication-quality Security Audit PDF Reports using ReportLab (SRS 4.6.8).
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
        c_primary = colors.HexColor("#0F172A")
        c_accent = colors.HexColor("#2563EB")
        c_bg_light = colors.HexColor("#F8FAFC")
        c_border = colors.HexColor("#E2E8F0")

        # Custom Typography Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=c_primary,
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=14
        )
        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=c_primary,
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155")
        )
        code_style = ParagraphStyle(
            'CodeBlock',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
            backColor=colors.HexColor("#F1F5F9"),
            borderColor=c_border,
            borderWidth=0.5,
            borderPadding=6,
            spaceBefore=4,
            spaceAfter=4
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("FLAWFIX SECUREASSIST", title_style))
        story.append(Paragraph("Automated Vulnerability Detection, Semantic LLVM IR Analysis & Patch Verification Audit Report", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=0, spaceAfter=12))

        # 2. Audit Metadata Card
        meta_data = [
            [
                Paragraph(f"<b>Target File:</b> {request.file_name}", body_style),
                Paragraph(f"<b>Language:</b> {request.language.upper()}", body_style)
            ],
            [
                Paragraph(f"<b>Project:</b> {request.project_name}", body_style),
                Paragraph(f"<b>Audit Date:</b> {timestamp_str}", body_style)
            ],
            [
                Paragraph(f"<b>Report ID:</b> {report_id}", body_style),
                Paragraph(f"<b>Engine:</b> FlawFix LLVM+XAI v1.0", body_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[270, 270])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # 3. Executive Summary & Severity Breakdown
        story.append(Paragraph("1. Executive Security Assessment", section_heading))
        story.append(Paragraph(request.analysis_result.summary, body_style))
        story.append(Spacer(1, 8))

        # Count Severities
        crit_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "critical")
        high_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "high")
        med_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "medium")
        low_cnt = sum(1 for v in request.analysis_result.vulnerabilities if v.severity.lower() == "low")
        total_cnt = request.analysis_result.total_vulnerabilities

        scorecard_data = [
            [
                Paragraph("<b>TOTAL FLAWS</b>", body_style),
                Paragraph("<b>CRITICAL</b>", body_style),
                Paragraph("<b>HIGH</b>", body_style),
                Paragraph("<b>MEDIUM</b>", body_style),
                Paragraph("<b>LOW</b>", body_style),
            ],
            [
                Paragraph(f"<font size=14><b>{total_cnt}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#DC2626'><b>{crit_cnt}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#EA580C'><b>{high_cnt}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#D97706'><b>{med_cnt}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#2563EB'><b>{low_cnt}</b></font>", body_style),
            ]
        ]
        score_table = Table(scorecard_data, colWidths=[108, 108, 108, 108, 108])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 14))

        # 4. Findings Table
        story.append(Paragraph("2. Detected Vulnerability Inventory", section_heading))
        if request.analysis_result.vulnerabilities:
            findings_data = [
                [
                    Paragraph("<b>ID</b>", body_style),
                    Paragraph("<b>Classification (CWE)</b>", body_style),
                    Paragraph("<b>Severity</b>", body_style),
                    Paragraph("<b>Function</b>", body_style),
                    Paragraph("<b>Lines</b>", body_style)
                ]
            ]
            for v in request.analysis_result.vulnerabilities:
                sev_color = "#DC2626" if v.severity.lower() == "critical" else "#EA580C" if v.severity.lower() == "high" else "#D97706" if v.severity.lower() == "medium" else "#2563EB"
                lines_str = ", ".join(map(str, v.affected_lines)) if v.affected_lines else "N/A"
                findings_data.append([
                    Paragraph(f"<b>{v.vulnerability_id}</b>", body_style),
                    Paragraph(f"<b>{v.cwe_id}</b><br/>{v.title}", body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{v.severity.upper()}</b></font>", body_style),
                    Paragraph(f"@{v.function_name}", body_style),
                    Paragraph(lines_str, body_style)
                ])

            findings_table = Table(findings_data, colWidths=[55, 235, 75, 115, 60])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(findings_table)
        else:
            story.append(Paragraph("<font color='#16A34A'><b>✓ No security vulnerabilities detected in this source code.</b></font>", body_style))
        story.append(Spacer(1, 14))

        # 5. Explainable AI (XAI) Deep-Dive per finding
        if request.analysis_result.vulnerabilities:
            story.append(Paragraph("3. Explainable AI (XAI) Diagnostic Details", section_heading))
            for i, v in enumerate(request.analysis_result.vulnerabilities, 1):
                card = []
                card.append(Paragraph(f"<b>Finding {i}: {v.title} ({v.cwe_id})</b>", ParagraphStyle('H3', parent=section_heading, fontSize=11, leading=13)))
                card.append(Spacer(1, 4))
                card.append(Paragraph(f"<b>Root Cause:</b> {v.root_cause}", body_style))
                card.append(Spacer(1, 4))
                card.append(Paragraph(f"<b>Security Exploit Impact:</b> {v.security_impact}", body_style))
                card.append(Spacer(1, 4))
                card.append(Paragraph(f"<b>Remediation Guideline:</b> {v.recommendation}", body_style))
                card.append(Spacer(1, 6))

                # If patch candidates exist, show the top patch
                if v.patch_candidates:
                    top_patch = v.patch_candidates[0]
                    card.append(Paragraph(f"<b>AI-Generated Secure Patch:</b> <i>{top_patch.title}</i>", body_style))
                    card.append(Paragraph(top_patch.patched_code.replace("\n", "<br/>&nbsp;&nbsp;").replace(" ", "&nbsp;"), code_style))
                    if top_patch.optimization_notes:
                        card.append(Paragraph(f"<b>Optimization Notes:</b> {top_patch.optimization_notes}", body_style))

                card_table = Table([[card]], colWidths=[540])
                card_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), c_bg_light),
                    ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(KeepTogether(card_table))
                story.append(Spacer(1, 10))

        # 6. Verification Status Stamp
        if request.verified_patches:
            story.append(Paragraph("4. Automated Patch Verification Audit", section_heading))
            for vp in request.verified_patches:
                v_text = f"<b>Patch for {vp.get('vulnerability_id', 'Flaw')}:</b> <font color='#16A34A'><b>VERIFIED & COMPILER-VALIDATED</b></font><br/>{vp.get('message', 'Passed syntax validation and LLVM IR re-compilation.')}"
                story.append(Paragraph(v_text, body_style))
                story.append(Spacer(1, 4))

        # 7. Code Optimizations
        if request.analysis_result.general_optimizations:
            story.append(Paragraph("5. AI Code Optimization Recommendations", section_heading))
            for opt in request.analysis_result.general_optimizations:
                story.append(Paragraph(f"• <b>{opt.title}:</b> {opt.description} <i>(Impact: {opt.impact})</i>", body_style))
                story.append(Spacer(1, 3))

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
