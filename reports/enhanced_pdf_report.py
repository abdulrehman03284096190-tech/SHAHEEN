from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT


class EnhancedPDFReport:
    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        self.styles = getSampleStyleSheet()
        self._setup_styles()
    
    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            name='CoverTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=12,
        ))
    
    def generate_report(self, data: dict[str, Any]) -> Path:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(self.output_path), pagesize=A4)
        story = []
        
        # Cover page
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("SHAHEEN", self.styles['CoverTitle']))
        story.append(Paragraph("Network Traffic Analysis & Threat Detection System", self.styles['CoverTitle']))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("SECURITY REPORT", self.styles['CoverTitle']))
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("1. Executive Summary", self.styles['SectionHeader']))
        summary_text = data.get('executive_summary', 'No summary available.')
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Capture Information
        story.append(Paragraph("2. Capture Information", self.styles['SectionHeader']))
        capture_info = [
            ['Parameter', 'Value'],
            ['Session ID', str(data.get('session_id', 'N/A'))],
            ['Source', data.get('source_path', 'N/A')],
            ['Packet Count', str(data.get('packet_count', 0))],
            ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        t = Table(capture_info)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(t)
        story.append(Spacer(1, 12))
        
        # Alerts
        alerts = data.get('alerts', [])
        if alerts:
            story.append(Paragraph("3. Security Alerts", self.styles['SectionHeader']))
            alert_data = [['Severity', 'Rule', 'Source', 'Destination', 'Description']]
            for alert in alerts[:50]:  # Limit to 50
                alert_data.append([
                    str(alert.get('severity', 'N/A')),
                    str(alert.get('rule_id', 'N/A')),
                    str(alert.get('source_address', 'N/A')),
                    str(alert.get('destination_address', 'N/A')),
                    str(alert.get('title', ''))[:50],
                ])
            t2 = Table(alert_data)
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ]))
            story.append(t2)
            story.append(Spacer(1, 12))
        
        # Recommendations
        story.append(Paragraph("4. Recommendations", self.styles['SectionHeader']))
        story.append(Paragraph("1. Review all high and critical alerts for potential threats.", self.styles['Normal']))
        story.append(Paragraph("2. Investigate suspicious IP addresses identified in alerts.", self.styles['Normal']))
        story.append(Paragraph("3. Monitor network traffic for recurrence of detected patterns.", self.styles['Normal']))
        story.append(Paragraph("4. Document findings in the Investigation module for future reference.", self.styles['Normal']))
        
        doc.build(story)
        return self.output_path
