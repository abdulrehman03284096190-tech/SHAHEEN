from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PDFReport:
    def __init__(self, out_path: str) -> None:
        self.out_path = out_path

    @staticmethod
    def _safe_text(value: Any) -> str:
        text = str(value)
        text = "".join(char if ord(char) <= 255 else "?" for char in text)
        return escape(text).replace("\n", "<br/>")

    def _build(self, title: str, story: list[Any]) -> str:
        output = Path(self.out_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(output),
            pagesize=letter,
            rightMargin=0.65 * inch,
            leftMargin=0.65 * inch,
            topMargin=0.65 * inch,
            bottomMargin=0.65 * inch,
            title=title,
            author="Shaheen",
        )
        doc.build(story)
        return str(output)

    def generate(self, title: str, sections: list[str]) -> str:
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ShaheenTitle", parent=styles["Title"], alignment=TA_LEFT))
        story: list[Any] = [
            Paragraph(self._safe_text(title), styles["ShaheenTitle"]),
            Spacer(1, 0.18 * inch),
            Paragraph(
                f"Generated: {datetime.now(timezone.utc).isoformat()}",
                styles["Normal"],
            ),
            Spacer(1, 0.18 * inch),
        ]
        for section in sections:
            story.append(Paragraph(self._safe_text(section), styles["BodyText"]))
            story.append(Spacer(1, 0.12 * inch))
        return self._build(title, story)

    def generate_investigation(
        self,
        title: str,
        investigation: dict[str, Any],
        events: Iterable[Any],
    ) -> str:
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ShaheenTitle", parent=styles["Title"], alignment=TA_LEFT))
        story: list[Any] = [
            Paragraph(self._safe_text(title), styles["ShaheenTitle"]),
            Spacer(1, 0.15 * inch),
        ]

        details = [
            ["Investigation ID", investigation.get("id", "")],
            ["Status", investigation.get("status", "")],
            ["Description", investigation.get("description", "")],
            ["Analyst notes", investigation.get("analyst_notes", "")],
            ["Report generated (UTC)", datetime.now(timezone.utc).isoformat()],
        ]
        metadata_table = Table(
            [[Paragraph(self._safe_text(label), styles["Heading4"]),
              Paragraph(self._safe_text(value), styles["BodyText"])] for label, value in details],
            colWidths=[1.6 * inch, 5.4 * inch],
            repeatRows=0,
        )
        metadata_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF5")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9AA8B7")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.extend([metadata_table, Spacer(1, 0.25 * inch), Paragraph("Investigation timeline", styles["Heading2"])])

        table_data = [[
            Paragraph("Timestamp", styles["Heading4"]),
            Paragraph("Type", styles["Heading4"]),
            Paragraph("Event", styles["Heading4"]),
            Paragraph("Evidence reference", styles["Heading4"]),
        ]]
        for event in events:
            row = event if isinstance(event, dict) else vars(event)
            table_data.append(
                [
                    Paragraph(self._safe_text(row.get("timestamp") or "Not timestamped"), styles["BodyText"]),
                    Paragraph(self._safe_text(row.get("event_type", "")), styles["BodyText"]),
                    Paragraph(self._safe_text(row.get("summary", "")), styles["BodyText"]),
                    Paragraph(self._safe_text(row.get("source_reference") or ""), styles["BodyText"]),
                ]
            )
        if len(table_data) == 1:
            table_data.append([Paragraph("No timeline events", styles["BodyText"]), "", "", ""])

        timeline = Table(
            table_data,
            colWidths=[1.35 * inch, 0.85 * inch, 3.35 * inch, 1.05 * inch],
            repeatRows=1,
        )
        timeline.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D7E5F3")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9AA8B7")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(timeline)
        return self._build(title, story)
