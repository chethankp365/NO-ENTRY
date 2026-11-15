"""
NO ENTRY - Executive Incident & Penetration Test Report Service
Compiles live event/metric data into structured reports and renders authentic
cyber incident PDFs using ReportLab.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports_data"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

class IncidentReport:
    def __init__(
        self,
        id: str,
        title: str,
        type: str,
        generated_at: str,
        target: str,
        summary: str,
        techniques: List[str],
        timeline: List[str],
        response_actions: List[str],
        mttd: str,
        mttr: str,
        recommendations: List[str],
        pdf_path: Optional[str] = None
    ):
        self.id = id
        self.title = title
        self.type = type
        self.generated_at = generated_at
        self.target = target
        self.summary = summary
        self.techniques = techniques
        self.timeline = timeline
        self.response_actions = response_actions
        self.mttd = mttd
        self.mttr = mttr
        self.recommendations = recommendations
        self.pdf_path = pdf_path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "type": self.type,
            "generated_at": self.generated_at,
            "target": self.target,
            "summary": self.summary,
            "techniques": self.techniques,
            "timeline": self.timeline,
            "response_actions": self.response_actions,
            "mttd": self.mttd,
            "mttr": self.mttr,
            "recommendations": self.recommendations,
            "has_pdf": self.pdf_path is not None and Path(self.pdf_path).exists()
        }

class ReportsService:
    def __init__(self):
        self.reports: Dict[str, IncidentReport] = {}
        self._seed_default_reports()

    def _seed_default_reports(self):
        rep1 = IncidentReport(
            id="rep-001",
            title="Ransomware Incident Executive Brief",
            type="Incident Response",
            generated_at="2026-11-01 14:30",
            target="Accounting Workstation (ws-02)",
            summary="Targeted spear-phishing attack resulted in encoded PowerShell execution and attempt to deploy LockBit ransomware payload. Automated SOAR playbook isolated the host before lateral propagation occurred.",
            techniques=["T1566 Phishing", "T1059 Command & Scripting", "T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery"],
            timeline=[
                "11:58:22 - Phishing attachment opened on ws-01",
                "12:00:14 - Encoded PowerShell script executed",
                "12:02:18 - LSASS memory read attempt",
                "12:03:19 - SMB lateral movement to ws-02",
                "12:04:12 - Reflex SOAR isolated ws-02"
            ],
            response_actions=[
                "Host ws-02 quarantined from 10.0.2.0/24 subnet",
                "Perimeter firewall blocked external C2 IP 185.220.101.4",
                "Compromised service account svc_backup revoked"
            ],
            mttd="0.42 s",
            mttr="1.18 s",
            recommendations=[
                "Enforce Application Whitelisting via AppLocker on all workstations",
                "Deploy LAPS across member servers to mitigate credential reuse",
                "Restrict outbound egress filtering on UDP port 53"
            ]
        )
        self.generate_pdf(rep1)
        self.reports[rep1.id] = rep1

        rep2 = IncidentReport(
            id="rep-002",
            title="Web Application Penetration Test Audit",
            type="Security Audit",
            generated_at="2026-11-01 16:15",
            target="DMZ Public Nginx Portal (web01)",
            summary="Automated and manual offensive assessment against public-facing customer portal. SQL injection vulnerability detected in API query endpoint and mitigated via ModSecurity WAF rule.",
            techniques=["T1190 Exploit Public App", "T1595 Active Scanning", "T1005 Data from Local System"],
            timeline=[
                "10:14:00 - Perimeter TCP port sweep against 10.0.1.10",
                "10:16:30 - SQLMap automated injection test on parameter 'q'",
                "10:18:02 - ModSecurity anomaly score exceeded threshold",
                "10:18:03 - HTTP 403 Forbidden applied to 45.9.148.22"
            ],
            response_actions=[
                "WAF blocking rule deployed dynamically",
                "SQL injection vector patched in application code"
            ],
            mttd="0.30 s",
            mttr="0.85 s",
            recommendations=[
                "Migrate raw SQL queries to parameterized ORM queries",
                "Implement strict rate-limiting on /api/v1/search"
            ]
        )
        self.generate_pdf(rep2)
        self.reports[rep2.id] = rep2

        rep3 = IncidentReport(
            id="rep-003",
            title="Perimeter Hardening Before vs After Review",
            type="Compliance Review",
            generated_at="2026-11-02 09:00",
            target="All Network Segments (10.0.0.0/16)",
            summary="Comparative security posture audit demonstrating risk score reduction from 38 to 86 through implementation of SMB signing, WAF activation, and legacy protocol deprecation.",
            techniques=["T1021 Remote Services", "T1110 Brute Force", "T1071 Application Protocol"],
            timeline=[
                "Baseline score calculated at 38/100 (HIGH RISK)",
                "SMB packet signing enforced on domain controllers",
                "TLS 1.0 and 1.1 disabled on pfSense perimeter gateway",
                "Post-hardening verification achieved 86/100"
            ],
            response_actions=[
                "GPO hardening pushed to 5 hosts",
                "Decoy canary honeytokens placed across 3 zones"
            ],
            mttd="0.25 s",
            mttr="0.60 s",
            recommendations=[
                "Complete Tiered Administration model implementation",
                "Remove remaining default credentials on auxiliary hardware"
            ]
        )
        self.generate_pdf(rep3)
        self.reports[rep3.id] = rep3

    def get_reports_list(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.reports.values()]

    def get_report(self, report_id: str) -> Optional[IncidentReport]:
        return self.reports.get(report_id)

    def generate_report_from_sim(self, sim_engine) -> IncidentReport:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        rep_id = f"rep-{uuid.uuid4().hex[:6]}"

        events = sim_engine.recent_events[:8]
        techniques = list({f"{e.technique_id} {e.technique_name}" for e in events}) or ["T1110 Brute Force", "T1190 Exploit Public App"]
        timeline = [f"{e.time} - {e.event} ({e.target_host})" for e in events] or [
            "12:00:10 - Attack vector detected",
            "12:02:40 - Threat classified as HIGH",
            "12:03:15 - Containment rule deployed"
        ]

        mttd = f"{sim_engine.metrics.mean_time_to_detect:.2f} s"
        mttr = f"{sim_engine.metrics.mean_time_to_respond:.2f} s"

        rep = IncidentReport(
            id=rep_id,
            title=f"Incident Analysis Brief #{rep_id.upper()}",
            type="Simulation Incident Brief",
            generated_at=now_str,
            target="Virtual Lab Network (10.0.0.0/16)",
            summary=f"Automated incident brief compiled from {len(events)} telemetry events. Threat level was evaluated at {sim_engine.metrics.threat_level} with {sim_engine.metrics.alerts_today} alerts matched.",
            techniques=techniques,
            timeline=timeline,
            response_actions=[
                "Perimeter firewall drop rules evaluated by Reflex",
                "Host status synchronized with SIEM correlation engine"
            ],
            mttd=mttd,
            mttr=mttr,
            recommendations=[
                "Continue automated threat detection rule verification",
                "Maintain SOAR playbook isolation triggers"
            ]
        )

        self.generate_pdf(rep)
        self.reports[rep.id] = rep
        return rep

    def generate_pdf(self, report: IncidentReport) -> str:
        pdf_filename = f"{report.id}.pdf"
        filepath = REPORTS_DIR / pdf_filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'CyberTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#FF1F3D')
        )
        subtitle_style = ParagraphStyle(
            'CyberSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#00E5FF')
        )
        body_style = ParagraphStyle(
            'CyberBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#1A1F29')
        )
        heading_style = ParagraphStyle(
            'CyberHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#04060A')
        )

        elements = []

        # Header Title
        elements.append(Paragraph("NO ENTRY // CYBER RANGE INCIDENT REPORT", subtitle_style))
        elements.append(Paragraph(report.title, title_style))
        elements.append(Spacer(1, 8))

        # Metadata Table
        meta_data = [
            ["Report ID:", report.id, "Generated At:", report.generated_at],
            ["Report Type:", report.type, "Target Scope:", report.target],
            ["Mean Time to Detect:", report.mttd, "Mean Time to Respond:", report.mttr]
        ]
        meta_table = Table(meta_data, colWidths=[120, 150, 120, 150])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F4F6F9')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1A1F29')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D1D5DB')),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 14))

        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#FF1F3D'), spaceAfter=8))
        elements.append(Paragraph(report.summary, body_style))
        elements.append(Spacer(1, 14))

        # MITRE ATT&CK Techniques
        elements.append(Paragraph("IDENTIFIED MITRE ATT&CK TECHNIQUES", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#00E5FF'), spaceAfter=8))
        tech_data = [[f"• {t}"] for t in report.techniques]
        tech_table = Table(tech_data, colWidths=[540])
        tech_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Courier-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1A1F29')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(tech_table)
        elements.append(Spacer(1, 14))

        # Incident Timeline
        elements.append(Paragraph("INCIDENT TIMELINE", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1A1F29'), spaceAfter=8))
        time_data = [[t] for t in report.timeline]
        time_table = Table(time_data, colWidths=[540])
        time_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#374151')),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F9FAFB')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
        ]))
        elements.append(time_table)
        elements.append(Spacer(1, 14))

        # Defense Actions & Recommendations
        elements.append(Paragraph("DEFENSE ACTIONS & RECOMMENDATIONS", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#00FF6A'), spaceAfter=8))
        recs = [Paragraph(f"<b>[ACTION]</b> {a}", body_style) for a in report.response_actions]
        recs += [Paragraph(f"<b>[RECOMMENDATION]</b> {r}", body_style) for r in report.recommendations]
        for r in recs:
            elements.append(r)
            elements.append(Spacer(1, 4))

        doc.build(elements)
        report.pdf_path = str(filepath)
        return str(filepath)

reports_service = ReportsService()
