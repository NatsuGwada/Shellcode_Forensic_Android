#!/usr/bin/env python3
"""
PDF Report Generator for AndroSleuth
Generates professional PDF reports with charts and detailed analysis
"""

import os
from datetime import datetime
from typing import Dict, Any, List
import io

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class PDFReportGenerator:
    """Generate professional PDF reports for APK analysis"""
    
    @staticmethod
    def _hex_to_rgb(hex_color: str) -> colors.Color:
        """Convert hex color to RGB Color object"""
        hex_color = hex_color.lstrip('#')
        r = int(hex_color[0:2], 16) / 255.0
        g = int(hex_color[2:4], 16) / 255.0
        b = int(hex_color[4:6], 16) / 255.0
        return colors.Color(r, g, b)
    
    def __init__(self, output_path: str):
        """
        Initialize PDF report generator
        
        Args:
            output_path: Path to save the PDF report
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab not available. Install with: pip install reportlab")
        
        self.output_path = output_path
        self.story = []
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=self._hex_to_rgb('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=self._hex_to_rgb('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self._hex_to_rgb('#34495e'),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))
        
        # Status styles
        self.styles.add(ParagraphStyle(
            name='StatusSafe',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=self._hex_to_rgb('#27ae60'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='StatusWarning',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=self._hex_to_rgb('#f39c12'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='StatusDanger',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=self._hex_to_rgb('#e74c3c'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Info box style
        self.styles.add(ParagraphStyle(
            name='InfoBox',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self._hex_to_rgb('#2c3e50'),
            leftIndent=20,
            rightIndent=20,
            spaceAfter=10
        ))
    
    def _get_threat_color(self, score: float) -> colors.Color:
        """Get color based on threat score"""
        if score >= 70:
            return colors.Color(0.906, 0.298, 0.235)  # Red #e74c3c
        elif score >= 40:
            return colors.Color(0.953, 0.612, 0.071)  # Orange #f39c12
        else:
            return colors.Color(0.153, 0.682, 0.376)  # Green #27ae60
    
    def _get_threat_level(self, score: float) -> str:
        """Get threat level text based on score"""
        if score >= 70:
            return "HIGH RISK"
        elif score >= 40:
            return "MEDIUM RISK"
        else:
            return "SAFE"
    
    def add_cover_page(self, apk_name: str, analysis_date: str):
        """Add cover page"""
        # Logo/Title
        title = Paragraph(
            "<b>AndroSleuth</b><br/>APK Forensic Analysis Report",
            self.styles['CustomTitle']
        )
        self.story.append(title)
        self.story.append(Spacer(1, 0.5 * inch))
        
        # APK name
        apk_para = Paragraph(
            f"<b>Application:</b> {apk_name}",
            self.styles['CustomHeading1']
        )
        self.story.append(apk_para)
        self.story.append(Spacer(1, 0.3 * inch))
        
        # Date
        date_para = Paragraph(
            f"<b>Analysis Date:</b> {analysis_date}",
            self.styles['CustomHeading2']
        )
        self.story.append(date_para)
        self.story.append(Spacer(1, 0.5 * inch))
        
        # Disclaimer
        disclaimer = Paragraph(
            "<i>This report contains the results of automated static and dynamic analysis "
            "performed by AndroSleuth. The findings should be reviewed by security professionals "
            "before making final decisions.</i>",
            self.styles['InfoBox']
        )
        self.story.append(disclaimer)
        self.story.append(PageBreak())
    
    def add_executive_summary(self, results: Dict[str, Any]):
        """Add executive summary section"""
        self.story.append(Paragraph("Executive Summary", self.styles['CustomHeading1']))
        self.story.append(Spacer(1, 0.2 * inch))
        
        # Overall threat score
        score = results.get('overall_score', 0)
        threat_level = self._get_threat_level(score)
        threat_color = self._get_threat_color(score)
        
        # Threat level box
        threat_data = [
            ['Overall Threat Score', f'{score:.1f}/100'],
            ['Threat Level', threat_level]
        ]
        
        threat_table = Table(threat_data, colWidths=[3*inch, 2*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self._hex_to_rgb('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (0, -1), self._hex_to_rgb('#2c3e50')),
            ('TEXTCOLOR', (1, 1), (1, 1), threat_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('GRID', (0, 0), (-1, -1), 1, colors.white),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [self._hex_to_rgb('#ecf0f1'), colors.white]),
            ('PADDING', (0, 0), (-1, -1), 12),
        ]))
        
        self.story.append(threat_table)
        self.story.append(Spacer(1, 0.3 * inch))
        
        # Key findings
        self.story.append(Paragraph("Key Findings", self.styles['CustomHeading2']))
        findings = []
        
        # Manifest findings
        if 'manifest_analysis' in results:
            manifest = results['manifest_analysis']
            findings.append(f"• Permissions: {manifest.get('total_permissions', 0)} total, "
                          f"{manifest.get('dangerous_permissions_count', 0)} dangerous")
        
        # Obfuscation findings
        if 'obfuscation_analysis' in results:
            obf = results['obfuscation_analysis']
            if obf.get('is_obfuscated'):
                findings.append("• ⚠️ Code obfuscation detected")
            if obf.get('packers_detected'):
                findings.append(f"• ⚠️ Packers detected: {len(obf['packers_detected'])}")
        
        # Static analysis findings
        if 'static_analysis' in results:
            static = results['static_analysis']
            findings.append(f"• Strings extracted: {static.get('total_strings', 0):,}")
            if static.get('dynamic_loading_count', 0) > 0:
                findings.append(f"• ⚠️ Dynamic code loading: {static['dynamic_loading_count']} instances")
        
        # Shellcode findings
        if 'shellcode_analysis' in results:
            shell = results['shellcode_analysis']
            if shell.get('shellcode_patterns_count', 0) > 0:
                findings.append(f"• ⚠️ Shellcode patterns: {shell['shellcode_patterns_count']} detected")
        
        for finding in findings:
            self.story.append(Paragraph(finding, self.styles['Normal']))
        
        self.story.append(PageBreak())
    
    def add_apk_information(self, apk_info: Dict[str, Any]):
        """Add APK information section"""
        self.story.append(Paragraph("APK Information", self.styles['CustomHeading1']))
        self.story.append(Spacer(1, 0.2 * inch))
        
        # Basic info table
        data = [
            ['Property', 'Value'],
            ['Package Name', apk_info.get('package_name', 'N/A')],
            ['Application Name', apk_info.get('app_name', 'N/A')],
            ['Version Name', apk_info.get('version_name', 'N/A')],
            ['Version Code', str(apk_info.get('version_code', 'N/A'))],
            ['File Size', apk_info.get('file_size_formatted', 'N/A')],
            ['Min SDK', str(apk_info.get('min_sdk_version', 'N/A'))],
            ['Target SDK', str(apk_info.get('target_sdk_version', 'N/A'))],
        ]
        
        table = Table(data, colWidths=[2.5*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self._hex_to_rgb('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ]))
        
        self.story.append(table)
        self.story.append(Spacer(1, 0.3 * inch))
        
        # Hashes
        if 'hashes' in apk_info:
            self.story.append(Paragraph("File Hashes", self.styles['CustomHeading2']))
            hashes = apk_info['hashes']
            hash_text = f"""
            <b>MD5:</b> {hashes.get('md5', 'N/A')}<br/>
            <b>SHA1:</b> {hashes.get('sha1', 'N/A')}<br/>
            <b>SHA256:</b> {hashes.get('sha256', 'N/A')}
            """
            self.story.append(Paragraph(hash_text, self.styles['Normal']))
        
        self.story.append(PageBreak())
    
    def add_permissions_analysis(self, manifest: Dict[str, Any]):
        """Add permissions analysis with chart"""
        self.story.append(Paragraph("Permissions Analysis", self.styles['CustomHeading1']))
        self.story.append(Spacer(1, 0.2 * inch))
        
        permissions = manifest.get('permissions', [])
        dangerous = manifest.get('dangerous_permissions', [])
        
        # Summary
        summary_text = f"""
        Total Permissions: <b>{len(permissions)}</b><br/>
        Dangerous Permissions: <b>{len(dangerous)}</b>
        """
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2 * inch))
        
        # Pie chart if matplotlib available
        if MATPLOTLIB_AVAILABLE and len(permissions) > 0:
            fig, ax = plt.subplots(figsize=(6, 4))
            safe_count = len(permissions) - len(dangerous)
            
            sizes = [len(dangerous), safe_count]
            labels = ['Dangerous', 'Normal']
            colors_chart = ['#e74c3c', '#27ae60']
            explode = (0.1, 0)
            
            ax.pie(sizes, explode=explode, labels=labels, colors=colors_chart,
                   autopct='%1.1f%%', shadow=True, startangle=90)
            ax.axis('equal')
            ax.set_title('Permission Distribution')
            
            # Save to buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            buf.seek(0)
            plt.close()
            
            # Add to PDF
            img = Image(buf, width=4*inch, height=3*inch)
            self.story.append(img)
            self.story.append(Spacer(1, 0.2 * inch))
        
        # Dangerous permissions list
        if dangerous:
            self.story.append(Paragraph("Dangerous Permissions Detected:", self.styles['CustomHeading2']))
            for perm in dangerous[:10]:  # Limit to 10
                perm_name = perm if isinstance(perm, str) else perm.get('name', 'Unknown')
                self.story.append(Paragraph(f"• {perm_name}", self.styles['Normal']))
        
        self.story.append(PageBreak())
    
    def add_threat_scores(self, results: Dict[str, Any]):
        """Add threat scores breakdown with bar chart"""
        self.story.append(Paragraph("Threat Score Breakdown", self.styles['CustomHeading1']))
        self.story.append(Spacer(1, 0.2 * inch))
        
        # Collect scores
        scores = {}
        if 'manifest_analysis' in results:
            scores['Manifest'] = results['manifest_analysis'].get('threat_score', 0)
        if 'obfuscation_analysis' in results:
            scores['Obfuscation'] = results['obfuscation_analysis'].get('threat_score', 0)
        if 'static_analysis' in results:
            scores['Static Analysis'] = results['static_analysis'].get('threat_score', 0)
        if 'shellcode_analysis' in results:
            scores['Shellcode'] = results['shellcode_analysis'].get('threat_score', 0)
        if 'yara_analysis' in results:
            scores['YARA'] = results['yara_analysis'].get('threat_score', 0)
        
        # Bar chart
        if MATPLOTLIB_AVAILABLE and scores:
            fig, ax = plt.subplots(figsize=(8, 5))
            
            modules = list(scores.keys())
            values = list(scores.values())
            # Convert scores to colors for matplotlib (needs hex strings)
            colors_bar = []
            for v in values:
                if v >= 70:
                    colors_bar.append('#e74c3c')  # Red
                elif v >= 40:
                    colors_bar.append('#f39c12')  # Orange
                else:
                    colors_bar.append('#27ae60')  # Green
            
            ax.barh(modules, values, color=colors_bar)
            ax.set_xlabel('Threat Score')
            ax.set_title('Analysis Module Scores')
            ax.set_xlim(0, 100)
            
            for i, v in enumerate(values):
                ax.text(v + 2, i, f'{v:.1f}', va='center')
            
            # Save to buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            buf.seek(0)
            plt.close()
            
            # Add to PDF
            img = Image(buf, width=6*inch, height=4*inch)
            self.story.append(img)
        
        self.story.append(PageBreak())
    
    def add_detailed_findings(self, results: Dict[str, Any]):
        """Add detailed findings section"""
        self.story.append(Paragraph("Detailed Analysis Findings", self.styles['CustomHeading1']))
        self.story.append(Spacer(1, 0.2 * inch))
        
        # Static Analysis
        if 'static_analysis' in results:
            static = results['static_analysis']
            self.story.append(Paragraph("Static Code Analysis", self.styles['CustomHeading2']))
            
            findings = [
                f"Total Strings: {static.get('total_strings', 0):,}",
                f"Suspicious Strings: {static.get('suspicious_strings_count', 0)}",
                f"Dynamic Loading: {static.get('dynamic_loading_count', 0)} instances",
                f"Cryptography APIs: {static.get('crypto_usage_count', 0)}",
                f"Network APIs: {static.get('network_usage_count', 0)}",
                f"Reflection Calls: {static.get('reflection_usage_count', 0)}",
            ]
            
            for finding in findings:
                self.story.append(Paragraph(f"• {finding}", self.styles['Normal']))
            
            self.story.append(Spacer(1, 0.2 * inch))
        
        # Obfuscation
        if 'obfuscation_analysis' in results:
            obf = results['obfuscation_analysis']
            self.story.append(Paragraph("Obfuscation & Packing", self.styles['CustomHeading2']))
            
            obf_text = f"Obfuscated: <b>{'Yes' if obf.get('is_obfuscated') else 'No'}</b><br/>"
            if obf.get('packers_detected'):
                obf_text += f"Packers: <b>{', '.join([p.get('name', 'Unknown') for p in obf['packers_detected']])}</b>"
            else:
                obf_text += "Packers: <b>None detected</b>"
            
            self.story.append(Paragraph(obf_text, self.styles['Normal']))
            self.story.append(Spacer(1, 0.2 * inch))
        
        # Shellcode
        if 'shellcode_analysis' in results:
            shell = results['shellcode_analysis']
            self.story.append(Paragraph("Native Code & Shellcode", self.styles['CustomHeading2']))
            
            shell_text = f"""
            Native Libraries: {shell.get('native_libs_count', 0)}<br/>
            Shellcode Patterns: {shell.get('shellcode_patterns_count', 0)}<br/>
            Suspicious Syscalls: {shell.get('syscalls_count', 0)}
            """
            self.story.append(Paragraph(shell_text, self.styles['Normal']))
    
    def add_recommendations(self, results: Dict[str, Any]):
        """Add security recommendations"""
        self.story.append(PageBreak())
        self.story.append(Paragraph("Security Recommendations", self.styles['CustomHeading1']))
        self.story.append(Spacer(1, 0.2 * inch))
        
        score = results.get('overall_score', 0)
        recommendations = []
        
        if score >= 70:
            recommendations.append("🔴 <b>CRITICAL:</b> This APK shows high-risk indicators. Do NOT install on production devices.")
            recommendations.append("• Perform dynamic analysis in isolated sandbox environment")
            recommendations.append("• Submit to VirusTotal for multi-engine scanning")
            recommendations.append("• Reverse engineer suspicious components")
        elif score >= 40:
            recommendations.append("🟡 <b>WARNING:</b> This APK shows suspicious behaviors that warrant investigation.")
            recommendations.append("• Review dangerous permissions carefully")
            recommendations.append("• Test in isolated environment before deployment")
            recommendations.append("• Monitor network traffic during execution")
        else:
            recommendations.append("🟢 <b>LOW RISK:</b> This APK appears to be relatively safe, but always exercise caution.")
            recommendations.append("• Verify application source and developer")
            recommendations.append("• Review permissions before installation")
            recommendations.append("• Keep application updated")
        
        for rec in recommendations:
            self.story.append(Paragraph(rec, self.styles['Normal']))
            self.story.append(Spacer(1, 0.1 * inch))
    
    def add_footer(self):
        """Add footer information"""
        self.story.append(PageBreak())
        footer_text = f"""
        <para align=center>
        <i>Report generated by AndroSleuth v1.0.0</i><br/>
        <i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i><br/>
        <i>https://github.com/NatsuGwada/Shellcode_Forensic_Android</i>
        </para>
        """
        self.story.append(Paragraph(footer_text, self.styles['Normal']))
    
    def generate(self, results: Dict[str, Any]) -> str:
        """
        Generate PDF report
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            Path to generated PDF file
        """
        # Create document
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )
        
        # Build content
        apk_info = results.get('apk_info', {})
        apk_name = apk_info.get('app_name', apk_info.get('package_name', 'Unknown'))
        analysis_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        self.add_cover_page(apk_name, analysis_date)
        self.add_executive_summary(results)
        self.add_apk_information(apk_info)
        
        if 'manifest_analysis' in results:
            self.add_permissions_analysis(results['manifest_analysis'])
        
        self.add_threat_scores(results)
        self.add_detailed_findings(results)
        self.add_recommendations(results)
        self.add_footer()
        
        # Build PDF
        doc.build(self.story)
        
        return self.output_path


def generate_pdf_report(results: Dict[str, Any], output_path: str) -> str:
    """
    Convenience function to generate PDF report
    
    Args:
        results: Analysis results dictionary
        output_path: Path to save PDF report
        
    Returns:
        Path to generated PDF file
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "ReportLab not available. PDF generation disabled.\n"
            "Install with: pip install reportlab matplotlib pillow"
        )
    
    generator = PDFReportGenerator(output_path)
    return generator.generate(results)
