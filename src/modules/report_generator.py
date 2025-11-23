#!/usr/bin/env python3
"""
Report Generator Module
Generate comprehensive HTML and JSON reports with visualizations
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from ..utils.logger import setup_logger

logger = setup_logger('report_generator')


class ReportGenerator:
    """Generate analysis reports in HTML and JSON formats"""
    
    def __init__(self, apk_path: str, output_dir: str):
        """
        Initialize report generator
        
        Args:
            apk_path: Path to analyzed APK file
            output_dir: Directory to save reports
        """
        self.apk_path = apk_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.apk_name = Path(apk_path).stem
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.results: Dict[str, Any] = {
            'apk_info': {},
            'manifest_analysis': {},
            'obfuscation_analysis': {},
            'static_analysis': {},
            'virustotal_analysis': {},
            'shellcode_analysis': {},
            'yara_analysis': {},
            'emulation_analysis': {},
            'frida_analysis': {},
            'overall_score': 0,
            'risk_level': 'UNKNOWN',
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Report generator initialized for: {self.apk_name}")
    
    
    def add_apk_info(self, info: Dict[str, Any]):
        """Add APK metadata information"""
        self.results['apk_info'] = info
        logger.debug("Added APK info to report")
    
    
    def add_manifest_results(self, results: Dict[str, Any]):
        """Add manifest analysis results"""
        self.results['manifest_analysis'] = results
        logger.debug("Added manifest analysis to report")
    
    
    def add_obfuscation_results(self, results: Dict[str, Any]):
        """Add obfuscation detection results"""
        self.results['obfuscation_analysis'] = results
        logger.debug("Added obfuscation analysis to report")
    
    
    def add_static_analysis_results(self, results: Dict[str, Any]):
        """Add static analysis results"""
        self.results['static_analysis'] = results
        logger.debug("Added static analysis to report")
    
    
    def add_virustotal_results(self, results: Dict[str, Any]):
        """Add VirusTotal analysis results"""
        self.results['virustotal_analysis'] = results
        logger.debug("Added VirusTotal analysis to report")
    
    
    def add_shellcode_results(self, results: Dict[str, Any]):
        """Add shellcode detection results"""
        self.results['shellcode_analysis'] = results
        logger.debug("Added shellcode analysis to report")
    
    
    def add_yara_results(self, results: Dict[str, Any]):
        """Add YARA scan results"""
        self.results['yara_analysis'] = results
        logger.debug("Added YARA analysis to report")
    
    
    def add_emulation_results(self, results: Dict[str, Any]):
        """Add emulation results"""
        self.results['emulation_analysis'] = results
        logger.debug("Added emulation analysis to report")
    
    
    def add_frida_results(self, results: Dict[str, Any]):
        """Add Frida dynamic analysis results"""
        self.results['frida_analysis'] = results
        logger.debug("Added Frida analysis to report")
    
    
    def set_overall_score(self, score: int, risk_level: str):
        """Set overall threat score and risk level"""
        self.results['overall_score'] = score
        self.results['risk_level'] = risk_level
        logger.info(f"Overall score: {score}/100 - Risk: {risk_level}")
    
    
    def generate_json_report(self) -> str:
        """
        Generate JSON report
        
        Returns:
            Path to generated JSON file
        """
        json_filename = f"{self.apk_name}_{self.timestamp}.json"
        json_path = self.output_dir / json_filename
        
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {json_path}")
            return str(json_path)
        
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise
    
    
    def generate_html_report(self) -> str:
        """
        Generate HTML report with visualizations
        
        Returns:
            Path to generated HTML file
        """
        html_filename = f"{self.apk_name}_{self.timestamp}.html"
        html_path = self.output_dir / html_filename
        
        try:
            html_content = self._build_html_content()
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {html_path}")
            return str(html_path)
        
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise
    
    
    def _build_html_content(self) -> str:
        """Build complete HTML report content"""
        
        # Risk level color
        risk_colors = {
            'CLEAN': '#28a745',
            'LOW': '#17a2b8',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545',
            'UNKNOWN': '#6c757d'
        }
        
        risk_color = risk_colors.get(self.results['risk_level'], '#6c757d')
        
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AndroSleuth Report - {self.apk_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .score-card {{
            background: {risk_color};
            color: white;
            padding: 30px;
            text-align: center;
            margin: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .score-card h2 {{
            font-size: 4em;
            margin-bottom: 10px;
        }}
        
        .score-card p {{
            font-size: 1.5em;
            font-weight: bold;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            border-left: 5px solid #667eea;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            display: flex;
            align-items: center;
        }}
        
        .section h2::before {{
            content: "▸";
            margin-right: 10px;
            font-size: 1.2em;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}
        
        .info-item strong {{
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }}
        
        .finding {{
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid #dc3545;
        }}
        
        .finding.medium {{
            border-left-color: #ffc107;
        }}
        
        .finding.low {{
            border-left-color: #17a2b8;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
            margin-bottom: 5px;
        }}
        
        .badge.danger {{
            background: #dc3545;
            color: white;
        }}
        
        .badge.warning {{
            background: #ffc107;
            color: #333;
        }}
        
        .badge.info {{
            background: #17a2b8;
            color: white;
        }}
        
        .badge.success {{
            background: #28a745;
            color: white;
        }}
        
        .progress-bar {{
            background: #e9ecef;
            border-radius: 10px;
            height: 25px;
            overflow: hidden;
            margin-bottom: 10px;
        }}
        
        .progress-fill {{
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .footer {{
            background: #333;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }}
        
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        .code {{
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AndroSleuth Analysis Report</h1>
            <p>Advanced APK Forensic Analysis</p>
        </div>
        
        <div class="score-card">
            <h2>{self.results['overall_score']}/100</h2>
            <p>Risk Level: {self.results['risk_level']}</p>
        </div>
        
        <div class="content">
            {self._generate_apk_info_section()}
            {self._generate_manifest_section()}
            {self._generate_obfuscation_section()}
            {self._generate_static_analysis_section()}
            {self._generate_virustotal_section()}
            {self._generate_shellcode_section()}
            {self._generate_yara_section()}
            {self._generate_emulation_section()}
            {self._generate_frida_section()}
            {self._generate_summary_section()}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>AndroSleuth</strong> on {self.results['timestamp']}</p>
            <p><a href="https://github.com/NatsuGwada/Shellcode_Forensic_Android">GitHub Repository</a></p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    
    def _generate_apk_info_section(self) -> str:
        """Generate APK information section"""
        info = self.results.get('apk_info', {})
        
        if not info:
            return ""
        
        return f"""
        <div class="section">
            <h2>📦 APK Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Package Name</strong>
                    {info.get('package_name', 'N/A')}
                </div>
                <div class="info-item">
                    <strong>Version</strong>
                    {info.get('version_name', 'N/A')} ({info.get('version_code', 'N/A')})
                </div>
                <div class="info-item">
                    <strong>Min SDK</strong>
                    Android {info.get('min_sdk', 'N/A')}
                </div>
                <div class="info-item">
                    <strong>Target SDK</strong>
                    Android {info.get('target_sdk', 'N/A')}
                </div>
                <div class="info-item">
                    <strong>MD5</strong>
                    <div class="code" style="margin-top: 5px;">{info.get('md5', 'N/A')}</div>
                </div>
                <div class="info-item">
                    <strong>SHA256</strong>
                    <div class="code" style="margin-top: 5px;">{info.get('sha256', 'N/A')}</div>
                </div>
            </div>
        </div>
        """
    
    
    def _generate_manifest_section(self) -> str:
        """Generate manifest analysis section"""
        manifest = self.results.get('manifest_analysis', {})
        
        if not manifest:
            return ""
        
        permissions_html = ""
        dangerous_perms = manifest.get('dangerous_permissions', [])
        if dangerous_perms:
            permissions_html = "<h3>⚠️ Dangerous Permissions</h3>"
            for perm in dangerous_perms:
                permissions_html += f'<span class="badge danger">{perm}</span>'
        
        anomalies_html = ""
        anomalies = manifest.get('anomalies', [])
        if anomalies:
            anomalies_html = "<h3>🚨 Anomalies Detected</h3>"
            for anomaly in anomalies:
                anomalies_html += f'<div class="finding">{anomaly}</div>'
        
        return f"""
        <div class="section">
            <h2>📋 Manifest Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Total Permissions</strong>
                    {manifest.get('total_permissions', 0)}
                </div>
                <div class="info-item">
                    <strong>Dangerous Permissions</strong>
                    {len(dangerous_perms)}
                </div>
                <div class="info-item">
                    <strong>Activities</strong>
                    {manifest.get('total_activities', 0)}
                </div>
                <div class="info-item">
                    <strong>Services</strong>
                    {manifest.get('total_services', 0)}
                </div>
                <div class="info-item">
                    <strong>Receivers</strong>
                    {manifest.get('total_receivers', 0)}
                </div>
                <div class="info-item">
                    <strong>Providers</strong>
                    {manifest.get('total_providers', 0)}
                </div>
            </div>
            {permissions_html}
            {anomalies_html}
        </div>
        """
    
    
    def _generate_obfuscation_section(self) -> str:
        """Generate obfuscation detection section"""
        obf = self.results.get('obfuscation_analysis', {})
        
        if not obf:
            return ""
        
        packers_html = ""
        packers = obf.get('packers_detected', [])
        if packers:
            packers_html = "<h3>📦 Packers Detected</h3>"
            for packer in packers:
                packers_html += f'<span class="badge danger">{packer}</span>'
        
        return f"""
        <div class="section">
            <h2>🔒 Obfuscation Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>ProGuard Detected</strong>
                    {'✅ Yes' if obf.get('proguard_detected') else '❌ No'}
                </div>
                <div class="info-item">
                    <strong>Obfuscated Classes</strong>
                    {obf.get('obfuscated_classes', 0)}
                </div>
                <div class="info-item">
                    <strong>Average Entropy</strong>
                    {obf.get('average_entropy', 0):.2f}
                </div>
                <div class="info-item">
                    <strong>High Entropy Files</strong>
                    {len(obf.get('high_entropy_files', []))}
                </div>
            </div>
            {packers_html}
        </div>
        """
    
    
    def _generate_static_analysis_section(self) -> str:
        """Generate static analysis section"""
        static = self.results.get('static_analysis', {})
        
        if not static:
            return ""
        
        patterns_html = ""
        patterns = static.get('suspicious_patterns', [])
        if patterns:
            patterns_html = "<h3>🔍 Suspicious Patterns</h3>"
            for pattern in patterns[:20]:  # Limit to 20
                patterns_html += f'<div class="finding">{pattern}</div>'
        
        return f"""
        <div class="section">
            <h2>🔬 Static Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Total Strings</strong>
                    {static.get('total_strings', 0):,}
                </div>
                <div class="info-item">
                    <strong>Suspicious Patterns</strong>
                    {len(patterns)}
                </div>
                <div class="info-item">
                    <strong>URLs Found</strong>
                    {len(static.get('urls', []))}
                </div>
                <div class="info-item">
                    <strong>IP Addresses</strong>
                    {len(static.get('ip_addresses', []))}
                </div>
            </div>
            {patterns_html}
        </div>
        """
    
    
    def _generate_virustotal_section(self) -> str:
        """Generate VirusTotal analysis section"""
        vt = self.results.get('virustotal_analysis', {})
        
        if not vt or vt.get('status') == 'ERROR':
            return ""
        
        stats = vt.get('stats', {})
        
        return f"""
        <div class="section">
            <h2>🛡️ VirusTotal Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Reputation</strong>
                    {vt.get('reputation', 'UNKNOWN')}
                </div>
                <div class="info-item">
                    <strong>Detections</strong>
                    {stats.get('malicious', 0)} / {stats.get('total', 0)} engines
                </div>
                <div class="info-item">
                    <strong>Detection Rate</strong>
                    {(stats.get('malicious', 0) / max(stats.get('total', 1), 1) * 100):.1f}%
                </div>
                <div class="info-item">
                    <strong>VT Score</strong>
                    {vt.get('score', 0)}/100
                </div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {vt.get('score', 0)}%;">
                    {vt.get('score', 0)}/100
                </div>
            </div>
        </div>
        """
    
    
    def _generate_shellcode_section(self) -> str:
        """Generate shellcode analysis section"""
        sc = self.results.get('shellcode_analysis', {})
        
        if not sc:
            return ""
        
        syscalls_html = ""
        syscalls = sc.get('syscalls_detected', [])
        if syscalls:
            syscalls_html = "<h3>⚠️ Dangerous Syscalls</h3>"
            for syscall in syscalls[:10]:  # Limit to 10
                syscalls_html += f'<span class="badge danger">{syscall.get("syscall", "")}</span>'
        
        patterns_html = ""
        patterns = sc.get('shellcode_patterns', [])
        if patterns:
            patterns_html = "<h3>🚨 Shellcode Patterns</h3>"
            for pattern in patterns:
                patterns_html += f'<div class="finding">{pattern.get("type", "")}: {pattern.get("description", "")}</div>'
        
        return f"""
        <div class="section">
            <h2>💀 Shellcode Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Native Libraries</strong>
                    {sc.get('total_libraries', 0)}
                </div>
                <div class="info-item">
                    <strong>Dangerous Syscalls</strong>
                    {len(syscalls)}
                </div>
                <div class="info-item">
                    <strong>Shellcode Patterns</strong>
                    {len(patterns)}
                </div>
                <div class="info-item">
                    <strong>Threat Score</strong>
                    {sc.get('threat_score', 0)}/100
                </div>
            </div>
            {syscalls_html}
            {patterns_html}
        </div>
        """
    
    
    def _generate_yara_section(self) -> str:
        """Generate YARA analysis section"""
        yara = self.results.get('yara_analysis', {})
        
        if not yara or not yara.get('yara_available'):
            return ""
        
        matches_html = ""
        matches = yara.get('matches', [])
        if matches:
            matches_html = "<h3>🚨 YARA Detections</h3>"
            for match in matches[:20]:  # Limit to 20
                meta = match.get('meta', {})
                severity = meta.get('severity', 'medium')
                category = meta.get('category', 'unknown')
                
                severity_class = 'danger' if severity in ['critical', 'high'] else 'warning'
                
                matches_html += f'''<div class="finding {severity_class}">
                    <strong>{match.get("rule", "Unknown")}</strong> 
                    <span class="badge {severity_class}">{severity.upper()}</span>
                    <span class="badge info">{category}</span>
                    <br>
                    <small>{meta.get("description", "No description")}</small>
                    <br>
                    <small>File: {match.get("file", "Unknown")}</small>
                </div>'''
        
        categories_html = ""
        categories = yara.get('categories', {})
        if categories:
            categories_html = "<h3>📊 Detection Categories</h3>"
            for category, count in categories.items():
                categories_html += f'<span class="badge warning">{category}: {count}</span>'
        
        return f"""
        <div class="section">
            <h2>🦠 YARA Malware Scanning</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Rules Loaded</strong>
                    {yara.get('total_rules', 0)}
                </div>
                <div class="info-item">
                    <strong>Total Matches</strong>
                    {len(matches)}
                </div>
                <div class="info-item">
                    <strong>Files Matched</strong>
                    {yara.get('matched_files', 0)}
                </div>
                <div class="info-item">
                    <strong>Threat Score</strong>
                    {yara.get('threat_score', 0)}/100
                </div>
            </div>
            {categories_html}
            {matches_html}
        </div>
        """
    
    
    def _generate_emulation_section(self) -> str:
        """Generate emulation analysis section"""
        emu = self.results.get('emulation_analysis', {})
        
        if not emu or not emu.get('unicorn_available'):
            return ""
        
        ops_html = ""
        ops = emu.get('suspicious_operations', [])
        if ops:
            ops_html = "<h3>⚠️ Suspicious Operations</h3>"
            for op in ops[:10]:  # Limit to 10
                severity_class = 'danger' if op.get('severity') in ['HIGH', 'CRITICAL'] else 'warning'
                ops_html += f'''<div class="finding {severity_class}">
                    <strong>{op.get("type", "Unknown")}</strong>
                    <span class="badge {severity_class}">{op.get("severity", "MEDIUM")}</span>
                    <br>
                    <small>{op.get("description", "No description")}</small>
                </div>'''
        
        return f"""
        <div class="section">
            <h2>🔬 Emulation Analysis</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Libraries Emulated</strong>
                    {emu.get('libraries_emulated', 0)}
                </div>
                <div class="info-item">
                    <strong>Decryption Detected</strong>
                    {'✅ Yes' if emu.get('decryption_detected') else '❌ No'}
                </div>
                <div class="info-item">
                    <strong>Self-Modifying Code</strong>
                    {'✅ Yes' if emu.get('self_modifying_code') else '❌ No'}
                </div>
                <div class="info-item">
                    <strong>Threat Score</strong>
                    {emu.get('threat_score', 0)}/100
                </div>
            </div>
            {ops_html}
        </div>
        """
    
    
    def _generate_frida_section(self) -> str:
        """Generate Frida dynamic analysis section"""
        frida = self.results.get('frida_analysis', {})
        
        if not frida or not frida.get('frida_available'):
            return ""
        
        behaviors_html = ""
        behaviors = frida.get('suspicious_behavior', [])
        if behaviors:
            behaviors_html = "<h3>🚨 Suspicious Behaviors</h3>"
            for behavior in behaviors[:15]:  # Limit to 15
                severity = behavior.get('severity', 'MEDIUM')
                severity_class = 'danger' if severity in ['HIGH', 'CRITICAL'] else 'warning'
                api = behavior.get('api', 'Unknown')
                
                behaviors_html += f'''<div class="finding {severity_class}">
                    <strong>{api}</strong>
                    <span class="badge {severity_class}">{severity}</span>
                    <br>
                    <small>Type: {behavior.get("type", "unknown")}</small>
                </div>'''
        
        network_html = ""
        networks = frida.get('network_requests', [])[:10]  # First 10
        if networks:
            network_html = "<h3>🌐 Network Requests</h3><ul style='list-style: none; padding: 0;'>"
            for req in networks:
                network_html += f"<li style='padding: 5px; margin: 5px 0; background: #f8f9fa; border-radius: 5px;'><strong>{req.get('method', 'GET')}</strong> {req.get('url', 'Unknown')}</li>"
            network_html += "</ul>"
        
        return f"""
        <div class="section">
            <h2>📱 Dynamic Analysis (Frida)</h2>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Hooks Installed</strong>
                    {'✅ Yes' if frida.get('hooks_installed') else '❌ No'}
                </div>
                <div class="info-item">
                    <strong>API Calls Monitored</strong>
                    {len(frida.get('api_calls', []))}
                </div>
                <div class="info-item">
                    <strong>Suspicious Behaviors</strong>
                    {len(behaviors)}
                </div>
                <div class="info-item">
                    <strong>Threat Score</strong>
                    {frida.get('threat_score', 0)}/100
                </div>
            </div>
            {behaviors_html}
            {network_html}
        </div>
        """
    
    
    def _generate_summary_section(self) -> str:
        """Generate analysis summary section"""
        
        # Calculate module scores
        scores = []
        if self.results.get('manifest_analysis'):
            scores.append(('Manifest', self.results['manifest_analysis'].get('score', 0)))
        if self.results.get('obfuscation_analysis'):
            scores.append(('Obfuscation', self.results['obfuscation_analysis'].get('score', 0)))
        if self.results.get('static_analysis'):
            scores.append(('Static', self.results['static_analysis'].get('score', 0)))
        if self.results.get('virustotal_analysis'):
            scores.append(('VirusTotal', self.results['virustotal_analysis'].get('score', 0)))
        if self.results.get('shellcode_analysis'):
            scores.append(('Shellcode', self.results['shellcode_analysis'].get('threat_score', 0)))
        if self.results.get('yara_analysis') and self.results['yara_analysis'].get('yara_available'):
            scores.append(('YARA', self.results['yara_analysis'].get('threat_score', 0)))
        if self.results.get('emulation_analysis') and self.results['emulation_analysis'].get('unicorn_available'):
            scores.append(('Emulation', self.results['emulation_analysis'].get('threat_score', 0)))
        if self.results.get('frida_analysis') and self.results['frida_analysis'].get('frida_available'):
            scores.append(('Frida', self.results['frida_analysis'].get('threat_score', 0)))
        
        scores_html = ""
        for module, score in scores:
            scores_html += f"""
            <div class="info-item">
                <strong>{module}</strong>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {score}%;">
                        {score}/100
                    </div>
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>📊 Analysis Summary</h2>
            <div class="info-grid">
                {scores_html}
            </div>
        </div>
        """
    
    
    def generate_reports(self) -> Dict[str, str]:
        """
        Generate both HTML and JSON reports
        
        Returns:
            Dictionary with paths to generated reports
        """
        json_path = self.generate_json_report()
        html_path = self.generate_html_report()
        
        return {
            'json': json_path,
            'html': html_path
        }
