#!/usr/bin/env python3
"""
YARA Scanner Module
Scan APK files with custom YARA rules for malware detection
"""

import os
from pathlib import Path
from typing import Dict, List, Any

# Try to import yara-python
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from ..utils.logger import setup_logger

logger = setup_logger('yara_scanner')


class YaraScanner:
    """Scan APK files and components using YARA rules"""
    
    def __init__(self, extracted_files: Dict[str, Any], rules_dir: str = None):
        """
        Initialize YARA scanner
        
        Args:
            extracted_files: Dictionary containing extracted APK components
            rules_dir: Path to YARA rules directory (default: yara_rules/)
        """
        self.extracted_files = extracted_files
        
        # Default rules directory
        if rules_dir is None:
            project_root = Path(__file__).parent.parent.parent
            self.rules_dir = project_root / "yara_rules"
        else:
            self.rules_dir = Path(rules_dir)
        
        self.rules = None
        self.results = {
            'yara_available': YARA_AVAILABLE,
            'rules_loaded': False,
            'total_rules': 0,
            'matches': [],
            'matched_files': [],
            'threat_score': 0
        }
        
        if not YARA_AVAILABLE:
            logger.warning("YARA not available. Install with: pip install yara-python")
            return
        
        # Load YARA rules
        self._load_rules()
        
        logger.info("YARA scanner initialized")
    
    
    def _load_rules(self):
        """Load YARA rules from rules directory"""
        if not YARA_AVAILABLE:
            return
        
        if not self.rules_dir.exists():
            logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            return
        
        # Find all .yar and .yara files
        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        
        if not rule_files:
            logger.warning(f"No YARA rules found in {self.rules_dir}")
            return
        
        # Compile rules
        try:
            rules_dict = {}
            for rule_file in rule_files:
                namespace = rule_file.stem
                rules_dict[namespace] = str(rule_file)
                logger.debug(f"Loading YARA rules from: {rule_file.name}")
            
            self.rules = yara.compile(filepaths=rules_dict)
            self.results['rules_loaded'] = True
            self.results['total_rules'] = len(rule_files)
            
            logger.info(f"Loaded {len(rule_files)} YARA rule files")
        
        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
    
    
    def scan(self) -> Dict[str, Any]:
        """
        Scan extracted APK files with YARA rules
        
        Returns:
            Dictionary with scan results
        """
        if not YARA_AVAILABLE:
            logger.warning("YARA scanning skipped (not installed)")
            return self.results
        
        if not self.results['rules_loaded']:
            logger.warning("YARA scanning skipped (no rules loaded)")
            return self.results
        
        logger.info("Starting YARA scan...")
        
        # Scan DEX files
        dex_files = self.extracted_files.get('dex_files', [])
        for dex_file in dex_files:
            self._scan_file(dex_file, 'dex')
        
        # Scan native libraries
        native_libs = self.extracted_files.get('native_libs', [])
        for lib in native_libs:
            self._scan_file(lib, 'native')
        
        # Scan resources
        resources = self.extracted_files.get('resources', [])
        for resource in resources:
            if os.path.isfile(resource):
                self._scan_file(resource, 'resource')
        
        # Scan other files
        other_files = self.extracted_files.get('other_files', [])
        for file in other_files:
            if os.path.isfile(file):
                self._scan_file(file, 'other')
        
        # Calculate threat score
        self._calculate_threat_score()
        
        logger.info(f"YARA scan complete: {len(self.results['matches'])} matches found")
        
        return self.results
    
    
    def _scan_file(self, file_path: str, file_type: str):
        """
        Scan a single file with YARA rules
        
        Args:
            file_path: Path to file to scan
            file_type: Type of file (dex, native, resource, other)
        """
        if not os.path.exists(file_path):
            logger.debug(f"File not found: {file_path}")
            return
        
        try:
            # Check file size (skip very large files > 50MB)
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:
                logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return
            
            # Scan file
            matches = self.rules.match(file_path)
            
            if matches:
                logger.info(f"YARA matches in {os.path.basename(file_path)}: {len(matches)} rules")
                
                for match in matches:
                    match_info = {
                        'file': os.path.basename(file_path),
                        'file_path': file_path,
                        'file_type': file_type,
                        'rule': match.rule,
                        'namespace': match.namespace,
                        'tags': match.tags,
                        'meta': match.meta,
                        'strings': []
                    }
                    
                    # Extract matched strings (limit to 10)
                    for string_match in match.strings[:10]:
                        match_info['strings'].append({
                            'offset': string_match[0],
                            'identifier': string_match[1],
                            'data': string_match[2][:100]  # Limit to 100 bytes
                        })
                    
                    self.results['matches'].append(match_info)
                
                if file_path not in self.results['matched_files']:
                    self.results['matched_files'].append(file_path)
        
        except yara.Error as e:
            logger.debug(f"YARA scan error for {file_path}: {e}")
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
    
    
    def _calculate_threat_score(self):
        """Calculate threat score based on YARA matches"""
        if not self.results['matches']:
            self.results['threat_score'] = 0
            return
        
        score = 0
        severity_weights = {
            'critical': 30,
            'high': 20,
            'medium': 10,
            'low': 5
        }
        
        category_weights = {
            'trojan': 1.5,
            'ransomware': 2.0,
            'spyware': 1.8,
            'backdoor': 1.8,
            'banker': 2.0,
            'keylogger': 1.8,
            'exfiltration': 1.5,
            'fraud': 1.3,
            'exploit': 1.7,
            'miner': 1.2,
            'adware': 0.8,
            'packer': 0.5
        }
        
        for match in self.results['matches']:
            meta = match.get('meta', {})
            severity = meta.get('severity', 'medium')
            category = meta.get('category', 'unknown')
            
            # Base score from severity
            base_score = severity_weights.get(severity, 5)
            
            # Apply category multiplier
            multiplier = category_weights.get(category, 1.0)
            
            score += base_score * multiplier
        
        # Cap at 100
        self.results['threat_score'] = min(int(score), 100)
    
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of YARA scan results
        
        Returns:
            Dictionary with scan summary
        """
        summary = {
            'yara_available': self.results['yara_available'],
            'rules_loaded': self.results['rules_loaded'],
            'total_rules': self.results['total_rules'],
            'total_matches': len(self.results['matches']),
            'matched_files': len(self.results['matched_files']),
            'threat_score': self.results['threat_score'],
            'categories': {},
            'critical_matches': [],
            'high_matches': []
        }
        
        # Count matches by category
        for match in self.results['matches']:
            meta = match.get('meta', {})
            category = meta.get('category', 'unknown')
            severity = meta.get('severity', 'medium')
            
            if category not in summary['categories']:
                summary['categories'][category] = 0
            summary['categories'][category] += 1
            
            # Collect critical and high severity matches
            if severity == 'critical':
                summary['critical_matches'].append({
                    'rule': match['rule'],
                    'file': match['file'],
                    'description': meta.get('description', 'N/A')
                })
            elif severity == 'high':
                summary['high_matches'].append({
                    'rule': match['rule'],
                    'file': match['file'],
                    'description': meta.get('description', 'N/A')
                })
        
        return summary
    
    
    def get_detailed_results(self) -> Dict[str, Any]:
        """
        Get detailed YARA scan results
        
        Returns:
            Dictionary with all results
        """
        return self.results
