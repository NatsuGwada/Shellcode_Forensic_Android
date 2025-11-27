"""
JADX Decompiler Module for AndroSleuth
Integrates JADX for Java source code decompilation and advanced analysis
"""

import os
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import re

from ..utils.logger import get_logger

logger = get_logger()


class JADXDecompiler:
    """Decompile and analyze APK using JADX"""
    
    def __init__(self, apk_path: str, output_dir: Optional[str] = None):
        """
        Initialize JADX Decompiler
        
        Args:
            apk_path: Path to APK file
            output_dir: Optional output directory for decompiled sources
        """
        self.apk_path = apk_path
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="jadx_")
        self.sources_dir = os.path.join(self.output_dir, "sources")
        self.resources_dir = os.path.join(self.output_dir, "resources")
        
        self.results = {
            'decompiled': False,
            'classes_count': 0,
            'methods_count': 0,
            'suspicious_code': [],
            'hardcoded_secrets': [],
            'dangerous_apis': [],
            'obfuscation_indicators': [],
            'code_complexity': {},
            'threat_score': 0
        }
        
        logger.info(f"Initializing JADX Decompiler for: {apk_path}")
    
    def check_jadx_installed(self) -> bool:
        """
        Check if JADX is installed and accessible
        
        Returns:
            bool: True if JADX is available
        """
        try:
            result = subprocess.run(
                ['jadx', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"✓ JADX found: {version}")
                return True
            return False
        except FileNotFoundError:
            logger.error("✗ JADX not found. Install with: sudo apt install jadx")
            return False
        except Exception as e:
            logger.error(f"Error checking JADX: {e}")
            return False
    
    def decompile(self, timeout: int = 300) -> bool:
        """
        Decompile APK using JADX
        
        Args:
            timeout: Timeout in seconds for decompilation
            
        Returns:
            bool: True if decompilation successful
        """
        try:
            if not self.check_jadx_installed():
                logger.warning("JADX not available - skipping decompilation")
                return False
            
            logger.info(f"Decompiling APK with JADX (timeout: {timeout}s)...")
            logger.info(f"Output directory: {self.output_dir}")
            
            # JADX command with optimal flags
            cmd = [
                'jadx',
                '--output-dir', self.output_dir,
                '--no-res',  # Skip resources for faster decompilation
                '--no-debug-info',  # Skip debug info
                '--deobf',  # Enable deobfuscation
                '--threads-count', '4',  # Use 4 threads
                '--show-bad-code',  # Show problematic code
                self.apk_path
            ]
            
            # Run JADX
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                
                if process.returncode == 0:
                    logger.info("✓ Decompilation successful")
                    self.results['decompiled'] = True
                    
                    # Count decompiled files
                    self._count_decompiled_files()
                    return True
                else:
                    logger.error(f"✗ JADX failed with code {process.returncode}")
                    if stderr:
                        logger.error(f"Error: {stderr[:500]}")
                    return False
                    
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error(f"✗ Decompilation timeout after {timeout}s")
                return False
                
        except Exception as e:
            logger.error(f"Decompilation failed: {e}")
            return False
    
    def _count_decompiled_files(self):
        """Count decompiled Java files and methods"""
        try:
            java_files = list(Path(self.sources_dir).rglob("*.java"))
            self.results['classes_count'] = len(java_files)
            
            # Count methods in all files
            method_count = 0
            for java_file in java_files:
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Count method declarations
                        method_count += len(re.findall(r'(public|private|protected|static|\s)+[\w<>\[\]]+\s+\w+\s*\([^\)]*\)\s*\{', content))
                except:
                    pass
            
            self.results['methods_count'] = method_count
            logger.info(f"✓ Decompiled {self.results['classes_count']} classes, {method_count} methods")
            
        except Exception as e:
            logger.error(f"Error counting files: {e}")
    
    def scan_hardcoded_secrets(self) -> List[Dict]:
        """
        Scan decompiled code for hardcoded secrets
        
        Returns:
            list: Found secrets
        """
        try:
            logger.info("Scanning for hardcoded secrets...")
            
            if not self.results['decompiled']:
                logger.warning("APK not decompiled - skipping secret scan")
                return []
            
            secrets = []
            
            # Patterns for secrets
            patterns = {
                'api_key': re.compile(r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE),
                'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
                'private_key': re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----'),
                'password': re.compile(r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', re.IGNORECASE),
                'secret': re.compile(r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
                'token': re.compile(r'["\']?(?:auth[_-]?token|token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE),
                'firebase': re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
                'jdbc_url': re.compile(r'jdbc:[a-z]+://[^\s"\']+'),
                'base64_key': re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'),
            }
            
            java_files = list(Path(self.sources_dir).rglob("*.java"))
            
            for java_file in java_files[:100]:  # Limit to first 100 files for performance
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for secret_type, pattern in patterns.items():
                            matches = pattern.finditer(content)
                            for match in matches:
                                secret_value = match.group(1) if match.groups() else match.group(0)
                                
                                # Skip common false positives
                                if self._is_false_positive(secret_value):
                                    continue
                                
                                secrets.append({
                                    'type': secret_type,
                                    'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                                    'file': str(java_file.relative_to(self.sources_dir)),
                                    'severity': self._get_secret_severity(secret_type)
                                })
                except:
                    continue
            
            # Remove duplicates
            unique_secrets = []
            seen = set()
            for secret in secrets:
                key = (secret['type'], secret['value'])
                if key not in seen:
                    seen.add(key)
                    unique_secrets.append(secret)
            
            self.results['hardcoded_secrets'] = unique_secrets
            logger.info(f"✓ Found {len(unique_secrets)} potential hardcoded secrets")
            
            return unique_secrets
            
        except Exception as e:
            logger.error(f"Error scanning secrets: {e}")
            return []
    
    def _is_false_positive(self, value: str) -> bool:
        """Check if a secret value is likely a false positive"""
        false_positives = [
            'test', 'example', 'sample', 'demo', 'default',
            'your_key_here', 'your_password', 'insert_key',
            '12345', 'abcdef', 'null', 'none', 'empty',
            'xxxxxxxxxx', '**********'
        ]
        value_lower = value.lower()
        return any(fp in value_lower for fp in false_positives)
    
    def _get_secret_severity(self, secret_type: str) -> str:
        """Get severity level for secret type"""
        critical = ['private_key', 'aws_key']
        high = ['api_key', 'password', 'token']
        medium = ['secret', 'firebase', 'jdbc_url']
        
        if secret_type in critical:
            return 'CRITICAL'
        elif secret_type in high:
            return 'HIGH'
        elif secret_type in medium:
            return 'MEDIUM'
        return 'LOW'
    
    def detect_dangerous_apis(self) -> List[Dict]:
        """
        Detect usage of dangerous APIs in decompiled code
        
        Returns:
            list: Dangerous API usage
        """
        try:
            logger.info("Detecting dangerous API usage...")
            
            if not self.results['decompiled']:
                logger.warning("APK not decompiled - skipping API detection")
                return []
            
            dangerous_apis = []
            
            # Define dangerous API patterns
            api_patterns = {
                'Runtime.exec': {'severity': 'CRITICAL', 'description': 'Command execution'},
                'ProcessBuilder': {'severity': 'HIGH', 'description': 'Process creation'},
                'System.loadLibrary': {'severity': 'MEDIUM', 'description': 'Native library loading'},
                'Class.forName': {'severity': 'HIGH', 'description': 'Dynamic class loading'},
                'DexClassLoader': {'severity': 'CRITICAL', 'description': 'Dynamic DEX loading'},
                'HttpURLConnection': {'severity': 'LOW', 'description': 'HTTP connection'},
                'SSLSocketFactory': {'severity': 'MEDIUM', 'description': 'SSL socket'},
                'TrustManager': {'severity': 'HIGH', 'description': 'SSL trust manager'},
                'WebView.addJavascriptInterface': {'severity': 'HIGH', 'description': 'JS interface (XSS risk)'},
                'Cipher.getInstance': {'severity': 'MEDIUM', 'description': 'Cryptography usage'},
                'MessageDigest.getInstance': {'severity': 'LOW', 'description': 'Hashing'},
                'getRuntime': {'severity': 'HIGH', 'description': 'Runtime access'},
                'getSystemService': {'severity': 'LOW', 'description': 'System service access'},
                'sendTextMessage': {'severity': 'MEDIUM', 'description': 'SMS sending'},
                'ContentResolver.query': {'severity': 'MEDIUM', 'description': 'Content query'},
                'getDeviceId': {'severity': 'MEDIUM', 'description': 'Device ID access'},
                'getSubscriberId': {'severity': 'MEDIUM', 'description': 'Subscriber ID access'},
                'getLastKnownLocation': {'severity': 'MEDIUM', 'description': 'Location access'},
            }
            
            java_files = list(Path(self.sources_dir).rglob("*.java"))
            
            for java_file in java_files[:150]:  # Limit for performance
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        
                        for api, info in api_patterns.items():
                            if api in content:
                                # Find line numbers
                                line_nums = [i+1 for i, line in enumerate(lines) if api in line]
                                
                                dangerous_apis.append({
                                    'api': api,
                                    'severity': info['severity'],
                                    'description': info['description'],
                                    'file': str(java_file.relative_to(self.sources_dir)),
                                    'occurrences': len(line_nums),
                                    'lines': line_nums[:5]  # First 5 occurrences
                                })
                except:
                    continue
            
            self.results['dangerous_apis'] = dangerous_apis
            logger.info(f"✓ Detected {len(dangerous_apis)} dangerous API usages")
            
            return dangerous_apis
            
        except Exception as e:
            logger.error(f"Error detecting APIs: {e}")
            return []
    
    def detect_obfuscation(self) -> Dict:
        """
        Detect code obfuscation indicators
        
        Returns:
            dict: Obfuscation analysis
        """
        try:
            logger.info("Detecting code obfuscation...")
            
            if not self.results['decompiled']:
                logger.warning("APK not decompiled - skipping obfuscation detection")
                return {}
            
            indicators = {
                'short_names': 0,
                'single_char_classes': 0,
                'numeric_names': 0,
                'string_encryption': 0,
                'control_flow_obfuscation': 0,
                'total_score': 0
            }
            
            java_files = list(Path(self.sources_dir).rglob("*.java"))
            
            for java_file in java_files[:100]:
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Check class name
                        class_match = re.search(r'class\s+([a-zA-Z0-9_]+)', content)
                        if class_match:
                            class_name = class_match.group(1)
                            
                            # Single character class names
                            if len(class_name) == 1:
                                indicators['single_char_classes'] += 1
                            
                            # Very short names (2-3 chars, all lowercase)
                            if len(class_name) <= 3 and class_name.islower():
                                indicators['short_names'] += 1
                            
                            # Numeric or mixed naming pattern
                            if re.match(r'^[a-z]\d+$', class_name):
                                indicators['numeric_names'] += 1
                        
                        # String encryption patterns
                        if 'decrypt' in content.lower() or 'deobfuscate' in content.lower():
                            indicators['string_encryption'] += 1
                        
                        # XOR operations (common in obfuscation)
                        if content.count('^') > 10:  # Many XOR operations
                            indicators['string_encryption'] += 1
                        
                        # Control flow obfuscation (excessive switch/goto)
                        switch_count = content.count('switch')
                        if switch_count > 5:
                            indicators['control_flow_obfuscation'] += 1
                        
                except:
                    continue
            
            # Calculate obfuscation score
            score = (
                indicators['single_char_classes'] * 10 +
                indicators['short_names'] * 5 +
                indicators['numeric_names'] * 5 +
                indicators['string_encryption'] * 15 +
                indicators['control_flow_obfuscation'] * 10
            )
            indicators['total_score'] = min(score, 100)
            
            # Determine if obfuscated
            indicators['is_obfuscated'] = indicators['total_score'] > 30
            indicators['obfuscation_level'] = (
                'HEAVY' if indicators['total_score'] > 70 else
                'MODERATE' if indicators['total_score'] > 40 else
                'LIGHT' if indicators['total_score'] > 20 else
                'NONE'
            )
            
            self.results['obfuscation_indicators'] = indicators
            
            if indicators['is_obfuscated']:
                logger.warning(f"⚠ Code appears to be obfuscated - Level: {indicators['obfuscation_level']}")
            else:
                logger.info("✓ No significant obfuscation detected")
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error detecting obfuscation: {e}")
            return {}
    
    def analyze_code_complexity(self) -> Dict:
        """
        Analyze code complexity metrics
        
        Returns:
            dict: Complexity metrics
        """
        try:
            logger.info("Analyzing code complexity...")
            
            if not self.results['decompiled']:
                return {}
            
            metrics = {
                'avg_methods_per_class': 0,
                'max_method_length': 0,
                'deep_nesting_count': 0,
                'complexity_score': 0
            }
            
            java_files = list(Path(self.sources_dir).rglob("*.java"))
            total_methods = 0
            
            for java_file in java_files[:50]:
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Count methods
                        methods = re.findall(r'(public|private|protected|static|\s)+[\w<>\[\]]+\s+\w+\s*\([^\)]*\)\s*\{', content)
                        total_methods += len(methods)
                        
                        # Check nesting depth (4+ levels)
                        max_depth = content.count('{' * 4)
                        if max_depth > 0:
                            metrics['deep_nesting_count'] += 1
                        
                except:
                    continue
            
            if java_files:
                metrics['avg_methods_per_class'] = round(total_methods / len(java_files), 2)
            
            # Complexity score
            if metrics['avg_methods_per_class'] > 20:
                metrics['complexity_score'] += 20
            if metrics['deep_nesting_count'] > 10:
                metrics['complexity_score'] += 30
            
            self.results['code_complexity'] = metrics
            logger.info(f"✓ Avg methods/class: {metrics['avg_methods_per_class']}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error analyzing complexity: {e}")
            return {}
    
    def calculate_threat_score(self) -> float:
        """
        Calculate threat score based on JADX analysis
        
        Returns:
            float: Threat score (0-100)
        """
        score = 0
        
        # Hardcoded secrets (max 25 points)
        secrets = self.results.get('hardcoded_secrets', [])
        for secret in secrets:
            if secret['severity'] == 'CRITICAL':
                score += 5
            elif secret['severity'] == 'HIGH':
                score += 3
            elif secret['severity'] == 'MEDIUM':
                score += 2
            else:
                score += 1
        score = min(score, 25)
        
        # Dangerous APIs (max 30 points)
        apis = self.results.get('dangerous_apis', [])
        for api in apis:
            if api['severity'] == 'CRITICAL':
                score += 4
            elif api['severity'] == 'HIGH':
                score += 2
            elif api['severity'] == 'MEDIUM':
                score += 1
        score = min(score + len([a for a in apis if a['severity'] in ['CRITICAL', 'HIGH']]) * 2, score + 30)
        
        # Obfuscation (max 20 points)
        obf = self.results.get('obfuscation_indicators', {})
        obf_score = obf.get('total_score', 0)
        score += min(obf_score / 5, 20)
        
        # Code complexity (max 10 points)
        complexity = self.results.get('code_complexity', {})
        score += min(complexity.get('complexity_score', 0) / 5, 10)
        
        score = min(score, 100)
        self.results['threat_score'] = round(score, 2)
        
        return score
    
    def analyze(self, decompile_timeout: int = 300) -> Dict:
        """
        Run complete JADX analysis
        
        Args:
            decompile_timeout: Timeout for decompilation
            
        Returns:
            dict: Complete analysis results
        """
        logger.info("=" * 60)
        logger.info("Starting JADX Deep Analysis")
        logger.info("=" * 60)
        
        # Decompile APK
        if self.decompile(timeout=decompile_timeout):
            # Run analyses
            self.scan_hardcoded_secrets()
            self.detect_dangerous_apis()
            self.detect_obfuscation()
            self.analyze_code_complexity()
            
            # Calculate threat score
            threat_score = self.calculate_threat_score()
            
            logger.info("=" * 60)
            logger.info(f"JADX Analysis Complete - Threat Score: {threat_score}/100")
            logger.info("=" * 60)
        else:
            logger.warning("JADX analysis skipped - decompilation failed")
        
        return self.results
    
    def cleanup(self):
        """Clean up temporary decompiled files"""
        try:
            if os.path.exists(self.output_dir) and self.output_dir.startswith('/tmp/'):
                shutil.rmtree(self.output_dir)
                logger.info(f"✓ Cleaned up: {self.output_dir}")
        except Exception as e:
            logger.warning(f"Failed to cleanup: {e}")
    
    def get_summary(self) -> Dict:
        """
        Get summary of JADX analysis
        
        Returns:
            dict: Summary
        """
        obf_indicators = self.results.get('obfuscation_indicators', {})
        is_obf = obf_indicators.get('is_obfuscated', False) if isinstance(obf_indicators, dict) else False
        
        return {
            'decompiled': self.results.get('decompiled', False),
            'classes_count': self.results.get('classes_count', 0),
            'methods_count': self.results.get('methods_count', 0),
            'secrets_found': len(self.results.get('hardcoded_secrets', [])),
            'dangerous_apis_found': len(self.results.get('dangerous_apis', [])),
            'is_obfuscated': is_obf,
            'threat_score': self.results.get('threat_score', 0)
        }
