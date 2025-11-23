"""
Static Code Analyzer Module for AndroSleuth
Analyzes code for suspicious patterns, strings, and API calls
"""

import re
import yaml
from collections import Counter

from ..utils.logger import get_logger
from ..utils.helpers import extract_strings

logger = get_logger()


class StaticAnalyzer:
    """Static code analyzer for suspicious patterns"""
    
    def __init__(self, apk_object, extracted_files, config_path="config/config.yaml"):
        """
        Initialize Static Analyzer
        
        Args:
            apk_object: Androguard APK object
            extracted_files: Dictionary of extracted file paths
            config_path: Path to configuration file
        """
        self.apk = apk_object
        self.extracted_files = extracted_files
        self.config = self._load_config(config_path)
        self.results = {
            'suspicious_strings': [],
            'suspicious_api_calls': [],
            'dynamic_code_loading': [],
            'native_code_usage': [],
            'crypto_usage': [],
            'network_activity': [],
            'threat_score': 0
        }
        
        logger.info("Initializing Static Analyzer")
    
    def _load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            return {}
    
    def extract_all_strings(self):
        """
        Extract all strings from DEX files
        
        Returns:
            list: All extracted strings
        """
        try:
            logger.info("Extracting strings from DEX files...")
            
            all_strings = []
            
            for dex_file in self.extracted_files.get('dex_files', []):
                try:
                    with open(dex_file, 'rb') as f:
                        data = f.read()
                        strings = extract_strings(data, min_length=4)
                        all_strings.extend(strings)
                except Exception as e:
                    logger.warning(f"Failed to extract from {dex_file}: {e}")
            
            # Remove duplicates while preserving order
            unique_strings = list(dict.fromkeys(all_strings))
            
            logger.info(f"✓ Extracted {len(unique_strings)} unique strings")
            return unique_strings
        
        except Exception as e:
            logger.error(f"Failed to extract strings: {str(e)}")
            return []
    
    def scan_suspicious_strings(self):
        """
        Scan for suspicious string patterns
        
        Returns:
            list: Suspicious strings found
        """
        try:
            logger.info("Scanning for suspicious strings...")
            
            all_strings = self.extract_all_strings()
            suspicious_patterns = self.config.get('detection', {}).get('suspicious_patterns', [])
            
            findings = []
            
            for pattern in suspicious_patterns:
                for string in all_strings:
                    if pattern.lower() in string.lower():
                        findings.append({
                            'pattern': pattern,
                            'matched_string': string,
                            'category': self._categorize_pattern(pattern)
                        })
            
            # Scan for additional patterns
            
            # URLs and IPs
            url_pattern = re.compile(r'https?://[^\s]+')
            ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
            
            for string in all_strings:
                # URLs
                urls = url_pattern.findall(string)
                for url in urls:
                    findings.append({
                        'pattern': 'URL',
                        'matched_string': url,
                        'category': 'NETWORK'
                    })
                
                # IP addresses
                ips = ip_pattern.findall(string)
                for ip in ips:
                    # Skip common local/broadcast IPs
                    if not ip.startswith(('127.', '192.168.', '10.', '0.0.0.0', '255.255')):
                        findings.append({
                            'pattern': 'IP_ADDRESS',
                            'matched_string': ip,
                            'category': 'NETWORK'
                        })
            
            # Shell commands
            shell_commands = ['su', 'sh', 'bash', 'chmod', 'chown', 'mount', 'busybox', 'pm install']
            for cmd in shell_commands:
                for string in all_strings:
                    if cmd in string.lower() and len(string) < 100:
                        findings.append({
                            'pattern': cmd,
                            'matched_string': string,
                            'category': 'SHELL_COMMAND'
                        })
            
            self.results['suspicious_strings'] = findings
            logger.info(f"✓ Found {len(findings)} suspicious strings")
            
            return findings
        
        except Exception as e:
            logger.error(f"Failed to scan strings: {str(e)}")
            return []
    
    def _categorize_pattern(self, pattern):
        """Categorize a pattern"""
        pattern_lower = pattern.lower()
        
        if any(x in pattern_lower for x in ['su', 'root', 'chmod', 'shell']):
            return 'ROOT_ACCESS'
        elif any(x in pattern_lower for x in ['cipher', 'crypto', 'encrypt']):
            return 'CRYPTOGRAPHY'
        elif any(x in pattern_lower for x in ['reflect', 'classloader', 'dexclassloader']):
            return 'DYNAMIC_LOADING'
        elif any(x in pattern_lower for x in ['runtime.exec', 'processbuilder']):
            return 'PROCESS_EXECUTION'
        else:
            return 'OTHER'
    
    def detect_dynamic_code_loading(self):
        """
        Detect dynamic code loading mechanisms
        
        Returns:
            list: Dynamic code loading detections
        """
        try:
            logger.info("Detecting dynamic code loading...")
            
            dangerous_loaders = [
                'DexClassLoader',
                'PathClassLoader',
                'URLClassLoader',
                'InMemoryDexClassLoader',
                'BaseDexClassLoader',
                'loadClass',
                'defineClass'
            ]
            
            findings = []
            all_strings = self.extract_all_strings()
            
            for loader in dangerous_loaders:
                for string in all_strings:
                    if loader in string:
                        findings.append({
                            'loader': loader,
                            'context': string[:100],
                            'risk': 'HIGH'
                        })
            
            if findings:
                logger.warning(f"⚠ Detected {len(findings)} dynamic code loading mechanisms")
            
            self.results['dynamic_code_loading'] = findings
            return findings
        
        except Exception as e:
            logger.error(f"Failed to detect dynamic loading: {str(e)}")
            return []
    
    def detect_native_code_usage(self):
        """
        Detect and analyze native code (JNI) usage
        
        Returns:
            dict: Native code analysis
        """
        try:
            logger.info("Analyzing native code usage...")
            
            native_libs = self.extracted_files.get('native_libs', [])
            
            jni_methods = []
            all_strings = self.extract_all_strings()
            
            # Look for System.loadLibrary calls
            for string in all_strings:
                if 'loadLibrary' in string or 'System.load' in string:
                    jni_methods.append({
                        'type': 'LIBRARY_LOAD',
                        'context': string
                    })
            
            # Look for native method declarations
            for string in all_strings:
                if 'native ' in string and ('public' in string or 'private' in string):
                    jni_methods.append({
                        'type': 'NATIVE_METHOD',
                        'context': string[:100]
                    })
            
            analysis = {
                'native_libs_count': len(native_libs),
                'native_libs': [{'name': lib.split('/')[-1], 'path': lib} for lib in native_libs],
                'jni_calls': jni_methods,
                'risk_level': 'HIGH' if len(native_libs) > 5 else 'MEDIUM' if len(native_libs) > 0 else 'LOW'
            }
            
            if native_libs:
                logger.info(f"✓ Found {len(native_libs)} native libraries")
            
            self.results['native_code_usage'] = analysis
            return analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze native code: {str(e)}")
            return {}
    
    def detect_crypto_usage(self):
        """
        Detect cryptography API usage
        
        Returns:
            list: Cryptography usage detections
        """
        try:
            logger.info("Detecting cryptography usage...")
            
            crypto_apis = [
                'javax.crypto.Cipher',
                'javax.crypto.spec.SecretKeySpec',
                'java.security.MessageDigest',
                'javax.crypto.Mac',
                'java.security.KeyPairGenerator',
                'javax.crypto.KeyGenerator',
                'AES', 'DES', 'RSA', 'MD5', 'SHA',
                'Cipher.getInstance',
                'MessageDigest.getInstance'
            ]
            
            findings = []
            all_strings = self.extract_all_strings()
            
            for api in crypto_apis:
                count = sum(1 for s in all_strings if api in s)
                if count > 0:
                    findings.append({
                        'api': api,
                        'occurrences': count,
                        'risk': 'MEDIUM' if api in ['MD5', 'DES'] else 'LOW'
                    })
            
            if findings:
                logger.info(f"✓ Detected {len(findings)} cryptography API usages")
            
            self.results['crypto_usage'] = findings
            return findings
        
        except Exception as e:
            logger.error(f"Failed to detect crypto usage: {str(e)}")
            return []
    
    def detect_network_activity(self):
        """
        Detect network-related API calls
        
        Returns:
            list: Network activity detections
        """
        try:
            logger.info("Detecting network activity...")
            
            network_apis = [
                'HttpURLConnection',
                'HttpClient',
                'OkHttp',
                'Socket',
                'ServerSocket',
                'URL.openConnection',
                'SSLSocket',
                'DatagramSocket',
                'InetAddress',
                'URLConnection'
            ]
            
            findings = []
            all_strings = self.extract_all_strings()
            
            for api in network_apis:
                count = sum(1 for s in all_strings if api in s)
                if count > 0:
                    findings.append({
                        'api': api,
                        'occurrences': count,
                        'category': 'HTTP' if 'Http' in api else 'SOCKET'
                    })
            
            if findings:
                logger.info(f"✓ Detected {len(findings)} network API usages")
            
            self.results['network_activity'] = findings
            return findings
        
        except Exception as e:
            logger.error(f"Failed to detect network activity: {str(e)}")
            return []
    
    def detect_reflection_api(self):
        """
        Detect Java reflection API usage
        
        Returns:
            dict: Reflection API analysis
        """
        try:
            logger.info("Detecting reflection API usage...")
            
            reflection_apis = [
                'Class.forName',
                'getDeclaredMethod',
                'getDeclaredField',
                'getMethod',
                'getField',
                'invoke',
                'newInstance',
                'setAccessible'
            ]
            
            findings = []
            all_strings = self.extract_all_strings()
            
            for api in reflection_apis:
                count = sum(1 for s in all_strings if api in s)
                if count > 0:
                    findings.append({
                        'api': api,
                        'occurrences': count
                    })
            
            total_reflection = sum(f['occurrences'] for f in findings)
            
            result = {
                'apis_found': findings,
                'total_occurrences': total_reflection,
                'is_heavy_usage': total_reflection > 50
            }
            
            if result['is_heavy_usage']:
                logger.warning(f"⚠ Heavy reflection usage detected ({total_reflection} calls)")
            
            self.results['suspicious_api_calls'].extend(findings)
            return result
        
        except Exception as e:
            logger.error(f"Failed to detect reflection: {str(e)}")
            return {}
    
    def calculate_threat_score(self):
        """
        Calculate threat score based on static analysis
        
        Returns:
            float: Threat score (0-100)
        """
        score = 0
        
        # Suspicious strings (max 20 points)
        suspicious_strings = self.results.get('suspicious_strings', [])
        score += min(len(suspicious_strings) * 0.5, 20)
        
        # Dynamic code loading (max 25 points)
        dynamic_loading = self.results.get('dynamic_code_loading', [])
        score += min(len(dynamic_loading) * 5, 25)
        
        # Native code usage (max 15 points)
        native_usage = self.results.get('native_code_usage', {})
        native_count = native_usage.get('native_libs_count', 0)
        score += min(native_count * 3, 15)
        
        # Category-based scoring
        category_counter = Counter()
        for finding in suspicious_strings:
            category_counter[finding.get('category', 'OTHER')] += 1
        
        # Extra points for dangerous categories
        if category_counter.get('ROOT_ACCESS', 0) > 0:
            score += 15
        if category_counter.get('SHELL_COMMAND', 0) > 0:
            score += 10
        if category_counter.get('DYNAMIC_LOADING', 0) > 0:
            score += 10
        
        score = min(score, 100)
        self.results['threat_score'] = score
        
        return score
    
    def analyze(self):
        """
        Run complete static analysis
        
        Returns:
            dict: Complete analysis results
        """
        logger.info("=" * 60)
        logger.info("Starting Static Code Analysis")
        logger.info("=" * 60)
        
        # Run all analyses
        self.scan_suspicious_strings()
        self.detect_dynamic_code_loading()
        self.detect_native_code_usage()
        self.detect_crypto_usage()
        self.detect_network_activity()
        self.detect_reflection_api()
        
        # Calculate threat score
        threat_score = self.calculate_threat_score()
        
        logger.info("=" * 60)
        logger.info(f"Static Analysis Complete - Threat Score: {threat_score}/100")
        logger.info("=" * 60)
        
        return self.results
    
    def get_summary(self):
        """
        Get summary of static analysis
        
        Returns:
            dict: Summary
        """
        return {
            'threat_score': self.results.get('threat_score', 0),
            'suspicious_strings_count': len(self.results.get('suspicious_strings', [])),
            'dynamic_loading_count': len(self.results.get('dynamic_code_loading', [])),
            'native_libs_count': self.results.get('native_code_usage', {}).get('native_libs_count', 0),
            'crypto_apis_count': len(self.results.get('crypto_usage', [])),
            'network_apis_count': len(self.results.get('network_activity', []))
        }
