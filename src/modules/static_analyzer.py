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
    
    def detect_anti_analysis(self):
        """
        Detect anti-analysis and anti-debugging techniques
        
        Returns:
            list: Anti-analysis techniques found
        """
        try:
            logger.info("Detecting anti-analysis techniques...")
            
            techniques = []
            all_strings = self.extract_all_strings()
            
            # Anti-debugging patterns
            anti_debug_patterns = {
                'android.os.Debug.isDebuggerConnected': 'Debugger detection',
                'TracerPid': 'Tracer detection via /proc/self/status',
                '/proc/self/status': 'Process status inspection',
                'ptrace': 'Ptrace anti-debugging',
                'JDWP': 'Java Debug Wire Protocol detection',
                'BuildConfig.DEBUG': 'Debug build check',
                'ApplicationInfo.FLAG_DEBUGGABLE': 'Debuggable flag check',
            }
            
            # Emulator detection patterns
            emulator_patterns = {
                'Build.FINGERPRINT': 'Build fingerprint check',
                'generic': 'Generic device check',
                'goldfish': 'Goldfish emulator check',
                'sdk_phone': 'SDK phone emulator check',
                'Emulator': 'Emulator string detection',
                'vbox': 'VirtualBox detection',
                'qemu': 'QEMU emulator detection',
                'genymotion': 'Genymotion emulator detection',
            }
            
            # Root detection patterns
            root_patterns = {
                '/system/app/Superuser.apk': 'Superuser APK check',
                '/system/xbin/su': 'su binary check',
                'com.noshufou.android.su': 'SuperSU check',
                'eu.chainfire.supersu': 'SuperSU package check',
                'com.topjohnwu.magisk': 'Magisk detection',
                'test-keys': 'Test keys detection (rooted)',
            }
            
            # Check all patterns
            all_patterns = {
                **anti_debug_patterns,
                **emulator_patterns,
                **root_patterns
            }
            
            for pattern, description in all_patterns.items():
                for string in all_strings:
                    if pattern.lower() in string.lower():
                        technique_type = (
                            'ANTI_DEBUG' if pattern in anti_debug_patterns else
                            'EMULATOR_DETECTION' if pattern in emulator_patterns else
                            'ROOT_DETECTION'
                        )
                        
                        techniques.append({
                            'type': technique_type,
                            'pattern': pattern,
                            'description': description,
                            'severity': 'HIGH'
                        })
                        break
            
            # Remove duplicates
            unique_techniques = []
            seen = set()
            for tech in techniques:
                key = (tech['type'], tech['pattern'])
                if key not in seen:
                    seen.add(key)
                    unique_techniques.append(tech)
            
            self.results['anti_analysis'] = unique_techniques
            
            if unique_techniques:
                logger.warning(f"⚠ Detected {len(unique_techniques)} anti-analysis techniques")
            else:
                logger.info("✓ No anti-analysis techniques detected")
            
            return unique_techniques
            
        except Exception as e:
            logger.error(f"Failed to detect anti-analysis: {e}")
            return []
    
    def detect_packing_obfuscation(self):
        """
        Detect packing and advanced obfuscation techniques
        
        Returns:
            dict: Packing/obfuscation analysis
        """
        try:
            logger.info("Detecting packing and obfuscation...")
            
            indicators = {
                'is_packed': False,
                'packer_names': [],
                'obfuscation_score': 0,
                'indicators': []
            }
            
            all_strings = self.extract_all_strings()
            
            # Known packer signatures
            packers = {
                'jiagu': 'Qihoo 360 Jiagu',
                'bangcle': 'Bangcle/SecNeo',
                'ijiami': 'Ijiami',
                'apkprotect': 'APKProtect',
                'dexprotector': 'DexProtector',
                'allatori': 'Allatori Obfuscator',
                'proguard': 'ProGuard',
                'dexguard': 'DexGuard',
            }
            
            for packer_sig, packer_name in packers.items():
                for string in all_strings:
                    if packer_sig.lower() in string.lower():
                        indicators['packer_names'].append(packer_name)
                        indicators['is_packed'] = True
                        indicators['indicators'].append({
                            'type': 'PACKER_SIGNATURE',
                            'value': packer_name,
                            'evidence': string[:100]
                        })
                        break
            
            # Check for encrypted/encoded strings (high entropy in string literals)
            base64_pattern = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')
            hex_pattern = re.compile(r'^[0-9a-fA-F]{40,}$')
            
            encoded_strings = 0
            for string in all_strings[:500]:  # Check first 500 strings
                if len(string) > 20:
                    if base64_pattern.match(string):
                        encoded_strings += 1
                    elif hex_pattern.match(string):
                        encoded_strings += 1
            
            if encoded_strings > 10:
                indicators['indicators'].append({
                    'type': 'ENCODED_STRINGS',
                    'value': f'{encoded_strings} encoded strings found',
                    'evidence': 'High number of Base64/Hex strings'
                })
                indicators['obfuscation_score'] += 20
            
            # Check DEX file count (multiple DEX = possible packing)
            dex_count = len(self.extracted_files.get('dex_files', []))
            if dex_count > 2:
                indicators['indicators'].append({
                    'type': 'MULTIPLE_DEX',
                    'value': f'{dex_count} DEX files',
                    'evidence': 'Multidex or packed application'
                })
                indicators['obfuscation_score'] += 15
            
            # Native library checks
            native_libs = self.extracted_files.get('native_libs', [])
            if len(native_libs) > 10:
                indicators['indicators'].append({
                    'type': 'EXCESSIVE_NATIVE_LIBS',
                    'value': f'{len(native_libs)} native libraries',
                    'evidence': 'High native library count (possible packer)'
                })
                indicators['obfuscation_score'] += 10
            
            # Calculate final score
            if indicators['is_packed']:
                indicators['obfuscation_score'] += 30
            
            indicators['obfuscation_score'] = min(indicators['obfuscation_score'], 100)
            
            self.results['packing_obfuscation'] = indicators
            
            if indicators['is_packed']:
                logger.warning(f"⚠ App appears to be packed: {', '.join(indicators['packer_names'])}")
            
            return indicators
            
        except Exception as e:
            logger.error(f"Failed to detect packing: {e}")
            return {}
    
    def detect_data_exfiltration(self):
        """
        Detect potential data exfiltration patterns
        
        Returns:
            list: Data exfiltration indicators
        """
        try:
            logger.info("Detecting data exfiltration patterns...")
            
            exfil_patterns = []
            all_strings = self.extract_all_strings()
            
            # Suspicious data collection patterns
            data_collection = {
                'getDeviceId': 'Device ID collection',
                'getSubscriberId': 'Subscriber ID (IMSI) collection',
                'getSimSerialNumber': 'SIM serial collection',
                'getLine1Number': 'Phone number collection',
                'getLastKnownLocation': 'Location data collection',
                'getAllByName': 'DNS resolution (C&C)',
                'ContentResolver.query': 'Content provider queries',
                'getInstalledPackages': 'Installed apps enumeration',
                'getAccounts': 'Account information access',
                'getCellLocation': 'Cell tower location',
            }
            
            for pattern, description in data_collection.items():
                count = sum(1 for s in all_strings if pattern in s)
                if count > 0:
                    exfil_patterns.append({
                        'pattern': pattern,
                        'description': description,
                        'occurrences': count,
                        'severity': 'HIGH' if count > 5 else 'MEDIUM'
                    })
            
            # Network transmission indicators
            network_transmission = [
                'HttpURLConnection',
                'HttpClient',
                'OkHttp',
                'Socket',
                'URLConnection'
            ]
            
            has_network = any(
                any(net_api in s for s in all_strings)
                for net_api in network_transmission
            )
            
            # If has data collection + network = potential exfiltration
            if exfil_patterns and has_network:
                exfil_patterns.append({
                    'pattern': 'DATA_COLLECTION_WITH_NETWORK',
                    'description': 'Collects sensitive data + has network capability',
                    'occurrences': 1,
                    'severity': 'CRITICAL'
                })
            
            self.results['data_exfiltration'] = exfil_patterns
            
            if exfil_patterns:
                logger.warning(f"⚠ Detected {len(exfil_patterns)} data exfiltration indicators")
            
            return exfil_patterns
            
        except Exception as e:
            logger.error(f"Failed to detect exfiltration: {e}")
            return []
    
    def calculate_threat_score(self):
        """
        Calculate threat score based on static analysis
        
        Returns:
            float: Threat score (0-100)
        """
        score = 0
        
        # Suspicious strings (max 15 points)
        suspicious_strings = self.results.get('suspicious_strings', [])
        score += min(len(suspicious_strings) * 0.5, 15)
        
        # Dynamic code loading (max 20 points)
        dynamic_loading = self.results.get('dynamic_code_loading', [])
        score += min(len(dynamic_loading) * 5, 20)
        
        # Native code usage (max 10 points)
        native_usage = self.results.get('native_code_usage', {})
        native_count = native_usage.get('native_libs_count', 0)
        score += min(native_count * 2, 10)
        
        # Packing/obfuscation (max 20 points)
        packing = self.results.get('packing_obfuscation', {})
        obf_score = packing.get('obfuscation_score', 0)
        score += min(obf_score / 5, 20)
        
        # Anti-analysis techniques (max 15 points)
        anti_analysis = self.results.get('anti_analysis', [])
        score += min(len(anti_analysis) * 5, 15)
        
        # Data exfiltration (max 20 points)
        exfil = self.results.get('data_exfiltration', [])
        for pattern in exfil:
            if pattern['severity'] == 'CRITICAL':
                score += 8
            elif pattern['severity'] == 'HIGH':
                score += 4
            else:
                score += 2
        score = min(score, 100)
        
        # Category-based scoring
        category_counter = Counter()
        for finding in suspicious_strings:
            category_counter[finding.get('category', 'OTHER')] += 1
        
        # Extra points for dangerous categories
        if category_counter.get('ROOT_ACCESS', 0) > 0:
            score += 10
        if category_counter.get('SHELL_COMMAND', 0) > 0:
            score += 8
        if category_counter.get('DYNAMIC_LOADING', 0) > 0:
            score += 7
        
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
        self.detect_anti_analysis()
        self.detect_packing_obfuscation()
        self.detect_data_exfiltration()
        
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
            'network_apis_count': len(self.results.get('network_activity', [])),
            'anti_analysis_count': len(self.results.get('anti_analysis', [])),
            'is_packed': self.results.get('packing_obfuscation', {}).get('is_packed', False),
            'data_exfiltration_count': len(self.results.get('data_exfiltration', []))
        }
