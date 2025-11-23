"""
Obfuscation Detector Module for AndroSleuth
Detects code obfuscation, packers, and encryption in APK files
"""

import os
import re
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.entropy import calculate_entropy, analyze_file_entropy, entropy_description
from ..utils.helpers import extract_strings

logger = get_logger()


class ObfuscationDetector:
    """Detector for code obfuscation and packers"""
    
    def __init__(self, apk_object, extracted_files):
        """
        Initialize Obfuscation Detector
        
        Args:
            apk_object: Androguard APK object
            extracted_files: Dictionary of extracted file paths
        """
        self.apk = apk_object
        self.extracted_files = extracted_files
        self.results = {
            'is_obfuscated': False,
            'obfuscation_score': 0,
            'techniques_detected': [],
            'entropy_analysis': {},
            'packer_detected': None,
            'suspicious_files': []
        }
        
        logger.info("Initializing Obfuscation Detector")
    
    def detect_proguard(self):
        """
        Detect ProGuard obfuscation
        
        Returns:
            dict: ProGuard detection results
        """
        try:
            logger.info("Checking for ProGuard obfuscation...")
            
            # ProGuard typically creates short class/method names
            short_name_count = 0
            total_classes = 0
            
            # Analyze class names from APK
            for cls in self.apk.get_files():
                if cls.endswith('.class') or 'classes' in cls:
                    total_classes += 1
                    # Check for single letter class names (typical ProGuard)
                    class_name = os.path.basename(cls).replace('.class', '')
                    if len(class_name) <= 2:
                        short_name_count += 1
            
            proguard_ratio = short_name_count / total_classes if total_classes > 0 else 0
            is_proguard = proguard_ratio > 0.3
            
            if is_proguard:
                logger.info(f"✓ ProGuard detected ({proguard_ratio*100:.1f}% short names)")
                self.results['techniques_detected'].append({
                    'technique': 'ProGuard',
                    'confidence': 'HIGH' if proguard_ratio > 0.5 else 'MEDIUM',
                    'description': 'Code obfuscated with ProGuard/R8'
                })
            
            return {
                'detected': is_proguard,
                'short_name_ratio': proguard_ratio,
                'short_names': short_name_count,
                'total_classes': total_classes
            }
        
        except Exception as e:
            logger.error(f"Failed to detect ProGuard: {str(e)}")
            return {'detected': False}
    
    def analyze_dex_entropy(self):
        """
        Analyze entropy of DEX files
        
        Returns:
            dict: DEX entropy analysis
        """
        try:
            logger.info("Analyzing DEX file entropy...")
            
            dex_files = self.extracted_files.get('dex_files', [])
            dex_analysis = []
            
            for dex_file in dex_files:
                entropy_stats = analyze_file_entropy(dex_file)
                
                dex_info = {
                    'file': os.path.basename(dex_file),
                    'entropy': entropy_stats.get('overall_entropy', 0),
                    'description': entropy_description(entropy_stats.get('overall_entropy', 0)),
                    'is_suspicious': entropy_stats.get('is_suspicious', False),
                    'file_size': entropy_stats.get('file_size', 0)
                }
                
                dex_analysis.append(dex_info)
                
                if dex_info['is_suspicious']:
                    logger.warning(f"⚠ High entropy detected in {dex_info['file']}: {dex_info['entropy']:.2f}")
                    self.results['suspicious_files'].append(dex_info)
            
            self.results['entropy_analysis']['dex_files'] = dex_analysis
            
            return dex_analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze DEX entropy: {str(e)}")
            return []
    
    def analyze_native_libs_entropy(self):
        """
        Analyze entropy of native libraries (.so files)
        
        Returns:
            dict: Native library entropy analysis
        """
        try:
            logger.info("Analyzing native library entropy...")
            
            native_libs = self.extracted_files.get('native_libs', [])
            lib_analysis = []
            
            for lib_file in native_libs:
                entropy_stats = analyze_file_entropy(lib_file)
                
                lib_info = {
                    'file': os.path.basename(lib_file),
                    'path': lib_file,
                    'entropy': entropy_stats.get('overall_entropy', 0),
                    'description': entropy_description(entropy_stats.get('overall_entropy', 0)),
                    'is_suspicious': entropy_stats.get('is_suspicious', False),
                    'file_size': entropy_stats.get('file_size', 0)
                }
                
                lib_analysis.append(lib_info)
                
                if lib_info['is_suspicious']:
                    logger.warning(f"⚠ High entropy in native lib {lib_info['file']}: {lib_info['entropy']:.2f}")
                    self.results['suspicious_files'].append(lib_info)
            
            self.results['entropy_analysis']['native_libs'] = lib_analysis
            
            return lib_analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze native library entropy: {str(e)}")
            return []
    
    def detect_known_packers(self):
        """
        Detect known Android packers/protectors
        
        Returns:
            list: Detected packers
        """
        try:
            logger.info("Scanning for known packers...")
            
            # Known packer signatures in file names or strings
            known_packers = {
                'UPX': ['upx', 'UPX!'],
                'Bangcle': ['bangcle', 'secshell', 'SecShell'],
                'Qihoo 360': ['libjiagu', 'qihoo', '360'],
                'Baidu': ['baiduprotect', 'libmobisec'],
                'Tencent': ['libtup', 'libshell', 'tencent'],
                'Alibaba': ['aliprotect', 'libmobisec'],
                'Ijiami': ['ijiami', 'libexec'],
                'Nagain': ['nagain'],
                'DexGuard': ['dexguard'],
                'APKProtect': ['apkprotect']
            }
            
            detected_packers = []
            
            # Check in native libraries
            for lib_file in self.extracted_files.get('native_libs', []):
                lib_name = os.path.basename(lib_file).lower()
                
                # Read first 1KB for signature checking
                try:
                    with open(lib_file, 'rb') as f:
                        header = f.read(1024)
                        header_str = header.decode('utf-8', errors='ignore').lower()
                    
                    for packer_name, signatures in known_packers.items():
                        for signature in signatures:
                            if signature.lower() in lib_name or signature.lower() in header_str:
                                if packer_name not in detected_packers:
                                    detected_packers.append(packer_name)
                                    logger.warning(f"⚠ Packer detected: {packer_name} in {lib_name}")
                                    self.results['techniques_detected'].append({
                                        'technique': f'Packer: {packer_name}',
                                        'confidence': 'HIGH',
                                        'description': f'Application protected with {packer_name}'
                                    })
                                break
                except:
                    continue
            
            # Check in DEX files
            for dex_file in self.extracted_files.get('dex_files', []):
                try:
                    strings = extract_strings(open(dex_file, 'rb').read(10000))
                    
                    for packer_name, signatures in known_packers.items():
                        for signature in signatures:
                            if any(signature.lower() in s.lower() for s in strings):
                                if packer_name not in detected_packers:
                                    detected_packers.append(packer_name)
                                    logger.warning(f"⚠ Packer signature found: {packer_name}")
                                break
                except:
                    continue
            
            if detected_packers:
                self.results['packer_detected'] = detected_packers
                self.results['is_obfuscated'] = True
            
            return detected_packers
        
        except Exception as e:
            logger.error(f"Failed to detect packers: {str(e)}")
            return []
    
    def detect_string_obfuscation(self):
        """
        Detect string obfuscation techniques
        
        Returns:
            dict: String obfuscation analysis
        """
        try:
            logger.info("Analyzing string obfuscation...")
            
            # Extract strings from DEX files
            all_strings = []
            for dex_file in self.extracted_files.get('dex_files', []):
                try:
                    with open(dex_file, 'rb') as f:
                        data = f.read()
                        strings = extract_strings(data, min_length=4)
                        all_strings.extend(strings)
                except:
                    continue
            
            # Analyze string characteristics
            total_strings = len(all_strings)
            
            # Count encoded/obfuscated strings
            base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
            hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
            
            base64_count = sum(1 for s in all_strings if len(s) > 10 and base64_pattern.match(s))
            hex_count = sum(1 for s in all_strings if len(s) > 10 and hex_pattern.match(s))
            
            # Count suspicious string operations
            suspicious_keywords = ['decrypt', 'decode', 'deobfuscate', 'unpack', 'cipher', 'fromBase64']
            suspicious_count = sum(1 for s in all_strings if any(kw in s.lower() for kw in suspicious_keywords))
            
            obfuscation_ratio = (base64_count + hex_count + suspicious_count) / total_strings if total_strings > 0 else 0
            
            result = {
                'total_strings': total_strings,
                'base64_like': base64_count,
                'hex_like': hex_count,
                'suspicious_operations': suspicious_count,
                'obfuscation_ratio': obfuscation_ratio,
                'is_obfuscated': obfuscation_ratio > 0.1
            }
            
            if result['is_obfuscated']:
                logger.warning(f"⚠ String obfuscation detected (ratio: {obfuscation_ratio*100:.1f}%)")
                self.results['techniques_detected'].append({
                    'technique': 'String Obfuscation',
                    'confidence': 'HIGH' if obfuscation_ratio > 0.2 else 'MEDIUM',
                    'description': f'Strings appear to be encoded/obfuscated'
                })
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to analyze string obfuscation: {str(e)}")
            return {}
    
    def detect_reflection_usage(self):
        """
        Detect heavy use of Java reflection (common in obfuscated code)
        
        Returns:
            dict: Reflection usage analysis
        """
        try:
            logger.info("Detecting reflection API usage...")
            
            reflection_apis = [
                'java/lang/reflect',
                'Class.forName',
                'getDeclaredMethod',
                'getDeclaredField',
                'getMethod',
                'invoke'
            ]
            
            reflection_count = 0
            total_strings = 0
            
            for dex_file in self.extracted_files.get('dex_files', []):
                try:
                    with open(dex_file, 'rb') as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        total_strings += len(content)
                        
                        for api in reflection_apis:
                            reflection_count += content.count(api)
                except:
                    continue
            
            is_heavy_reflection = reflection_count > 50
            
            if is_heavy_reflection:
                logger.warning(f"⚠ Heavy reflection usage detected ({reflection_count} occurrences)")
                self.results['techniques_detected'].append({
                    'technique': 'Heavy Reflection Usage',
                    'confidence': 'MEDIUM',
                    'description': f'Found {reflection_count} reflection API calls'
                })
            
            return {
                'reflection_count': reflection_count,
                'is_heavy_reflection': is_heavy_reflection
            }
        
        except Exception as e:
            logger.error(f"Failed to detect reflection: {str(e)}")
            return {}
    
    def calculate_obfuscation_score(self):
        """
        Calculate overall obfuscation score
        
        Returns:
            int: Obfuscation score (0-100)
        """
        score = 0
        
        # Packer detected (+30 points)
        if self.results['packer_detected']:
            score += 30
        
        # Number of techniques detected
        score += len(self.results['techniques_detected']) * 10
        
        # Suspicious files with high entropy
        score += len(self.results['suspicious_files']) * 5
        
        # Cap at 100
        score = min(score, 100)
        self.results['obfuscation_score'] = score
        
        # Set overall flag
        self.results['is_obfuscated'] = score >= 30
        
        return score
    
    def analyze(self):
        """
        Run complete obfuscation detection
        
        Returns:
            dict: Complete analysis results
        """
        logger.info("=" * 60)
        logger.info("Starting Obfuscation Detection")
        logger.info("=" * 60)
        
        # Run all detections
        self.detect_proguard()
        self.detect_known_packers()
        self.analyze_dex_entropy()
        self.analyze_native_libs_entropy()
        self.detect_string_obfuscation()
        self.detect_reflection_usage()
        
        # Calculate score
        obf_score = self.calculate_obfuscation_score()
        
        logger.info("=" * 60)
        logger.info(f"Obfuscation Detection Complete - Score: {obf_score}/100")
        logger.info(f"Obfuscated: {'YES' if self.results['is_obfuscated'] else 'NO'}")
        logger.info("=" * 60)
        
        return self.results
    
    def get_summary(self):
        """
        Get summary of obfuscation detection
        
        Returns:
            dict: Summary
        """
        return {
            'is_obfuscated': self.results['is_obfuscated'],
            'obfuscation_score': self.results['obfuscation_score'],
            'techniques_count': len(self.results['techniques_detected']),
            'packer_detected': self.results['packer_detected'],
            'suspicious_files_count': len(self.results['suspicious_files'])
        }
