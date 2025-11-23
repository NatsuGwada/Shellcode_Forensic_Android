"""
Shellcode Detector Module for AndroSleuth
Analyzes native libraries (.so files) for shellcode patterns and suspicious code
"""

import os
import re
import struct
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_64, CS_MODE_32
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from ..utils.logger import get_logger
from ..utils.helpers import read_file_safely
from ..utils.entropy import calculate_entropy

logger = get_logger()


class ShellcodeDetector:
    """Detector for shellcode patterns in native libraries"""
    
    def __init__(self, extracted_files):
        """
        Initialize Shellcode Detector
        
        Args:
            extracted_files: Dictionary with paths to extracted files
        """
        self.extracted_files = extracted_files
        self.results = {
            'native_libs': [],
            'suspicious_libraries': [],
            'shellcode_patterns': [],
            'syscalls_detected': [],
            'executable_sections': [],
            'threat_score': 0
        }
        
        if not CAPSTONE_AVAILABLE:
            logger.warning("Capstone not available - disassembly features disabled")
            logger.warning("Install with: pip install capstone")
        
        logger.info("Initializing Shellcode Detector")
    
    def analyze_elf_header(self, lib_path):
        """
        Analyze ELF header of native library
        
        Args:
            lib_path: Path to .so file
        
        Returns:
            dict: ELF header information
        """
        try:
            with open(lib_path, 'rb') as f:
                # Read ELF magic and header
                magic = f.read(4)
                
                if magic != b'\x7fELF':
                    return {'is_elf': False, 'error': 'Not an ELF file'}
                
                # Read ELF class (32/64 bit)
                elf_class = struct.unpack('B', f.read(1))[0]
                architecture = '64-bit' if elf_class == 2 else '32-bit'
                
                # Read endianness
                endian = struct.unpack('B', f.read(1))[0]
                endianness = 'Little-endian' if endian == 1 else 'Big-endian'
                
                # Seek to e_machine (architecture type)
                f.seek(18)
                e_machine = struct.unpack('<H', f.read(2))[0]
                
                arch_map = {
                    0x28: 'ARM',
                    0xB7: 'ARM64',
                    0x03: 'x86',
                    0x3E: 'x86-64'
                }
                
                arch_type = arch_map.get(e_machine, f'Unknown (0x{e_machine:x})')
                
                return {
                    'is_elf': True,
                    'architecture': architecture,
                    'arch_type': arch_type,
                    'endianness': endianness,
                    'e_machine': e_machine
                }
        
        except Exception as e:
            logger.error(f"Error analyzing ELF header for {lib_path}: {str(e)}")
            return {'is_elf': False, 'error': str(e)}
    
    def detect_suspicious_syscalls(self, lib_path):
        """
        Detect suspicious system calls in binary
        
        Args:
            lib_path: Path to library
        
        Returns:
            list: Suspicious syscalls found
        """
        try:
            data = read_file_safely(lib_path)
            if not data:
                return []
            
            # Common dangerous syscalls
            dangerous_syscalls = [
                b'execve',
                b'system',
                b'fork',
                b'ptrace',
                b'chmod',
                b'chown',
                b'mount',
                b'setuid',
                b'setgid',
                b'kill',
                b'socket',
                b'connect',
                b'bind'
            ]
            
            found_syscalls = []
            
            for syscall in dangerous_syscalls:
                if syscall in data:
                    found_syscalls.append({
                        'syscall': syscall.decode('utf-8'),
                        'risk': 'HIGH' if syscall in [b'execve', b'system', b'ptrace'] else 'MEDIUM'
                    })
            
            return found_syscalls
        
        except Exception as e:
            logger.error(f"Error detecting syscalls: {str(e)}")
            return []
    
    def detect_shellcode_patterns(self, lib_path):
        """
        Detect common shellcode patterns
        
        Args:
            lib_path: Path to library
        
        Returns:
            list: Shellcode patterns detected
        """
        try:
            data = read_file_safely(lib_path)
            if not data:
                return []
            
            patterns = []
            
            # NOP sled detection (common in exploits)
            nop_patterns = [
                (b'\x90' * 10, 'x86 NOP sled'),
                (b'\x00\x00\xa0\xe1' * 4, 'ARM NOP sled'),
                (b'\x1f\x20\x03\xd5' * 4, 'ARM64 NOP sled')
            ]
            
            for pattern, description in nop_patterns:
                if pattern in data:
                    patterns.append({
                        'type': 'NOP_SLED',
                        'description': description,
                        'risk': 'HIGH'
                    })
            
            # Egg hunter pattern (used in exploits)
            egg_hunter = b'\x50\x90' * 4  # Common x86 egg hunter
            if egg_hunter in data:
                patterns.append({
                    'type': 'EGG_HUNTER',
                    'description': 'Possible egg hunter pattern detected',
                    'risk': 'HIGH'
                })
            
            # Reverse shell patterns (common IPs and ports)
            # Looking for patterns like connect() syscalls
            if b'\x02\x00' in data:  # AF_INET
                patterns.append({
                    'type': 'NETWORK_SYSCALL',
                    'description': 'Network socket code detected',
                    'risk': 'MEDIUM'
                })
            
            # Self-modifying code indicators
            if b'\xeb\xfe' in data:  # JMP to self (x86)
                patterns.append({
                    'type': 'SELF_MODIFYING',
                    'description': 'Self-modifying code pattern',
                    'risk': 'HIGH'
                })
            
            return patterns
        
        except Exception as e:
            logger.error(f"Error detecting shellcode patterns: {str(e)}")
            return []
    
    def disassemble_suspicious_sections(self, lib_path, elf_info):
        """
        Disassemble suspicious code sections using Capstone
        
        Args:
            lib_path: Path to library
            elf_info: ELF header information
        
        Returns:
            list: Disassembly results
        """
        if not CAPSTONE_AVAILABLE:
            return []
        
        try:
            data = read_file_safely(lib_path, max_size=5*1024*1024)  # Max 5MB
            if not data:
                return []
            
            # Determine architecture for Capstone
            arch_type = elf_info.get('arch_type', '')
            
            if 'ARM64' in arch_type or 'ARM64' in arch_type:
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            elif 'ARM' in arch_type:
                md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            elif 'x86-64' in arch_type:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            elif 'x86' in arch_type:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            else:
                logger.warning(f"Unsupported architecture for disassembly: {arch_type}")
                return []
            
            suspicious_instructions = []
            
            # Find executable sections (simple heuristic: look for high-entropy regions)
            chunk_size = 1024
            for offset in range(0, min(len(data), 100*1024), chunk_size):
                chunk = data[offset:offset+chunk_size]
                entropy = calculate_entropy(chunk)
                
                # High but not too high entropy might indicate code
                if 5.0 < entropy < 7.0:
                    try:
                        # Try to disassemble
                        instructions = list(md.disasm(chunk, offset))
                        
                        # Look for suspicious instructions
                        for instr in instructions[:50]:  # Limit to first 50 instructions
                            mnemonic = instr.mnemonic.lower()
                            
                            # Detect suspicious operations
                            if mnemonic in ['syscall', 'svc', 'int', 'call', 'jmp']:
                                suspicious_instructions.append({
                                    'offset': hex(instr.address),
                                    'instruction': f"{instr.mnemonic} {instr.op_str}",
                                    'type': 'CONTROL_FLOW',
                                    'risk': 'MEDIUM'
                                })
                            
                            elif mnemonic in ['xor', 'ror', 'rol']:
                                suspicious_instructions.append({
                                    'offset': hex(instr.address),
                                    'instruction': f"{instr.mnemonic} {instr.op_str}",
                                    'type': 'CRYPTO_OP',
                                    'risk': 'LOW'
                                })
                    
                    except Exception:
                        # Disassembly failed, probably not code
                        continue
            
            return suspicious_instructions[:20]  # Return top 20
        
        except Exception as e:
            logger.error(f"Error during disassembly: {str(e)}")
            return []
    
    def analyze_strings_in_library(self, lib_path):
        """
        Analyze strings in native library
        
        Args:
            lib_path: Path to library
        
        Returns:
            dict: String analysis results
        """
        try:
            from ..utils.helpers import extract_strings
            
            data = read_file_safely(lib_path)
            if not data:
                return {}
            
            strings = extract_strings(data, min_length=4)
            
            suspicious_strings = []
            shell_commands = ['sh', 'bash', 'su', 'chmod', 'chown', 'mount', 'system']
            network_indicators = ['http://', 'https://', 'socket', 'connect', 'bind']
            crypto_indicators = ['encrypt', 'decrypt', 'cipher', 'aes', 'rsa', 'key']
            
            for string in strings:
                string_lower = string.lower()
                
                # Check for shell commands
                if any(cmd in string_lower for cmd in shell_commands):
                    suspicious_strings.append({
                        'string': string,
                        'category': 'SHELL_COMMAND',
                        'risk': 'HIGH'
                    })
                
                # Check for network indicators
                elif any(net in string_lower for net in network_indicators):
                    suspicious_strings.append({
                        'string': string,
                        'category': 'NETWORK',
                        'risk': 'MEDIUM'
                    })
                
                # Check for crypto indicators
                elif any(cry in string_lower for cry in crypto_indicators):
                    suspicious_strings.append({
                        'string': string,
                        'category': 'CRYPTO',
                        'risk': 'LOW'
                    })
            
            return {
                'total_strings': len(strings),
                'suspicious_strings': suspicious_strings[:20],  # Top 20
                'has_suspicious': len(suspicious_strings) > 0
            }
        
        except Exception as e:
            logger.error(f"Error analyzing strings: {str(e)}")
            return {}
    
    def analyze_native_library(self, lib_path):
        """
        Complete analysis of a single native library
        
        Args:
            lib_path: Path to .so file
        
        Returns:
            dict: Complete analysis results
        """
        logger.info(f"Analyzing native library: {os.path.basename(lib_path)}")
        
        analysis = {
            'path': lib_path,
            'name': os.path.basename(lib_path),
            'size': os.path.getsize(lib_path),
            'elf_info': {},
            'syscalls': [],
            'shellcode_patterns': [],
            'suspicious_instructions': [],
            'string_analysis': {},
            'entropy': 0,
            'threat_level': 'LOW'
        }
        
        # Analyze ELF header
        analysis['elf_info'] = self.analyze_elf_header(lib_path)
        
        # Calculate entropy
        data = read_file_safely(lib_path)
        if data:
            analysis['entropy'] = calculate_entropy(data)
        
        # Detect syscalls
        analysis['syscalls'] = self.detect_suspicious_syscalls(lib_path)
        
        # Detect shellcode patterns
        analysis['shellcode_patterns'] = self.detect_shellcode_patterns(lib_path)
        
        # Disassemble suspicious sections
        if analysis['elf_info'].get('is_elf'):
            analysis['suspicious_instructions'] = self.disassemble_suspicious_sections(
                lib_path, 
                analysis['elf_info']
            )
        
        # Analyze strings
        analysis['string_analysis'] = self.analyze_strings_in_library(lib_path)
        
        # Calculate threat level
        threat_score = 0
        
        if len(analysis['syscalls']) > 5:
            threat_score += 30
        if len(analysis['shellcode_patterns']) > 0:
            threat_score += 40
        if len(analysis['suspicious_instructions']) > 10:
            threat_score += 20
        if analysis['string_analysis'].get('has_suspicious'):
            threat_score += 10
        
        if threat_score >= 70:
            analysis['threat_level'] = 'CRITICAL'
        elif threat_score >= 50:
            analysis['threat_level'] = 'HIGH'
        elif threat_score >= 30:
            analysis['threat_level'] = 'MEDIUM'
        else:
            analysis['threat_level'] = 'LOW'
        
        return analysis
    
    def analyze(self):
        """
        Run complete shellcode detection on all native libraries
        
        Returns:
            dict: Complete analysis results
        """
        logger.info("=" * 60)
        logger.info("Starting Native Code / Shellcode Analysis")
        logger.info("=" * 60)
        
        native_libs = self.extracted_files.get('native_libs', [])
        
        if not native_libs:
            logger.info("No native libraries found in APK")
            return self.results
        
        logger.info(f"Found {len(native_libs)} native libraries to analyze")
        
        for lib_path in native_libs:
            try:
                analysis = self.analyze_native_library(lib_path)
                self.results['native_libs'].append(analysis)
                
                # Track suspicious libraries
                if analysis['threat_level'] in ['HIGH', 'CRITICAL']:
                    self.results['suspicious_libraries'].append(analysis)
                    logger.warning(f"⚠ Suspicious library: {analysis['name']} - {analysis['threat_level']}")
                
                # Aggregate patterns
                self.results['shellcode_patterns'].extend(analysis['shellcode_patterns'])
                self.results['syscalls_detected'].extend(analysis['syscalls'])
            
            except Exception as e:
                logger.error(f"Error analyzing {lib_path}: {str(e)}")
        
        # Calculate overall threat score
        threat_score = self.calculate_threat_score()
        
        logger.info("=" * 60)
        logger.info(f"Shellcode Analysis Complete - Threat Score: {threat_score}/100")
        logger.info(f"Suspicious libraries: {len(self.results['suspicious_libraries'])}/{len(native_libs)}")
        logger.info("=" * 60)
        
        return self.results
    
    def calculate_threat_score(self):
        """
        Calculate overall threat score for native code
        
        Returns:
            int: Threat score (0-100)
        """
        score = 0
        
        total_libs = len(self.results['native_libs'])
        suspicious_libs = len(self.results['suspicious_libraries'])
        
        # Suspicious libraries (max 40 points)
        if total_libs > 0:
            score += min((suspicious_libs / total_libs) * 40, 40)
        
        # Shellcode patterns (max 30 points)
        pattern_count = len(self.results['shellcode_patterns'])
        score += min(pattern_count * 10, 30)
        
        # Dangerous syscalls (max 30 points)
        syscall_count = len(self.results['syscalls_detected'])
        score += min(syscall_count * 3, 30)
        
        score = min(score, 100)
        self.results['threat_score'] = score
        
        return score
    
    def get_summary(self):
        """
        Get summary of shellcode analysis
        
        Returns:
            dict: Summary
        """
        return {
            'total_libraries': len(self.results['native_libs']),
            'suspicious_libraries': len(self.results['suspicious_libraries']),
            'shellcode_patterns_found': len(self.results['shellcode_patterns']),
            'dangerous_syscalls': len(self.results['syscalls_detected']),
            'threat_score': self.results['threat_score'],
            'capstone_available': CAPSTONE_AVAILABLE
        }
