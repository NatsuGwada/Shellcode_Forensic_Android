#!/usr/bin/env python3
"""
Emulation Module
Emulate native code using Unicorn Engine to detect self-decrypting malware
"""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional

# Try to import unicorn
try:
    from unicorn import *
    from unicorn.arm_const import *
    from unicorn.arm64_const import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

from ..utils.logger import setup_logger

logger = setup_logger('emulator')


class NativeEmulator:
    """Emulate native code to detect self-decrypting and obfuscated malware"""
    
    def __init__(self, extracted_files: Dict[str, Any]):
        """
        Initialize emulator
        
        Args:
            extracted_files: Dictionary containing extracted APK components
        """
        self.extracted_files = extracted_files
        self.results = {
            'unicorn_available': UNICORN_AVAILABLE,
            'emulated_libraries': [],
            'decryption_detected': False,
            'self_modifying_code': False,
            'suspicious_operations': [],
            'memory_writes': [],
            'threat_score': 0
        }
        
        if not UNICORN_AVAILABLE:
            logger.warning("Unicorn Engine not available. Install with: pip install unicorn")
            return
        
        # Emulation configuration
        self.memory_base = 0x400000
        self.memory_size = 2 * 1024 * 1024  # 2MB
        self.stack_base = 0x7F000000
        self.stack_size = 512 * 1024  # 512KB
        
        logger.info("Emulator initialized")
    
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze native libraries with emulation
        
        Returns:
            Dictionary with emulation results
        """
        if not UNICORN_AVAILABLE:
            logger.warning("Emulation skipped (Unicorn not installed)")
            return self.results
        
        logger.info("Starting emulation analysis...")
        
        # Get native libraries
        native_libs = self.extracted_files.get('native_libs', [])
        
        if not native_libs:
            logger.info("No native libraries found for emulation")
            return self.results
        
        # Emulate each library
        for lib_path in native_libs[:5]:  # Limit to first 5 libraries
            if os.path.exists(lib_path):
                self._emulate_library(lib_path)
        
        # Calculate threat score
        self._calculate_threat_score()
        
        logger.info(f"Emulation complete: {len(self.results['emulated_libraries'])} libraries analyzed")
        
        return self.results
    
    
    def _emulate_library(self, lib_path: str):
        """
        Emulate a native library
        
        Args:
            lib_path: Path to native library
        """
        lib_name = os.path.basename(lib_path)
        logger.debug(f"Emulating library: {lib_name}")
        
        try:
            # Read library
            with open(lib_path, 'rb') as f:
                lib_data = f.read()
            
            # Detect architecture from ELF header
            arch_info = self._detect_architecture(lib_data)
            
            if not arch_info:
                logger.debug(f"Unsupported architecture for {lib_name}")
                return
            
            # Create emulator instance
            mu = self._create_emulator(arch_info)
            
            if not mu:
                return
            
            # Setup memory and hooks
            self._setup_memory(mu, lib_data)
            self._setup_hooks(mu, lib_name)
            
            # Emulate interesting functions
            emulation_results = self._emulate_functions(mu, lib_data, arch_info)
            
            # Record results
            self.results['emulated_libraries'].append({
                'name': lib_name,
                'path': lib_path,
                'architecture': arch_info['name'],
                'decryption_detected': emulation_results.get('decryption_detected', False),
                'self_modifying': emulation_results.get('self_modifying', False),
                'suspicious_ops': emulation_results.get('suspicious_ops', [])
            })
            
            # Update global flags
            if emulation_results.get('decryption_detected'):
                self.results['decryption_detected'] = True
            if emulation_results.get('self_modifying'):
                self.results['self_modifying_code'] = True
        
        except Exception as e:
            logger.debug(f"Emulation error for {lib_name}: {e}")
    
    
    def _detect_architecture(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Detect architecture from ELF header
        
        Args:
            data: Binary data
        
        Returns:
            Dictionary with architecture info or None
        """
        if len(data) < 20:
            return None
        
        # Check ELF magic
        if data[:4] != b'\x7fELF':
            return None
        
        # Get architecture from e_machine field (offset 18-19)
        e_machine = int.from_bytes(data[18:20], byteorder='little')
        
        arch_map = {
            0x28: {'name': 'ARM', 'uc_arch': UC_ARCH_ARM, 'uc_mode': UC_MODE_ARM},
            0xB7: {'name': 'ARM64', 'uc_arch': UC_ARCH_ARM64, 'uc_mode': UC_MODE_ARM},
            0x03: {'name': 'x86', 'uc_arch': UC_ARCH_X86, 'uc_mode': UC_MODE_32},
            0x3E: {'name': 'x86-64', 'uc_arch': UC_ARCH_X86, 'uc_mode': UC_MODE_64}
        }
        
        return arch_map.get(e_machine)
    
    
    def _create_emulator(self, arch_info: Dict[str, Any]):
        """
        Create Unicorn emulator instance
        
        Args:
            arch_info: Architecture information
        
        Returns:
            Unicorn instance or None
        """
        try:
            mu = Uc(arch_info['uc_arch'], arch_info['uc_mode'])
            return mu
        except Exception as e:
            logger.debug(f"Failed to create emulator: {e}")
            return None
    
    
    def _setup_memory(self, mu, lib_data: bytes):
        """
        Setup memory regions for emulation
        
        Args:
            mu: Unicorn instance
            lib_data: Library binary data
        """
        try:
            # Map code memory
            mu.mem_map(self.memory_base, self.memory_size)
            
            # Write library code (first 1MB)
            code_size = min(len(lib_data), 1024 * 1024)
            mu.mem_write(self.memory_base, lib_data[:code_size])
            
            # Map stack
            mu.mem_map(self.stack_base, self.stack_size)
        
        except Exception as e:
            logger.debug(f"Memory setup error: {e}")
    
    
    def _setup_hooks(self, mu, lib_name: str):
        """
        Setup emulation hooks for monitoring
        
        Args:
            mu: Unicorn instance
            lib_name: Library name for logging
        """
        # Hook memory writes (detect self-modification)
        def hook_mem_write(uc, access, address, size, value, user_data):
            # Check if writing to code region
            if self.memory_base <= address < self.memory_base + self.memory_size:
                self.results['memory_writes'].append({
                    'library': lib_name,
                    'address': hex(address),
                    'size': size,
                    'value': hex(value) if value < 0x100000000 else 'large'
                })
        
        # Hook invalid memory access
        def hook_mem_invalid(uc, access, address, size, value, user_data):
            logger.debug(f"Invalid memory access at {hex(address)}")
            return False
        
        try:
            mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
            mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        except Exception as e:
            logger.debug(f"Hook setup error: {e}")
    
    
    def _emulate_functions(self, mu, lib_data: bytes, arch_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Emulate interesting code sections
        
        Args:
            mu: Unicorn instance
            lib_data: Library data
            arch_info: Architecture info
        
        Returns:
            Dictionary with emulation results
        """
        results = {
            'decryption_detected': False,
            'self_modifying': False,
            'suspicious_ops': []
        }
        
        # Look for initialization functions (JNI_OnLoad, .init_array, etc.)
        init_offsets = self._find_init_functions(lib_data)
        
        for offset in init_offsets[:3]:  # Emulate first 3 init functions
            try:
                # Setup registers
                self._setup_registers(mu, arch_info)
                
                # Record memory state before emulation
                mem_before = self._snapshot_memory(mu, 100)  # First 100 bytes
                
                # Emulate (limit to 10000 instructions)
                start_addr = self.memory_base + offset
                end_addr = self.memory_base + offset + 1000
                
                mu.emu_start(start_addr, end_addr, timeout=1000, count=10000)
                
                # Check memory state after emulation
                mem_after = self._snapshot_memory(mu, 100)
                
                # Detect decryption (memory changed significantly)
                if self._detect_decryption(mem_before, mem_after):
                    results['decryption_detected'] = True
                    results['suspicious_ops'].append('Self-decryption detected')
                
                # Check for self-modifying code
                if len(self.results['memory_writes']) > 0:
                    results['self_modifying'] = True
                    results['suspicious_ops'].append('Self-modifying code detected')
            
            except UcError as e:
                logger.debug(f"Emulation error at offset {hex(offset)}: {e}")
                
                # Some errors indicate suspicious behavior
                if e.errno == UC_ERR_FETCH_UNMAPPED:
                    results['suspicious_ops'].append('Attempted to execute unmapped memory')
                elif e.errno == UC_ERR_WRITE_PROT:
                    results['suspicious_ops'].append('Attempted to write protected memory')
        
        return results
    
    
    def _find_init_functions(self, data: bytes) -> List[int]:
        """
        Find initialization function offsets in ELF
        
        Args:
            data: Binary data
        
        Returns:
            List of offsets
        """
        offsets = []
        
        # Look for common patterns
        # JNI_OnLoad signature
        jni_pattern = b'JNI_OnLoad'
        idx = data.find(jni_pattern)
        if idx != -1:
            offsets.append(idx)
        
        # Add some common entry points
        offsets.extend([0x1000, 0x2000, 0x3000])  # Common offsets
        
        return offsets
    
    
    def _setup_registers(self, mu, arch_info: Dict[str, Any]):
        """
        Setup initial register state
        
        Args:
            mu: Unicorn instance
            arch_info: Architecture info
        """
        try:
            if arch_info['name'] == 'ARM':
                mu.reg_write(UC_ARM_REG_SP, self.stack_base + self.stack_size - 0x1000)
                mu.reg_write(UC_ARM_REG_PC, self.memory_base)
            elif arch_info['name'] == 'ARM64':
                mu.reg_write(UC_ARM64_REG_SP, self.stack_base + self.stack_size - 0x1000)
                mu.reg_write(UC_ARM64_REG_PC, self.memory_base)
            elif arch_info['name'] in ['x86', 'x86-64']:
                mu.reg_write(UC_X86_REG_ESP if arch_info['name'] == 'x86' else UC_X86_REG_RSP,
                            self.stack_base + self.stack_size - 0x1000)
        except Exception as e:
            logger.debug(f"Register setup error: {e}")
    
    
    def _snapshot_memory(self, mu, size: int) -> bytes:
        """
        Take snapshot of memory region
        
        Args:
            mu: Unicorn instance
            size: Size to read
        
        Returns:
            Memory contents
        """
        try:
            return mu.mem_read(self.memory_base, size)
        except:
            return b''
    
    
    def _detect_decryption(self, before: bytes, after: bytes) -> bool:
        """
        Detect if memory was decrypted
        
        Args:
            before: Memory before emulation
            after: Memory after emulation
        
        Returns:
            True if decryption detected
        """
        if len(before) != len(after):
            return False
        
        # Count changed bytes
        changes = sum(1 for b1, b2 in zip(before, after) if b1 != b2)
        
        # If more than 30% changed, likely decryption
        change_ratio = changes / len(before)
        return change_ratio > 0.3
    
    
    def _calculate_threat_score(self):
        """Calculate threat score based on emulation findings"""
        score = 0
        
        # Decryption detected
        if self.results['decryption_detected']:
            score += 40
            self.results['suspicious_operations'].append({
                'type': 'DECRYPTION',
                'severity': 'HIGH',
                'description': 'Self-decrypting code detected during emulation'
            })
        
        # Self-modifying code
        if self.results['self_modifying_code']:
            score += 35
            self.results['suspicious_operations'].append({
                'type': 'SELF_MODIFYING',
                'severity': 'HIGH',
                'description': 'Code modifies itself at runtime'
            })
        
        # Memory writes to code section
        if len(self.results['memory_writes']) > 10:
            score += 25
            self.results['suspicious_operations'].append({
                'type': 'EXCESSIVE_CODE_WRITES',
                'severity': 'MEDIUM',
                'description': f'{len(self.results["memory_writes"])} writes to code section'
            })
        
        self.results['threat_score'] = min(score, 100)
    
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get emulation analysis summary
        
        Returns:
            Summary dictionary
        """
        return {
            'unicorn_available': self.results['unicorn_available'],
            'libraries_emulated': len(self.results['emulated_libraries']),
            'decryption_detected': self.results['decryption_detected'],
            'self_modifying_code': self.results['self_modifying_code'],
            'suspicious_operations': len(self.results['suspicious_operations']),
            'memory_writes': len(self.results['memory_writes']),
            'threat_score': self.results['threat_score']
        }
    
    
    def get_detailed_results(self) -> Dict[str, Any]:
        """
        Get detailed emulation results
        
        Returns:
            Detailed results dictionary
        """
        return self.results
