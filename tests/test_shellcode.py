#!/usr/bin/env python3
"""
Test suite for Shellcode Detector module
"""

import sys
import tempfile
import struct
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.shellcode_detector import ShellcodeDetector, CAPSTONE_AVAILABLE
from rich.console import Console

console = Console()


def create_fake_elf():
    """Create a minimal fake ELF file for testing"""
    # ELF magic + minimal header
    elf_data = bytearray()
    elf_data.extend(b'\x7fELF')  # ELF magic
    elf_data.extend(b'\x01')  # 32-bit
    elf_data.extend(b'\x01')  # Little-endian
    elf_data.extend(b'\x01')  # ELF version
    elf_data.extend(b'\x00' * 9)  # Padding
    elf_data.extend(struct.pack('<H', 0x02))  # e_type (executable)
    elf_data.extend(struct.pack('<H', 0x28))  # e_machine (ARM)
    elf_data.extend(b'\x00' * 100)  # Rest of header
    
    # Add some suspicious strings
    elf_data.extend(b'execve\x00')
    elf_data.extend(b'system\x00')
    elf_data.extend(b'chmod\x00')
    
    # Add some NOP sleds (x86)
    elf_data.extend(b'\x90' * 20)
    
    return bytes(elf_data)


def test_elf_header_analysis():
    """Test ELF header analysis"""
    console.print("\n[bold cyan]Testing ELF Header Analysis[/bold cyan]")
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
        elf_data = create_fake_elf()
        f.write(elf_data)
        temp_path = f.name
    
    try:
        detector = ShellcodeDetector({'native_libs': [temp_path]})
        elf_info = detector.analyze_elf_header(temp_path)
        
        assert elf_info['is_elf'] == True
        assert 'architecture' in elf_info
        assert 'arch_type' in elf_info
        
        console.print(f"✓ ELF detected: {elf_info['arch_type']}")
        console.print("[green]✓ Test passed: ELF header analysis works[/green]")
    
    finally:
        import os
        os.unlink(temp_path)


def test_syscall_detection():
    """Test syscall detection"""
    console.print("\n[bold cyan]Testing Syscall Detection[/bold cyan]")
    
    # Create file with dangerous syscalls
    with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
        data = create_fake_elf()
        f.write(data)
        temp_path = f.name
    
    try:
        detector = ShellcodeDetector({'native_libs': [temp_path]})
        syscalls = detector.detect_suspicious_syscalls(temp_path)
        
        assert len(syscalls) > 0
        assert any('execve' in str(s) for s in syscalls)
        
        console.print(f"✓ Detected {len(syscalls)} dangerous syscalls")
        console.print("[green]✓ Test passed: Syscall detection works[/green]")
    
    finally:
        import os
        os.unlink(temp_path)


def test_shellcode_pattern_detection():
    """Test shellcode pattern detection"""
    console.print("\n[bold cyan]Testing Shellcode Pattern Detection[/bold cyan]")
    
    # Create file with NOP sled
    with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
        data = create_fake_elf()
        f.write(data)
        temp_path = f.name
    
    try:
        detector = ShellcodeDetector({'native_libs': [temp_path]})
        patterns = detector.detect_shellcode_patterns(temp_path)
        
        assert len(patterns) > 0
        assert any('NOP' in str(p) for p in patterns)
        
        console.print(f"✓ Detected {len(patterns)} shellcode patterns")
        console.print("[green]✓ Test passed: Pattern detection works[/green]")
    
    finally:
        import os
        os.unlink(temp_path)


def test_string_analysis():
    """Test string analysis in libraries"""
    console.print("\n[bold cyan]Testing String Analysis[/bold cyan]")
    
    with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
        data = create_fake_elf()
        f.write(data)
        temp_path = f.name
    
    try:
        detector = ShellcodeDetector({'native_libs': [temp_path]})
        string_analysis = detector.analyze_strings_in_library(temp_path)
        
        assert 'total_strings' in string_analysis
        assert string_analysis['total_strings'] > 0
        
        console.print(f"✓ Found {string_analysis['total_strings']} strings")
        console.print(f"✓ Suspicious: {len(string_analysis.get('suspicious_strings', []))}")
        console.print("[green]✓ Test passed: String analysis works[/green]")
    
    finally:
        import os
        os.unlink(temp_path)


def test_threat_scoring():
    """Test threat score calculation"""
    console.print("\n[bold cyan]Testing Threat Scoring[/bold cyan]")
    
    detector = ShellcodeDetector({'native_libs': []})
    
    # Simulate some detections
    detector.results['shellcode_patterns'] = [
        {'type': 'NOP_SLED', 'risk': 'HIGH'},
        {'type': 'EGG_HUNTER', 'risk': 'HIGH'}
    ]
    detector.results['syscalls_detected'] = [
        {'syscall': 'execve', 'risk': 'HIGH'},
        {'syscall': 'system', 'risk': 'HIGH'}
    ]
    
    score = detector.calculate_threat_score()
    
    assert 0 <= score <= 100
    assert score > 0  # Should have some score due to detections
    
    console.print(f"✓ Calculated threat score: {score}/100")
    console.print("[green]✓ Test passed: Threat scoring works[/green]")


def main():
    """Run all shellcode detector tests"""
    console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  Shellcode Detector Tests            [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
    
    # Check Capstone availability
    if CAPSTONE_AVAILABLE:
        console.print("\n[bold green]✓ Capstone is available[/bold green]")
        console.print("[dim]Disassembly features are enabled[/dim]")
    else:
        console.print("\n[bold yellow]⚠ Capstone not available[/bold yellow]")
        console.print("[dim]Disassembly features will be disabled[/dim]")
        console.print("[dim]Install with: pip install capstone[/dim]")
    
    try:
        test_elf_header_analysis()
        test_syscall_detection()
        test_shellcode_pattern_detection()
        test_string_analysis()
        test_threat_scoring()
        
        console.print("\n[bold green]✓ All shellcode detector tests passed![/bold green]")
        
        return 0
    
    except Exception as e:
        console.print(f"\n[bold red]✗ Tests failed:[/bold red] {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
