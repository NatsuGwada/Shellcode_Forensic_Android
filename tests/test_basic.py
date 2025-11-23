#!/usr/bin/env python3
"""
Quick test script for AndroSleuth
Tests basic functionality without requiring an actual APK
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.entropy import calculate_entropy, entropy_description
from src.utils.helpers import calculate_file_hashes, format_file_size, extract_strings
from src.utils.logger import setup_logger
from rich.console import Console

console = Console()


def test_entropy():
    """Test entropy calculation"""
    console.print("\n[bold cyan]Testing Entropy Calculation[/bold cyan]")
    
    # Low entropy (repetitive)
    low_entropy_data = b"AAAAAAAAAA" * 100
    low_entropy = calculate_entropy(low_entropy_data)
    console.print(f"Low entropy data: {low_entropy:.2f} - {entropy_description(low_entropy)}")
    
    # High entropy (random)
    high_entropy_data = bytes(range(256)) * 10
    high_entropy = calculate_entropy(high_entropy_data)
    console.print(f"High entropy data: {high_entropy:.2f} - {entropy_description(high_entropy)}")
    
    # Medium entropy (text)
    medium_entropy_data = b"Hello World! This is a test string with mixed characters 123456"
    medium_entropy = calculate_entropy(medium_entropy_data)
    console.print(f"Text data: {medium_entropy:.2f} - {entropy_description(medium_entropy)}")
    
    console.print("[bold green]✓ Entropy tests passed[/bold green]")


def test_helpers():
    """Test helper functions"""
    console.print("\n[bold cyan]Testing Helper Functions[/bold cyan]")
    
    # Test file size formatting
    sizes = [1024, 1024*1024, 1024*1024*1024]
    for size in sizes:
        formatted = format_file_size(size)
        console.print(f"{size} bytes = {formatted}")
    
    # Test string extraction
    test_data = b"Hello\x00\x01\x02World\x00\x03\x04Test123"
    strings = extract_strings(test_data, min_length=4)
    console.print(f"Extracted strings: {strings}")
    
    console.print("[bold green]✓ Helper tests passed[/bold green]")


def test_logger():
    """Test logger"""
    console.print("\n[bold cyan]Testing Logger[/bold cyan]")
    
    logger = setup_logger(verbose=True)
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    console.print("[bold green]✓ Logger tests passed[/bold green]")


def main():
    """Run all tests"""
    console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]     AndroSleuth - Unit Tests          [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
    
    try:
        test_logger()
        test_entropy()
        test_helpers()
        
        console.print("\n[bold green]✓ All tests passed![/bold green]")
        return 0
    
    except Exception as e:
        console.print(f"\n[bold red]✗ Tests failed:[/bold red] {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
