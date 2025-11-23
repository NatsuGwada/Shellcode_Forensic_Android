"""
Test suite for VirusTotal integration
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.virustotal_checker import VirusTotalChecker
from rich.console import Console

console = Console()


def test_virustotal_without_api():
    """Test VirusTotal checker without API key"""
    console.print("\n[bold cyan]Testing VirusTotal without API key[/bold cyan]")
    
    checker = VirusTotalChecker(api_key=None)
    
    if checker.api_key:
        console.print("[yellow]⚠ API key found - skipping this test[/yellow]")
        return
    
    # Should handle gracefully without API key
    results = checker.check_file_reputation("dummy.apk")
    
    assert results['error'] is not None
    assert not results['checked'] or results['error'] == 'API key not configured'
    
    console.print("[green]✓ Test passed: Handles missing API key correctly[/green]")


def test_virustotal_summary():
    """Test VirusTotal summary generation"""
    console.print("\n[bold cyan]Testing VirusTotal summary[/bold cyan]")
    
    checker = VirusTotalChecker()
    
    # Test with no check performed
    summary = checker.get_summary()
    assert summary['available'] == False or summary['found'] == False
    
    console.print("[green]✓ Test passed: Summary generation works[/green]")


def test_reputation_scoring():
    """Test reputation score calculation"""
    console.print("\n[bold cyan]Testing reputation scoring[/bold cyan]")
    
    checker = VirusTotalChecker()
    
    # Test different reputation levels
    test_cases = [
        ('CLEAN', 0),
        ('POTENTIALLY_UNWANTED', 30),
        ('SUSPICIOUS', 50),
        ('HIGHLY_SUSPICIOUS', 75),
        ('MALICIOUS', 100)
    ]
    
    for reputation, expected_score in test_cases:
        checker.results['checked'] = True
        checker.results['found'] = True
        checker.results['reputation'] = reputation
        
        score = checker.get_reputation_score()
        assert score == expected_score, f"Expected {expected_score} for {reputation}, got {score}"
    
    console.print("[green]✓ Test passed: Reputation scoring correct[/green]")


def main():
    """Run VirusTotal tests"""
    console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  VirusTotal Integration Tests        [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
    
    try:
        test_virustotal_without_api()
        test_virustotal_summary()
        test_reputation_scoring()
        
        console.print("\n[bold green]✓ All VirusTotal tests passed![/bold green]")
        
        # Check if API key is configured
        checker = VirusTotalChecker()
        if checker.api_key:
            console.print("\n[bold green]✓ VirusTotal API key is configured[/bold green]")
            console.print("[dim]You can now use VirusTotal reputation checks in your analysis[/dim]")
        else:
            console.print("\n[bold yellow]⚠ VirusTotal API key not configured[/bold yellow]")
            console.print("[dim]Add your API key to config/secrets.yaml or set VIRUSTOTAL_API_KEY[/dim]")
        
        return 0
    
    except Exception as e:
        console.print(f"\n[bold red]✗ Tests failed:[/bold red] {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
