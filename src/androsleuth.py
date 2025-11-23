#!/usr/bin/env python3
"""
AndroSleuth - Main Entry Point
Advanced Android APK Forensic Analysis Tool

Author: NatsuGwada
Repository: Shellcode_Forensic_Android
"""

import argparse
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src import __version__, __author__, __description__

console = Console()


def print_banner():
    """Display the AndroSleuth banner"""
    banner = f"""
    [bold cyan]
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗           ║
    ║    ██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗          ║
    ║    ███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║          ║
    ║    ██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║          ║
    ║    ██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝          ║
    ║    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝           ║
    ║                                                           ║
    ║    ███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗   ║
    ║    ██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║   ║
    ║    ███████╗██║     █████╗  ██║   ██║   ██║   ███████║   ║
    ║    ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║   ║
    ║    ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║   ║
    ║    ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝   ║
    ║                                                           ║
    ║          Advanced APK Forensic Analysis Tool             ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    [/bold cyan]
    
    [bold white]Version:[/bold white] {__version__}
    [bold white]Author:[/bold white] {__author__}
    [bold white]Description:[/bold white] {__description__}
    """
    console.print(banner)


def validate_apk_path(apk_path):
    """Validate that the APK file exists and has .apk extension"""
    if not os.path.exists(apk_path):
        console.print(f"[bold red]Error:[/bold red] APK file not found: {apk_path}")
        return False
    
    if not apk_path.lower().endswith('.apk'):
        console.print(f"[bold yellow]Warning:[/bold yellow] File does not have .apk extension: {apk_path}")
        user_input = input("Continue anyway? (y/n): ")
        if user_input.lower() != 'y':
            return False
    
    return True


def main():
    """Main entry point for AndroSleuth"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="AndroSleuth - Advanced Android APK Forensic Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick static analysis
  python androsleuth.py -a sample.apk
  
  # Deep analysis with dynamic instrumentation
  python androsleuth.py -a sample.apk -m deep
  
  # Generate HTML and JSON reports
  python androsleuth.py -a sample.apk -o reports/malware_report
  
  # Verbose mode with all modules
  python androsleuth.py -a sample.apk -v --all-modules
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-a', '--apk',
        required=True,
        help='Path to the APK file to analyze'
    )
    
    # Analysis mode
    parser.add_argument(
        '-m', '--mode',
        choices=['quick', 'standard', 'deep'],
        default='standard',
        help='Analysis mode: quick (static only), standard (static + shellcode), deep (all + dynamic)'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        help='Output directory/file prefix for reports (default: reports/report_<timestamp>)'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'both'],
        default='both',
        help='Report format (default: both)'
    )
    
    # Analysis modules
    parser.add_argument(
        '--skip-manifest',
        action='store_true',
        help='Skip manifest analysis'
    )
    
    parser.add_argument(
        '--skip-strings',
        action='store_true',
        help='Skip string extraction and analysis'
    )
    
    parser.add_argument(
        '--skip-shellcode',
        action='store_true',
        help='Skip shellcode detection'
    )
    
    parser.add_argument(
        '--skip-obfuscation',
        action='store_true',
        help='Skip obfuscation detection'
    )
    
    parser.add_argument(
        '--all-modules',
        action='store_true',
        help='Enable all analysis modules (overrides skip flags)'
    )
    
    # Dynamic analysis options
    parser.add_argument(
        '--frida',
        action='store_true',
        help='Enable Frida instrumentation (requires device/emulator)'
    )
    
    parser.add_argument(
        '--device',
        help='Specify device ID for dynamic analysis'
    )
    
    # Additional options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Path to custom configuration file'
    )
    
    parser.add_argument(
        '--no-cleanup',
        action='store_true',
        help='Do not clean up temporary files after analysis'
    )
    
    args = parser.parse_args()
    
    # Validate APK path
    if not validate_apk_path(args.apk):
        sys.exit(1)
    
    # Display analysis configuration
    console.print("\n[bold cyan]═══ Analysis Configuration ═══[/bold cyan]")
    console.print(f"[bold]APK File:[/bold] {args.apk}")
    console.print(f"[bold]Mode:[/bold] {args.mode}")
    console.print(f"[bold]Output Format:[/bold] {args.format}")
    console.print(f"[bold]Config File:[/bold] {args.config}")
    
    # Import analysis modules
    from src.modules.apk_ingestion import APKIngestion
    from src.modules.manifest_analyzer import ManifestAnalyzer
    from src.modules.obfuscation_detector import ObfuscationDetector
    from src.modules.static_analyzer import StaticAnalyzer
    from src.modules.virustotal_checker import VirusTotalChecker
    from src.utils.logger import setup_logger
    
    # Setup logger
    log_file = f"logs/androsleuth_{Path(args.apk).stem}_{args.mode}.log" if not args.no_cleanup else None
    logger = setup_logger(verbose=args.verbose, log_file=log_file)
    
    console.print("\n[bold green]Starting analysis...[/bold green]")
    
    try:
        # Phase 1: APK Ingestion
        console.print("\n[bold cyan]Phase 1: APK Ingestion[/bold cyan]")
        ingestion = APKIngestion(args.apk)
        ingestion_results = ingestion.process()
        
        if not ingestion_results['valid']:
            console.print("[bold red]✗ APK validation failed[/bold red]")
            return 1
        
        console.print("[bold green]✓ APK validation successful[/bold green]")
        
        # Get APK object
        apk_object = ingestion.get_apk_object()
        extracted_files = ingestion_results['extracted_files']
        metadata = ingestion_results['metadata']
        
        # Display basic info
        console.print(f"\n[bold]Package:[/bold] {metadata.get('package_name', 'Unknown')}")
        console.print(f"[bold]App Name:[/bold] {metadata.get('app_name', 'Unknown')}")
        console.print(f"[bold]Version:[/bold] {metadata.get('version_name', 'Unknown')} ({metadata.get('version_code', 'Unknown')})")
        console.print(f"[bold]File Size:[/bold] {metadata.get('file_size_formatted', 'Unknown')}")
        console.print(f"[bold]SHA-256:[/bold] {metadata.get('hashes', {}).get('sha256', 'Unknown')}")
        
        # VirusTotal Reputation Check (if API key available)
        console.print("\n[bold cyan]VirusTotal Reputation Check[/bold cyan]")
        vt_checker = VirusTotalChecker()
        vt_results = vt_checker.check_file_reputation(args.apk)
        vt_summary = vt_checker.get_summary()
        
        if vt_summary.get('available') and vt_summary.get('found'):
            reputation = vt_summary.get('reputation', 'UNKNOWN')
            malicious = vt_summary.get('malicious_count', 0)
            suspicious = vt_summary.get('suspicious_count', 0)
            
            # Color code reputation
            if reputation == 'MALICIOUS':
                rep_color = '[bold red]'
            elif reputation in ['HIGHLY_SUSPICIOUS', 'SUSPICIOUS']:
                rep_color = '[bold yellow]'
            elif reputation == 'POTENTIALLY_UNWANTED':
                rep_color = '[yellow]'
            else:
                rep_color = '[green]'
            
            console.print(f"[bold]Reputation:[/bold] {rep_color}{reputation}[/{rep_color.split('[')[1].split(']')[0]}]")
            console.print(f"[bold]Detections:[/bold] {malicious} malicious, {suspicious} suspicious")
            console.print(f"[bold]VirusTotal:[/bold] {vt_summary.get('permalink', 'N/A')}")
            
            if reputation in ['MALICIOUS', 'HIGHLY_SUSPICIOUS']:
                console.print("\n[bold red]⚠ WARNING: This file has been flagged as malicious by multiple antivirus engines![/bold red]")
        elif vt_summary.get('available') and not vt_summary.get('found'):
            console.print("[yellow]⚠ File not found in VirusTotal database[/yellow]")
            console.print("[dim]The file may be new or uncommon. Consider uploading to VirusTotal for analysis.[/dim]")
        else:
            console.print("[dim]✓ VirusTotal check skipped (API key not configured)[/dim]")
        
        # Phase 2: Manifest Analysis
        if not args.skip_manifest:
            console.print("\n[bold cyan]Phase 2: Manifest Analysis[/bold cyan]")
            manifest_analyzer = ManifestAnalyzer(apk_object, args.config)
            manifest_results = manifest_analyzer.analyze()
            manifest_summary = manifest_analyzer.get_summary()
            console.print(f"[bold green]✓ Manifest analyzed - Threat Score: {manifest_summary['threat_score']:.1f}/100[/bold green]")
        
        # Phase 3: Obfuscation Detection
        if not args.skip_obfuscation and args.mode in ['standard', 'deep']:
            console.print("\n[bold cyan]Phase 3: Obfuscation Detection[/bold cyan]")
            obf_detector = ObfuscationDetector(apk_object, extracted_files)
            obf_results = obf_detector.analyze()
            obf_summary = obf_detector.get_summary()
            console.print(f"[bold green]✓ Obfuscation analyzed - Score: {obf_summary['obfuscation_score']}/100[/bold green]")
        
        # Phase 4: Static Code Analysis
        if not args.skip_strings and args.mode in ['standard', 'deep']:
            console.print("\n[bold cyan]Phase 4: Static Code Analysis[/bold cyan]")
            static_analyzer = StaticAnalyzer(apk_object, extracted_files, args.config)
            static_results = static_analyzer.analyze()
            static_summary = static_analyzer.get_summary()
            console.print(f"[bold green]✓ Static analysis complete - Threat Score: {static_summary['threat_score']:.1f}/100[/bold green]")
        
        # Calculate overall threat score
        console.print("\n[bold cyan]═══ Analysis Summary ═══[/bold cyan]")
        
        overall_score = 0
        score_components = []
        
        if not args.skip_manifest:
            score_components.append(manifest_summary['threat_score'])
        if not args.skip_obfuscation and args.mode in ['standard', 'deep']:
            score_components.append(obf_summary['obfuscation_score'])
        if not args.skip_strings and args.mode in ['standard', 'deep']:
            score_components.append(static_summary['threat_score'])
        
        # Add VirusTotal score if available
        vt_score = vt_checker.get_reputation_score()
        if vt_score > 0:
            score_components.append(vt_score)
            console.print(f"[bold]VirusTotal Score:[/bold] {vt_score}/100")
        
        if score_components:
            overall_score = sum(score_components) / len(score_components)
        
        # Determine threat level
        if overall_score >= 86:
            threat_level = "[bold red]CRITICAL[/bold red]"
        elif overall_score >= 71:
            threat_level = "[bold red]HIGH[/bold red]"
        elif overall_score >= 51:
            threat_level = "[bold yellow]MEDIUM[/bold yellow]"
        elif overall_score >= 31:
            threat_level = "[bold yellow]LOW[/bold yellow]"
        else:
            threat_level = "[bold green]SAFE[/bold green]"
        
        console.print(f"\n[bold]Overall Threat Score:[/bold] {overall_score:.1f}/100")
        console.print(f"[bold]Threat Level:[/bold] {threat_level}")
        
        # Cleanup
        if not args.no_cleanup:
            ingestion.cleanup()
        
        console.print("\n[bold green]✓ Analysis complete![/bold green]")
        
        return 0
    
    except Exception as e:
        console.print(f"\n[bold red]Error during analysis:[/bold red] {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Analysis interrupted by user[/bold red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error:[/bold red] {str(e)}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
