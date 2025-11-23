"""
VirusTotal Integration Module for AndroSleuth
Check APK reputation using VirusTotal API
"""

import os
import time
import requests
import hashlib
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.helpers import calculate_file_hashes

logger = get_logger()


class VirusTotalChecker:
    """VirusTotal API integration for APK reputation checking"""
    
    def __init__(self, api_key=None):
        """
        Initialize VirusTotal checker
        
        Args:
            api_key: VirusTotal API key (optional, will read from env/config)
        """
        self.api_key = api_key or self._get_api_key()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.results = {
            'checked': False,
            'found': False,
            'stats': {},
            'scan_date': None,
            'permalink': None,
            'detections': [],
            'reputation': 'UNKNOWN',
            'error': None
        }
        
        if self.api_key:
            logger.info("VirusTotal integration enabled")
        else:
            logger.warning("VirusTotal API key not found - reputation check disabled")
    
    def _get_api_key(self):
        """Get API key from environment or config file"""
        # Try environment variable first
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if api_key:
            return api_key
        
        # Try config file
        config_file = Path('config/secrets.yaml')
        if config_file.exists():
            try:
                import yaml
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    return config.get('virustotal', {}).get('api_key')
            except Exception as e:
                logger.debug(f"Could not read secrets.yaml: {e}")
        
        return None
    
    def check_file_reputation(self, file_path):
        """
        Check file reputation on VirusTotal
        
        Args:
            file_path: Path to APK file
        
        Returns:
            dict: Reputation results
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured - skipping reputation check")
            self.results['error'] = 'API key not configured'
            return self.results
        
        try:
            logger.info("Checking file reputation on VirusTotal...")
            
            # Calculate SHA256 hash
            hashes = calculate_file_hashes(file_path)
            sha256 = hashes.get('sha256')
            
            if not sha256:
                self.results['error'] = 'Could not calculate file hash'
                return self.results
            
            # Check if file already exists in VT database
            logger.info(f"Looking up SHA-256: {sha256}")
            report = self._get_file_report(sha256)
            
            if report:
                self.results['checked'] = True
                self.results['found'] = True
                self._parse_report(report, sha256)
            else:
                # File not found, offer to upload
                logger.info("File not found in VirusTotal database")
                self.results['checked'] = True
                self.results['found'] = False
                self.results['reputation'] = 'UNKNOWN'
            
            return self.results
        
        except Exception as e:
            logger.error(f"VirusTotal check failed: {str(e)}")
            self.results['error'] = str(e)
            return self.results
    
    def _get_file_report(self, sha256):
        """
        Get file report from VirusTotal
        
        Args:
            sha256: SHA256 hash of the file
        
        Returns:
            dict: Report data or None
        """
        try:
            url = f"{self.base_url}/files/{sha256}"
            headers = {
                'x-apikey': self.api_key
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return None
        
        except requests.exceptions.Timeout:
            logger.error("VirusTotal API request timed out")
            return None
        except Exception as e:
            logger.error(f"Error querying VirusTotal: {str(e)}")
            return None
    
    def _parse_report(self, report, sha256):
        """
        Parse VirusTotal report
        
        Args:
            report: VT API response
            sha256: File hash
        """
        try:
            data = report.get('data', {})
            attributes = data.get('attributes', {})
            
            # Get statistics
            stats = attributes.get('last_analysis_stats', {})
            self.results['stats'] = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'failure': stats.get('failure', 0)
            }
            
            # Get scan date
            self.results['scan_date'] = attributes.get('last_analysis_date')
            
            # Create permalink
            self.results['permalink'] = f"https://www.virustotal.com/gui/file/{sha256}"
            
            # Get individual engine detections
            analysis_results = attributes.get('last_analysis_results', {})
            detections = []
            
            for engine, result in analysis_results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'category': result.get('category'),
                        'result': result.get('result'),
                        'method': result.get('method')
                    })
            
            self.results['detections'] = sorted(detections, key=lambda x: x['engine'])
            
            # Determine reputation
            malicious_count = self.results['stats']['malicious']
            suspicious_count = self.results['stats']['suspicious']
            total_detections = malicious_count + suspicious_count
            
            if malicious_count >= 10:
                self.results['reputation'] = 'MALICIOUS'
            elif malicious_count >= 5:
                self.results['reputation'] = 'HIGHLY_SUSPICIOUS'
            elif total_detections >= 3:
                self.results['reputation'] = 'SUSPICIOUS'
            elif total_detections >= 1:
                self.results['reputation'] = 'POTENTIALLY_UNWANTED'
            else:
                self.results['reputation'] = 'CLEAN'
            
            # Log results
            logger.info(f"VirusTotal Results: {malicious_count} malicious, {suspicious_count} suspicious")
            logger.info(f"Reputation: {self.results['reputation']}")
        
        except Exception as e:
            logger.error(f"Error parsing VirusTotal report: {str(e)}")
            self.results['error'] = f"Parse error: {str(e)}"
    
    def upload_file(self, file_path):
        """
        Upload file to VirusTotal for scanning
        
        Args:
            file_path: Path to file
        
        Returns:
            dict: Upload results
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {'error': 'API key not configured'}
        
        try:
            logger.info("Uploading file to VirusTotal for scanning...")
            
            url = f"{self.base_url}/files"
            headers = {
                'x-apikey': self.api_key
            }
            
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, headers=headers, files=files, timeout=120)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                logger.info(f"File uploaded successfully. Analysis ID: {analysis_id}")
                logger.info("Note: Analysis may take several minutes. Check back later.")
                return {
                    'success': True,
                    'analysis_id': analysis_id,
                    'message': 'File uploaded for analysis'
                }
            else:
                logger.error(f"Upload failed with status {response.status_code}")
                return {'error': f'Upload failed: {response.status_code}'}
        
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            return {'error': str(e)}
    
    def get_summary(self):
        """
        Get summary of VirusTotal check
        
        Returns:
            dict: Summary
        """
        if not self.results['checked']:
            return {
                'available': False,
                'message': 'VirusTotal check not performed'
            }
        
        if not self.results['found']:
            return {
                'available': True,
                'found': False,
                'message': 'File not found in VirusTotal database',
                'reputation': 'UNKNOWN'
            }
        
        return {
            'available': True,
            'found': True,
            'reputation': self.results['reputation'],
            'malicious_count': self.results['stats'].get('malicious', 0),
            'suspicious_count': self.results['stats'].get('suspicious', 0),
            'permalink': self.results['permalink'],
            'scan_date': self.results['scan_date']
        }
    
    def get_reputation_score(self):
        """
        Get numeric reputation score (0-100, higher = worse)
        
        Returns:
            int: Reputation score
        """
        if not self.results['checked'] or not self.results['found']:
            return 0
        
        reputation_scores = {
            'CLEAN': 0,
            'POTENTIALLY_UNWANTED': 30,
            'SUSPICIOUS': 50,
            'HIGHLY_SUSPICIOUS': 75,
            'MALICIOUS': 100,
            'UNKNOWN': 0
        }
        
        return reputation_scores.get(self.results['reputation'], 0)
