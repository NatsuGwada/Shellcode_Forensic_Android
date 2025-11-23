"""
Manifest Analyzer Module for AndroSleuth
Analyzes AndroidManifest.xml for suspicious permissions, components, and configurations
"""

import yaml
from pathlib import Path
from xml.dom import minidom

from ..utils.logger import get_logger

logger = get_logger()


class ManifestAnalyzer:
    """Analyzer for AndroidManifest.xml"""
    
    def __init__(self, apk_object, config_path="config/config.yaml"):
        """
        Initialize Manifest Analyzer
        
        Args:
            apk_object: Androguard APK object
            config_path: Path to configuration file
        """
        self.apk = apk_object
        self.config = self._load_config(config_path)
        self.results = {
            'permissions': {},
            'components': {},
            'receivers': [],
            'services': [],
            'activities': [],
            'providers': [],
            'threat_score': 0
        }
        
        logger.info("Initializing Manifest Analyzer")
    
    def _load_config(self, config_path):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Could not load config from {config_path}: {e}")
            return {}
    
    def analyze_permissions(self):
        """
        Analyze permissions declared in manifest
        
        Returns:
            dict: Permission analysis results
        """
        try:
            logger.info("Analyzing permissions...")
            
            permissions = self.apk.get_permissions()
            dangerous_perms = self.config.get('detection', {}).get('dangerous_permissions', [])
            
            permission_analysis = {
                'total_count': len(permissions),
                'all_permissions': permissions,
                'dangerous_permissions': [],
                'normal_permissions': [],
                'risk_level': 'LOW'
            }
            
            # Categorize permissions
            for perm in permissions:
                if perm in dangerous_perms:
                    permission_analysis['dangerous_permissions'].append(perm)
                else:
                    permission_analysis['normal_permissions'].append(perm)
            
            # Determine risk level
            dangerous_count = len(permission_analysis['dangerous_permissions'])
            if dangerous_count >= 10:
                permission_analysis['risk_level'] = 'CRITICAL'
            elif dangerous_count >= 7:
                permission_analysis['risk_level'] = 'HIGH'
            elif dangerous_count >= 4:
                permission_analysis['risk_level'] = 'MEDIUM'
            elif dangerous_count >= 1:
                permission_analysis['risk_level'] = 'LOW'
            else:
                permission_analysis['risk_level'] = 'SAFE'
            
            logger.info(f"✓ Found {dangerous_count} dangerous permissions - Risk: {permission_analysis['risk_level']}")
            
            self.results['permissions'] = permission_analysis
            return permission_analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze permissions: {str(e)}")
            return {}
    
    def analyze_receivers(self):
        """
        Analyze broadcast receivers for suspicious behavior
        
        Returns:
            list: Suspicious receivers
        """
        try:
            logger.info("Analyzing broadcast receivers...")
            
            receivers = self.apk.get_receivers()
            suspicious_receivers = []
            
            # Suspicious intent filters
            suspicious_intents = [
                'android.intent.action.BOOT_COMPLETED',
                'android.intent.action.USER_PRESENT',
                'android.intent.action.PHONE_STATE',
                'android.intent.action.NEW_OUTGOING_CALL',
                'android.net.conn.CONNECTIVITY_CHANGE',
                'android.provider.Telephony.SMS_RECEIVED',
                'android.intent.action.PACKAGE_ADDED',
                'android.intent.action.PACKAGE_REMOVED',
                'android.intent.action.SCREEN_OFF',
                'android.intent.action.SCREEN_ON'
            ]
            
            for receiver in receivers:
                receiver_info = {
                    'name': receiver,
                    'suspicious': False,
                    'reason': []
                }
                
                # Check if receiver has suspicious characteristics
                if 'boot' in receiver.lower():
                    receiver_info['suspicious'] = True
                    receiver_info['reason'].append("Contains 'boot' - may auto-start")
                
                if 'sms' in receiver.lower():
                    receiver_info['suspicious'] = True
                    receiver_info['reason'].append("Contains 'sms' - may intercept messages")
                
                if 'phone' in receiver.lower() or 'call' in receiver.lower():
                    receiver_info['suspicious'] = True
                    receiver_info['reason'].append("Contains 'phone/call' - may monitor calls")
                
                if receiver_info['suspicious']:
                    suspicious_receivers.append(receiver_info)
            
            logger.info(f"✓ Found {len(suspicious_receivers)} suspicious receivers out of {len(receivers)}")
            
            self.results['receivers'] = suspicious_receivers
            return suspicious_receivers
        
        except Exception as e:
            logger.error(f"Failed to analyze receivers: {str(e)}")
            return []
    
    def analyze_services(self):
        """
        Analyze services for suspicious behavior
        
        Returns:
            list: Service analysis results
        """
        try:
            logger.info("Analyzing services...")
            
            services = self.apk.get_services()
            service_analysis = []
            
            for service in services:
                service_info = {
                    'name': service,
                    'suspicious': False,
                    'reason': []
                }
                
                # Check for suspicious service names
                suspicious_keywords = [
                    'hide', 'stealth', 'spy', 'monitor', 'track',
                    'inject', 'hook', 'root', 'su', 'daemon'
                ]
                
                service_lower = service.lower()
                for keyword in suspicious_keywords:
                    if keyword in service_lower:
                        service_info['suspicious'] = True
                        service_info['reason'].append(f"Contains suspicious keyword: '{keyword}'")
                
                service_analysis.append(service_info)
            
            suspicious_count = sum(1 for s in service_analysis if s['suspicious'])
            logger.info(f"✓ Found {suspicious_count} suspicious services out of {len(services)}")
            
            self.results['services'] = service_analysis
            return service_analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze services: {str(e)}")
            return []
    
    def analyze_activities(self):
        """
        Analyze activities for suspicious configurations
        
        Returns:
            list: Activity analysis results
        """
        try:
            logger.info("Analyzing activities...")
            
            activities = self.apk.get_activities()
            main_activity = self.apk.get_main_activity()
            
            activity_analysis = {
                'total_count': len(activities),
                'main_activity': main_activity,
                'exported_activities': [],
                'hidden_activities': []
            }
            
            # Analyze each activity
            for activity in activities:
                # Check if activity might be hidden (no UI)
                if not activity.startswith(self.apk.get_package()):
                    activity_analysis['exported_activities'].append(activity)
            
            logger.info(f"✓ Analyzed {len(activities)} activities")
            
            self.results['activities'] = activity_analysis
            return activity_analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze activities: {str(e)}")
            return {}
    
    def analyze_providers(self):
        """
        Analyze content providers
        
        Returns:
            list: Provider analysis results
        """
        try:
            logger.info("Analyzing content providers...")
            
            providers = self.apk.get_providers()
            
            provider_analysis = {
                'total_count': len(providers),
                'providers': providers,
                'risk': 'LOW' if len(providers) == 0 else 'MEDIUM'
            }
            
            logger.info(f"✓ Found {len(providers)} content providers")
            
            self.results['providers'] = provider_analysis
            return provider_analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze providers: {str(e)}")
            return {}
    
    def detect_anomalies(self):
        """
        Detect manifest anomalies and suspicious configurations
        
        Returns:
            dict: Detected anomalies
        """
        try:
            logger.info("Detecting manifest anomalies...")
            
            anomalies = {
                'count': 0,
                'issues': []
            }
            
            # Check for debuggable flag
            if self.apk.get_attribute_value('application', 'debuggable') == 'true':
                anomalies['issues'].append({
                    'type': 'CONFIGURATION',
                    'severity': 'MEDIUM',
                    'description': 'Application is debuggable - security risk'
                })
                anomalies['count'] += 1
            
            # Check for backup allowed
            backup_allowed = self.apk.get_attribute_value('application', 'allowBackup')
            if backup_allowed == 'true' or backup_allowed is None:
                anomalies['issues'].append({
                    'type': 'CONFIGURATION',
                    'severity': 'LOW',
                    'description': 'Backup is allowed - data may be extracted via adb'
                })
                anomalies['count'] += 1
            
            # Check for cleartext traffic
            cleartext = self.apk.get_attribute_value('application', 'usesCleartextTraffic')
            if cleartext == 'true':
                anomalies['issues'].append({
                    'type': 'SECURITY',
                    'severity': 'HIGH',
                    'description': 'Cleartext traffic allowed - data may be intercepted'
                })
                anomalies['count'] += 1
            
            # Check for suspicious combinations
            perm_analysis = self.results.get('permissions', {})
            if perm_analysis:
                dangerous_perms = perm_analysis.get('dangerous_permissions', [])
                
                # SMS + Internet = potential SMS stealing
                if any('SMS' in p for p in dangerous_perms) and \
                   any('INTERNET' in p for p in self.apk.get_permissions()):
                    anomalies['issues'].append({
                        'type': 'SUSPICIOUS_COMBINATION',
                        'severity': 'HIGH',
                        'description': 'SMS + Internet permissions - may exfiltrate messages'
                    })
                    anomalies['count'] += 1
                
                # Location + Internet = tracking
                if any('LOCATION' in p for p in dangerous_perms) and \
                   any('INTERNET' in p for p in self.apk.get_permissions()):
                    anomalies['issues'].append({
                        'type': 'SUSPICIOUS_COMBINATION',
                        'severity': 'MEDIUM',
                        'description': 'Location + Internet permissions - may track user'
                    })
                    anomalies['count'] += 1
                
                # Camera/Mic + Internet = spyware
                if (any('CAMERA' in p for p in dangerous_perms) or \
                    any('RECORD_AUDIO' in p for p in dangerous_perms)) and \
                   any('INTERNET' in p for p in self.apk.get_permissions()):
                    anomalies['issues'].append({
                        'type': 'SUSPICIOUS_COMBINATION',
                        'severity': 'CRITICAL',
                        'description': 'Camera/Microphone + Internet - potential spyware'
                    })
                    anomalies['count'] += 1
            
            logger.info(f"✓ Detected {anomalies['count']} manifest anomalies")
            
            return anomalies
        
        except Exception as e:
            logger.error(f"Failed to detect anomalies: {str(e)}")
            return {'count': 0, 'issues': []}
    
    def calculate_threat_score(self):
        """
        Calculate threat score based on manifest analysis
        
        Returns:
            float: Threat score (0-100)
        """
        score = 0
        
        # Permissions (max 25 points)
        perm_analysis = self.results.get('permissions', {})
        if perm_analysis:
            dangerous_count = len(perm_analysis.get('dangerous_permissions', []))
            score += min(dangerous_count * 2.5, 25)
        
        # Suspicious receivers (max 15 points)
        suspicious_receivers = [r for r in self.results.get('receivers', []) if r.get('suspicious')]
        score += min(len(suspicious_receivers) * 5, 15)
        
        # Suspicious services (max 10 points)
        suspicious_services = [s for s in self.results.get('services', []) if s.get('suspicious')]
        score += min(len(suspicious_services) * 5, 10)
        
        # Anomalies (max 15 points)
        anomalies = self.detect_anomalies()
        for anomaly in anomalies.get('issues', []):
            severity = anomaly.get('severity', 'LOW')
            if severity == 'CRITICAL':
                score += 5
            elif severity == 'HIGH':
                score += 3
            elif severity == 'MEDIUM':
                score += 2
            else:
                score += 1
        
        score = min(score, 100)
        self.results['threat_score'] = score
        
        return score
    
    def analyze(self):
        """
        Run complete manifest analysis
        
        Returns:
            dict: Complete analysis results
        """
        logger.info("=" * 60)
        logger.info("Starting Manifest Analysis")
        logger.info("=" * 60)
        
        # Run all analyses
        self.analyze_permissions()
        self.analyze_receivers()
        self.analyze_services()
        self.analyze_activities()
        self.analyze_providers()
        
        # Detect anomalies
        anomalies = self.detect_anomalies()
        self.results['anomalies'] = anomalies
        
        # Calculate threat score
        threat_score = self.calculate_threat_score()
        
        logger.info("=" * 60)
        logger.info(f"Manifest Analysis Complete - Threat Score: {threat_score}/100")
        logger.info("=" * 60)
        
        return self.results
    
    def get_summary(self):
        """
        Get a summary of the manifest analysis
        
        Returns:
            dict: Analysis summary
        """
        perm_analysis = self.results.get('permissions', {})
        
        return {
            'threat_score': self.results.get('threat_score', 0),
            'dangerous_permissions_count': len(perm_analysis.get('dangerous_permissions', [])),
            'suspicious_receivers_count': len([r for r in self.results.get('receivers', []) if r.get('suspicious')]),
            'suspicious_services_count': len([s for s in self.results.get('services', []) if s.get('suspicious')]),
            'anomalies_count': self.results.get('anomalies', {}).get('count', 0),
            'risk_level': perm_analysis.get('risk_level', 'UNKNOWN')
        }
