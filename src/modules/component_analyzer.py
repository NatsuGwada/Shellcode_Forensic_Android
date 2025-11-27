"""
Component Analyzer Module for AndroSleuth
Advanced analysis of Android components (Activities, Services, Receivers, Providers)
"""

import re
from typing import Dict, List
from xml.etree import ElementTree as ET

from ..utils.logger import get_logger

logger = get_logger()


class ComponentAnalyzer:
    """Analyzer for Android application components"""
    
    def __init__(self, apk_object):
        """
        Initialize Component Analyzer
        
        Args:
            apk_object: Androguard APK object
        """
        self.apk = apk_object
        self.results = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': [],
            'intent_filters': [],
            'exported_components': [],
            'deep_links': [],
            'custom_permissions': [],
            'threat_score': 0
        }
        
        logger.info("Initializing Component Analyzer")
    
    def analyze_activities(self) -> List[Dict]:
        """
        Analyze activities with detailed information
        
        Returns:
            list: Activity analysis
        """
        try:
            logger.info("Analyzing activities in detail...")
            
            activities = []
            activity_names = self.apk.get_activities()
            main_activity = self.apk.get_main_activity()
            
            for activity in activity_names:
                activity_info = {
                    'name': activity,
                    'is_main': activity == main_activity,
                    'exported': self._is_exported(activity, 'activity'),
                    'intent_filters': self._get_intent_filters(activity, 'activity'),
                    'permissions': self._get_component_permissions(activity, 'activity'),
                    'risk_level': 'LOW'
                }
                
                # Risk assessment
                if activity_info['exported'] and not activity_info['is_main']:
                    activity_info['risk_level'] = 'MEDIUM'
                    activity_info['risk_reason'] = 'Exported activity (accessible by other apps)'
                
                if activity_info['intent_filters']:
                    activity_info['risk_level'] = 'MEDIUM'
                
                # Check for suspicious patterns in name
                suspicious_keywords = ['webview', 'browser', 'proxy', 'hidden', 'stealth']
                if any(keyword in activity.lower() for keyword in suspicious_keywords):
                    activity_info['risk_level'] = 'HIGH'
                    activity_info['risk_reason'] = 'Suspicious activity name pattern'
                
                activities.append(activity_info)
            
            self.results['activities'] = activities
            logger.info(f"✓ Analyzed {len(activities)} activities")
            
            return activities
            
        except Exception as e:
            logger.error(f"Failed to analyze activities: {e}")
            return []
    
    def analyze_services(self) -> List[Dict]:
        """
        Analyze services with detailed information
        
        Returns:
            list: Service analysis
        """
        try:
            logger.info("Analyzing services in detail...")
            
            services = []
            service_names = self.apk.get_services()
            
            for service in service_names:
                service_info = {
                    'name': service,
                    'exported': self._is_exported(service, 'service'),
                    'intent_filters': self._get_intent_filters(service, 'service'),
                    'permissions': self._get_component_permissions(service, 'service'),
                    'is_foreground': self._is_foreground_service(service),
                    'risk_level': 'LOW'
                }
                
                # Risk assessment
                if service_info['exported']:
                    service_info['risk_level'] = 'HIGH'
                    service_info['risk_reason'] = 'Exported service (accessible by other apps)'
                
                # Check for suspicious patterns
                suspicious_keywords = [
                    'accessibility', 'admin', 'devicepolicy', 'notification',
                    'background', 'persistent', 'hidden', 'spy', 'monitor'
                ]
                if any(keyword in service.lower() for keyword in suspicious_keywords):
                    service_info['risk_level'] = 'CRITICAL'
                    service_info['risk_reason'] = 'Potentially malicious service pattern'
                
                services.append(service_info)
            
            self.results['services'] = services
            logger.info(f"✓ Analyzed {len(services)} services")
            
            return services
            
        except Exception as e:
            logger.error(f"Failed to analyze services: {e}")
            return []
    
    def analyze_receivers(self) -> List[Dict]:
        """
        Analyze broadcast receivers with detailed information
        
        Returns:
            list: Receiver analysis
        """
        try:
            logger.info("Analyzing broadcast receivers in detail...")
            
            receivers = []
            receiver_names = self.apk.get_receivers()
            
            for receiver in receiver_names:
                receiver_info = {
                    'name': receiver,
                    'exported': self._is_exported(receiver, 'receiver'),
                    'intent_filters': self._get_intent_filters(receiver, 'receiver'),
                    'permissions': self._get_component_permissions(receiver, 'receiver'),
                    'priority': self._get_receiver_priority(receiver),
                    'risk_level': 'LOW'
                }
                
                # Analyze intent filters for risk
                high_risk_actions = [
                    'android.intent.action.BOOT_COMPLETED',
                    'android.provider.Telephony.SMS_RECEIVED',
                    'android.intent.action.PHONE_STATE',
                    'android.intent.action.NEW_OUTGOING_CALL',
                    'android.intent.action.PACKAGE_ADDED',
                    'android.intent.action.PACKAGE_REMOVED'
                ]
                
                for intent in receiver_info['intent_filters']:
                    if intent in high_risk_actions:
                        receiver_info['risk_level'] = 'CRITICAL'
                        receiver_info['risk_reason'] = f'Listens to sensitive intent: {intent}'
                        break
                
                receivers.append(receiver_info)
            
            self.results['receivers'] = receivers
            logger.info(f"✓ Analyzed {len(receivers)} receivers")
            
            return receivers
            
        except Exception as e:
            logger.error(f"Failed to analyze receivers: {e}")
            return []
    
    def analyze_providers(self) -> List[Dict]:
        """
        Analyze content providers with detailed information
        
        Returns:
            list: Provider analysis
        """
        try:
            logger.info("Analyzing content providers in detail...")
            
            providers = []
            provider_names = self.apk.get_providers()
            
            for provider in provider_names:
                provider_info = {
                    'name': provider,
                    'exported': self._is_exported(provider, 'provider'),
                    'authorities': self._get_provider_authorities(provider),
                    'permissions': self._get_component_permissions(provider, 'provider'),
                    'grant_uri_permissions': self._grants_uri_permissions(provider),
                    'risk_level': 'LOW'
                }
                
                # Risk assessment
                if provider_info['exported']:
                    provider_info['risk_level'] = 'HIGH'
                    provider_info['risk_reason'] = 'Exported provider (data accessible by other apps)'
                
                if provider_info['grant_uri_permissions']:
                    provider_info['risk_level'] = 'CRITICAL'
                    provider_info['risk_reason'] = 'Grants URI permissions (potential data leak)'
                
                providers.append(provider_info)
            
            self.results['providers'] = providers
            logger.info(f"✓ Analyzed {len(providers)} providers")
            
            return providers
            
        except Exception as e:
            logger.error(f"Failed to analyze providers: {e}")
            return []
    
    def analyze_intent_filters(self) -> List[Dict]:
        """
        Analyze all intent filters across components
        
        Returns:
            list: Intent filter analysis
        """
        try:
            logger.info("Analyzing intent filters...")
            
            all_filters = []
            
            # Gather from all components
            for component_type in ['activities', 'services', 'receivers']:
                components = self.results.get(component_type, [])
                for component in components:
                    for intent_filter in component.get('intent_filters', []):
                        all_filters.append({
                            'component': component['name'],
                            'component_type': component_type[:-1],  # Remove 's'
                            'action': intent_filter,
                            'risk': self._assess_intent_risk(intent_filter)
                        })
            
            self.results['intent_filters'] = all_filters
            logger.info(f"✓ Analyzed {len(all_filters)} intent filters")
            
            return all_filters
            
        except Exception as e:
            logger.error(f"Failed to analyze intent filters: {e}")
            return []
    
    def analyze_deep_links(self) -> List[Dict]:
        """
        Analyze deep links and URL schemes
        
        Returns:
            list: Deep link analysis
        """
        try:
            logger.info("Analyzing deep links and URL schemes...")
            
            deep_links = []
            
            # Parse AndroidManifest.xml
            manifest = self.apk.get_android_manifest_xml()
            
            # Look for data elements in intent filters
            for elem in manifest.iter():
                if elem.tag.endswith('data'):
                    scheme = elem.get('{http://schemas.android.com/apk/res/android}scheme')
                    host = elem.get('{http://schemas.android.com/apk/res/android}host')
                    path = elem.get('{http://schemas.android.com/apk/res/android}path')
                    path_prefix = elem.get('{http://schemas.android.com/apk/res/android}pathPrefix')
                    
                    if scheme or host:
                        deep_link = {
                            'scheme': scheme or '',
                            'host': host or '',
                            'path': path or path_prefix or '',
                            'risk_level': 'LOW'
                        }
                        
                        # Assess risk
                        if scheme and scheme not in ['http', 'https']:
                            deep_link['risk_level'] = 'MEDIUM'
                            deep_link['risk_reason'] = 'Custom URL scheme'
                        
                        # Check for wildcard or overly broad patterns
                        if host and ('*' in host or not host):
                            deep_link['risk_level'] = 'HIGH'
                            deep_link['risk_reason'] = 'Overly broad host pattern'
                        
                        deep_links.append(deep_link)
            
            self.results['deep_links'] = deep_links
            logger.info(f"✓ Found {len(deep_links)} deep links")
            
            return deep_links
            
        except Exception as e:
            logger.error(f"Failed to analyze deep links: {e}")
            return []
    
    def analyze_custom_permissions(self) -> List[Dict]:
        """
        Analyze custom permissions defined by the app
        
        Returns:
            list: Custom permission analysis
        """
        try:
            logger.info("Analyzing custom permissions...")
            
            custom_perms = []
            manifest = self.apk.get_android_manifest_xml()
            
            # Look for permission definitions
            for elem in manifest.iter():
                if elem.tag.endswith('permission'):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    protection_level = elem.get('{http://schemas.android.com/apk/res/android}protectionLevel')
                    label = elem.get('{http://schemas.android.com/apk/res/android}label')
                    
                    if name:
                        custom_perm = {
                            'name': name,
                            'protection_level': protection_level or 'normal',
                            'label': label or '',
                            'risk_level': 'LOW'
                        }
                        
                        # Assess risk based on protection level
                        if protection_level in ['signature', 'signatureOrSystem']:
                            custom_perm['risk_level'] = 'MEDIUM'
                            custom_perm['risk_reason'] = 'Signature-level permission'
                        
                        custom_perms.append(custom_perm)
            
            self.results['custom_permissions'] = custom_perms
            logger.info(f"✓ Found {len(custom_perms)} custom permissions")
            
            return custom_perms
            
        except Exception as e:
            logger.error(f"Failed to analyze custom permissions: {e}")
            return []
    
    def find_exported_components(self) -> List[Dict]:
        """
        Find all exported components (security risk)
        
        Returns:
            list: Exported component list
        """
        try:
            logger.info("Finding exported components...")
            
            exported = []
            
            # Check all component types
            for component_type in ['activities', 'services', 'receivers', 'providers']:
                components = self.results.get(component_type, [])
                for component in components:
                    if component.get('exported', False):
                        exported.append({
                            'name': component['name'],
                            'type': component_type[:-1],  # Remove 's'
                            'risk_level': component.get('risk_level', 'MEDIUM'),
                            'reason': component.get('risk_reason', 'Exported component')
                        })
            
            self.results['exported_components'] = exported
            
            if exported:
                logger.warning(f"⚠ Found {len(exported)} exported components")
            else:
                logger.info("✓ No exported components found")
            
            return exported
            
        except Exception as e:
            logger.error(f"Failed to find exported components: {e}")
            return []
    
    def _is_exported(self, component_name: str, component_type: str) -> bool:
        """Check if a component is exported"""
        try:
            manifest = self.apk.get_android_manifest_xml()
            
            # Find component in manifest
            for elem in manifest.iter():
                if elem.tag.endswith(component_type):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name and name.endswith(component_name.split('.')[-1]):
                        exported = elem.get('{http://schemas.android.com/apk/res/android}exported')
                        
                        # Default export behavior based on intent filters
                        if exported is None:
                            # Has intent filters = exported by default
                            intent_filters = [child for child in elem if child.tag.endswith('intent-filter')]
                            return len(intent_filters) > 0
                        
                        return exported == 'true'
            
            return False
        except:
            return False
    
    def _get_intent_filters(self, component_name: str, component_type: str) -> List[str]:
        """Get intent filters for a component"""
        try:
            manifest = self.apk.get_android_manifest_xml()
            filters = []
            
            for elem in manifest.iter():
                if elem.tag.endswith(component_type):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name and name.endswith(component_name.split('.')[-1]):
                        for child in elem:
                            if child.tag.endswith('intent-filter'):
                                for action in child:
                                    if action.tag.endswith('action'):
                                        action_name = action.get('{http://schemas.android.com/apk/res/android}name')
                                        if action_name:
                                            filters.append(action_name)
            
            return filters
        except:
            return []
    
    def _get_component_permissions(self, component_name: str, component_type: str) -> List[str]:
        """Get permissions required by a component"""
        try:
            manifest = self.apk.get_android_manifest_xml()
            
            for elem in manifest.iter():
                if elem.tag.endswith(component_type):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name and name.endswith(component_name.split('.')[-1]):
                        permission = elem.get('{http://schemas.android.com/apk/res/android}permission')
                        if permission:
                            return [permission]
            
            return []
        except:
            return []
    
    def _is_foreground_service(self, service_name: str) -> bool:
        """Check if service is a foreground service"""
        try:
            manifest = self.apk.get_android_manifest_xml()
            
            for elem in manifest.iter():
                if elem.tag.endswith('service'):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name and name.endswith(service_name.split('.')[-1]):
                        foreground = elem.get('{http://schemas.android.com/apk/res/android}foregroundServiceType')
                        return foreground is not None
            
            return False
        except:
            return False
    
    def _get_receiver_priority(self, receiver_name: str) -> int:
        """Get broadcast receiver priority"""
        try:
            manifest = self.apk.get_android_manifest_xml()
            
            for elem in manifest.iter():
                if elem.tag.endswith('receiver'):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name and name.endswith(receiver_name.split('.')[-1]):
                        for child in elem:
                            if child.tag.endswith('intent-filter'):
                                priority = child.get('{http://schemas.android.com/apk/res/android}priority')
                                if priority:
                                    return int(priority)
            
            return 0
        except:
            return 0
    
    def _get_provider_authorities(self, provider_name: str) -> List[str]:
        """Get content provider authorities"""
        try:
            manifest = self.apk.get_android_manifest_xml()
            
            for elem in manifest.iter():
                if elem.tag.endswith('provider'):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name and name.endswith(provider_name.split('.')[-1]):
                        authorities = elem.get('{http://schemas.android.com/apk/res/android}authorities')
                        if authorities:
                            return authorities.split(';')
            
            return []
        except:
            return []
    
    def _grants_uri_permissions(self, provider_name: str) -> bool:
        """Check if provider grants URI permissions"""
        try:
            manifest = self.apk.get_android_manifest_xml()
            
            for elem in manifest.iter():
                if elem.tag.endswith('provider'):
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    if name and name.endswith(provider_name.split('.')[-1]):
                        grant_perms = elem.get('{http://schemas.android.com/apk/res/android}grantUriPermissions')
                        return grant_perms == 'true'
            
            return False
        except:
            return False
    
    def _assess_intent_risk(self, intent_action: str) -> str:
        """Assess risk level of an intent action"""
        critical_intents = [
            'android.provider.Telephony.SMS_RECEIVED',
            'android.intent.action.PHONE_STATE',
            'android.intent.action.NEW_OUTGOING_CALL'
        ]
        
        high_risk_intents = [
            'android.intent.action.BOOT_COMPLETED',
            'android.intent.action.PACKAGE_ADDED',
            'android.intent.action.PACKAGE_REMOVED',
            'android.net.conn.CONNECTIVITY_CHANGE'
        ]
        
        if intent_action in critical_intents:
            return 'CRITICAL'
        elif intent_action in high_risk_intents:
            return 'HIGH'
        else:
            return 'LOW'
    
    def calculate_threat_score(self) -> float:
        """
        Calculate threat score based on component analysis
        
        Returns:
            float: Threat score (0-100)
        """
        score = 0
        
        # Exported components (max 25 points)
        exported = self.results.get('exported_components', [])
        score += min(len(exported) * 5, 25)
        
        # Critical receivers (max 20 points)
        receivers = self.results.get('receivers', [])
        critical_receivers = [r for r in receivers if r.get('risk_level') == 'CRITICAL']
        score += min(len(critical_receivers) * 10, 20)
        
        # Suspicious services (max 20 points)
        services = self.results.get('services', [])
        suspicious_services = [s for s in services if s.get('risk_level') in ['HIGH', 'CRITICAL']]
        score += min(len(suspicious_services) * 7, 20)
        
        # Deep links (max 15 points)
        deep_links = self.results.get('deep_links', [])
        risky_links = [d for d in deep_links if d.get('risk_level') in ['HIGH', 'MEDIUM']]
        score += min(len(risky_links) * 5, 15)
        
        # Content providers (max 10 points)
        providers = self.results.get('providers', [])
        risky_providers = [p for p in providers if p.get('risk_level') in ['HIGH', 'CRITICAL']]
        score += min(len(risky_providers) * 10, 10)
        
        score = min(score, 100)
        self.results['threat_score'] = round(score, 2)
        
        return score
    
    def analyze(self) -> Dict:
        """
        Run complete component analysis
        
        Returns:
            dict: Complete analysis results
        """
        logger.info("=" * 60)
        logger.info("Starting Component Analysis")
        logger.info("=" * 60)
        
        # Run all analyses
        self.analyze_activities()
        self.analyze_services()
        self.analyze_receivers()
        self.analyze_providers()
        self.analyze_intent_filters()
        self.analyze_deep_links()
        self.analyze_custom_permissions()
        self.find_exported_components()
        
        # Calculate threat score
        threat_score = self.calculate_threat_score()
        
        logger.info("=" * 60)
        logger.info(f"Component Analysis Complete - Threat Score: {threat_score}/100")
        logger.info("=" * 60)
        
        return self.results
    
    def get_summary(self) -> Dict:
        """
        Get summary of component analysis
        
        Returns:
            dict: Summary
        """
        return {
            'threat_score': self.results.get('threat_score', 0),
            'activities_count': len(self.results.get('activities', [])),
            'services_count': len(self.results.get('services', [])),
            'receivers_count': len(self.results.get('receivers', [])),
            'providers_count': len(self.results.get('providers', [])),
            'exported_count': len(self.results.get('exported_components', [])),
            'deep_links_count': len(self.results.get('deep_links', [])),
            'custom_permissions_count': len(self.results.get('custom_permissions', []))
        }
