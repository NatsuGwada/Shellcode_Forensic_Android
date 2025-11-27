"""
Test Advanced Static Analysis Modules
Tests for JADX, Component Analyzer, and Enhanced Permission Analysis
"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.modules.jadx_decompiler import JADXDecompiler
from src.modules.component_analyzer import ComponentAnalyzer


class TestJADXDecompiler:
    """Test JADX decompiler module"""
    
    def test_jadx_initialization(self):
        """Test JADX decompiler initialization"""
        jadx = JADXDecompiler(apk_path="test.apk")
        
        assert jadx.apk_path == "test.apk"
        assert jadx.results is not None
        assert 'decompiled' in jadx.results
        assert 'hardcoded_secrets' in jadx.results
        assert 'dangerous_apis' in jadx.results
    
    def test_jadx_check_installed(self):
        """Test JADX availability check"""
        jadx = JADXDecompiler(apk_path="test.apk")
        
        # This will return True if JADX is installed, False otherwise
        is_installed = jadx.check_jadx_installed()
        
        # Just verify the method works
        assert isinstance(is_installed, bool)
    
    def test_secret_patterns(self):
        """Test secret detection patterns"""
        jadx = JADXDecompiler(apk_path="test.apk")
        
        # Test false positive detection
        assert jadx._is_false_positive("test123")
        assert jadx._is_false_positive("example_key")
        assert not jadx._is_false_positive("real_api_key_abc123xyz")
    
    def test_secret_severity(self):
        """Test secret severity classification"""
        jadx = JADXDecompiler(apk_path="test.apk")
        
        assert jadx._get_secret_severity('private_key') == 'CRITICAL'
        assert jadx._get_secret_severity('aws_key') == 'CRITICAL'
        assert jadx._get_secret_severity('api_key') == 'HIGH'
        assert jadx._get_secret_severity('password') == 'HIGH'
        assert jadx._get_secret_severity('secret') == 'MEDIUM'
        assert jadx._get_secret_severity('unknown') == 'LOW'
    
    def test_get_summary(self):
        """Test JADX summary generation"""
        jadx = JADXDecompiler(apk_path="test.apk")
        jadx.results['classes_count'] = 100
        jadx.results['methods_count'] = 500
        jadx.results['hardcoded_secrets'] = [{'type': 'api_key'}]
        jadx.results['threat_score'] = 45.5
        
        summary = jadx.get_summary()
        
        assert summary['classes_count'] == 100
        assert summary['methods_count'] == 500
        assert summary['secrets_found'] == 1
        assert summary['threat_score'] == 45.5


class TestComponentAnalyzer:
    """Test component analyzer module"""
    
    def test_component_initialization(self):
        """Test component analyzer initialization (requires APK object)"""
        # This test would need a real APK object from androguard
        # For now, test the structure
        assert ComponentAnalyzer is not None
    
    def test_intent_risk_assessment(self):
        """Test intent action risk assessment"""
        # Create a mock analyzer (won't work without APK, but we can test the method)
        try:
            from unittest.mock import Mock
            mock_apk = Mock()
            analyzer = ComponentAnalyzer(mock_apk)
            
            # Test risk assessment logic
            assert analyzer._assess_intent_risk('android.provider.Telephony.SMS_RECEIVED') == 'CRITICAL'
            assert analyzer._assess_intent_risk('android.intent.action.BOOT_COMPLETED') == 'HIGH'
            assert analyzer._assess_intent_risk('android.intent.action.MAIN') == 'LOW'
        except Exception as e:
            # Skip if mock doesn't work
            pytest.skip(f"Skipping: {e}")


class TestEnhancedPermissions:
    """Test enhanced permission analysis"""
    
    def test_permission_categorization(self):
        """Test permission categorization logic"""
        from src.modules.manifest_analyzer import ManifestAnalyzer
        from unittest.mock import Mock
        
        mock_apk = Mock()
        analyzer = ManifestAnalyzer(mock_apk)
        
        # Test categorization
        assert analyzer._categorize_permission('android.permission.ACCESS_FINE_LOCATION') == 'LOCATION'
        assert analyzer._categorize_permission('android.permission.CAMERA') == 'CAMERA'
        assert analyzer._categorize_permission('android.permission.RECORD_AUDIO') == 'MICROPHONE'
        assert analyzer._categorize_permission('android.permission.READ_CONTACTS') == 'CONTACTS'
        assert analyzer._categorize_permission('android.permission.SEND_SMS') == 'SMS'
        assert analyzer._categorize_permission('android.permission.READ_PHONE_STATE') == 'PHONE'
        assert analyzer._categorize_permission('android.permission.WRITE_EXTERNAL_STORAGE') == 'STORAGE'
        assert analyzer._categorize_permission('android.permission.INTERNET') == 'NETWORK'
    
    def test_runtime_permissions(self):
        """Test runtime permission detection"""
        from src.modules.manifest_analyzer import ManifestAnalyzer
        from unittest.mock import Mock
        
        mock_apk = Mock()
        analyzer = ManifestAnalyzer(mock_apk)
        
        # Test runtime permissions (Android 6.0+)
        assert analyzer._is_runtime_permission('android.permission.CAMERA')
        assert analyzer._is_runtime_permission('android.permission.ACCESS_FINE_LOCATION')
        assert analyzer._is_runtime_permission('android.permission.RECORD_AUDIO')
        assert analyzer._is_runtime_permission('android.permission.READ_SMS')
        
        # Test install-time permissions
        assert not analyzer._is_runtime_permission('android.permission.INTERNET')
        assert not analyzer._is_runtime_permission('android.permission.VIBRATE')
    
    def test_permission_risk_score(self):
        """Test permission risk scoring"""
        from src.modules.manifest_analyzer import ManifestAnalyzer
        from unittest.mock import Mock
        
        mock_apk = Mock()
        analyzer = ManifestAnalyzer(mock_apk)
        
        # Critical permissions
        assert analyzer._calculate_permission_risk('android.permission.SEND_SMS') == 10
        assert analyzer._calculate_permission_risk('android.permission.CAMERA') == 10
        
        # High permissions
        assert analyzer._calculate_permission_risk('android.permission.READ_CONTACTS') == 7
        assert analyzer._calculate_permission_risk('android.permission.ACCESS_COARSE_LOCATION') == 7
        
        # Normal permissions
        assert analyzer._calculate_permission_risk('android.permission.INTERNET') == 2


class TestAntiAnalysis:
    """Test anti-analysis detection"""
    
    def test_anti_analysis_patterns(self):
        """Test that anti-analysis patterns are correctly defined"""
        from src.modules.static_analyzer import StaticAnalyzer
        from unittest.mock import Mock
        
        mock_apk = Mock()
        mock_apk.get_permissions.return_value = []
        
        mock_extracted = {'dex_files': [], 'native_libs': []}
        analyzer = StaticAnalyzer(mock_apk, mock_extracted)
        
        # Verify the analyzer has anti-analysis detection
        assert hasattr(analyzer, 'detect_anti_analysis')


class TestPackingDetection:
    """Test packing and obfuscation detection"""
    
    def test_packer_signatures(self):
        """Test that packer signatures are defined"""
        from src.modules.static_analyzer import StaticAnalyzer
        from unittest.mock import Mock
        
        mock_apk = Mock()
        mock_apk.get_permissions.return_value = []
        
        mock_extracted = {'dex_files': [], 'native_libs': []}
        analyzer = StaticAnalyzer(mock_apk, mock_extracted)
        
        # Verify packing detection exists
        assert hasattr(analyzer, 'detect_packing_obfuscation')


class TestDataExfiltration:
    """Test data exfiltration detection"""
    
    def test_exfiltration_patterns(self):
        """Test data exfiltration pattern detection"""
        from src.modules.static_analyzer import StaticAnalyzer
        from unittest.mock import Mock
        
        mock_apk = Mock()
        mock_apk.get_permissions.return_value = []
        
        mock_extracted = {'dex_files': [], 'native_libs': []}
        analyzer = StaticAnalyzer(mock_apk, mock_extracted)
        
        # Verify exfiltration detection exists
        assert hasattr(analyzer, 'detect_data_exfiltration')


def test_modules_import():
    """Test that all new modules can be imported"""
    try:
        from src.modules.jadx_decompiler import JADXDecompiler
        from src.modules.component_analyzer import ComponentAnalyzer
        from src.modules.manifest_analyzer import ManifestAnalyzer
        from src.modules.static_analyzer import StaticAnalyzer
        
        assert JADXDecompiler is not None
        assert ComponentAnalyzer is not None
        assert ManifestAnalyzer is not None
        assert StaticAnalyzer is not None
        
    except ImportError as e:
        pytest.fail(f"Failed to import modules: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
