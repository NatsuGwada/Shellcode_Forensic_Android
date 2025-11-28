#!/usr/bin/env python3
"""
Integration tests for report structure validation
Verifies that generated reports contain expected sections with proper data
"""

import os
import sys
import json
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from src.modules.report_generator import ReportGenerator


class TestReportStructure:
    """Test that reports contain expected structure and fields"""
    
    @pytest.fixture
    def sample_results(self):
        """Create sample analysis results with complete structure"""
        return {
            'apk_info': {
                'package_name': 'com.example.testapp',
                'app_name': 'TestApp',
                'version_name': '1.0.0',
                'version_code': 1,
                'file_size': 5242880,
                'file_size_formatted': '5.0 MB',
                'min_sdk_version': 21,
                'target_sdk_version': 30,
                'hashes': {
                    'md5': 'abc123def456',
                    'sha1': '1234567890abcdef',
                    'sha256': 'fedcba0987654321'
                },
                'signers': [
                    {
                        'subject_cn': 'Test Developer',
                        'issuer_cn': 'Test CA',
                        'serial': '12345'
                    }
                ]
            },
            'manifest_analysis': {
                'permissions': {
                    'total_count': 10,
                    'all_permissions': [
                        'android.permission.INTERNET',
                        'android.permission.ACCESS_FINE_LOCATION',
                        'android.permission.CAMERA',
                        'android.permission.READ_CONTACTS',
                        'android.permission.WRITE_EXTERNAL_STORAGE',
                        'android.permission.READ_PHONE_STATE',
                        'android.permission.SEND_SMS',
                        'android.permission.RECORD_AUDIO',
                        'android.permission.ACCESS_NETWORK_STATE',
                        'android.permission.WAKE_LOCK'
                    ],
                    'dangerous_permissions': [
                        'android.permission.ACCESS_FINE_LOCATION',
                        'android.permission.CAMERA',
                        'android.permission.READ_CONTACTS',
                        'android.permission.WRITE_EXTERNAL_STORAGE',
                        'android.permission.READ_PHONE_STATE',
                        'android.permission.SEND_SMS',
                        'android.permission.RECORD_AUDIO'
                    ],
                    'normal_permissions': [
                        'android.permission.INTERNET',
                        'android.permission.ACCESS_NETWORK_STATE',
                        'android.permission.WAKE_LOCK'
                    ],
                    'runtime_permissions': [
                        'android.permission.ACCESS_FINE_LOCATION',
                        'android.permission.CAMERA',
                        'android.permission.READ_CONTACTS',
                        'android.permission.WRITE_EXTERNAL_STORAGE',
                        'android.permission.READ_PHONE_STATE',
                        'android.permission.SEND_SMS',
                        'android.permission.RECORD_AUDIO'
                    ],
                    'install_time_permissions': [
                        'android.permission.INTERNET',
                        'android.permission.ACCESS_NETWORK_STATE',
                        'android.permission.WAKE_LOCK'
                    ],
                    'permission_matrix': [
                        {
                            'name': 'android.permission.INTERNET',
                            'group': 'NETWORK',
                            'protection_level': 'normal',
                            'is_dangerous': False,
                            'is_runtime': False,
                            'risk_score': 1
                        },
                        {
                            'name': 'android.permission.ACCESS_FINE_LOCATION',
                            'group': 'LOCATION',
                            'protection_level': 'dangerous',
                            'is_dangerous': True,
                            'is_runtime': True,
                            'risk_score': 8
                        },
                        {
                            'name': 'android.permission.CAMERA',
                            'group': 'CAMERA',
                            'protection_level': 'dangerous',
                            'is_dangerous': True,
                            'is_runtime': True,
                            'risk_score': 7
                        }
                    ],
                    'permission_groups': {
                        'NETWORK': ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'],
                        'LOCATION': ['android.permission.ACCESS_FINE_LOCATION'],
                        'CAMERA': ['android.permission.CAMERA'],
                        'CONTACTS': ['android.permission.READ_CONTACTS'],
                        'STORAGE': ['android.permission.WRITE_EXTERNAL_STORAGE'],
                        'PHONE': ['android.permission.READ_PHONE_STATE'],
                        'SMS': ['android.permission.SEND_SMS'],
                        'MICROPHONE': ['android.permission.RECORD_AUDIO'],
                        'SYSTEM': ['android.permission.WAKE_LOCK'],
                        'OTHER': []
                    },
                    'over_privileged': True,
                    'risk_level': 'HIGH'
                },
                'activities': [
                    {
                        'name': 'com.example.testapp.MainActivity',
                        'exported': True,
                        'launch_mode': 'standard'
                    },
                    {
                        'name': 'com.example.testapp.SettingsActivity',
                        'exported': False,
                        'launch_mode': 'standard'
                    }
                ],
                'services': [
                    {
                        'name': 'com.example.testapp.BackgroundService',
                        'exported': False,
                        'permission': None
                    }
                ],
                'receivers': [
                    {
                        'name': 'com.example.testapp.BootReceiver',
                        'exported': True,
                        'actions': ['android.intent.action.BOOT_COMPLETED']
                    }
                ],
                'providers': [
                    {
                        'name': 'com.example.testapp.DataProvider',
                        'exported': False,
                        'authorities': 'com.example.testapp.provider'
                    }
                ],
                'anomalies': {
                    'count': 2,
                    'issues': [
                        'Exported component without permission check: BootReceiver',
                        'Over-privileged: App requests 7 dangerous permissions'
                    ]
                },
                'threat_score': 65
            },
            'static_analysis': {
                'total_strings': 1523,
                'suspicious_strings_count': 8,
                'dynamic_loading_count': 2,
                'crypto_usage_count': 5,
                'network_usage_count': 12,
                'reflection_usage_count': 3,
                'threat_score': 40
            },
            'obfuscation_analysis': {
                'is_obfuscated': True,
                'obfuscation_techniques': ['ProGuard'],
                'packers_detected': [],
                'threat_score': 30
            },
            'shellcode_analysis': {
                'native_libs_count': 2,
                'shellcode_patterns_count': 0,
                'syscalls_count': 0,
                'threat_score': 10
            },
            'yara_analysis': {
                'matches': [],
                'threat_score': 0
            },
            'overall_score': 45,
            'risk_level': 'MEDIUM',
            'timestamp': '2025-11-28T10:00:00'
        }
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create temporary directory for test outputs"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_json_report_structure(self, sample_results, temp_output_dir):
        """Test that JSON report contains all expected fields"""
        # Create report generator
        report_gen = ReportGenerator(
            apk_path='/tmp/testapp.apk',  # Fake path, just needs a name
            output_dir=str(temp_output_dir)
        )
        
        # Add results
        report_gen.results = sample_results.copy()
        
        # Generate JSON report
        json_path = report_gen.generate_json_report()
        
        # Verify file exists
        assert os.path.exists(json_path), "JSON report file should exist"
        
        # Load and verify structure
        with open(json_path, 'r') as f:
            report_data = json.load(f)
        
        # Check top-level fields
        assert 'apk_info' in report_data, "Report should contain apk_info"
        assert 'manifest_analysis' in report_data, "Report should contain manifest_analysis"
        assert 'overall_score' in report_data, "Report should contain overall_score"
        assert 'risk_level' in report_data, "Report should contain risk_level"
        
        # Check APK info structure
        apk_info = report_data['apk_info']
        assert 'package_name' in apk_info, "APK info should contain package_name"
        assert 'app_name' in apk_info, "APK info should contain app_name"
        assert 'version_name' in apk_info, "APK info should contain version_name"
        assert 'hashes' in apk_info, "APK info should contain hashes"
        assert 'signers' in apk_info, "APK info should contain signers"
        assert isinstance(apk_info['signers'], list), "Signers should be a list"
        
        # Check manifest analysis structure
        manifest = report_data['manifest_analysis']
        assert 'permissions' in manifest, "Manifest should contain permissions"
        
        # Check permissions structure
        perms = manifest['permissions']
        assert isinstance(perms, dict), "Permissions should be a dict"
        assert 'all_permissions' in perms, "Permissions should contain all_permissions"
        assert 'dangerous_permissions' in perms, "Permissions should contain dangerous_permissions"
        assert 'permission_matrix' in perms, "Permissions should contain permission_matrix"
        
        # Verify permission matrix structure
        assert isinstance(perms['permission_matrix'], list), "Permission matrix should be a list"
        if len(perms['permission_matrix']) > 0:
            perm_entry = perms['permission_matrix'][0]
            assert 'name' in perm_entry, "Permission entry should have name"
            assert 'group' in perm_entry, "Permission entry should have group"
            assert 'protection_level' in perm_entry, "Permission entry should have protection_level"
            assert 'risk_score' in perm_entry, "Permission entry should have risk_score"
        
        # Check components
        for comp_type in ['activities', 'services', 'receivers', 'providers']:
            if comp_type in manifest:
                comps = manifest[comp_type]
                assert isinstance(comps, (list, dict)), f"{comp_type} should be list or dict"
    
    def test_html_report_generation(self, sample_results, temp_output_dir):
        """Test that HTML report is generated without errors"""
        # Create report generator
        report_gen = ReportGenerator(
            apk_path='/tmp/testapp.apk',  # Fake path, just needs a name
            output_dir=str(temp_output_dir)
        )
        
        # Add results
        report_gen.results = sample_results.copy()
        
        # Generate HTML report
        html_path = report_gen.generate_html_report()
        
        # Verify file exists
        assert os.path.exists(html_path), "HTML report file should exist"
        
        # Read and check basic content
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Check for key sections
        assert 'com.example.testapp' in html_content, "HTML should contain package name"
        assert 'Permission Matrix' in html_content or 'Permissions' in html_content, "HTML should contain permissions section"
        assert 'Activities' in html_content or 'Components' in html_content, "HTML should contain components section"
        
        # Check permission matrix elements
        assert 'android.permission.INTERNET' in html_content, "HTML should list permissions"
        assert 'android.permission.CAMERA' in html_content, "HTML should list dangerous permissions"
        
    def test_normalize_results_with_old_structure(self, temp_output_dir):
        """Test that old permission structure is properly normalized"""
        # Create report with old structure (permissions as list)
        old_results = {
            'apk_info': {
                'package_name': 'com.old.app'
            },
            'manifest_analysis': {
                'permissions': [
                    'android.permission.INTERNET',
                    'android.permission.CAMERA'
                ],
                'threat_score': 30
            },
            'overall_score': 30,
            'risk_level': 'LOW'
        }
        
        # Create report generator
        report_gen = ReportGenerator(
            apk_path='/tmp/oldapp.apk',  # Fake path, just needs a name
            output_dir=str(temp_output_dir)
        )
        
        # Add old structure results
        report_gen.results = old_results.copy()
        
        # Generate JSON (which normalizes)
        json_path = report_gen.generate_json_report()
        
        # Load and verify normalization
        with open(json_path, 'r') as f:
            normalized = json.load(f)
        
        # Check that permissions was converted to dict
        manifest = normalized['manifest_analysis']
        assert isinstance(manifest['permissions'], dict), "Permissions should be normalized to dict"
        assert 'all_permissions' in manifest['permissions'], "Should have all_permissions field"
        assert len(manifest['permissions']['all_permissions']) == 2, "Should preserve permission list"
        
        # Check required apk_info fields added
        apk_info = normalized['apk_info']
        assert 'app_name' in apk_info, "Should add missing app_name"
        assert 'hashes' in apk_info, "Should add missing hashes"
        assert 'signers' in apk_info, "Should add missing signers"
    
    def test_pdf_report_generation(self, sample_results, temp_output_dir):
        """Test that PDF report generation handles new structure"""
        try:
            from src.modules.pdf_generator import generate_pdf_report
        except ImportError:
            pytest.skip("ReportLab not available, skipping PDF test")
        
        # Generate PDF
        pdf_path = str(temp_output_dir / 'test_report.pdf')
        result_path = generate_pdf_report(sample_results, pdf_path)
        
        # Verify file exists
        assert os.path.exists(result_path), "PDF report file should exist"
        assert os.path.getsize(result_path) > 0, "PDF file should not be empty"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
