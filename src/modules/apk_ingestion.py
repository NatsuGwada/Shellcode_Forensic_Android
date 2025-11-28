"""
APK Ingestion Module for AndroSleuth
Handles APK extraction, validation, and basic file processing
"""

import os
import zipfile
import tempfile
from pathlib import Path
from androguard.core.apk import APK

from ..utils.logger import get_logger
from ..utils.helpers import (
    calculate_file_hashes,
    get_file_size,
    format_file_size,
    create_temp_directory,
    cleanup_temp_directory
)

logger = get_logger()


class APKIngestion:
    """Class for handling APK file ingestion and extraction"""
    
    def __init__(self, apk_path, temp_dir=None):
        """
        Initialize APK ingestion
        
        Args:
            apk_path: Path to APK file
            temp_dir: Optional temporary directory for extraction
        """
        self.apk_path = apk_path
        self.temp_dir = temp_dir or create_temp_directory()
        self.apk = None
        self.metadata = {}
        
        logger.info(f"Initializing APK ingestion for: {apk_path}")
    
    def validate_apk(self):
        """
        Validate that the file is a valid APK
        
        Returns:
            bool: True if valid APK
        """
        try:
            # Check if file exists
            if not os.path.exists(self.apk_path):
                logger.error(f"APK file not found: {self.apk_path}")
                return False
            
            # Check if it's a valid ZIP file
            if not zipfile.is_zipfile(self.apk_path):
                logger.error("File is not a valid ZIP/APK file")
                return False
            
            # Try to load with androguard
            self.apk = APK(self.apk_path)
            
            # Check for AndroidManifest.xml
            if not self.apk.get_android_manifest_xml():
                logger.error("No AndroidManifest.xml found in APK")
                return False
            
            logger.info("✓ APK validation successful")
            return True
        
        except Exception as e:
            logger.error(f"APK validation failed: {str(e)}")
            return False
    
    def extract_metadata(self):
        """
        Extract basic metadata from APK
        
        Returns:
            dict: Metadata information
        """
        try:
            if not self.apk:
                logger.error("APK not loaded. Run validate_apk() first.")
                return {}
            
            logger.debug(f"Starting metadata extraction for: {self.apk_path}")
            
            # Calculate file hashes (always succeeds or returns N/A)
            hashes = calculate_file_hashes(self.apk_path)
            logger.debug(f"Calculated hashes: {hashes}")
            
            # Get file size
            file_size = get_file_size(self.apk_path)
            logger.debug(f"File size: {file_size}")
            
            # Initialize metadata with basic file info
            self.metadata = {
                'file_name': os.path.basename(self.apk_path),
                'file_path': os.path.abspath(self.apk_path),
                'file_size': file_size,
                'file_size_formatted': format_file_size(file_size),
                'hashes': hashes,
            }
            
            # Extract APK information with individual error handling
            # Package name (usually reliable)
            try:
                self.metadata['package_name'] = self.apk.get_package()
            except Exception as e:
                logger.warning(f"Failed to extract package name: {e}")
                self.metadata['package_name'] = 'N/A'
            
            # App name (may fail with malformed resources.arsc)
            try:
                self.metadata['app_name'] = self.apk.get_app_name()
            except Exception as e:
                logger.warning(f"Failed to extract app name: {e}")
                self.metadata['app_name'] = 'N/A'
            
            # Version info
            try:
                self.metadata['version_name'] = self.apk.get_androidversion_name()
            except Exception as e:
                logger.warning(f"Failed to extract version name: {e}")
                self.metadata['version_name'] = 'N/A'
            
            try:
                self.metadata['version_code'] = self.apk.get_androidversion_code()
            except Exception as e:
                logger.warning(f"Failed to extract version code: {e}")
                self.metadata['version_code'] = 'N/A'
            
            # SDK versions
            try:
                self.metadata['min_sdk_version'] = self.apk.get_min_sdk_version()
            except Exception as e:
                logger.warning(f"Failed to extract min SDK: {e}")
                self.metadata['min_sdk_version'] = 'N/A'
            
            try:
                self.metadata['target_sdk_version'] = self.apk.get_target_sdk_version()
            except Exception as e:
                logger.warning(f"Failed to extract target SDK: {e}")
                self.metadata['target_sdk_version'] = 'N/A'
            
            try:
                self.metadata['max_sdk_version'] = self.apk.get_max_sdk_version()
            except Exception as e:
                logger.warning(f"Failed to extract max SDK: {e}")
                self.metadata['max_sdk_version'] = 'N/A'
            
            # Signature info
            try:
                self.metadata['is_signed'] = self.apk.is_signed()
                self.metadata['is_signed_v1'] = self.apk.is_signed_v1()
                self.metadata['is_signed_v2'] = self.apk.is_signed_v2()
                self.metadata['is_signed_v3'] = self.apk.is_signed_v3()
            except Exception as e:
                logger.warning(f"Failed to extract signature info: {e}")
                self.metadata['is_signed'] = False
                self.metadata['is_signed_v1'] = False
                self.metadata['is_signed_v2'] = False
                self.metadata['is_signed_v3'] = False
            
            logger.debug(f"Extracted package_name: {self.metadata.get('package_name', 'N/A')}")
            logger.debug(f"Extracted app_name: {self.metadata.get('app_name', 'N/A')}")
            logger.debug(f"Extracted version: {self.metadata.get('version_name', 'N/A')}")
            
            # Extract certificate information
            try:
                signers = []
                certs = self.apk.get_certificates()
                logger.debug(f"Found {len(certs)} certificate(s)")
                for cert in certs:
                    # Parse certificate subject and issuer
                    subject_dict = {}
                    issuer_dict = {}
                    
                    # Get subject and issuer from certificate
                    try:
                        subject = cert.subject
                        issuer = cert.issuer
                        
                        # Extract CN (Common Name) from subject
                        for attr in subject:
                            for rdn in attr:
                                if rdn.oid._name == 'commonName':
                                    subject_dict['cn'] = rdn.value
                                elif rdn.oid._name == 'organizationName':
                                    subject_dict['org'] = rdn.value
                                elif rdn.oid._name == 'countryName':
                                    subject_dict['country'] = rdn.value
                        
                        # Extract CN from issuer
                        for attr in issuer:
                            for rdn in attr:
                                if rdn.oid._name == 'commonName':
                                    issuer_dict['cn'] = rdn.value
                                elif rdn.oid._name == 'organizationName':
                                    issuer_dict['org'] = rdn.value
                        
                        # Get serial number
                        serial = hex(cert.serial_number)[2:].upper()
                        
                        signer_info = {
                            'subject_cn': subject_dict.get('cn', 'Unknown'),
                            'subject_org': subject_dict.get('org', 'N/A'),
                            'subject_country': subject_dict.get('country', 'N/A'),
                            'issuer_cn': issuer_dict.get('cn', 'Self-signed'),
                            'issuer_org': issuer_dict.get('org', 'N/A'),
                            'serial': serial,
                            'not_before': cert.not_valid_before.isoformat() if hasattr(cert, 'not_valid_before') else 'N/A',
                            'not_after': cert.not_valid_after.isoformat() if hasattr(cert, 'not_valid_after') else 'N/A'
                        }
                        signers.append(signer_info)
                        logger.debug(f"Extracted certificate: {signer_info['subject_cn']}")
                    except Exception as cert_parse_error:
                        logger.debug(f"Error parsing certificate details: {cert_parse_error}")
                        # Fallback to basic info
                        signers.append({
                            'subject_cn': 'Unknown',
                            'issuer_cn': 'Unknown',
                            'serial': 'N/A'
                        })
                
                self.metadata['signers'] = signers
            except Exception as cert_error:
                logger.warning(f"Could not extract certificate info: {cert_error}")
                self.metadata['signers'] = []
            
            logger.info(f"✓ Extracted metadata for package: {self.metadata.get('package_name', 'Unknown')}")
            logger.debug(f"Full metadata: {self.metadata}")
            return self.metadata
        
        except Exception as e:
            logger.error(f"Failed to extract metadata: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            # Return at least basic file info if available
            return {
                'file_name': os.path.basename(self.apk_path) if self.apk_path else 'unknown.apk',
                'hashes': calculate_file_hashes(self.apk_path) if self.apk_path else {'md5': 'N/A', 'sha1': 'N/A', 'sha256': 'N/A'},
                'package_name': 'N/A',
                'app_name': 'N/A',
                'version_name': 'N/A',
                'version_code': 'N/A',
            }
    
    def extract_files(self):
        """
        Extract APK contents to temporary directory
        
        Returns:
            dict: Paths to extracted components
        """
        try:
            logger.info(f"Extracting APK to: {self.temp_dir}")
            
            extracted_paths = {
                'root': self.temp_dir,
                'dex_files': [],
                'native_libs': [],
                'resources': [],
                'manifest': None,
                'assets': []
            }
            
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
            
            # Find extracted files
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # DEX files
                    if file.endswith('.dex'):
                        extracted_paths['dex_files'].append(file_path)
                    
                    # Native libraries
                    elif file.endswith('.so'):
                        extracted_paths['native_libs'].append(file_path)
                    
                    # Manifest
                    elif file == 'AndroidManifest.xml':
                        extracted_paths['manifest'] = file_path
                    
                    # Resources
                    elif file.endswith(('.xml', '.png', '.jpg', '.jpeg')):
                        extracted_paths['resources'].append(file_path)
                    
                    # Assets
                    elif 'assets' in root:
                        extracted_paths['assets'].append(file_path)
            
            logger.info(f"✓ Extracted {len(extracted_paths['dex_files'])} DEX files")
            logger.info(f"✓ Extracted {len(extracted_paths['native_libs'])} native libraries")
            logger.info(f"✓ Extracted {len(extracted_paths['resources'])} resource files")
            
            return extracted_paths
        
        except Exception as e:
            logger.error(f"Failed to extract APK: {str(e)}")
            return {}
    
    def get_apk_object(self):
        """
        Get the androguard APK object
        
        Returns:
            APK: Androguard APK object
        """
        return self.apk
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            cleanup_temp_directory(self.temp_dir)
            logger.info("✓ Cleaned up temporary files")
        except Exception as e:
            logger.warning(f"Failed to cleanup temp directory: {str(e)}")
    
    def process(self):
        """
        Process the complete APK ingestion pipeline
        
        Returns:
            dict: Complete ingestion results
        """
        results = {
            'valid': False,
            'metadata': {},
            'extracted_files': {}
        }
        
        # Validate APK
        if not self.validate_apk():
            return results
        
        results['valid'] = True
        
        # Extract metadata
        results['metadata'] = self.extract_metadata()
        
        # Extract files
        results['extracted_files'] = self.extract_files()
        
        return results
