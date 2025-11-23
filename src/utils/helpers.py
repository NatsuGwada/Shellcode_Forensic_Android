"""
Helper utilities for AndroSleuth
Common functions used across modules
"""

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from datetime import datetime


def calculate_file_hashes(file_path):
    """
    Calculate MD5, SHA1, and SHA256 hashes of a file
    
    Args:
        file_path: Path to file
    
    Returns:
        dict: Dictionary with hash values
    """
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
    except Exception as e:
        return {
            'error': str(e),
            'md5': None,
            'sha1': None,
            'sha256': None
        }


def get_file_size(file_path):
    """
    Get file size in bytes
    
    Args:
        file_path: Path to file
    
    Returns:
        int: File size in bytes
    """
    try:
        return os.path.getsize(file_path)
    except:
        return 0


def format_file_size(size_bytes):
    """
    Format file size in human-readable format
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        str: Formatted size
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def create_temp_directory(prefix="androsleuth_"):
    """
    Create a temporary directory for analysis
    
    Args:
        prefix: Directory name prefix
    
    Returns:
        str: Path to temporary directory
    """
    temp_dir = tempfile.mkdtemp(prefix=prefix)
    return temp_dir


def cleanup_temp_directory(temp_dir):
    """
    Remove temporary directory and its contents
    
    Args:
        temp_dir: Path to temporary directory
    """
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            return True
    except Exception as e:
        return False


def ensure_directory(directory):
    """
    Ensure directory exists, create if it doesn't
    
    Args:
        directory: Path to directory
    """
    Path(directory).mkdir(parents=True, exist_ok=True)


def get_timestamp():
    """
    Get current timestamp in ISO format
    
    Returns:
        str: Timestamp
    """
    return datetime.now().isoformat()


def get_filename_timestamp():
    """
    Get timestamp suitable for filenames
    
    Returns:
        str: Timestamp string
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def is_valid_file(file_path, extensions=None):
    """
    Check if file exists and has valid extension
    
    Args:
        file_path: Path to file
        extensions: List of valid extensions (e.g., ['.apk', '.zip'])
    
    Returns:
        bool: True if valid
    """
    if not os.path.isfile(file_path):
        return False
    
    if extensions:
        return any(file_path.lower().endswith(ext) for ext in extensions)
    
    return True


def read_file_safely(file_path, max_size=10*1024*1024):
    """
    Read file content safely with size limit
    
    Args:
        file_path: Path to file
        max_size: Maximum file size to read (default: 10MB)
    
    Returns:
        bytes: File content or None
    """
    try:
        file_size = get_file_size(file_path)
        if file_size > max_size:
            return None
        
        with open(file_path, 'rb') as f:
            return f.read()
    except:
        return None


def extract_strings(data, min_length=4):
    """
    Extract printable strings from binary data
    
    Args:
        data: Binary data
        min_length: Minimum string length
    
    Returns:
        list: List of strings found
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')
    
    strings = []
    current_string = []
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
            current_string = []
    
    # Don't forget the last string
    if len(current_string) >= min_length:
        strings.append(''.join(current_string))
    
    return strings


def sanitize_filename(filename):
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename: Original filename
    
    Returns:
        str: Sanitized filename
    """
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename
