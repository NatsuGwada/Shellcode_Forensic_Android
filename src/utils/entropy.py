"""
Entropy calculation utilities for AndroSleuth
Used to detect encrypted/compressed data
"""

import math
from collections import Counter


def calculate_entropy(data):
    """
    Calculate Shannon entropy of data
    
    Args:
        data: Bytes or string to analyze
    
    Returns:
        float: Entropy value (0-8 for bytes, 0-log2(len(unique_chars)) for strings)
    """
    if not data:
        return 0.0
    
    # Convert to bytes if string
    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')
    
    # Count byte frequencies
    counter = Counter(data)
    length = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def is_high_entropy(data, threshold=7.0):
    """
    Check if data has high entropy (likely encrypted/compressed)
    
    Args:
        data: Data to check
        threshold: Entropy threshold (default: 7.0)
    
    Returns:
        tuple: (bool, float) - (is_high, entropy_value)
    """
    entropy = calculate_entropy(data)
    return entropy >= threshold, entropy


def analyze_file_entropy(file_path, chunk_size=4096):
    """
    Analyze entropy of a file in chunks
    
    Args:
        file_path: Path to file
        chunk_size: Size of chunks to analyze
    
    Returns:
        dict: Statistics about file entropy
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return {
                'overall_entropy': 0.0,
                'is_suspicious': False,
                'file_size': 0
            }
        
        overall_entropy = calculate_entropy(data)
        
        # Analyze chunks
        chunk_entropies = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunk_entropy = calculate_entropy(chunk)
            chunk_entropies.append(chunk_entropy)
        
        avg_chunk_entropy = sum(chunk_entropies) / len(chunk_entropies) if chunk_entropies else 0
        max_chunk_entropy = max(chunk_entropies) if chunk_entropies else 0
        
        return {
            'overall_entropy': overall_entropy,
            'average_chunk_entropy': avg_chunk_entropy,
            'max_chunk_entropy': max_chunk_entropy,
            'is_suspicious': overall_entropy >= 7.0,
            'file_size': len(data),
            'num_chunks': len(chunk_entropies)
        }
    
    except Exception as e:
        return {
            'error': str(e),
            'overall_entropy': 0.0,
            'is_suspicious': False
        }


def entropy_description(entropy_value):
    """
    Get human-readable description of entropy value
    
    Args:
        entropy_value: Float entropy value
    
    Returns:
        str: Description
    """
    if entropy_value < 3.0:
        return "Very low (likely plain text or repetitive data)"
    elif entropy_value < 5.0:
        return "Low (structured data)"
    elif entropy_value < 6.5:
        return "Medium (mixed content)"
    elif entropy_value < 7.5:
        return "High (possibly compressed)"
    else:
        return "Very high (likely encrypted or random)"
