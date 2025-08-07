#!/usr/bin/env python3
"""
Quick test to validate TXT record limits specifically
"""

import tempfile
import subprocess
import sys

def test_txt_limits():
    """Test TXT record specific limits"""
    
    # Test with TXT records within limit (should pass)
    zone_content_good = """$ORIGIN txt-test.com.
$TTL 3600

@       IN  SOA ns1.txt-test.com. admin.txt-test.com. (
            2023080601
            7200
            3600
            604800
            86400
            )

        IN  NS  ns1.txt-test.com.

; 5 TXT records (well within 400 limit)
test    IN  TXT "record1"
test    IN  TXT "record2"
test    IN  TXT "record3"
test    IN  TXT "record4"
test    IN  TXT "record5"
"""
    
    # Test good TXT records
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(zone_content_good)
        temp_file = f.name
    
    try:
        result = subprocess.run([
            sys.executable, "azure_dns_evaluator.py", temp_file
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ TXT records within limit test passed")
        else:
            print("✗ TXT records within limit test failed")
            print("Output:", result.stdout[:300])
            
    finally:
        import os
        os.unlink(temp_file)

if __name__ == "__main__":
    test_txt_limits()
