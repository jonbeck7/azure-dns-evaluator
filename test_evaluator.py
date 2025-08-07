#!/usr/bin/env python3
"""
Test script for Azure DNS Evaluator

This script tests the functionality of the Azure DNS zone file evaluator
with various test cases.
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

def run_evaluator(zone_file, format_type="text", verbose=False, split=False):
    """Run the evaluator and return the result"""
    cmd = [sys.executable, "azure_dns_evaluator.py", zone_file, "--format", format_type]
    if verbose:
        cmd.append("--verbose")
    if split:
        cmd.append("--split")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)

def test_valid_zone():
    """Test with a valid zone file"""
    print("Testing valid zone file...")
    
    zone_content = """$ORIGIN example.com.
$TTL 3600

@       IN  SOA ns1.example.com. admin.example.com. (
            2023080601
            7200
            3600
            604800
            86400
            )

        IN  NS  ns1.example.com.
        IN  A   192.168.1.1
www     IN  A   192.168.1.2
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(zone_content)
        temp_file = f.name
    
    try:
        returncode, stdout, stderr = run_evaluator(temp_file)
        
        if returncode == 0:
            print("✓ Valid zone test passed")
            print("Sample output:")
            print(stdout[:200] + "..." if len(stdout) > 200 else stdout)
            return True
        else:
            print(f"✗ Valid zone test failed with return code {returncode}")
            print("Error:", stderr)
            return False
    finally:
        os.unlink(temp_file)

def test_invalid_zone():
    """Test with an invalid zone file"""
    print("\nTesting invalid zone file...")
    
    zone_content = """$ORIGIN problematic.com.
$TTL 60

@       IN  SOA ns1.problematic.com. admin.problematic.com. (
            2023080601
            7200
            3600
            604800
            30
            )

        IN  NS  ns1.problematic.com.
        IN  A   192.168.1.1

; Unsupported record type
computer IN  HINFO  "PC-Intel" "Linux"

; TTL too high
high-ttl 2147483648 IN A 192.168.1.2
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(zone_content)
        temp_file = f.name
    
    try:
        returncode, stdout, stderr = run_evaluator(temp_file)
        
        if returncode != 0:
            print("✓ Invalid zone test passed (correctly detected errors)")
            print("Sample output:")
            print(stdout[:300] + "..." if len(stdout) > 300 else stdout)
            return True
        else:
            print("✗ Invalid zone test failed (should have detected errors)")
            return False
    finally:
        os.unlink(temp_file)

def test_json_output():
    """Test JSON output format"""
    print("\nTesting JSON output format...")
    
    zone_content = """$ORIGIN test.com.
$TTL 3600

@       IN  SOA ns1.test.com. admin.test.com. (
            2023080601
            7200
            3600
            604800
            86400
            )

        IN  NS  ns1.test.com.
        IN  A   192.168.1.1
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(zone_content)
        temp_file = f.name
    
    try:
        returncode, stdout, stderr = run_evaluator(temp_file, format_type="json")
        
        # Try to parse JSON
        import json
        try:
            json_data = json.loads(stdout)
            if "zone_info" in json_data and "validation_results" in json_data:
                print("✓ JSON output test passed")
                return True
            else:
                print("✗ JSON output test failed (missing expected fields)")
                return False
        except json.JSONDecodeError:
            print("✗ JSON output test failed (invalid JSON)")
            print("Output:", stdout[:200])
            return False
    finally:
        os.unlink(temp_file)

def test_nonexistent_file():
    """Test with non-existent file"""
    print("\nTesting non-existent file...")
    
    returncode, stdout, stderr = run_evaluator("nonexistent_file.txt")
    
    if returncode != 0 and "not found" in stderr.lower():
        print("✓ Non-existent file test passed")
        return True
    else:
        print("✗ Non-existent file test failed")
        return False

def test_example_files():
    """Test the example files if they exist"""
    print("\nTesting example files...")
    
    examples_dir = Path("examples")
    if not examples_dir.exists():
        print("Examples directory not found, skipping example file tests")
        return True
    
    results = []
    
    # Test valid example
    valid_example = examples_dir / "valid_zone.txt"
    if valid_example.exists():
        returncode, stdout, stderr = run_evaluator(str(valid_example))
        if returncode == 0:
            print("✓ Valid example file test passed")
            results.append(True)
        else:
            print("✗ Valid example file test failed")
            results.append(False)
    
    # Test problematic example
    problematic_example = examples_dir / "problematic_zone.txt"
    if problematic_example.exists():
        returncode, stdout, stderr = run_evaluator(str(problematic_example))
        if returncode != 0:
            print("✓ Problematic example file test passed (correctly detected errors)")
            results.append(True)
        else:
            print("✗ Problematic example file test failed (should have detected errors)")
            results.append(False)
    
    # Test large TXT record set example
    large_txt_example = examples_dir / "large_txt_zone.txt"
    if large_txt_example.exists():
        returncode, stdout, stderr = run_evaluator(str(large_txt_example))
        if returncode != 0 and "4096 bytes" in stdout:
            print("✓ Large TXT record set test passed (correctly detected size limit)")
            results.append(True)
        else:
            print("✗ Large TXT record set test failed (should have detected size limit)")
            results.append(False)
    
    # Test large record set example (too many records in a set)
    large_recordset_example = examples_dir / "large_recordset_zone.txt"
    if large_recordset_example.exists():
        returncode, stdout, stderr = run_evaluator(str(large_recordset_example))
        if returncode != 0 and ("22 records" in stdout or "exceeds Azure DNS limit of 20" in stdout):
            print("✓ Large record set test passed (correctly detected record count limit)")
            results.append(True)
        else:
            print("✗ Large record set test failed (should have detected record count limit)")
            results.append(False)
    
    # Test large zone file (import API limits)
    large_zone_example = examples_dir / "large_zone_test.txt"
    if large_zone_example.exists():
        returncode, stdout, stderr = run_evaluator(str(large_zone_example))
        if returncode != 0 and ("3000 record sets" in stdout or "3502 record sets" in stdout):
            print("✓ Large zone import test passed (correctly detected import API limits)")
            results.append(True)
        else:
            print("✗ Large zone import test failed (should have detected import API limits)")
            results.append(False)
    
    # Test zone splitting functionality
    mega_large_example = examples_dir / "mega_large_zone.txt"
    if mega_large_example.exists():
        # Test splitting functionality with verbose mode to see validation results
        returncode, stdout, stderr = run_evaluator(str(mega_large_example), "text", True, split=True)
        
        # Check for splitting success indicators
        has_split_message = "Zone file has been split into" in stdout
        
        # Check if split directory was created successfully
        split_dir = mega_large_example.parent / f"{mega_large_example.stem}_split"
        split_files_exist = split_dir.exists() and len(list(split_dir.glob("*.txt"))) > 0
        
        # For zone splitting, we care more about the files being created than the return code
        # since the original file may still have validation errors
        if has_split_message and split_files_exist:
            print("✓ Zone splitting test passed (successfully split large file)")
            results.append(True)
            
            # Clean up split files
            import shutil
            if split_dir.exists():
                shutil.rmtree(split_dir)
        else:
            print("✗ Zone splitting test failed (should have split large file)")
            print(f"  Return code: {returncode}")
            print(f"  Has split message: {has_split_message}")
            print(f"  Split files exist: {split_files_exist}")
            if split_dir.exists():
                print(f"  Split files count: {len(list(split_dir.glob('*.txt')))}")
            results.append(False)
    
    return all(results) if results else True

def main():
    """Run all tests"""
    print("Azure DNS Evaluator Test Suite")
    print("=" * 40)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Check if the main script exists
    if not Path("azure_dns_evaluator.py").exists():
        print("Error: azure_dns_evaluator.py not found in current directory")
        sys.exit(1)
    
    tests = [
        test_valid_zone,
        test_invalid_zone,
        test_json_output,
        test_nonexistent_file,
        test_example_files
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
