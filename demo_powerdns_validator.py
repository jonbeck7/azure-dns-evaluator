#!/usr/bin/env python3
"""
Simple PowerDNS to Azure DNS validator demonstration
This is a simplified example showing how to integrate PowerDNS with the Azure DNS evaluator
"""

import json
import subprocess
import tempfile
import os

# Mock PowerDNS zone data (would normally come from PowerDNS API)
MOCK_POWERDNS_ZONE = {
    "name": "example.com.",
    "rrsets": [
        {
            "name": "example.com.",
            "type": "SOA",
            "ttl": 86400,
            "records": [
                {
                    "content": "ns1.example.com. admin.example.com. 2023080601 7200 3600 604800 86400"
                }
            ]
        },
        {
            "name": "example.com.",
            "type": "NS",
            "ttl": 86400,
            "records": [
                {"content": "ns1.example.com."},
                {"content": "ns2.example.com."}
            ]
        },
        {
            "name": "example.com.",
            "type": "A",
            "ttl": 3600,
            "records": [
                {"content": "192.168.1.1"}
            ]
        },
        {
            "name": "www.example.com.",
            "type": "A",
            "ttl": 3600,
            "records": [
                {"content": "192.168.1.2"}
            ]
        },
        {
            "name": "mail.example.com.",
            "type": "A",
            "ttl": 3600,
            "records": [
                {"content": "192.168.1.3"}
            ]
        },
        {
            "name": "example.com.",
            "type": "MX",
            "ttl": 3600,
            "records": [
                {"content": "10 mail.example.com."}
            ]
        },
        {
            "name": "blog.example.com.",
            "type": "CNAME",
            "ttl": 3600,
            "records": [
                {"content": "www.example.com."}
            ]
        },
        {
            "name": "example.com.",
            "type": "TXT",
            "ttl": 3600,
            "records": [
                {"content": "v=spf1 include:_spf.google.com ~all"}
            ]
        }
    ]
}

def convert_powerdns_to_bind(zone_data):
    """Convert PowerDNS zone data to BIND format"""
    zone_name = zone_data['name']
    bind_lines = [
        f"$ORIGIN {zone_name}",
        "$TTL 3600",
        ""
    ]
    
    for rrset in zone_data.get('rrsets', []):
        name = rrset['name'].replace(f".{zone_name}", "").replace(zone_name, "@")
        if not name:
            name = "@"
        
        record_type = rrset['type']
        ttl = rrset.get('ttl', 3600)
        
        for record in rrset.get('records', []):
            content = record['content']
            
            if record_type == 'SOA':
                # Parse SOA content
                parts = content.split()
                if len(parts) >= 7:
                    bind_lines.extend([
                        f"{name}    {ttl}    IN    SOA    {parts[0]} {parts[1]} (",
                        f"                {parts[2]}    ; Serial",
                        f"                {parts[3]}    ; Refresh",
                        f"                {parts[4]}    ; Retry",
                        f"                {parts[5]}    ; Expire",
                        f"                {parts[6]}    ; Minimum",
                        "                )"
                    ])
            elif record_type == 'TXT':
                # Ensure TXT records are quoted
                quoted_content = f'"{content}"' if not content.startswith('"') else content
                bind_lines.append(f"{name}    {ttl}    IN    {record_type}    {quoted_content}")
            else:
                bind_lines.append(f"{name}    {ttl}    IN    {record_type}    {content}")
    
    return "\n".join(bind_lines)

def validate_powerdns_zone(zone_data):
    """Validate PowerDNS zone data using Azure DNS evaluator"""
    try:
        # Convert to BIND format
        bind_content = convert_powerdns_to_bind(zone_data)
        
        print("Converted PowerDNS zone to BIND format:")
        print("=" * 50)
        print(bind_content)
        print("=" * 50)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            temp_file.write(bind_content)
            temp_file_path = temp_file.name
        
        try:
            # Validate with Azure DNS evaluator
            result = subprocess.run([
                'python', 'azure_dns_evaluator.py', temp_file_path
            ], capture_output=True, text=True)
            
            print(f"\nValidation results for PowerDNS zone {zone_data['name']}:")
            print(result.stdout)
            
            if result.stderr:
                print("Errors:")
                print(result.stderr)
            
            return result.returncode == 0
            
        finally:
            os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"Error validating PowerDNS zone: {e}")
        return False

def main():
    print("PowerDNS to Azure DNS Validator Demo")
    print("=" * 40)
    
    # Validate the mock zone
    success = validate_powerdns_zone(MOCK_POWERDNS_ZONE)
    
    if success:
        print("\n✅ PowerDNS zone validation passed!")
        print("The zone is compatible with Azure DNS.")
    else:
        print("\n❌ PowerDNS zone validation failed!")
        print("Please review the errors above.")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
