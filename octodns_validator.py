#!/usr/bin/env python3
"""
OctoDNS to Azure DNS evaluator integration
Converts OctoDNS YAML configs to BIND format and validates them using the Azure DNS evaluator
"""

import yaml
import os
import sys
import subprocess
import tempfile
import argparse
from pathlib import Path

class OctoDNSValidator:
    def __init__(self, azure_dns_evaluator_path="azure_dns_evaluator.py"):
        self.evaluator_path = azure_dns_evaluator_path
    
    def octodns_to_bind(self, zone_data, zone_name):
        """Convert OctoDNS YAML structure to BIND format"""
        bind_lines = [
            f"$ORIGIN {zone_name}",
            "$TTL 3600",
            ""
        ]
        
        for name, records in zone_data.items():
            display_name = '@' if name == '' else name
            
            for record in records:
                record_type = record['type']
                ttl = record.get('ttl', 3600)
                
                if record_type == 'SOA':
                    soa = record['value']
                    bind_lines.extend([
                        f"{display_name}    {ttl}    IN    SOA    {soa['mname']} {soa['rname']} (",
                        f"                {soa['serial']}    ; Serial",
                        f"                {soa['refresh']}        ; Refresh", 
                        f"                {soa['retry']}        ; Retry",
                        f"                {soa['expire']}      ; Expire",
                        f"                {soa['minimum']}       ; Minimum",
                        "                )"
                    ])
                elif record_type == 'NS':
                    values = record.get('values', [record.get('value')])
                    for value in values:
                        if value:
                            bind_lines.append(f"{display_name}    {ttl}    IN    NS    {value}")
                elif record_type == 'MX':
                    mx = record['value']
                    bind_lines.append(f"{display_name}    {ttl}    IN    MX    {mx['preference']} {mx['exchange']}")
                elif record_type == 'CNAME':
                    bind_lines.append(f"{display_name}    {ttl}    IN    CNAME    {record['value']}")
                elif record_type in ['A', 'AAAA']:
                    values = record.get('values', [record.get('value')])
                    for value in values:
                        if value:
                            bind_lines.append(f"{display_name}    {ttl}    IN    {record_type}    {value}")
                elif record_type == 'TXT':
                    values = record.get('values', [record.get('value')])
                    for value in values:
                        if value:
                            # Ensure TXT values are properly quoted
                            quoted_value = f'"{value}"' if not (value.startswith('"') and value.endswith('"')) else value
                            bind_lines.append(f"{display_name}    {ttl}    IN    TXT    {quoted_value}")
                elif record_type == 'SRV':
                    srv = record['value']
                    bind_lines.append(f"{display_name}    {ttl}    IN    SRV    {srv['priority']} {srv['weight']} {srv['port']} {srv['target']}")
                elif record_type == 'CAA':
                    caa = record['value']
                    bind_lines.append(f"{display_name}    {ttl}    IN    CAA    {caa['flags']} {caa['tag']} \"{caa['value']}\"")
                elif record_type == 'PTR':
                    bind_lines.append(f"{display_name}    {ttl}    IN    PTR    {record['value']}")
        
        return "\n".join(bind_lines)
    
    def validate_octodns_zone(self, zone_file_path, verbose=False):
        """Validate an OctoDNS zone file by converting to BIND and using azure_dns_evaluator"""
        try:
            with open(zone_file_path, 'r') as f:
                zone_data = yaml.safe_load(f)
            
            if not zone_data:
                print(f"❌ Empty or invalid YAML file: {zone_file_path}")
                return False
            
            zone_name = Path(zone_file_path).stem + '.'
            bind_content = self.octodns_to_bind(zone_data, zone_name)
            
            if verbose:
                print(f"Converted BIND content for {zone_name}:")
                print("-" * 40)
                print(bind_content)
                print("-" * 40)
            
            # Create temporary BIND file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(bind_content)
                temp_file_path = temp_file.name
            
            try:
                # Run azure_dns_evaluator on the temporary BIND file
                cmd = ['python', self.evaluator_path, temp_file_path]
                if verbose:
                    cmd.append('--verbose')
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                print(f"Validation results for {zone_file_path}:")
                print(result.stdout)
                
                if result.stderr:
                    print("Errors:")
                    print(result.stderr)
                
                return result.returncode == 0
                
            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)
                
        except yaml.YAMLError as e:
            print(f"❌ YAML parsing error in {zone_file_path}: {e}")
            return False
        except Exception as e:
            print(f"❌ Error validating {zone_file_path}: {e}")
            return False
    
    def validate_octodns_config(self, config_path, zones_dir="zones", verbose=False):
        """Validate all zones referenced in an OctoDNS config"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            zones = config.get('zones', {})
            all_valid = True
            
            if not zones:
                print("❌ No zones found in OctoDNS config")
                return False
            
            print(f"Found {len(zones)} zone(s) in OctoDNS config")
            
            for zone_name in zones.keys():
                zone_file = os.path.join(zones_dir, f"{zone_name.rstrip('.')}.yaml")
                
                if os.path.exists(zone_file):
                    print(f"\n{'='*60}")
                    print(f"Validating zone: {zone_name}")
                    print(f"File: {zone_file}")
                    print('='*60)
                    
                    if not self.validate_octodns_zone(zone_file, verbose):
                        all_valid = False
                        print(f"❌ Validation failed for {zone_name}")
                    else:
                        print(f"✅ Validation passed for {zone_name}")
                else:
                    print(f"⚠️  Zone file not found: {zone_file}")
                    all_valid = False
            
            return all_valid
            
        except yaml.YAMLError as e:
            print(f"❌ YAML parsing error in OctoDNS config {config_path}: {e}")
            return False
        except Exception as e:
            print(f"❌ Error reading OctoDNS config {config_path}: {e}")
            return False
    
    def convert_to_bind(self, input_path, output_path=None, verbose=False):
        """Convert OctoDNS zone file to BIND format and save it"""
        try:
            with open(input_path, 'r') as f:
                zone_data = yaml.safe_load(f)
            
            zone_name = Path(input_path).stem + '.'
            bind_content = self.octodns_to_bind(zone_data, zone_name)
            
            if output_path:
                with open(output_path, 'w') as f:
                    f.write(bind_content)
                print(f"✅ Converted {input_path} to BIND format: {output_path}")
            else:
                print(bind_content)
            
            return True
            
        except Exception as e:
            print(f"❌ Error converting {input_path}: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description="Validate OctoDNS zone files using Azure DNS evaluator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate single zone file
  python octodns_validator.py zones/example.com.yaml
  
  # Validate all zones in OctoDNS config
  python octodns_validator.py octodns-config.yaml
  
  # Convert OctoDNS zone to BIND format
  python octodns_validator.py zones/example.com.yaml --convert-to-bind output.txt
  
  # Validate with verbose output
  python octodns_validator.py zones/example.com.yaml --verbose
        """
    )
    
    parser.add_argument('input_file', help='OctoDNS config file or zone file')
    parser.add_argument('--zones-dir', default='zones', 
                       help='Directory containing zone files (default: zones)')
    parser.add_argument('--evaluator-path', default='azure_dns_evaluator.py',
                       help='Path to azure_dns_evaluator.py script')
    parser.add_argument('--convert-to-bind', metavar='OUTPUT_FILE',
                       help='Convert zone file to BIND format and save to file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Check if azure_dns_evaluator.py exists
    if not os.path.exists(args.evaluator_path):
        print(f"❌ Azure DNS evaluator not found: {args.evaluator_path}")
        print("Make sure azure_dns_evaluator.py is in the current directory or specify the correct path with --evaluator-path")
        sys.exit(1)
    
    validator = OctoDNSValidator(args.evaluator_path)
    
    if args.convert_to_bind:
        # Convert mode
        success = validator.convert_to_bind(args.input_file, args.convert_to_bind, args.verbose)
    elif args.input_file.endswith(('-config.yaml', 'config.yaml')) or 'config' in args.input_file:
        # Treat as OctoDNS config file
        success = validator.validate_octodns_config(args.input_file, args.zones_dir, args.verbose)
    else:
        # Treat as individual zone file
        success = validator.validate_octodns_zone(args.input_file, args.verbose)
    
    if success:
        print(f"\n✅ All validations passed!")
    else:
        print(f"\n❌ Validation failed!")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
