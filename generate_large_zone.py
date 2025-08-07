#!/usr/bin/env python3
"""
Generate a large zone file for testing import size limits
"""

def generate_large_zone_file(filename, num_records=3500):
    """Generate a zone file with many records to test import limits"""
    
    with open(filename, 'w') as f:
        f.write("$ORIGIN large-zone.com.\n")
        f.write("$TTL 3600\n")
        f.write("\n")
        f.write("@       IN  SOA ns1.large-zone.com. admin.large-zone.com. (\n")
        f.write("            2023080601  ; Serial\n")
        f.write("            7200        ; Refresh\n")
        f.write("            3600        ; Retry\n")
        f.write("            604800      ; Expire\n")
        f.write("            86400       ; Minimum TTL\n")
        f.write("            )\n")
        f.write("\n")
        f.write("        IN  NS  ns1.large-zone.com.\n")
        f.write("        IN  NS  ns2.large-zone.com.\n")
        f.write("\n")
        
        # Generate many A records to exceed the record set limit
        for i in range(1, num_records + 1):
            f.write(f"host{i:04d}  IN  A   192.168.{(i-1)//255+1}.{(i-1)%255+1}\n")
            if i % 100 == 0:  # Add some comments to increase line count
                f.write(f"; Generated {i} records so far\n")

if __name__ == "__main__":
    generate_large_zone_file("examples/large_zone_test.txt", 3500)
    print("Generated large zone file with 3500+ records for testing")
