# Usage Examples

This document provides practical examples of using the Azure DNS Zone File Evaluator.

## Basic Usage

### Check a zone file for Azure DNS compatibility
```bash
python azure_dns_evaluator.py my_zone.txt
```

### Save report to a file
```bash
python azure_dns_evaluator.py my_zone.txt --output report.txt
```

### Generate JSON report
```bash
python azure_dns_evaluator.py my_zone.txt --format json --output report.json
```

### Verbose output (shows parsing details)
```bash
python azure_dns_evaluator.py my_zone.txt --verbose
```

## Sample Zone Files

### Valid Zone File Example
Create a file named `example_zone.txt`:
```dns
$ORIGIN example.com.
$TTL 3600

@       IN  SOA ns1.example.com. admin.example.com. (
            2023080601  ; Serial
            7200        ; Refresh
            3600        ; Retry
            604800      ; Expire
            86400       ; Minimum TTL
            )

        IN  NS  ns1.example.com.
        IN  NS  ns2.example.com.

        IN  A   192.168.1.1
www     IN  A   192.168.1.2
mail    IN  A   192.168.1.3

        IN  MX  10 mail.example.com.

blog    IN  CNAME   www.example.com.

        IN  TXT "v=spf1 include:_spf.google.com ~all"
```

Test it:
```bash
python azure_dns_evaluator.py example_zone.txt
```

## Common Issues and Solutions

### 1. Unsupported Record Types
**Problem**: Zone contains HINFO, RP, or other unsupported record types.
**Solution**: Remove or convert unsupported records to supported types.

### 2. TTL Values Out of Range
**Problem**: TTL values less than 1 or greater than 2,147,483,647.
**Solution**: Adjust TTL values to be within Azure DNS limits.

### 3. TXT Records Too Long
**Problem**: TXT record content exceeds 1,024 characters.
**Solution**: Split long TXT records into multiple records or reduce content.

### 4. TXT Record Set Too Large
**Problem**: Total size of all TXT records for the same name exceeds 4,096 bytes.
**Solution**: Reduce the total content across all TXT records for the same name, or split into different record names.

### 5. Domain Names Too Long
**Problem**: Domain names exceed 253 characters or labels exceed 63 characters.
**Solution**: Use shorter domain names or subdomain labels.

### 6. Record Set Too Large
**Problem**: Record set has too many records (more than 20 for most types, or more than 400 for TXT).
**Solution**: Split records across multiple record names or remove excess records.

### 7. Zone File Too Large for Import
**Problem**: Zone file exceeds import API limits (10,000 lines or 3,000 record sets).
**Solution**: Use the `--split` option to automatically split the zone file into smaller importable files.

```bash
# Automatically split large zone file
python azure_dns_evaluator.py large_zone.txt --split

# Split with verbose output to see validation results
python azure_dns_evaluator.py large_zone.txt --split --verbose

# Use even distribution method instead of subdomain grouping
python azure_dns_evaluator.py large_zone.txt --split --split-method even
```

After splitting, you'll get multiple files that need to be imported in sequence (see Batch Import section below).

```

## Batch Import for Split Zone Files

When your zone file has been split into multiple files using the `--split` option, you need to import them in the correct order. The evaluator creates files with a specific naming convention and structure.

### Understanding Split File Structure

After running `--split`, you'll get files like:
- `zone_split/zone_part_01.txt` - Main file with SOA and NS records
- `zone_split/zone_part_02.txt` - Additional records (subdomain group 1)
- `zone_split/zone_part_03.txt` - Additional records (subdomain group 2)
- ... and so on

### Batch Import Scripts

#### Azure CLI Batch Import Script
Create `batch_import_cli.sh`:
```bash
#!/bin/bash

RESOURCE_GROUP="myResourceGroup"
ZONE_NAME="example.com"
SPLIT_DIR="./zone_split"

# Function to import a zone file part
import_zone_part() {
    local file_path=$1
    local part_name=$(basename "$file_path" .txt)
    
    echo "Importing $part_name..."
    
    if az network dns zone import \
        --resource-group "$RESOURCE_GROUP" \
        --name "$ZONE_NAME" \
        --file-name "$file_path"; then
        echo "✓ Successfully imported $part_name"
        return 0
    else
        echo "✗ Failed to import $part_name"
        return 1
    fi
}

# Create DNS zone if it doesn't exist
echo "Creating DNS zone $ZONE_NAME..."
az network dns zone create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$ZONE_NAME" || true

# Import main file first (contains SOA and NS records)
main_file="$SPLIT_DIR/${ZONE_NAME%.*}_part_01.txt"
if [[ -f "$main_file" ]]; then
    echo "Importing main zone file..."
    if ! import_zone_part "$main_file"; then
        echo "Failed to import main zone file. Aborting."
        exit 1
    fi
else
    echo "Main zone file not found: $main_file"
    exit 1
fi

# Import additional files in order
for file in "$SPLIT_DIR"/*_part_*.txt; do
    # Skip the main file (already imported)
    if [[ "$file" != "$main_file" ]]; then
        if ! import_zone_part "$file"; then
            echo "Warning: Failed to import $file"
            # Continue with other files
        fi
        
        # Add delay between imports to avoid rate limiting
        sleep 2
    fi
done

echo "Batch import completed!"
```

#### PowerShell Batch Import Script
Create `batch_import_ps1.ps1`:
```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$ZoneName,
    
    [Parameter(Mandatory=$true)]
    [string]$SplitDirectory
)

function Import-ZonePart {
    param([string]$FilePath)
    
    $partName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    Write-Host "Importing $partName..." -ForegroundColor Yellow
    
    try {
        Import-AzDnsZone -ZoneName $ZoneName -ResourceGroupName $ResourceGroupName -ZoneFile $FilePath
        Write-Host "✓ Successfully imported $partName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ Failed to import $partName`: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Create DNS zone if it doesn't exist
Write-Host "Creating DNS zone $ZoneName..." -ForegroundColor Cyan
try {
    New-AzDnsZone -Name $ZoneName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
} catch {
    Write-Host "Zone may already exist or creation failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Find and import main file first
$mainFile = Get-ChildItem -Path $SplitDirectory -Filter "*_part_01.txt" | Select-Object -First 1

if ($mainFile) {
    Write-Host "Importing main zone file..." -ForegroundColor Cyan
    if (-not (Import-ZonePart -FilePath $mainFile.FullName)) {
        Write-Host "Failed to import main zone file. Aborting." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Main zone file not found in $SplitDirectory" -ForegroundColor Red
    exit 1
}

# Import additional files in order
$additionalFiles = Get-ChildItem -Path $SplitDirectory -Filter "*_part_*.txt" | 
                   Where-Object { $_.Name -ne $mainFile.Name } |
                   Sort-Object Name

foreach ($file in $additionalFiles) {
    if (-not (Import-ZonePart -FilePath $file.FullName)) {
        Write-Host "Warning: Failed to import $($file.Name)" -ForegroundColor Yellow
        # Continue with other files
    }
    
    # Add delay between imports to avoid rate limiting
    Start-Sleep -Seconds 2
}

Write-Host "Batch import completed!" -ForegroundColor Green
```

#### Python Batch Import Script
Create `batch_import.py`:
```python
#!/usr/bin/env python3
import os
import subprocess
import glob
import time
import argparse
from pathlib import Path

def run_az_command(command):
    """Run Azure CLI command and return success status"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Success: {command}")
            return True
        else:
            print(f"✗ Failed: {command}")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Exception running command: {e}")
        return False

def import_zone_files(resource_group, zone_name, split_directory):
    """Import split zone files in the correct order"""
    split_path = Path(split_directory)
    
    if not split_path.exists():
        print(f"Split directory not found: {split_directory}")
        return False
    
    # Create DNS zone
    print(f"Creating DNS zone {zone_name}...")
    create_zone_cmd = f"az network dns zone create --resource-group {resource_group} --name {zone_name}"
    run_az_command(create_zone_cmd)  # Don't fail if zone already exists
    
    # Find all split files
    split_files = sorted(glob.glob(str(split_path / "*_part_*.txt")))
    
    if not split_files:
        print(f"No split files found in {split_directory}")
        return False
    
    print(f"Found {len(split_files)} split files to import")
    
    # Import files in order
    success_count = 0
    for file_path in split_files:
        file_name = os.path.basename(file_path)
        part_number = file_name.split('_part_')[1].split('.')[0]
        
        print(f"
Importing part {part_number}: {file_name}")
        
        import_cmd = f'az network dns zone import --resource-group {resource_group} --name {zone_name} --file-name "{file_path}"'
        
        if run_az_command(import_cmd):
            success_count += 1
        else:
            print(f"Failed to import {file_name}")
            # Continue with next file rather than stopping
        
        # Rate limiting delay
        time.sleep(2)
    
    print(f"
Batch import completed: {success_count}/{len(split_files)} files imported successfully")
    return success_count == len(split_files)

def main():
    parser = argparse.ArgumentParser(description="Batch import split DNS zone files to Azure DNS")
    parser.add_argument("--resource-group", required=True, help="Azure resource group name")
    parser.add_argument("--zone-name", required=True, help="DNS zone name")
    parser.add_argument("--split-directory", required=True, help="Directory containing split zone files")
    parser.add_argument("--validate-first", action="store_true", help="Validate files before importing")
    
    args = parser.parse_args()
    
    # Optional validation step
    if args.validate_first:
        print("Validating split files first...")
        split_files = glob.glob(os.path.join(args.split_directory, "*_part_*.txt"))
        for file_path in split_files:
            print(f"Validating {os.path.basename(file_path)}...")
            result = subprocess.run([
                "python", "azure_dns_evaluator.py", file_path
            ], capture_output=True)
            
            if result.returncode != 0:
                print(f"✗ Validation failed for {file_path}")
                print("Fix validation errors before importing")
                return 1
            else:
                print(f"✓ Validation passed for {os.path.basename(file_path)}")
    
    # Import files
    success = import_zone_files(args.resource_group, args.zone_name, args.split_directory)
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
```

### Usage Examples

#### Using the Bash Script
```bash
# Make script executable
chmod +x batch_import_cli.sh

# Run batch import
./batch_import_cli.sh
```

#### Using the PowerShell Script
```powershell
# Run batch import
.\batch_import_ps1.ps1 -ResourceGroupName "myResourceGroup" -ZoneName "example.com" -SplitDirectory "./zone_split"
```

#### Using the Python Script
```bash
# Install Azure CLI first
# pip install azure-cli

# Run with validation
python batch_import.py --resource-group myResourceGroup --zone-name example.com --split-directory ./zone_split --validate-first

# Run without pre-validation
python batch_import.py --resource-group myResourceGroup --zone-name example.com --split-directory ./zone_split
```

### Automated Workflow Example

Complete workflow from splitting to importing:
```bash
#!/bin/bash

ZONE_FILE="large_zone.txt"
RESOURCE_GROUP="myResourceGroup"
ZONE_NAME="example.com"

# Step 1: Validate and split the large zone file
echo "Validating and splitting zone file..."
python azure_dns_evaluator.py "$ZONE_FILE" --split --verbose

# Step 2: Check if splitting was successful
if [ $? -eq 0 ]; then
    echo "Zone file successfully split"
    
    # Step 3: Batch import the split files
    echo "Starting batch import..."
    python batch_import.py \
        --resource-group "$RESOURCE_GROUP" \
        --zone-name "$ZONE_NAME" \
        --split-directory "./$(basename "$ZONE_FILE" .txt)_split" \
        --validate-first
    
    if [ $? -eq 0 ]; then
        echo "✓ All zone files imported successfully!"
    else
        echo "✗ Some imports failed. Check Azure DNS console for details."
    fi
else
    echo "✗ Zone file splitting failed. Check validation errors."
fi
```

### Best Practices for Batch Import

1. **Always validate first**: Use `--validate-first` flag to catch issues early
2. **Import main file first**: The _part_01.txt file contains SOA and NS records
3. **Handle failures gracefully**: Continue with remaining files if one fails
4. **Add delays**: Prevent rate limiting with small delays between imports
5. **Monitor progress**: Log each import attempt and result
6. **Verify results**: Check Azure DNS console after batch import
7. **Backup existing zones**: Always backup before large imports

## OctoDNS Integration

For teams using OctoDNS (DNS as Code), this tool provides seamless integration through the `octodns_validator.py` script.

### Basic OctoDNS Validation

```bash
# Validate a single OctoDNS zone file
python octodns_validator.py zones/example.com.yaml

# Validate with verbose output
python octodns_validator.py zones/example.com.yaml --verbose

# Convert OctoDNS zone to BIND format
python octodns_validator.py zones/example.com.yaml --convert-to-bind converted_zone.txt

# Validate an entire OctoDNS configuration
python octodns_validator.py octodns-config.yaml --zones-dir zones
```

### Installation for OctoDNS Support

```bash
# Install additional dependencies for OctoDNS validation
pip install PyYAML

# Optional: Install full OctoDNS if you want to use it for deployment
pip install octodns octodns-azure
```

## Popular DNS CI/CD Tools Integration

The Azure DNS evaluator can integrate with various popular DNS management and CI/CD tools. Here's a comprehensive overview:

### Supported Tools Summary

| Tool | Type | Language/Format | Azure Integration | Validation Support |
|------|------|----------------|-------------------|-------------------|
| **Azure CLI** | Direct API | Command Line | Native | ✅ Direct |
| **Terraform** | Infrastructure as Code | HCL | AzureRM Provider | ✅ Pre-deployment validation |
| **OctoDNS** | DNS as Code | YAML | Azure Provider | ✅ YAML to BIND conversion |
| **Pulumi** | Infrastructure as Code | Python/TypeScript/Go/C# | Azure Native | ✅ Pre-deployment validation |
| **DNSControl** | DNS as Code | JavaScript | Azure Provider | ✅ Generated zone validation |
| **External-DNS** | Kubernetes DNS | YAML Manifests | Azure Provider | ✅ Annotation-based validation |
| **PowerDNS** | DNS Server | API/JSON | Custom Integration | ✅ API export validation |
| **Route53** | Migration Tool | API Export | Migration Helper | ✅ Export and validate |
| **Cloudflare** | Migration Tool | API Export | Migration Helper | ✅ Export and validate |

### 1. Pulumi (Infrastructure as Code)

Pulumi is a modern Infrastructure as Code platform that supports multiple languages.

#### Pulumi with Python
```python
# pulumi_dns.py
import pulumi
import pulumi_azure_native as azure_native
import subprocess
import os

# Validate zone file before creating resources
def validate_zone_file(zone_file_path):
    """Validate zone file using Azure DNS evaluator"""
    result = subprocess.run([
        'python', 'azure_dns_evaluator.py', zone_file_path
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"Zone validation failed: {result.stderr}")
    
    print(f"✅ Zone validation passed for {zone_file_path}")
    return True

# Validate zone file
zone_file = "zones/example.com.txt"
validate_zone_file(zone_file)

# Create resource group
resource_group = azure_native.resources.ResourceGroup(
    "dns-rg",
    location="East US"
)

# Create DNS zone
dns_zone = azure_native.network.Zone(
    "example-com",
    location="Global",
    resource_group_name=resource_group.name,
    zone_name="example.com"
)

# Import zone file after creation
def import_zone_file():
    subprocess.run([
        'az', 'network', 'dns', 'zone', 'import',
        '--resource-group', resource_group.name,
        '--name', 'example.com',
        '--file-name', zone_file
    ])

# Export the name servers
pulumi.export("name_servers", dns_zone.name_servers)
```

#### GitHub Actions with Pulumi
```yaml
name: DNS with Pulumi

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  dns-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pulumi pulumi-azure-native
          
      - name: Validate DNS zones
        run: |
          for zone_file in zones/*.txt; do
            python azure_dns_evaluator.py "$zone_file"
          done
          
      - name: Pulumi Preview
        uses: pulumi/actions@v4
        with:
          command: preview
          stack-name: dev
        env:
          PULUMI_ACCESS_TOKEN: ${{ secrets.PULUMI_ACCESS_TOKEN }}
          ARM_CLIENT_ID: ${{ secrets.ARM_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.ARM_CLIENT_SECRET }}
          ARM_TENANT_ID: ${{ secrets.ARM_TENANT_ID }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.ARM_SUBSCRIPTION_ID }}
          
      - name: Pulumi Up
        if: github.ref == 'refs/heads/main'
        uses: pulumi/actions@v4
        with:
          command: up
          stack-name: dev
        env:
          PULUMI_ACCESS_TOKEN: ${{ secrets.PULUMI_ACCESS_TOKEN }}
          ARM_CLIENT_ID: ${{ secrets.ARM_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.ARM_CLIENT_SECRET }}
          ARM_TENANT_ID: ${{ secrets.ARM_TENANT_ID }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.ARM_SUBSCRIPTION_ID }}
```

### 2. DNSControl (Stack Exchange)

DNSControl is a powerful DNS-as-code tool from Stack Exchange.

#### DNSControl Configuration
```javascript
// dnsconfig.js
var REG_NONE = NewRegistrar("none");
var DSP_AZURE = NewDnsProvider("azure");

// Pre-validation function (custom implementation)
function validateZoneFile(zoneName) {
    // This would need to be implemented as a custom validation step
    console.log("Validating zone:", zoneName);
}

D("example.com", REG_NONE, DnsProvider(DSP_AZURE),
    validateZoneFile("example.com"),
    
    // SOA record
    SOA("ns1.example.com.", "admin.example.com.", 3600),
    
    // NS records
    NS("ns1.example.com."),
    NS("ns2.example.com."),
    
    // A records
    A("@", "192.168.1.1"),
    A("www", "192.168.1.2"),
    A("mail", "192.168.1.3"),
    
    // MX record
    MX("@", 10, "mail.example.com."),
    
    // CNAME record
    CNAME("blog", "www.example.com."),
    
    // TXT record
    TXT("@", "v=spf1 include:_spf.google.com ~all")
);
```

#### GitHub Actions with DNSControl
```yaml
name: DNS with DNSControl

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  dns-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python for validation
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install DNS evaluator dependencies
        run: pip install -r requirements.txt
        
      - name: Convert DNSControl to BIND and validate
        run: |
          # Install DNSControl
          curl -L https://github.com/StackExchange/dnscontrol/releases/latest/download/dnscontrol-Linux -o dnscontrol
          chmod +x dnscontrol
          
          # Generate zone files from DNSControl config
          ./dnscontrol print dnsconfig.js
          
          # Validate generated zone files
          for zone_file in zones/*.zone; do
            if [ -f "$zone_file" ]; then
              echo "Validating $zone_file..."
              python azure_dns_evaluator.py "$zone_file"
            fi
          done
          
      - name: DNSControl Preview
        run: |
          ./dnscontrol preview dnsconfig.js
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          
      - name: DNSControl Push
        if: github.ref == 'refs/heads/main'
        run: |
          ./dnscontrol push dnsconfig.js
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

### 3. External-DNS (Kubernetes)

External-DNS automatically manages DNS records for Kubernetes services.

#### External-DNS with Validation
```yaml
# external-dns-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  namespace: external-dns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: external-dns
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
      - name: external-dns
        image: k8s.gcr.io/external-dns/external-dns:v0.13.1
        args:
        - --source=service
        - --source=ingress
        - --domain-filter=example.com
        - --provider=azure
        - --azure-resource-group=dns-zones-rg
        - --azure-subscription-id=$(AZURE_SUBSCRIPTION_ID)
        - --txt-owner-id=external-dns
        - --interval=30s
        - --log-level=info
        env:
        - name: AZURE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: azure-config-file
              key: client-id
        - name: AZURE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: azure-config-file
              key: client-secret
        - name: AZURE_TENANT_ID
          valueFrom:
            secretKeyRef:
              name: azure-config-file
              key: tenant-id
        - name: AZURE_SUBSCRIPTION_ID
          valueFrom:
            secretKeyRef:
              name: azure-config-file
              key: subscription-id

---
# Service with DNS validation annotation
apiVersion: v1
kind: Service
metadata:
  name: web-service
  annotations:
    external-dns.alpha.kubernetes.io/hostname: web.example.com
    # Custom annotation for validation (requires custom controller)
    dns.azure.com/validate-with: "azure-dns-evaluator"
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: web-app
```

#### GitOps with ArgoCD and External-DNS
```yaml
# .github/workflows/gitops-dns.yml
name: GitOps DNS Validation

on:
  push:
    paths:
    - 'k8s/**'
    - 'dns/**'

jobs:
  validate-k8s-dns:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: pip install -r requirements.txt
        
      - name: Extract DNS records from Kubernetes manifests
        run: |
          # Create a script to extract DNS annotations
          cat > extract_dns.py << 'EOF'
          import yaml
          import os
          import re
          
          def extract_dns_from_k8s_manifests(directory):
              dns_records = []
              
              for root, dirs, files in os.walk(directory):
                  for file in files:
                      if file.endswith(('.yaml', '.yml')):
                          with open(os.path.join(root, file), 'r') as f:
                              try:
                                  docs = yaml.safe_load_all(f)
                                  for doc in docs:
                                      if doc and 'metadata' in doc:
                                          annotations = doc.get('metadata', {}).get('annotations', {})
                                          for key, value in annotations.items():
                                              if 'external-dns' in key and 'hostname' in key:
                                                  dns_records.append({
                                                      'hostname': value,
                                                      'type': 'A',  # Default assumption
                                                      'file': file
                                                  })
                              except yaml.YAMLError:
                                  continue
              
              return dns_records
          
          # Extract DNS records
          records = extract_dns_from_k8s_manifests('k8s')
          
          # Generate a mock zone file for validation
          zone_content = [
              "$ORIGIN example.com.",
              "$TTL 3600",
              "",
              "@    IN    SOA    ns1.example.com. admin.example.com. (",
              "                2023080601    ; Serial",
              "                7200          ; Refresh",
              "                3600          ; Retry", 
              "                604800        ; Expire",
              "                86400         ; Minimum",
              "                )",
              "",
              "     IN    NS     ns1.example.com.",
              "     IN    NS     ns2.example.com.",
              ""
          ]
          
          for record in records:
              hostname = record['hostname'].replace('.example.com', '')
              zone_content.append(f"{hostname}    3600    IN    A    203.0.113.1")
          
          with open('k8s_generated_zone.txt', 'w') as f:
              f.write('\n'.join(zone_content))
          
          print(f"Generated zone file with {len(records)} DNS records")
          EOF
          
          python extract_dns.py
          
      - name: Validate extracted DNS records
        run: |
          if [ -f "k8s_generated_zone.txt" ]; then
            echo "Validating DNS records extracted from Kubernetes manifests..."
            python azure_dns_evaluator.py k8s_generated_zone.txt
          fi
          
      - name: Validate existing zone files
        run: |
          for zone_file in dns/*.txt; do
            if [ -f "$zone_file" ]; then
              echo "Validating $zone_file..."
              python azure_dns_evaluator.py "$zone_file"
            fi
          done
```

### 4. PowerDNS with Automation

PowerDNS with API-driven automation for CI/CD.

#### PowerDNS API Integration
```python
# powerdns_validator.py
import requests
import json
import subprocess
import tempfile

class PowerDNSValidator:
    def __init__(self, api_url, api_key, azure_evaluator_path="azure_dns_evaluator.py"):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.evaluator_path = azure_evaluator_path
        self.headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
    
    def get_zone_records(self, zone_name):
        """Fetch zone records from PowerDNS API"""
        response = requests.get(
            f"{self.api_url}/api/v1/servers/localhost/zones/{zone_name}",
            headers=self.headers
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch zone: {response.status_code}")
    
    def convert_to_bind(self, zone_data):
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
    
    def validate_zone(self, zone_name):
        """Validate a PowerDNS zone against Azure DNS requirements"""
        try:
            # Fetch zone data
            zone_data = self.get_zone_records(zone_name)
            
            # Convert to BIND format
            bind_content = self.convert_to_bind(zone_data)
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(bind_content)
                temp_file_path = temp_file.name
            
            try:
                # Validate with Azure DNS evaluator
                result = subprocess.run([
                    'python', self.evaluator_path, temp_file_path
                ], capture_output=True, text=True)
                
                print(f"Validation results for PowerDNS zone {zone_name}:")
                print(result.stdout)
                
                if result.stderr:
                    print("Errors:")
                    print(result.stderr)
                
                return result.returncode == 0
                
            finally:
                import os
                os.unlink(temp_file_path)
                
        except Exception as e:
            print(f"Error validating PowerDNS zone {zone_name}: {e}")
            return False

# Usage example
if __name__ == "__main__":
    validator = PowerDNSValidator(
        api_url="http://powerdns.example.com:8081",
        api_key="your-api-key"
    )
    
    success = validator.validate_zone("example.com.")
    print("Validation passed!" if success else "Validation failed!")
```

### 5. Route53 Migration Tools

For teams migrating from AWS Route53 to Azure DNS.

#### Route53 to Azure DNS Migration
```python
# route53_to_azure_validator.py
import boto3
import subprocess
import tempfile
import os

class Route53ToAzureValidator:
    def __init__(self, aws_access_key, aws_secret_key, region='us-east-1'):
        self.route53 = boto3.client(
            'route53',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
    
    def export_route53_zone(self, hosted_zone_id):
        """Export Route53 zone to BIND format"""
        # Get hosted zone info
        zone_info = self.route53.get_hosted_zone(Id=hosted_zone_id)
        zone_name = zone_info['HostedZone']['Name']
        
        # Get all records
        paginator = self.route53.get_paginator('list_resource_record_sets')
        page_iterator = paginator.paginate(HostedZoneId=hosted_zone_id)
        
        bind_lines = [
            f"$ORIGIN {zone_name}",
            "$TTL 3600",
            ""
        ]
        
        for page in page_iterator:
            for record_set in page['ResourceRecordSets']:
                name = record_set['Name'].replace(zone_name, "").rstrip('.')
                if not name:
                    name = "@"
                
                record_type = record_set['Type']
                ttl = record_set.get('TTL', 3600)
                
                # Skip Route53 specific records that aren't supported in Azure DNS
                if record_type in ['NS'] and name == '@':
                    # Convert Route53 NS records to Azure-compatible format
                    for resource_record in record_set.get('ResourceRecords', []):
                        value = resource_record['Value']
                        bind_lines.append(f"{name}    {ttl}    IN    {record_type}    {value}")
                elif record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'PTR']:
                    for resource_record in record_set.get('ResourceRecords', []):
                        value = resource_record['Value']
                        
                        if record_type == 'TXT':
                            # Ensure TXT records are properly quoted
                            if not value.startswith('"'):
                                value = f'"{value}"'
                        elif record_type == 'SOA':
                            # Parse SOA format
                            parts = value.split()
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
                                continue
                        
                        bind_lines.append(f"{name}    {ttl}    IN    {record_type}    {value}")
        
        return "\n".join(bind_lines)
    
    def validate_migrated_zone(self, hosted_zone_id):
        """Export Route53 zone and validate for Azure DNS compatibility"""
        try:
            # Export to BIND format
            bind_content = self.export_route53_zone(hosted_zone_id)
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(bind_content)
                temp_file_path = temp_file.name
            
            try:
                # Validate with Azure DNS evaluator
                result = subprocess.run([
                    'python', 'azure_dns_evaluator.py', temp_file_path
                ], capture_output=True, text=True)
                
                print(f"Validation results for Route53 zone {hosted_zone_id}:")
                print(result.stdout)
                
                if result.stderr:
                    print("Errors:")
                    print(result.stderr)
                
                return result.returncode == 0
                
            finally:
                os.unlink(temp_file_path)
                
        except Exception as e:
            print(f"Error validating Route53 zone {hosted_zone_id}: {e}")
            return False

# GitHub Actions for Route53 migration
# .github/workflows/route53-migration.yml
migration_workflow = '''
name: Route53 to Azure DNS Migration

on:
  workflow_dispatch:
    inputs:
      hosted_zone_id:
        description: 'Route53 Hosted Zone ID'
        required: true
        type: string

jobs:
  migrate-dns:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install boto3
          
      - name: Export and validate Route53 zone
        run: |
          python route53_to_azure_validator.py ${{ github.event.inputs.hosted_zone_id }}
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          
      - name: Create Azure DNS zone if validation passes
        run: |
          # Zone creation and import logic here
          echo "Zone validation passed, proceeding with migration..."
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
'''
```

### 6. Cloudflare Migration Tools

For teams migrating from Cloudflare to Azure DNS.

#### Cloudflare API Integration
```python
# cloudflare_to_azure_validator.py
import requests
import subprocess
import tempfile
import os

class CloudflareToAzureValidator:
    def __init__(self, api_token, email=None):
        self.api_token = api_token
        self.email = email
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
    
    def get_zone_records(self, zone_id):
        """Fetch all DNS records for a Cloudflare zone"""
        records = []
        page = 1
        
        while True:
            response = requests.get(
                f"{self.base_url}/zones/{zone_id}/dns_records",
                headers=self.headers,
                params={'page': page, 'per_page': 100}
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to fetch records: {response.status_code}")
            
            data = response.json()
            records.extend(data['result'])
            
            if page >= data['result_info']['total_pages']:
                break
            page += 1
        
        return records
    
    def convert_to_bind(self, zone_name, records):
        """Convert Cloudflare records to BIND format"""
        bind_lines = [
            f"$ORIGIN {zone_name}",
            "$TTL 3600",
            ""
        ]
        
        # Sort records - SOA first, then NS, then others
        sorted_records = sorted(records, key=lambda x: (
            0 if x['type'] == 'SOA' else 1 if x['type'] == 'NS' else 2,
            x['name']
        ))
        
        for record in sorted_records:
            name = record['name'].replace(f".{zone_name.rstrip('.')}", "")
            if name == zone_name.rstrip('.'):
                name = "@"
            
            record_type = record['type']
            ttl = record.get('ttl', 3600)
            content = record['content']
            
            # Handle Cloudflare-specific record types
            if record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'PTR']:
                if record_type == 'TXT':
                    # Ensure TXT records are properly quoted
                    if not content.startswith('"'):
                        content = f'"{content}"'
                elif record_type == 'MX':
                    # Cloudflare MX format: "priority content"
                    priority = record.get('priority', 10)
                    content = f"{priority} {content}"
                elif record_type == 'SRV':
                    # Cloudflare SRV format
                    priority = record.get('priority', 0)
                    weight = record.get('data', {}).get('weight', 0)
                    port = record.get('data', {}).get('port', 80)
                    target = record.get('data', {}).get('target', content)
                    content = f"{priority} {weight} {port} {target}"
                
                bind_lines.append(f"{name}    {ttl}    IN    {record_type}    {content}")
        
        return "\n".join(bind_lines)
    
    def validate_zone(self, zone_id):
        """Validate a Cloudflare zone for Azure DNS compatibility"""
        try:
            # Get zone info
            zone_response = requests.get(
                f"{self.base_url}/zones/{zone_id}",
                headers=self.headers
            )
            
            if zone_response.status_code != 200:
                raise Exception(f"Failed to fetch zone info: {zone_response.status_code}")
            
            zone_name = zone_response.json()['result']['name']
            
            # Get all records
            records = self.get_zone_records(zone_id)
            
            # Convert to BIND format
            bind_content = self.convert_to_bind(zone_name, records)
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(bind_content)
                temp_file_path = temp_file.name
            
            try:
                # Validate with Azure DNS evaluator
                result = subprocess.run([
                    'python', 'azure_dns_evaluator.py', temp_file_path
                ], capture_output=True, text=True)
                
                print(f"Validation results for Cloudflare zone {zone_name}:")
                print(result.stdout)
                
                if result.stderr:
                    print("Errors:")
                    print(result.stderr)
                
                return result.returncode == 0
                
            finally:
                os.unlink(temp_file_path)
                
        except Exception as e:
            print(f"Error validating Cloudflare zone {zone_id}: {e}")
            return False
```

These additional integrations provide comprehensive support for the most popular DNS CI/CD tools in the industry:

1. **Pulumi** - Modern IaC with multiple language support
2. **DNSControl** - Stack Exchange's DNS-as-code solution
3. **External-DNS** - Kubernetes-native DNS management
4. **PowerDNS** - API-driven DNS server with automation
5. **Route53 Migration** - AWS to Azure migration tools
6. **Cloudflare Migration** - Cloudflare to Azure migration tools

Each integration includes validation steps using the Azure DNS evaluator to ensure compatibility before deployment.

### OctoDNS Configuration Examples

### GitHub Actions Example (Azure CLI)
```yaml
name: Validate and Deploy DNS Zone Files

on: [push, pull_request]

jobs:
  validate-dns:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Validate zone files
        run: |
          for zone_file in zones/*.txt; do
            python azure_dns_evaluator.py "$zone_file"
          done
      - name: Azure Login
        if: github.ref == 'refs/heads/main'
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - name: Deploy to Azure DNS
        if: github.ref == 'refs/heads/main'
        run: |
          for zone_file in zones/*.txt; do
            zone_name=$(basename "$zone_file" .txt)
            az network dns zone import \
              --resource-group ${{ secrets.RESOURCE_GROUP }} \
              --name "$zone_name" \
              --file-name "$zone_file"
          done
```

### GitHub Actions Example (Terraform)
```yaml
name: Validate DNS and Deploy with Terraform

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  validate-dns:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
          
      - name: Install DNS evaluator dependencies
        run: |
          pip install -r requirements.txt
          
      - name: Validate zone files
        run: |
          echo "Validating DNS zone files..."
          validation_failed=false
          for zone_file in zones/*.txt; do
            if ! python azure_dns_evaluator.py "$zone_file"; then
              echo "❌ Validation failed for $zone_file"
              validation_failed=true
            else
              echo "✅ Validation passed for $zone_file"
            fi
          done
          
          if [ "$validation_failed" = true ]; then
            echo "DNS validation failed. Fix errors before proceeding."
            exit 1
          fi
          
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: 1.5.0
          
      - name: Terraform Format Check
        run: terraform fmt -check -recursive
        
      - name: Terraform Init
        run: terraform init
        
      - name: Terraform Plan
        env:
          ARM_CLIENT_ID: ${{ secrets.ARM_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.ARM_CLIENT_SECRET }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.ARM_SUBSCRIPTION_ID }}
          ARM_TENANT_ID: ${{ secrets.ARM_TENANT_ID }}
        run: terraform plan -out=tfplan
        
      - name: Terraform Apply
        if: github.ref == 'refs/heads/main'
        env:
          ARM_CLIENT_ID: ${{ secrets.ARM_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.ARM_CLIENT_SECRET }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.ARM_SUBSCRIPTION_ID }}
          ARM_TENANT_ID: ${{ secrets.ARM_TENANT_ID }}
        run: terraform apply -auto-approve tfplan
```

### Azure DevOps Pipeline Example (Azure CLI)
```yaml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.8'

- script: |
    pip install -r requirements.txt
  displayName: 'Install dependencies'

- script: |
    for zone_file in zones/*.txt; do
      python azure_dns_evaluator.py "$zone_file"
    done
  displayName: 'Validate DNS zone files'

- task: AzureCLI@2
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  inputs:
    azureSubscription: 'MyAzureServiceConnection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      for zone_file in zones/*.txt; do
        zone_name=$(basename "$zone_file" .txt)
        az network dns zone import \
          --resource-group $(RESOURCE_GROUP) \
          --name "$zone_name" \
          --file-name "$zone_file"
      done
  displayName: 'Deploy to Azure DNS'
```

### Azure DevOps Pipeline Example (Terraform)
```yaml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
  terraformVersion: '1.5.0'

stages:
- stage: Validate
  displayName: 'Validate DNS Zone Files'
  jobs:
  - job: ValidateDNS
    displayName: 'DNS Validation'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.8'
        
    - script: |
        pip install -r requirements.txt
      displayName: 'Install DNS evaluator dependencies'
      
    - script: |
        echo "Validating DNS zone files..."
        validation_failed=false
        for zone_file in zones/*.txt; do
          if ! python azure_dns_evaluator.py "$zone_file"; then
            echo "❌ Validation failed for $zone_file"
            validation_failed=true
          else
            echo "✅ Validation passed for $zone_file"
          fi
        done
        
        if [ "$validation_failed" = true ]; then
          echo "DNS validation failed. Fix errors before proceeding."
          exit 1
        fi
      displayName: 'Validate DNS zone files'

- stage: Deploy
  displayName: 'Deploy Infrastructure'
  dependsOn: Validate
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - job: TerraformDeploy
    displayName: 'Terraform Deploy'
    steps:
    - task: TerraformInstaller@0
      inputs:
        terraformVersion: $(terraformVersion)
        
    - task: TerraformTaskV4@4
      inputs:
        provider: 'azurerm'
        command: 'init'
        backendServiceArm: 'MyAzureServiceConnection'
        backendAzureRmResourceGroupName: 'terraform-state-rg'
        backendAzureRmStorageAccountName: 'terraformstatestorage'
        backendAzureRmContainerName: 'terraform-state'
        backendAzureRmKey: 'dns.terraform.tfstate'
        
    - task: TerraformTaskV4@4
      inputs:
        provider: 'azurerm'
        command: 'plan'
        environmentServiceNameAzureRM: 'MyAzureServiceConnection'
        
    - task: TerraformTaskV4@4
      inputs:
        provider: 'azurerm'
        command: 'apply'
        environmentServiceNameAzureRM: 'MyAzureServiceConnection'
```

### OctoDNS Configuration Examples

#### Basic OctoDNS Setup with Zone Validation
```yaml
# octodns-config.yaml
providers:
  azure:
    class: octodns_azure.AzureProvider
    client_id: env/AZURE_CLIENT_ID
    key: env/AZURE_CLIENT_SECRET
    tenant_id: env/AZURE_TENANT_ID
    subscription_id: env/AZURE_SUBSCRIPTION_ID
    resource_group: my-dns-zones

zones:
  example.com.:
    sources:
      - config
    targets:
      - azure

# Pre-validation hook (custom script)
pre_hooks:
  - name: validate_zone_files
    command: python azure_dns_evaluator.py zones/example.com.yaml
```

#### OctoDNS Zone Configuration with Validation
```yaml
# zones/example.com.yaml
---
'':
  - type: A
    value: 192.168.1.1
    ttl: 3600
  - type: NS
    values:
      - ns1.example.com.
      - ns2.example.com.
    ttl: 86400
  - type: SOA
    value:
      mname: ns1.example.com.
      rname: admin.example.com.
      serial: 2023080601
      refresh: 7200
      retry: 3600
      expire: 604800
      minimum: 86400
    ttl: 86400
  - type: MX
    value:
      exchange: mail.example.com.
      preference: 10
    ttl: 3600

www:
  - type: A
    value: 192.168.1.2
    ttl: 3600

mail:
  - type: A
    value: 192.168.1.3
    ttl: 3600

blog:
  - type: CNAME
    value: www.example.com.
    ttl: 3600
```

#### GitHub Actions with OctoDNS
```yaml
name: DNS Management with OctoDNS

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  validate-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install octodns octodns-azure
          
      - name: Convert OctoDNS config to BIND format and validate
        run: |
          echo "Converting OctoDNS zones to BIND format for validation..."
          
          # Create conversion script
          cat > convert_octodns.py << 'EOF'
          #!/usr/bin/env python3
          import yaml
          import os
          
          def octodns_to_bind(zone_file, zone_name):
              """Convert OctoDNS YAML to BIND format for validation"""
              with open(zone_file, 'r') as f:
                  zone_data = yaml.safe_load(f)
              
              bind_content = [
                  f"$ORIGIN {zone_name}",
                  "$TTL 3600",
                  ""
              ]
              
              # Process records
              for name, records in zone_data.items():
                  if name == '':
                      name = '@'
                  
                  for record in records:
                      record_type = record['type']
                      ttl = record.get('ttl', 3600)
                      
                      if record_type == 'SOA':
                          soa = record['value']
                          bind_content.append(f"{name}    {ttl}    IN    SOA    {soa['mname']} {soa['rname']} (")
                          bind_content.append(f"                {soa['serial']}    ; Serial")
                          bind_content.append(f"                {soa['refresh']}        ; Refresh")
                          bind_content.append(f"                {soa['retry']}        ; Retry")
                          bind_content.append(f"                {soa['expire']}      ; Expire")
                          bind_content.append(f"                {soa['minimum']}       ; Minimum")
                          bind_content.append("                )")
                      elif record_type == 'NS':
                          if 'values' in record:
                              for value in record['values']:
                                  bind_content.append(f"{name}    {ttl}    IN    NS    {value}")
                          else:
                              bind_content.append(f"{name}    {ttl}    IN    NS    {record['value']}")
                      elif record_type == 'MX':
                          mx = record['value']
                          bind_content.append(f"{name}    {ttl}    IN    MX    {mx['preference']} {mx['exchange']}")
                      elif record_type == 'CNAME':
                          bind_content.append(f"{name}    {ttl}    IN    CNAME    {record['value']}")
                      elif record_type in ['A', 'AAAA', 'TXT']:
                          if 'values' in record:
                              for value in record['values']:
                                  if record_type == 'TXT':
                                      bind_content.append(f"{name}    {ttl}    IN    TXT    \"{value}\"")
                                  else:
                                      bind_content.append(f"{name}    {ttl}    IN    {record_type}    {value}")
                          else:
                              value = record['value']
                              if record_type == 'TXT':
                                  bind_content.append(f"{name}    {ttl}    IN    TXT    \"{value}\"")
                              else:
                                  bind_content.append(f"{name}    {ttl}    IN    {record_type}    {value}")
              
              return "\n".join(bind_content)
          
          # Convert all zone files
          for zone_file in os.listdir('zones'):
              if zone_file.endswith('.yaml'):
                  zone_name = zone_file.replace('.yaml', '.')
                  bind_content = octodns_to_bind(f'zones/{zone_file}', zone_name)
                  
                  bind_file = f'temp_{zone_file.replace(".yaml", ".txt")}'
                  with open(bind_file, 'w') as f:
                      f.write(bind_content)
                  
                  print(f"Converted {zone_file} to {bind_file}")
          EOF
          
          python convert_octodns.py
          
      - name: Validate converted zone files
        run: |
          echo "Validating converted BIND zone files..."
          validation_failed=false
          
          for bind_file in temp_*.txt; do
            if [ -f "$bind_file" ]; then
              echo "Validating $bind_file..."
              if ! python azure_dns_evaluator.py "$bind_file"; then
                echo "❌ Validation failed for $bind_file"
                validation_failed=true
              else
                echo "✅ Validation passed for $bind_file"
              fi
            fi
          done
          
          # Cleanup temp files
          rm -f temp_*.txt
          
          if [ "$validation_failed" = true ]; then
            echo "DNS validation failed. Fix errors before proceeding."
            exit 1
          fi
          
      - name: OctoDNS Plan
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
        run: |
          octodns-sync --config-file octodns-config.yaml --plan
          
      - name: OctoDNS Apply
        if: github.ref == 'refs/heads/main'
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
        run: |
          octodns-sync --config-file octodns-config.yaml
```

#### Azure DevOps with OctoDNS
```yaml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: dns-secrets  # Variable group containing Azure credentials

stages:
- stage: Validate
  displayName: 'Validate DNS Configuration'
  jobs:
  - job: ValidateDNS
    displayName: 'DNS Validation'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.8'
        
    - script: |
        pip install -r requirements.txt
        pip install octodns octodns-azure pyyaml
      displayName: 'Install dependencies'
      
    - script: |
        echo "Converting OctoDNS zones to BIND format for validation..."
        
        # Create conversion script (same as above)
        cat > convert_octodns.py << 'EOF'
        # ... (same conversion script as in GitHub Actions example)
        EOF
        
        python convert_octodns.py
      displayName: 'Convert OctoDNS to BIND format'
      
    - script: |
        echo "Validating converted BIND zone files..."
        validation_failed=false
        
        for bind_file in temp_*.txt; do
          if [ -f "$bind_file" ]; then
            echo "Validating $bind_file..."
            if ! python azure_dns_evaluator.py "$bind_file"; then
              echo "❌ Validation failed for $bind_file"
              validation_failed=true
            else
              echo "✅ Validation passed for $bind_file"
            fi
          fi
        done
        
        if [ "$validation_failed" = true ]; then
          echo "DNS validation failed. Fix errors before proceeding."
          exit 1
        fi
      displayName: 'Validate DNS zone files'

- stage: Deploy
  displayName: 'Deploy DNS Changes'
  dependsOn: Validate
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - job: OctoDNSDeploy
    displayName: 'OctoDNS Deploy'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.8'
        
    - script: |
        pip install octodns octodns-azure
      displayName: 'Install OctoDNS'
      
    - script: |
        echo "Planning DNS changes..."
        octodns-sync --config-file octodns-config.yaml --plan
      displayName: 'OctoDNS Plan'
      env:
        AZURE_CLIENT_ID: $(AZURE_CLIENT_ID)
        AZURE_CLIENT_SECRET: $(AZURE_CLIENT_SECRET)
        AZURE_TENANT_ID: $(AZURE_TENANT_ID)
        AZURE_SUBSCRIPTION_ID: $(AZURE_SUBSCRIPTION_ID)
        
    - script: |
        echo "Applying DNS changes..."
        octodns-sync --config-file octodns-config.yaml
      displayName: 'OctoDNS Apply'
      env:
        AZURE_CLIENT_ID: $(AZURE_CLIENT_ID)
        AZURE_CLIENT_SECRET: $(AZURE_CLIENT_SECRET)
        AZURE_TENANT_ID: $(AZURE_TENANT_ID)
        AZURE_SUBSCRIPTION_ID: $(AZURE_SUBSCRIPTION_ID)
```

#### OctoDNS Validation Integration Script
```python
# octodns_validator.py
#!/usr/bin/env python3
"""
OctoDNS to Azure DNS evaluator integration
Converts OctoDNS YAML configs to BIND format and validates them
"""

import yaml
import os
import sys
import subprocess
import tempfile
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
                        bind_lines.append(f"{display_name}    {ttl}    IN    NS    {value}")
                elif record_type == 'MX':
                    mx = record['value']
                    bind_lines.append(f"{display_name}    {ttl}    IN    MX    {mx['preference']} {mx['exchange']}")
                elif record_type == 'CNAME':
                    bind_lines.append(f"{display_name}    {ttl}    IN    CNAME    {record['value']}")
                elif record_type in ['A', 'AAAA']:
                    values = record.get('values', [record.get('value')])
                    for value in values:
                        bind_lines.append(f"{display_name}    {ttl}    IN    {record_type}    {value}")
                elif record_type == 'TXT':
                    values = record.get('values', [record.get('value')])
                    for value in values:
                        # Ensure TXT values are properly quoted
                        quoted_value = f'"{value}"' if not (value.startswith('"') and value.endswith('"')) else value
                        bind_lines.append(f"{display_name}    {ttl}    IN    TXT    {quoted_value}")
                elif record_type == 'SRV':
                    srv = record['value']
                    bind_lines.append(f"{display_name}    {ttl}    IN    SRV    {srv['priority']} {srv['weight']} {srv['port']} {srv['target']}")
                elif record_type == 'CAA':
                    caa = record['value']
                    bind_lines.append(f"{display_name}    {ttl}    IN    CAA    {caa['flags']} {caa['tag']} \"{caa['value']}\"")
        
        return "\n".join(bind_lines)
    
    def validate_octodns_zone(self, zone_file_path):
        """Validate an OctoDNS zone file by converting to BIND and using azure_dns_evaluator"""
        try:
            with open(zone_file_path, 'r') as f:
                zone_data = yaml.safe_load(f)
            
            zone_name = Path(zone_file_path).stem + '.'
            bind_content = self.octodns_to_bind(zone_data, zone_name)
            
            # Create temporary BIND file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(bind_content)
                temp_file_path = temp_file.name
            
            try:
                # Run azure_dns_evaluator on the temporary BIND file
                result = subprocess.run([
                    'python', self.evaluator_path, temp_file_path
                ], capture_output=True, text=True)
                
                print(f"Validation results for {zone_file_path}:")
                print(result.stdout)
                
                if result.stderr:
                    print("Errors:")
                    print(result.stderr)
                
                return result.returncode == 0
                
            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)
                
        except Exception as e:
            print(f"Error validating {zone_file_path}: {e}")
            return False
    
    def validate_octodns_config(self, config_path, zones_dir="zones"):
        """Validate all zones referenced in an OctoDNS config"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            zones = config.get('zones', {})
            all_valid = True
            
            for zone_name in zones.keys():
                zone_file = os.path.join(zones_dir, f"{zone_name.rstrip('.')}.yaml")
                
                if os.path.exists(zone_file):
                    print(f"\n{'='*50}")
                    print(f"Validating zone: {zone_name}")
                    print(f"File: {zone_file}")
                    print('='*50)
                    
                    if not self.validate_octodns_zone(zone_file):
                        all_valid = False
                        print(f"❌ Validation failed for {zone_name}")
                    else:
                        print(f"✅ Validation passed for {zone_name}")
                else:
                    print(f"⚠️  Zone file not found: {zone_file}")
                    all_valid = False
            
            return all_valid
            
        except Exception as e:
            print(f"Error reading OctoDNS config {config_path}: {e}")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python octodns_validator.py <octodns-config.yaml>")
        print("  python octodns_validator.py <zone-file.yaml>")
        sys.exit(1)
    
    input_path = sys.argv[1]
    validator = OctoDNSValidator()
    
    if input_path.endswith('-config.yaml') or 'config' in input_path:
        # Treat as OctoDNS config file
        success = validator.validate_octodns_config(input_path)
    else:
        # Treat as individual zone file
        success = validator.validate_octodns_zone(input_path)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

### Terraform Configuration Examples

#### Basic DNS Zone with File Import
```hcl
# terraform/main.tf
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "dns_rg" {
  name     = var.resource_group_name
  location = var.location
}

# DNS Zone
resource "azurerm_dns_zone" "main" {
  name                = var.zone_name
  resource_group_name = azurerm_resource_group.dns_rg.name
}

# Local exec to validate zone file before apply
resource "null_resource" "validate_zone_file" {
  triggers = {
    zone_file_hash = filemd5(var.zone_file_path)
  }

  provisioner "local-exec" {
    command = "python ${path.module}/../azure_dns_evaluator.py ${var.zone_file_path}"
  }
}

# Local exec to import zone file after zone creation
resource "null_resource" "import_zone_file" {
  depends_on = [
    azurerm_dns_zone.main,
    null_resource.validate_zone_file
  ]

  triggers = {
    zone_file_hash = filemd5(var.zone_file_path)
  }

  provisioner "local-exec" {
    command = <<-EOT
      az network dns zone import \
        --resource-group ${azurerm_resource_group.dns_rg.name} \
        --name ${azurerm_dns_zone.main.name} \
        --file-name ${var.zone_file_path}
    EOT
  }
}
```

#### Variables File
```hcl
# terraform/variables.tf
variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "dns-zones-rg"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

variable "zone_name" {
  description = "DNS zone name"
  type        = string
}

variable "zone_file_path" {
  description = "Path to the zone file"
  type        = string
}
```

#### Terraform Values File
```hcl
# terraform/terraform.tfvars
resource_group_name = "my-dns-zones"
location           = "East US"
zone_name          = "example.com"
zone_file_path     = "../zones/example.com.txt"
```

#### Advanced Multi-Zone Configuration
```hcl
# terraform/multi-zones.tf
locals {
  zone_files = {
    "example.com"     = "../zones/example.com.txt"
    "subdomain.com"   = "../zones/subdomain.com.txt"
    "another-zone.org" = "../zones/another-zone.org.txt"
  }
}

# Validate all zone files
resource "null_resource" "validate_all_zones" {
  for_each = local.zone_files

  triggers = {
    zone_file_hash = filemd5(each.value)
  }

  provisioner "local-exec" {
    command = "python ${path.module}/../azure_dns_evaluator.py ${each.value}"
  }
}

# Create DNS zones
resource "azurerm_dns_zone" "zones" {
  for_each = local.zone_files

  name                = each.key
  resource_group_name = azurerm_resource_group.dns_rg.name
}

# Import zone files
resource "null_resource" "import_zones" {
  for_each = local.zone_files

  depends_on = [
    azurerm_dns_zone.zones,
    null_resource.validate_all_zones
  ]

  triggers = {
    zone_file_hash = filemd5(each.value)
  }

  provisioner "local-exec" {
    command = <<-EOT
      az network dns zone import \
        --resource-group ${azurerm_resource_group.dns_rg.name} \
        --name ${each.key} \
        --file-name ${each.value}
    EOT
  }
}
```

## Automation Script Example

Create a batch validation script `validate_all_zones.py`:
```python
#!/usr/bin/env python3
import os
import subprocess
import glob

def validate_zones(zone_directory):
    """Validate all zone files in a directory"""
    zone_files = glob.glob(os.path.join(zone_directory, "*.txt"))
    results = {}
    
    for zone_file in zone_files:
        print(f"Validating {zone_file}...")
        result = subprocess.run([
            "python", "azure_dns_evaluator.py", zone_file
        ], capture_output=True, text=True)
        
        results[zone_file] = {
            "success": result.returncode == 0,
            "output": result.stdout,
            "errors": result.stderr
        }
    
    return results

if __name__ == "__main__":
    results = validate_zones("./zones")
    
    print("\n=== VALIDATION SUMMARY ===")
    for zone_file, result in results.items():
        status = "✓ PASS" if result["success"] else "✗ FAIL"
        print(f"{status} {os.path.basename(zone_file)}")
```

## Azure DNS Import Commands

After validation passes, import your zone to Azure DNS:

### Using Azure CLI
```bash
# Create resource group if needed
az group create --name myResourceGroup --location eastus

# Create DNS zone
az network dns zone create --resource-group myResourceGroup --name example.com

# Import zone file
az network dns zone import --resource-group myResourceGroup --name example.com --file-name zone.txt
```

### Using Azure PowerShell
```powershell
# Create resource group if needed
New-AzResourceGroup -Name "myResourceGroup" -Location "East US"

# Create DNS zone
New-AzDnsZone -Name "example.com" -ResourceGroupName "myResourceGroup"

# Import zone file
Import-AzDnsZone -ZoneName "example.com" -ResourceGroupName "myResourceGroup" -ZoneFile "zone.txt"
```

## Tips for Best Results

1. **Always validate before importing**: Use this tool before attempting Azure DNS import.

2. **Use proper FQDN format**: Ensure domain names end with a dot (.) in zone files.

3. **Set appropriate TTL values**: Use TTL values between 300 and 86400 for most records.

4. **Include all required records**: Ensure SOA and NS records are present.

5. **Test with small zones first**: Start with simple zone files before complex ones.

6. **Keep zone files in version control**: Track changes to your DNS configurations.

7. **Automate validation**: Include DNS validation in your deployment pipelines.
