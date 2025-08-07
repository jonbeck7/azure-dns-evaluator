# Azure DNS Zone File Evaluator

A Python tool that evaluates BIND-compliant zone files for compatibility with Azure DNS. This tool helps identify potential issues before importing DNS zones into Azure DNS, saving time and preventing import failures.

## ✨ Features

- **Complete Zone File Parsing**: Parses BIND-format zone files with support for standard DNS record types
- **Azure DNS Validation**: Validates against Azure DNS specific limitations and requirements
- **Post-Import Validation**: Validates that records were successfully imported to Azure DNS authoritative servers
- **Batch Validation**: Validates multiple zones in parallel for batch import verification
- **Automatic Zone Splitting**: Splits large zone files into smaller importable chunks (handles 200k+ line files)
- **Batch Import Tools**: Includes scripts for importing split zone files to Azure DNS in correct order
- **OctoDNS Integration**: Native support for OctoDNS (DNS as Code) with YAML to BIND conversion and validation
- **Comprehensive Error Reporting**: Provides detailed error messages with line numbers and recommendations
- **Multiple Output Formats**: Supports both human-readable text and machine-readable JSON reports
- **CLI Interface**: Easy-to-use command-line interface for automation and scripting
- **VS Code Integration**: Includes tasks for easy testing and development

## 🔍 Validation Tools

This project includes four main validation tools:

### 1. Pre-Import Validation (`azure_dns_evaluator.py`)

Validates zone files for Azure DNS compatibility **before** importing:

- Checks Azure DNS limitations and requirements
- Identifies unsupported record types
- Validates record format and content
- Automatically splits large files for import

### 2. Post-Import Validation (`zone_validation.py`)

Validates that records were successfully imported by querying Azure DNS authoritative servers:

- Queries Azure DNS nameservers directly
- Compares expected vs actual records
- Handles zones that aren't delegated yet
- Configurable nameservers per zone

### 3. Batch Validation (`batch_validation.py`)

Validates multiple zones in batch for large migrations:

- Parallel validation for faster processing
- Zone-specific nameserver configuration
- Comprehensive batch reporting
- Perfect for validating entire migrations

### 4. DNS Delegation Validator (`delegation_validator.py`)

Validates parent-child zone delegation relationships:

- Child zone file vs. child server validation
- Child zone vs. parent zone delegation validation
- Supports all DNS record types (A, AAAA, CNAME, TXT, MX, SRV, CAA, etc.)
- Multiple report formats (text, JSON, CSV, HTML)
- Interactive and configuration-based operation
- Concurrent DNS queries for performance

## Supported DNS Record Types

The tool validates the following DNS record types supported by Azure DNS:

- A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA

## Azure DNS Limitations Checked

- Maximum record sets per zone (10,000)
- Maximum records per record set (20 for most types, 400 for TXT)
- TTL value ranges (1 to 2,147,483,647 seconds)
- Maximum TXT record length (1,024 characters per record)
- Maximum TXT record set total size (4,096 bytes per record set)
- Maximum label length (63 characters)
- Maximum domain name length (253 characters)
- Import API limitations (10,000 lines, 3,000 record sets per import)
- Unsupported record types

## Quick Start

1. **Clone or download this project**
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Run the evaluator**: `python azure_dns_evaluator.py your_zone_file.txt`

### Tool-Specific Quick Start

**For OctoDNS users:**
```bash
pip install PyYAML
python octodns_validator.py zones/example.com.yaml --verbose
```

**For Terraform users:**
```hcl
resource "null_resource" "validate_zone" {
  provisioner "local-exec" {
    command = "python azure_dns_evaluator.py zone.txt"
  }
}
```

**For PowerDNS/API users:**
```bash
python demo_powerdns_validator.py  # See demo example
```

## Installation

1. Ensure you have Python 3.7 or later installed
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python azure_dns_evaluator.py zone.txt
```

### Save Report to File

```bash
python azure_dns_evaluator.py zone.txt --output report.txt
```

### Generate JSON Report

```bash
python azure_dns_evaluator.py zone.txt --format json --output report.json
```

### Verbose Output

```bash
python azure_dns_evaluator.py zone.txt --verbose
```

### Automatic Zone File Splitting

For large zone files that exceed Azure DNS import limits:

```bash
# Automatically split large zone files
python azure_dns_evaluator.py large_zone.txt --split

# Split with verbose output and subdomain grouping
python azure_dns_evaluator.py large_zone.txt --split --verbose

# Split using even distribution method
python azure_dns_evaluator.py large_zone.txt --split --split-method even
```

### Post-Import Validation

Validate that records were successfully imported to Azure DNS:

```bash
# Validate using specific Azure DNS nameservers
python zone_validation.py zone.txt --nameservers ns1-01.azure-dns.com ns2-01.azure-dns.net

# Auto-discover nameservers from the zone's NS records
python zone_validation.py zone.txt --auto-discover

# Use a configuration file for settings
python zone_validation.py zone.txt --config validation_config.json --verbose

# Generate JSON validation report
python zone_validation.py zone.txt --nameservers ns1-01.azure-dns.com --format json --output validation_report.json
```

### Batch Validation

Validate multiple zones in batch:

```bash
# Validate all zone files in a directory
python batch_validation.py /path/to/zones --config batch_config.json

# Validate specific zone files with parallel processing
python batch_validation.py zone1.txt zone2.txt zone3.txt --nameservers ns1-01.azure-dns.com --parallel

# Generate comprehensive batch report
python batch_validation.py /path/to/zones --config batch_config.json --format json --output batch_report.json
```

### DNS Delegation Validation

Validate parent-child zone delegation relationships:

```bash
# Interactive configuration mode (recommended for first-time users)
python delegation_validator.py --interactive

# Use configuration file
python delegation_validator.py --config delegation_config.json

# Command-line configuration
python delegation_validator.py --zone-file examples/delegation_test.zone --origin test.example.com --child-ns ns1.example.com --parent-ns 8.8.8.8

# Generate multiple report formats
python delegation_validator.py --config delegation_config.json --format html,json,csv
```

### Batch Import for Split Files

After splitting, use the included batch import tools:

```bash
# Python batch import script
python batch_import.py --resource-group myRG --zone-name example.com --split-directory ./zone_split --validate-first

# Bash script (Linux/macOS)
./batch_import.sh myResourceGroup example.com ./zone_split validate
```

## Command Line Options

- `zone_file`: Path to the BIND zone file (required)
- `-o, --output`: Output file for the report (optional)
- `-f, --format`: Output format - 'text' or 'json' (default: text)
- `-v, --verbose`: Enable verbose output
- `--split`: Automatically split large zone files into smaller importable files
- `--split-method`: Method for splitting files - 'subdomain' or 'even' (default: subdomain)

## Example Zone File

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
```

## Output Examples

### Text Report

```text
Azure DNS Zone File Evaluation Report
==================================================

Zone Information:
  Origin: example.com
  Total Records: 6
  Total Lines: 25
  Total Record Sets: 6

Record Types:
  [SUPPORTED] SOA: 1
  [SUPPORTED] NS: 2
  [SUPPORTED] A: 3
  [SUPPORTED] MX: 1

Validation Summary:
  Errors: 0
  Warnings: 0
  Info: 0

Recommendations:
  [PASS] Zone file appears compatible with Azure DNS!
  [PASS] You can proceed with importing this zone file to Azure DNS.
```

### JSON Report

```json
{
  "zone_info": {
    "origin": "example.com",
    "total_records": 6,
    "record_types": {
      "SOA": 1,
      "NS": 2,
      "A": 3,
      "MX": 1
    }
  },
  "validation_results": [],
  "summary": {
    "total_records": 6,
    "error_count": 0,
    "warning_count": 0,
    "is_azure_compatible": true
  }
}
```

## Error Handling

The tool provides detailed error messages for common issues:

- Missing SOA records
- Unsupported record types
- TTL values outside Azure DNS limits
- Individual TXT records exceeding length limitations (1,024 characters)
- TXT record sets exceeding total size limitations (4,096 bytes)
- Record sets exceeding count limitations (20 for most types, 400 for TXT)
- Zone files exceeding import API limitations (10,000 lines or 3,000 record sets)
- Records exceeding length limitations
- Malformed zone file syntax

## Exit Codes

- `0`: Success - Zone file is compatible with Azure DNS
- `1`: Error - Zone file has compatibility issues or tool encountered an error

## Integration with Azure

After validating your zone file with this tool, you can import it to Azure DNS using:

### Azure CLI

```bash
az network dns zone import -g MyResourceGroup -n example.com -f zone.txt
```

### Azure PowerShell

```powershell
Import-AzDnsZone -ZoneName "example.com" -ResourceGroupName "MyResourceGroup" -ZoneFile "zone.txt"
```

### Terraform

```hcl
# Validate zone file before applying
resource "null_resource" "validate_zone" {
  provisioner "local-exec" {
    command = "python azure_dns_evaluator.py zone.txt"
  }
}

# Create DNS zone and import records
resource "azurerm_dns_zone" "main" {
  name                = "example.com"
  resource_group_name = "MyResourceGroup"
}

resource "null_resource" "import_zone" {
  depends_on = [azurerm_dns_zone.main, null_resource.validate_zone]
  
  provisioner "local-exec" {
    command = "az network dns zone import -g MyResourceGroup -n example.com -f zone.txt"
  }
}
```

### CI/CD Integration

The tool supports integration with various CI/CD platforms and DNS management tools, including:

**CI/CD Platforms:**
- GitHub Actions 
- Azure DevOps
- GitLab CI/CD

**DNS Management Tools:**
- **Azure CLI** - Direct command-line management
- **Terraform** - Infrastructure as Code with HCL
- **OctoDNS** - DNS as Code with YAML
- **Pulumi** - Modern IaC with multiple languages
- **DNSControl** - Stack Exchange's DNS-as-code solution
- **External-DNS** - Kubernetes-native DNS management
- **PowerDNS** - API-driven automation
- **Route53 Migration** - AWS to Azure migration tools
- **Cloudflare Migration** - Migration from Cloudflare

See the [USAGE.md](USAGE.md) file for detailed CI/CD pipeline examples and integration guides.

### OctoDNS Support

For teams using OctoDNS (DNS as Code), this tool includes a special integration script (`octodns_validator.py`) that:
- Converts OctoDNS YAML configurations to BIND format
- Validates them against Azure DNS limitations
- Integrates seamlessly with CI/CD pipelines
- Supports both individual zone files and complete OctoDNS configurations

## Contributing

This tool was generated to help with Azure DNS zone file validation. Feel free to extend it with additional validation rules or features as needed.

## License

This project is provided as-is for educational and practical use.
