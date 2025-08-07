# Azure DNS Zone Validation Guide

This guide shows how to use the zone validation tools to verify your DNS setup and delegation.

## Available Validation Tools

1. **Post-Import Validation** (`zone_validation.py`) - Verify records imported to Azure DNS
2. **Batch Validation** (`batch_validation.py`) - Validate multiple zones in parallel
3. **DNS Delegation Validation** (`delegation_validator.py`) - Validate parent-child zone relationships

## Post-Import Validation Scenarios

### Scenario 1: Single Zone Validation with Known Nameserver

You know one of the Azure DNS nameservers for your zone:

```bash
python zone_validation.py example.com.txt --nameserver ns1-01.azure-dns.com
```

### Scenario 2: Auto-Discovery (Zone is Already Delegated)

If your zone is already delegated to Azure DNS:

```bash
python zone_validation.py example.com.txt --auto-discover --verbose
```

### Scenario 3: Using Configuration File

Create a `validation_config.json`:

```json
{
    "nameserver": "ns1-01.azure-dns.com",
    "timeout": 15,
    "retry_count": 3,
    "verbose": true
}
```

Then run:

```bash
python zone_validation.py example.com.txt --config validation_config.json
```

### Scenario 4: Batch Validation of Multiple Zones

For validating multiple zones after a batch import:

```bash
# Validate all .txt files in the zones directory
python batch_validation.py zones/ --config batch_config.json --parallel

# Validate specific zone files
python batch_validation.py zone1.txt zone2.txt zone3.txt --nameserver ns1-01.azure-dns.com
```

Create a `batch_config.json` for complex setups:

```json
{
    "nameserver": "ns1-01.azure-dns.com",
    "parallel": true,
    "max_workers": 5,
    "timeout": 10,
    "retry_count": 3,
    "verbose": false,
    "zones": {
        "example": {
            "nameserver": "ns1-example.azure-dns.com"
        },
        "test": {
            "nameserver": "ns1-test.azure-dns.net"
        }
    }
}
```

## Finding Your Azure DNS Nameservers

**Note:** You only need one nameserver for validation. Azure DNS uses multiple nameservers for redundancy, but any one of them will provide the same authoritative answers.

### Method 1: Azure Portal
1. Go to your DNS zone in the Azure portal
2. The nameservers are listed on the overview page

### Method 2: Azure CLI
```bash
az network dns zone show --name example.com --resource-group myResourceGroup --query nameServers
```

### Method 3: PowerShell
```powershell
Get-AzDnsZone -Name example.com -ResourceGroupName myResourceGroup | Select-Object NameServers
```

## Understanding Validation Results

### PASS Status
- Record was found in Azure DNS
- Values match exactly
- Import was successful

### FAIL Status  
- Record not found in Azure DNS
- Values don't match expected
- Import may have failed or been modified

### SKIP Status
- Root NS records (Azure DNS manages these)
- SOA records (Azure DNS modifies these)
- Unsupported record types

### ERROR Status
- DNS query failed
- Network connectivity issues
- Invalid record format

## Best Practices

1. **Wait Before Validating**: Allow 5-10 minutes after import for DNS propagation
2. **Use Correct Nameservers**: Always use the Azure DNS authoritative nameservers, not recursive resolvers
3. **Batch Processing**: For large migrations, use batch validation with parallel processing
4. **Monitor Success Rates**: Aim for >99% validation success rate
5. **Investigate Failures**: Check Azure DNS portal for any import errors or warnings

## Troubleshooting

### High Failure Rate
- Check if import actually completed successfully
- Verify you're using the correct Azure DNS nameservers
- Ensure zone is not still importing

### Timeout Errors
- Increase timeout value in config
- Check network connectivity
- Verify nameserver addresses are correct

### Permission Errors
- Ensure zone file is readable
- Check file path is correct
- Verify Python has necessary permissions

## Example Workflow

1. **Import zones to Azure DNS** (using Azure CLI, PowerShell, or Portal)
2. **Get nameservers** from Azure DNS zone
3. **Run validation**:
   ```bash
   python zone_validation.py myzone.txt --nameservers ns1-01.azure-dns.com ns2-01.azure-dns.net --verbose
   ```
4. **Review results** and investigate any failures
5. **For batch imports**:
   ```bash
   python batch_validation.py zones/ --config batch_config.json --format json --output validation_report.json
   ```
6. **Generate reports** for audit trails and documentation

## DNS Delegation Validation

For validating parent-child zone relationships and delegation setup:

### Interactive Mode (Recommended for First-Time Users)

```bash
python delegation_validator.py --interactive
```

This will prompt you for:
- Child zone file path
- Child zone origin (domain name)
- Child nameserver (the authoritative server for the child zone)
- Parent nameserver (the authoritative server for the parent zone)
- Validation options

### Configuration File Mode

Create a `delegation_config.json`:

```json
{
    "CHILD_ZONE_FILE": "examples/delegation_test.zone",
    "CHILD_ORIGIN": "test.example.com",
    "CHILD_NS": "ns1-01.azure-dns.com",
    "PARENT_NS": "8.8.8.8",
    "IGNORE_ADMINISTRATIVE_RECORDS": true,
    "REPORT_FORMATS": ["html", "json"],
    "DNS_TIMEOUT": 10,
    "DNS_RETRIES": 3
}
```

Then run:

```bash
python delegation_validator.py --config delegation_config.json
```

### Command Line Mode

```bash
python delegation_validator.py \
  --zone-file examples/delegation_test.zone \
  --origin test.example.com \
  --child-ns ns1-01.azure-dns.com \
  --parent-ns 8.8.8.8 \
  --format html,json
```

### What Gets Validated

1. **Child Zone File vs. Child Server**: Validates that the records in your zone file match what's actually served by the child nameserver
2. **Child Zone vs. Parent Zone**: Validates that the parent zone has proper NS records pointing to the child zone's nameservers
3. **Record Consistency**: Ensures all DNS record types are properly delegated and accessible

### Report Formats

- **Text**: Human-readable console output
- **JSON**: Machine-readable for automation
- **CSV**: Spreadsheet-compatible format
- **HTML**: Rich formatted report with styling

### Common Use Cases

- **Pre-Delegation Validation**: Verify zone files before setting up delegation
- **Post-Delegation Verification**: Confirm delegation is working correctly
- **Migration Validation**: Ensure proper delegation during DNS provider migrations
- **Audit and Compliance**: Generate reports for delegation verification
