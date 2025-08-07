# Azure DNS Zone Validation Guide

This guide shows how to use the zone validation tools to verify that your DNS records were successfully imported to Azure DNS.

## Scenarios

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
