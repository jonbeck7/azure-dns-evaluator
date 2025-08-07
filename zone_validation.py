#!/usr/bin/env python3
"""
Azure DNS Zone Validation Script

A tool to validate that DNS records have been successfully imported into Azure DNS
by querying the Azure DNS authoritative servers directly. This is particularly useful
for batch imports where zones may not be delegated yet.

Author: GitHub CoPilot with prompts from Jon Beck
Date: August 6, 2025
"""

import argparse
import sys
import os
import logging
import json
import time
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.exception

# Import our zone parser
from azure_dns_evaluator import ZoneFileParser, DNSRecord, ZoneInfo, setup_logging, UserOutput

# Example Azure DNS nameserver - this is just a placeholder!
# Azure DNS nameservers are zone-specific and authoritative only for zones they host.
# Use --auto-discover to find the actual nameservers for your zone.
# Real Azure DNS nameservers look like: ns1-XX.azure-dns.com, ns2-XX.azure-dns.net, etc.
DEFAULT_AZURE_NAMESERVER = 'ns1-XX.azure-dns.com'

# Record types that should be validated
VALIDATABLE_RECORD_TYPES = {
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'CAA'
}


class ValidationStatus(Enum):
    """Validation status for records"""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class RecordValidationResult:
    """Result of validating a single record"""
    record_name: str
    record_type: str
    expected_value: str
    actual_value: Optional[str]
    status: ValidationStatus
    error_message: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class ValidationSummary:
    """Summary of validation results"""
    total_records: int
    passed: int
    failed: int
    skipped: int
    errors: int
    pass_rate: float


class AzureDNSValidator:
    """Validates records against Azure DNS authoritative servers"""
    
    def __init__(self, nameserver: str, timeout: int = 10, 
                 retry_count: int = 3, logger: logging.Logger = None):
        self.nameserver = nameserver
        self.timeout = timeout
        self.retry_count = retry_count
        self.logger = logger or logging.getLogger('zone_validator')
        
        # Create a custom resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [nameserver]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        self.logger.info(f"Initialized validator with nameserver: {nameserver}")
    
    def validate_record(self, record: DNSRecord, zone_origin: str) -> RecordValidationResult:
        """Validate a single DNS record against Azure DNS"""
        
        # Skip root NS records as Azure DNS manages them
        if (record.record_type == 'NS' and 
            (record.name == '@' or 
             record.name == zone_origin or 
             record.name == f"{zone_origin}.")):
            return RecordValidationResult(
                record_name=record.name,
                record_type=record.record_type,
                expected_value=record.rdata,
                actual_value=None,
                status=ValidationStatus.SKIP,
                error_message="Root NS records are managed by Azure DNS",
                line_number=record.line_number
            )
        
        # Skip SOA records as Azure DNS modifies them
        if record.record_type == 'SOA':
            return RecordValidationResult(
                record_name=record.name,
                record_type=record.record_type,
                expected_value=record.rdata,
                actual_value=None,
                status=ValidationStatus.SKIP,
                error_message="SOA records are managed by Azure DNS",
                line_number=record.line_number
            )
        
        # Skip unsupported record types
        if record.record_type not in VALIDATABLE_RECORD_TYPES:
            return RecordValidationResult(
                record_name=record.name,
                record_type=record.record_type,
                expected_value=record.rdata,
                actual_value=None,
                status=ValidationStatus.SKIP,
                error_message=f"Record type {record.record_type} not supported for validation",
                line_number=record.line_number
            )
        
        try:
            # Construct the full domain name for querying
            query_name = self._construct_query_name(record.name, zone_origin)
            
            self.logger.debug(f"Validating {record.record_type} record for {query_name}")
            
            # Query the Azure DNS servers
            actual_records = self._query_record(query_name, record.record_type)
            
            if actual_records is None:
                return RecordValidationResult(
                    record_name=record.name,
                    record_type=record.record_type,
                    expected_value=record.rdata,
                    actual_value=None,
                    status=ValidationStatus.FAIL,
                    error_message="Record not found",
                    line_number=record.line_number
                )
            
            # Compare expected vs actual
            expected_normalized = self._normalize_record_data(record.rdata, record.record_type)
            
            # Check if expected value is in the actual records
            match_found = False
            actual_values = []
            
            for actual_record in actual_records:
                actual_normalized = self._normalize_record_data(str(actual_record), record.record_type)
                actual_values.append(actual_normalized)
                
                if expected_normalized == actual_normalized:
                    match_found = True
                    break
            
            if match_found:
                status = ValidationStatus.PASS
                error_message = None
            else:
                status = ValidationStatus.FAIL
                error_message = f"Expected '{expected_normalized}' not found in actual records: {actual_values}"
            
            return RecordValidationResult(
                record_name=record.name,
                record_type=record.record_type,
                expected_value=expected_normalized,
                actual_value='; '.join(actual_values) if actual_values else None,
                status=status,
                error_message=error_message,
                line_number=record.line_number
            )
            
        except Exception as e:
            self.logger.error(f"Error validating record {record.name} {record.record_type}: {e}")
            return RecordValidationResult(
                record_name=record.name,
                record_type=record.record_type,
                expected_value=record.rdata,
                actual_value=None,
                status=ValidationStatus.ERROR,
                error_message=str(e),
                line_number=record.line_number
            )
    
    def _construct_query_name(self, record_name: str, zone_origin: str) -> str:
        """Construct the full domain name for DNS queries"""
        if record_name == '@':
            return zone_origin
        elif record_name.endswith('.'):
            return record_name.rstrip('.')
        elif record_name == zone_origin:
            return zone_origin
        else:
            # Handle relative names
            return record_name
    
    def _query_record(self, name: str, record_type: str) -> Optional[List]:
        """Query DNS record with retries"""
        
        for attempt in range(self.retry_count):
            try:
                # Convert record type string to dns.rdatatype
                rdtype = getattr(dns.rdatatype, record_type)
                
                self.logger.debug(f"Querying {name} {record_type} (attempt {attempt + 1})")
                
                # Perform the query
                response = self.resolver.resolve(name, rdtype)
                records = [rdata for rdata in response]
                
                self.logger.debug(f"Query successful: found {len(records)} records")
                return records
                
            except dns.resolver.NXDOMAIN:
                self.logger.debug(f"NXDOMAIN for {name} {record_type}")
                return None
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No answer for {name} {record_type}")
                return None
            except dns.resolver.NoNameservers:
                self.logger.warning(f"No nameservers available for {name} {record_type}")
                if attempt < self.retry_count - 1:
                    time.sleep(1)
                continue
            except dns.exception.Timeout:
                self.logger.warning(f"Timeout querying {name} {record_type} (attempt {attempt + 1})")
                if attempt < self.retry_count - 1:
                    time.sleep(1)  # Brief delay before retry
                continue
            except Exception as e:
                self.logger.error(f"Error querying {name} {record_type}: {e}")
                if attempt < self.retry_count - 1:
                    time.sleep(1)
                continue
        
        # All attempts failed
        error_msg = f"Failed to query {name} {record_type} after {self.retry_count} attempts"
        
        # Check if this might be an authority issue
        if any(ns in self.resolver.nameservers[0] for ns in ['azure-dns.']):
            error_msg += f". Note: Azure DNS nameserver '{self.resolver.nameservers[0]}' may not be authoritative for this zone. Use --auto-discover to find the correct nameservers."
        
        raise Exception(error_msg)
    
    def _normalize_record_data(self, data: str, record_type: str) -> str:
        """Normalize record data for comparison"""
        data = data.strip()
        
        if record_type in ['CNAME', 'NS', 'PTR', 'MX', 'SRV']:
            # Remove trailing dots from domain names
            if record_type == 'MX':
                # MX records have priority followed by domain
                parts = data.split()
                if len(parts) >= 2:
                    priority = parts[0]
                    domain = parts[1].rstrip('.')
                    data = f"{priority} {domain}"
            elif record_type == 'SRV':
                # SRV records have priority, weight, port, domain
                parts = data.split()
                if len(parts) >= 4:
                    priority, weight, port = parts[0], parts[1], parts[2]
                    domain = parts[3].rstrip('.')
                    data = f"{priority} {weight} {port} {domain}"
            else:
                # Simple domain name
                data = data.rstrip('.')
        elif record_type == 'TXT':
            # Remove quotes from TXT records and normalize spacing
            data = data.strip('"\'')
        
        return data.lower()


class ZoneValidator:
    """Main zone validation orchestrator"""
    
    def __init__(self, nameserver: str, config: Dict = None, 
                 logger: logging.Logger = None):
        self.nameserver = nameserver
        self.config = config or {}
        self.logger = logger or logging.getLogger('zone_validator')
        self.user_output = UserOutput(self.config.get('verbose', False))
        
        # Initialize DNS validator
        self.dns_validator = AzureDNSValidator(
            nameserver=nameserver,
            timeout=self.config.get('timeout', 10),
            retry_count=self.config.get('retry_count', 3),
            logger=logger
        )
    
    def validate_zone_file(self, zone_file_path: str) -> Tuple[List[RecordValidationResult], ValidationSummary]:
        """Validate all records in a zone file"""
        
        self.user_output.info(f"Parsing zone file: {zone_file_path}")
        self.logger.info(f"Starting validation of zone file: {zone_file_path}")
        
        # Parse the zone file
        parser = ZoneFileParser(self.logger)
        zone_info = parser.parse_file(zone_file_path)
        
        self.user_output.info(f"Found {len(zone_info.records)} records in zone '{zone_info.origin}'")
        self.logger.info(f"Parsed {len(zone_info.records)} records from zone file")
        
        # Validate each record
        results = []
        total_records = len(zone_info.records)
        
        for i, record in enumerate(zone_info.records, 1):
            if self.config.get('verbose'):
                self.user_output.verbose_info(f"Validating record {i}/{total_records}: {record.name} {record.record_type}")
            
            result = self.dns_validator.validate_record(record, zone_info.origin)
            results.append(result)
            
            # Log the result
            if result.status == ValidationStatus.PASS:
                self.logger.debug(f"PASS: {record.name} {record.record_type}")
            elif result.status == ValidationStatus.FAIL:
                self.logger.warning(f"FAIL: {record.name} {record.record_type}: {result.error_message}")
            elif result.status == ValidationStatus.ERROR:
                self.logger.error(f"ERROR: {record.name} {record.record_type}: {result.error_message}")
            
            # Add small delay between queries to be respectful
            if i < total_records:
                time.sleep(0.1)
        
        # Calculate summary
        summary = self._calculate_summary(results)
        
        self.logger.info(f"Validation completed: {summary.passed}/{summary.total_records} passed "
                        f"({summary.pass_rate:.1f}% success rate)")
        
        return results, summary
    
    def _calculate_summary(self, results: List[RecordValidationResult]) -> ValidationSummary:
        """Calculate validation summary statistics"""
        total = len(results)
        passed = len([r for r in results if r.status == ValidationStatus.PASS])
        failed = len([r for r in results if r.status == ValidationStatus.FAIL])
        skipped = len([r for r in results if r.status == ValidationStatus.SKIP])
        errors = len([r for r in results if r.status == ValidationStatus.ERROR])
        
        pass_rate = (passed / (total - skipped)) * 100 if (total - skipped) > 0 else 0
        
        return ValidationSummary(
            total_records=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            pass_rate=pass_rate
        )


class ReportGenerator:
    """Generate validation reports"""
    
    def generate_text_report(self, results: List[RecordValidationResult], 
                           summary: ValidationSummary, zone_file: str,
                           nameserver: str) -> str:
        """Generate a text validation report"""
        report_lines = []
        report_lines.append("Azure DNS Zone Validation Report")
        report_lines.append("=" * 50)
        report_lines.append("")
        
        # Summary information
        report_lines.append("Validation Summary:")
        report_lines.append(f"  Zone File: {zone_file}")
        report_lines.append(f"  Nameserver: {nameserver}")
        report_lines.append(f"  Total Records: {summary.total_records}")
        report_lines.append(f"  Passed: {summary.passed}")
        report_lines.append(f"  Failed: {summary.failed}")
        report_lines.append(f"  Skipped: {summary.skipped}")
        report_lines.append(f"  Errors: {summary.errors}")
        report_lines.append(f"  Success Rate: {summary.pass_rate:.1f}%")
        report_lines.append("")
        
        # Failed records
        failed_results = [r for r in results if r.status == ValidationStatus.FAIL]
        if failed_results:
            report_lines.append("FAILED RECORDS:")
            for result in failed_results:
                line_info = f" (line {result.line_number})" if result.line_number else ""
                report_lines.append(f"  [FAIL] {result.record_name} {result.record_type}{line_info}")
                report_lines.append(f"         Expected: {result.expected_value}")
                if result.actual_value:
                    report_lines.append(f"         Actual: {result.actual_value}")
                if result.error_message:
                    report_lines.append(f"         Error: {result.error_message}")
                report_lines.append("")
        
        # Error records
        error_results = [r for r in results if r.status == ValidationStatus.ERROR]
        if error_results:
            report_lines.append("ERROR RECORDS:")
            for result in error_results:
                line_info = f" (line {result.line_number})" if result.line_number else ""
                report_lines.append(f"  [ERROR] {result.record_name} {result.record_type}{line_info}")
                report_lines.append(f"          Error: {result.error_message}")
                report_lines.append("")
        
        # Overall result
        if summary.failed == 0 and summary.errors == 0:
            report_lines.append("VALIDATION RESULT: PASS")
            report_lines.append("All records have been successfully imported to Azure DNS!")
        else:
            report_lines.append("VALIDATION RESULT: FAIL")
            report_lines.append("Some records failed validation. Check the details above.")
        
        return "\n".join(report_lines)
    
    def generate_json_report(self, results: List[RecordValidationResult], 
                           summary: ValidationSummary, zone_file: str,
                           nameserver: str) -> str:
        """Generate a JSON validation report"""
        report_data = {
            "zone_file": zone_file,
            "nameserver": nameserver,
            "summary": asdict(summary),
            "results": [asdict(result) for result in results],
            "overall_status": "PASS" if summary.failed == 0 and summary.errors == 0 else "FAIL"
        }
        return json.dumps(report_data, indent=2, default=str)


def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"Failed to load config file {config_file}: {e}")


def discover_azure_nameservers(zone_name: str) -> str:
    """Discover Azure DNS nameserver for a zone (returns first one found)"""
    try:
        resolver = dns.resolver.Resolver()
        # Query for NS records of the zone
        response = resolver.resolve(zone_name, 'NS')
        nameservers = [str(rdata).rstrip('.') for rdata in response]
        
        print(f"Found nameservers for {zone_name}: {', '.join(nameservers)}")
        
        # Return the first Azure DNS nameserver found
        for ns in nameservers:
            if 'azure-dns.' in ns:
                print(f"Using Azure DNS nameserver: {ns}")
                return ns
        
        # If no Azure DNS nameserver found, this zone might not be hosted on Azure DNS
        print(f"Warning: No Azure DNS nameservers found for {zone_name}")
        print(f"Found nameservers: {', '.join(nameservers)}")
        print("This zone may not be hosted on Azure DNS or may not be delegated yet.")
        
        # Return the first one anyway
        return nameservers[0] if nameservers else DEFAULT_AZURE_NAMESERVER
        
    except Exception as e:
        print(f"Warning: Could not discover nameservers for {zone_name}: {e}")
        print("This could mean:")
        print("  1. The zone is not delegated yet")
        print("  2. The zone doesn't exist") 
        print("  3. Network connectivity issues")
        print(f"Using default placeholder nameserver: {DEFAULT_AZURE_NAMESERVER}")
        return DEFAULT_AZURE_NAMESERVER


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Validate DNS zone files against Azure DNS authoritative servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate using specific nameserver
  python zone_validation.py zone.txt --nameserver ns1-01.azure-dns.com
  
  # Auto-discover nameserver for the zone
  python zone_validation.py zone.txt --auto-discover
  
  # Use configuration file
  python zone_validation.py zone.txt --config validation_config.json
  
  # Generate JSON report
  python zone_validation.py zone.txt --nameserver ns1-01.azure-dns.com --format json --output report.json
  
  # Verbose mode with detailed logging
  python zone_validation.py zone.txt --nameserver ns1-01.azure-dns.com --verbose --log-file validation.log

Configuration file format (JSON):
{
    "nameserver": "ns1-XX.azure-dns.com",
    "timeout": 10,
    "retry_count": 3,
    "verbose": false
}
        """
    )
    
    parser.add_argument("zone_file", help="Path to the zone file to validate")
    parser.add_argument("-n", "--nameserver", 
                       help="Azure DNS nameserver to query (only one needed)")
    parser.add_argument("--auto-discover", action="store_true",
                       help="Auto-discover nameserver from the zone's NS records")
    parser.add_argument("-c", "--config", help="Configuration file (JSON)")
    parser.add_argument("-o", "--output", help="Output file for the report")
    parser.add_argument("-f", "--format", choices=["text", "json"], 
                       default="text", help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose output")
    parser.add_argument("--timeout", type=int, default=10,
                       help="DNS query timeout in seconds (default: 10)")
    parser.add_argument("--retry-count", type=int, default=3,
                       help="Number of retry attempts for failed queries (default: 3)")
    parser.add_argument("--log-file", help="Save detailed logs to file")
    
    args = parser.parse_args()
    
    try:
        # Load configuration if provided
        config = {}
        if args.config:
            config = load_config(args.config)
        
        # Override config with command line arguments
        if args.verbose:
            config['verbose'] = True
        if args.timeout:
            config['timeout'] = args.timeout
        if args.retry_count:
            config['retry_count'] = args.retry_count
        
        # Setup logging
        logger = setup_logging(config.get('verbose', args.verbose), args.log_file)
        user_output = UserOutput(config.get('verbose', args.verbose))
        
        logger.info("Azure DNS Zone Validation started")
        
        # Check if zone file exists
        if not os.path.exists(args.zone_file):
            user_output.error(f"Zone file '{args.zone_file}' not found.")
            sys.exit(1)
        
        # Determine nameserver to use
        nameserver = None
        
        if args.nameserver:
            nameserver = args.nameserver
            user_output.info(f"Using specified nameserver: {nameserver}")
        elif config.get('nameserver'):
            nameserver = config['nameserver']
            user_output.info(f"Using nameserver from config: {nameserver}")
        elif args.auto_discover:
            # Parse zone file to get zone name for discovery
            parser = ZoneFileParser()
            zone_info = parser.parse_file(args.zone_file)
            if not zone_info.origin:
                user_output.error("Could not determine zone origin for nameserver discovery")
                sys.exit(1)
            
            user_output.info(f"Auto-discovering nameserver for zone: {zone_info.origin}")
            nameserver = discover_azure_nameservers(zone_info.origin)
            user_output.info(f"Discovered nameserver: {nameserver}")
        else:
            user_output.error("Must specify nameserver using --nameserver, --config, or --auto-discover")
            user_output.info("Example: python zone_validation.py zone.txt --nameserver ns1-XX.azure-dns.com")
            user_output.info("Use --auto-discover to find the actual nameservers for your zone")
            sys.exit(1)
        
        # Initialize validator
        validator = ZoneValidator(nameserver, config, logger)
        
        # Perform validation
        user_output.info("Starting zone validation...")
        results, summary = validator.validate_zone_file(args.zone_file)
        
        # Generate report
        reporter = ReportGenerator()
        
        if args.format == "json":
            report = reporter.generate_json_report(results, summary, args.zone_file, nameserver)
        else:
            report = reporter.generate_text_report(results, summary, args.zone_file, nameserver)
        
        # Output report
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            user_output.info(f"Validation report saved to: {args.output}")
        else:
            user_output.info("\n" + report)
        
        # Summary output
        if summary.failed == 0 and summary.errors == 0:
            user_output.success(f"\nVALIDATION PASSED: All {summary.passed} validated records found in Azure DNS")
            if summary.skipped > 0:
                user_output.info(f"({summary.skipped} records skipped as expected)")
            logger.info("Zone validation completed successfully")
            sys.exit(0)
        else:
            user_output.error(f"\nVALIDATION FAILED: {summary.failed} failed, {summary.errors} errors")
            user_output.info(f"Success rate: {summary.pass_rate:.1f}%")
            logger.warning(f"Zone validation failed: {summary.failed} failed, {summary.errors} errors")
            sys.exit(1)
    
    except KeyboardInterrupt:
        user_output.info("\nValidation cancelled by user")
        sys.exit(1)
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        user_output.error(f"Validation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
