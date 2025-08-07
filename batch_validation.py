#!/usr/bin/env python3
"""
Batch Zone Validation Script

A tool to validate multiple DNS zone files against Azure DNS in batch.
Useful for validating entire migration batches to ensure all records
were successfully imported.

Author: GitHub CoPilot with prompts from Jon Beck
Date: August 6, 2025
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

from zone_validation import ZoneValidator, ValidationSummary, RecordValidationResult, setup_logging, UserOutput


@dataclass
class BatchValidationResult:
    """Result for a single zone in batch validation"""
    zone_file: str
    zone_name: str
    status: str  # "PASS", "FAIL", "ERROR"
    summary: ValidationSummary
    error_message: str = None


class BatchValidator:
    """Validates multiple zones in batch"""
    
    def __init__(self, config: Dict, logger=None):
        self.config = config
        self.logger = logger
        self.user_output = UserOutput(config.get('verbose', False))
        
    def validate_batch(self, zone_files: List[str], nameserver: str = None) -> List[BatchValidationResult]:
        """Validate multiple zone files"""
        
        self.user_output.info(f"Starting batch validation of {len(zone_files)} zone files")
        
        results = []
        max_workers = self.config.get('max_workers', 3)  # Limit concurrent DNS queries
        
        if self.config.get('parallel', False) and len(zone_files) > 1:
            # Parallel validation
            self.user_output.info(f"Using parallel validation with {max_workers} workers")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all validation tasks
                future_to_file = {
                    executor.submit(self._validate_single_zone, zone_file, nameserver): zone_file
                    for zone_file in zone_files
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_file):
                    zone_file = future_to_file[future]
                    try:
                        result = future.result()
                        results.append(result)
                        self._log_zone_result(result)
                    except Exception as e:
                        error_result = BatchValidationResult(
                            zone_file=zone_file,
                            zone_name="unknown",
                            status="ERROR",
                            summary=ValidationSummary(0, 0, 0, 0, 1, 0.0),
                            error_message=str(e)
                        )
                        results.append(error_result)
                        self.user_output.error(f"Failed to validate {zone_file}: {e}")
        else:
            # Sequential validation
            for i, zone_file in enumerate(zone_files, 1):
                self.user_output.info(f"Validating zone {i}/{len(zone_files)}: {zone_file}")
                
                try:
                    result = self._validate_single_zone(zone_file, nameserver)
                    results.append(result)
                    self._log_zone_result(result)
                    
                except Exception as e:
                    error_result = BatchValidationResult(
                        zone_file=zone_file,
                        zone_name="unknown", 
                        status="ERROR",
                        summary=ValidationSummary(0, 0, 0, 0, 1, 0.0),
                        error_message=str(e)
                    )
                    results.append(error_result)
                    self.user_output.error(f"Failed to validate {zone_file}: {e}")
                
                # Brief pause between zones to be respectful to DNS servers
                if i < len(zone_files):
                    time.sleep(0.5)
        
        return results
    
    def _validate_single_zone(self, zone_file: str, nameserver: str = None) -> BatchValidationResult:
        """Validate a single zone file"""
        
        try:
            # Determine nameserver for this zone
            zone_nameserver = nameserver or self._get_nameserver_for_zone(zone_file)
            
            # Create validator for this zone
            validator = ZoneValidator(zone_nameserver, self.config, self.logger)
            
            # Perform validation
            validation_results, summary = validator.validate_zone_file(zone_file)
            
            # Determine zone name
            from azure_dns_evaluator import ZoneFileParser
            parser = ZoneFileParser()
            zone_info = parser.parse_file(zone_file)
            zone_name = zone_info.origin
            
            # Determine overall status
            if summary.failed == 0 and summary.errors == 0:
                status = "PASS"
            else:
                status = "FAIL"
            
            return BatchValidationResult(
                zone_file=zone_file,
                zone_name=zone_name,
                status=status,
                summary=summary
            )
            
        except Exception as e:
            raise Exception(f"Validation failed for {zone_file}: {e}")
    
    def _get_nameserver_for_zone(self, zone_file: str) -> str:
        """Get nameserver for a specific zone"""
        
        # Check if zone-specific nameserver is configured
        zone_configs = self.config.get('zones', {})
        zone_name = Path(zone_file).stem
        
        if zone_name in zone_configs:
            return zone_configs[zone_name].get('nameserver', self.config.get('nameserver', 'ns1-01.azure-dns.com'))
        
        # Use global nameserver
        return self.config.get('nameserver', 'ns1-01.azure-dns.com')
    
    def _log_zone_result(self, result: BatchValidationResult):
        """Log the result of a zone validation"""
        if result.status == "PASS":
            self.user_output.success(f"✓ {result.zone_name}: PASS ({result.summary.passed} records)")
        elif result.status == "FAIL":
            self.user_output.error(f"✗ {result.zone_name}: FAIL ({result.summary.failed} failed, {result.summary.errors} errors)")
        else:
            self.user_output.error(f"✗ {result.zone_name}: ERROR - {result.error_message}")


class BatchReportGenerator:
    """Generate batch validation reports"""
    
    def generate_text_report(self, results: List[BatchValidationResult], 
                           config: Dict) -> str:
        """Generate a text batch validation report"""
        
        report_lines = []
        report_lines.append("Azure DNS Batch Zone Validation Report")
        report_lines.append("=" * 60)
        report_lines.append("")
        
        # Overall summary
        total_zones = len(results)
        passed_zones = len([r for r in results if r.status == "PASS"])
        failed_zones = len([r for r in results if r.status == "FAIL"])
        error_zones = len([r for r in results if r.status == "ERROR"])
        
        report_lines.append("Batch Summary:")
        report_lines.append(f"  Total Zones: {total_zones}")
        report_lines.append(f"  Passed: {passed_zones}")
        report_lines.append(f"  Failed: {failed_zones}")
        report_lines.append(f"  Errors: {error_zones}")
        report_lines.append(f"  Success Rate: {(passed_zones/total_zones*100):.1f}%")
        report_lines.append("")
        
        # Individual zone results
        report_lines.append("Zone Results:")
        for result in results:
            status_icon = "✓" if result.status == "PASS" else "✗"
            report_lines.append(f"  {status_icon} {result.zone_name} ({result.status})")
            if result.status != "ERROR":
                report_lines.append(f"    Records: {result.summary.passed} passed, {result.summary.failed} failed, {result.summary.skipped} skipped")
                if result.summary.errors > 0:
                    report_lines.append(f"    Errors: {result.summary.errors}")
            else:
                report_lines.append(f"    Error: {result.error_message}")
            report_lines.append("")
        
        # Failed zones detail
        failed_results = [r for r in results if r.status == "FAIL"]
        if failed_results:
            report_lines.append("FAILED ZONES DETAIL:")
            for result in failed_results:
                report_lines.append(f"Zone: {result.zone_name}")
                report_lines.append(f"  File: {result.zone_file}")
                report_lines.append(f"  Failed Records: {result.summary.failed}")
                report_lines.append(f"  Error Records: {result.summary.errors}")
                report_lines.append(f"  Success Rate: {result.summary.pass_rate:.1f}%")
                report_lines.append("")
        
        # Overall result
        if failed_zones == 0 and error_zones == 0:
            report_lines.append("BATCH VALIDATION RESULT: PASS")
            report_lines.append("All zones have been successfully validated!")
        else:
            report_lines.append("BATCH VALIDATION RESULT: FAIL")
            report_lines.append(f"{failed_zones + error_zones} zones failed validation.")
        
        return "\n".join(report_lines)
    
    def generate_json_report(self, results: List[BatchValidationResult], 
                           config: Dict) -> str:
        """Generate a JSON batch validation report"""
        
        total_zones = len(results)
        passed_zones = len([r for r in results if r.status == "PASS"])
        failed_zones = len([r for r in results if r.status == "FAIL"])
        error_zones = len([r for r in results if r.status == "ERROR"])
        
        report_data = {
            "batch_summary": {
                "total_zones": total_zones,
                "passed": passed_zones,
                "failed": failed_zones,
                "errors": error_zones,
                "success_rate": (passed_zones/total_zones*100) if total_zones > 0 else 0,
                "overall_status": "PASS" if (failed_zones == 0 and error_zones == 0) else "FAIL"
            },
            "zone_results": [asdict(result) for result in results],
            "config": config
        }
        
        return json.dumps(report_data, indent=2, default=str)


def load_batch_config(config_file: str) -> Dict:
    """Load batch validation configuration"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"Failed to load config file {config_file}: {e}")


def find_zone_files(directory: str, pattern: str = "*.txt") -> List[str]:
    """Find zone files in a directory"""
    from pathlib import Path
    import glob
    
    if os.path.isdir(directory):
        pattern_path = os.path.join(directory, pattern)
        files = glob.glob(pattern_path)
        return [os.path.abspath(f) for f in files]
    else:
        return [directory] if os.path.exists(directory) else []


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Batch validate multiple DNS zone files against Azure DNS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate all .txt files in a directory
  python batch_validation.py /path/to/zones --config batch_config.json
  
  # Validate specific zone files
  python batch_validation.py zone1.txt zone2.txt --nameserver ns1-01.azure-dns.com
  
  # Parallel validation with custom config
  python batch_validation.py /path/to/zones --config batch_config.json --parallel
  
  # Generate JSON report
  python batch_validation.py /path/to/zones --config batch_config.json --format json --output batch_report.json

Batch configuration file format (JSON):
{
    "nameserver": "ns1-01.azure-dns.com",
    "timeout": 10,
    "retry_count": 3,
    "parallel": true,
    "max_workers": 3,
    "verbose": false,
    "zones": {
        "example": {
            "nameserver": "ns1-example.azure-dns.com"
        }
    }
}
        """
    )
    
    parser.add_argument("zones", nargs="+", 
                       help="Zone files or directory containing zone files")
    parser.add_argument("-n", "--nameserver", 
                       help="Default Azure DNS nameserver to use")
    parser.add_argument("-c", "--config", help="Batch configuration file (JSON)")
    parser.add_argument("-o", "--output", help="Output file for the report")
    parser.add_argument("-f", "--format", choices=["text", "json"], 
                       default="text", help="Output format (default: text)")
    parser.add_argument("--parallel", action="store_true",
                       help="Enable parallel validation")
    parser.add_argument("--max-workers", type=int, default=3,
                       help="Maximum parallel workers (default: 3)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose output")
    parser.add_argument("--pattern", default="*.txt",
                       help="File pattern for directory scanning (default: *.txt)")
    parser.add_argument("--log-file", help="Save detailed logs to file")
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = {}
        if args.config:
            config = load_batch_config(args.config)
        
        # Override config with command line arguments
        if args.nameservers:
            config['nameservers'] = args.nameservers
        if args.parallel:
            config['parallel'] = True
        if args.max_workers:
            config['max_workers'] = args.max_workers
        if args.verbose:
            config['verbose'] = True
        
        # Setup logging
        logger = setup_logging(config.get('verbose', False), args.log_file)
        user_output = UserOutput(config.get('verbose', False))
        
        logger.info("Batch zone validation started")
        
        # Find zone files
        zone_files = []
        for zone_path in args.zones:
            found_files = find_zone_files(zone_path, args.pattern)
            zone_files.extend(found_files)
        
        if not zone_files:
            user_output.error("No zone files found")
            sys.exit(1)
        
        user_output.info(f"Found {len(zone_files)} zone files to validate")
        
        # Check nameserver configuration
        if not config.get('nameserver') and not config.get('zones') and not args.nameserver:
            user_output.error("Must specify nameserver using --nameserver or --config")
            sys.exit(1)
        
        # Set nameserver from command line if provided
        if args.nameserver:
            config['nameserver'] = args.nameserver
        
        # Initialize batch validator
        validator = BatchValidator(config, logger)
        
        # Perform batch validation
        start_time = time.time()
        results = validator.validate_batch(zone_files, config.get('nameserver'))
        elapsed_time = time.time() - start_time
        
        # Generate report
        reporter = BatchReportGenerator()
        
        if args.format == "json":
            report = reporter.generate_json_report(results, config)
        else:
            report = reporter.generate_text_report(results, config)
        
        # Output report
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            user_output.info(f"Batch validation report saved to: {args.output}")
        else:
            user_output.info("\n" + report)
        
        # Summary
        total_zones = len(results)
        passed_zones = len([r for r in results if r.status == "PASS"])
        failed_zones = len([r for r in results if r.status == "FAIL"])
        error_zones = len([r for r in results if r.status == "ERROR"])
        
        user_output.info(f"\nBatch validation completed in {elapsed_time:.1f} seconds")
        user_output.info(f"Results: {passed_zones}/{total_zones} zones passed ({(passed_zones/total_zones*100):.1f}%)")
        
        if failed_zones == 0 and error_zones == 0:
            user_output.success("✓ BATCH VALIDATION PASSED: All zones validated successfully!")
            logger.info("Batch validation completed successfully")
            sys.exit(0)
        else:
            user_output.error(f"✗ BATCH VALIDATION FAILED: {failed_zones + error_zones} zones failed")
            logger.warning(f"Batch validation failed: {failed_zones} failed, {error_zones} errors")
            sys.exit(1)
    
    except KeyboardInterrupt:
        user_output.info("\nBatch validation cancelled by user")
        sys.exit(1)
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        user_output.error(f"Batch validation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
