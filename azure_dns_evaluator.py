#!/usr/bin/env python3
"""
Azure DNS Zone File Evaluator

A tool to evaluate BIND-compliant zone files for compatibility with Azure DNS.
This tool parses DNS zone files, validates records, and provides recommendations
for successful import into Azure DNS.

Author: GitHub CoPilot with prompts from Jon Beck
Date: August 6, 2025
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import json
import re
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime

# DNS record types supported by Azure DNS
AZURE_SUPPORTED_RECORD_TYPES = {
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'CAA'
}

# Azure DNS limitations
AZURE_DNS_LIMITS = {
    'max_record_sets': 10000,
    'max_records_per_set': 20,
    'max_txt_records_per_set': 400,  # TXT records have a higher limit
    'max_txt_record_length': 1024,
    'max_txt_record_set_size': 4096,  # 4KB total size for all TXT records in a record set
    'max_label_length': 63,
    'max_domain_name_length': 253,
    'min_ttl': 1,
    'max_ttl': 2147483647,
    # Import API limitations
    'max_import_lines': 10000,  # Maximum lines in zone file for import API
    'max_import_record_sets': 3000  # Maximum record sets for single import operation
}


def setup_logging(verbose: bool = False, log_file: str = None) -> logging.Logger:
    """Setup logging configuration"""
    # Create logger
    logger = logging.getLogger('azure_dns_evaluator')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler (only for DEBUG level in verbose mode)
    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler (if log file specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


class UserOutput:
    """Handle user-facing output separate from logging"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def info(self, message: str):
        """Print informational message to user"""
        print(message)
    
    def success(self, message: str):
        """Print success message to user"""
        print(message)
    
    def warning(self, message: str):
        """Print warning message to user"""
        print(f"WARNING: {message}")
    
    def error(self, message: str):
        """Print error message to user"""
        print(f"ERROR: {message}", file=sys.stderr)
    
    def verbose_info(self, message: str):
        """Print verbose information if verbose mode is enabled"""
        if self.verbose:
            print(f"[VERBOSE] {message}")
    
    def notice(self, message: str):
        """Print notice message to user"""
        print(f"NOTICE: {message}")


class ValidationLevel(Enum):
    """Validation severity levels"""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class ValidationResult:
    """Result of a validation check"""
    level: ValidationLevel
    message: str
    record_name: Optional[str] = None
    record_type: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class DNSRecord:
    """Represents a DNS record"""
    name: str
    ttl: int
    record_class: str
    record_type: str
    rdata: str
    line_number: int


@dataclass
class ZoneInfo:
    """Information about the DNS zone"""
    origin: str
    soa_record: Optional[DNSRecord] = None
    records: List[DNSRecord] = None
    total_records: int = 0
    total_lines: int = 0  # Total lines in the zone file
    record_types: Dict[str, int] = None

    def __post_init__(self):
        if self.records is None:
            self.records = []
        if self.record_types is None:
            self.record_types = {}


class ZoneFileParser:
    """Parser for BIND zone files"""
    
    def __init__(self, logger: logging.Logger = None):
        self.current_origin = ""
        self.current_ttl = 3600
        self.line_number = 0
        self.logger = logger or logging.getLogger('azure_dns_evaluator.parser')
    
    def parse_file(self, file_path: str) -> ZoneInfo:
        """Parse a zone file and return zone information"""
        self.logger.info(f"Starting to parse zone file: {file_path}")
        zone_info = ZoneInfo(origin="")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.logger.debug(f"Successfully read file with UTF-8 encoding")
        except UnicodeDecodeError:
            self.logger.warning(f"UTF-8 decode failed, trying latin-1 encoding")
            # Try with different encoding
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
            self.logger.debug(f"Successfully read file with latin-1 encoding")
        
        lines = content.splitlines()
        
        # Track total lines for import API limitation
        zone_info.total_lines = len(lines)
        self.logger.info(f"Zone file contains {zone_info.total_lines} lines")
        
        parsed_records = 0
        for line_num, line in enumerate(lines, 1):
            self.line_number = line_num
            processed_line = self._preprocess_line(line)
            
            if not processed_line:
                continue
                
            if processed_line.startswith('$ORIGIN'):
                self._parse_origin(processed_line, zone_info)
                self.logger.debug(f"Line {line_num}: Parsed $ORIGIN directive")
            elif processed_line.startswith('$TTL'):
                self._parse_ttl(processed_line)
                self.logger.debug(f"Line {line_num}: Parsed $TTL directive")
            else:
                record = self._parse_record_line(processed_line, zone_info)
                if record:
                    zone_info.records.append(record)
                    zone_info.record_types[record.record_type] = \
                        zone_info.record_types.get(record.record_type, 0) + 1
                    parsed_records += 1
                    
                    if record.record_type == 'SOA' and not zone_info.soa_record:
                        zone_info.soa_record = record
                        self.logger.debug(f"Line {line_num}: Found SOA record")
                else:
                    self.logger.warning(f"Line {line_num}: Failed to parse record: {processed_line}")
        
        zone_info.total_records = len(zone_info.records)
        self.logger.info(f"Successfully parsed {parsed_records} records from zone file")
        self.logger.debug(f"Record type distribution: {zone_info.record_types}")
        return zone_info
    
    def _preprocess_line(self, line: str) -> str:
        """Clean and preprocess a line from the zone file"""
        # Remove comments
        comment_pos = line.find(';')
        if comment_pos != -1:
            line = line[:comment_pos]
        
        # Strip whitespace
        line = line.strip()
        
        # Skip empty lines
        if not line:
            return ""
        
        return line
    
    def _parse_origin(self, line: str, zone_info: ZoneInfo):
        """Parse $ORIGIN directive"""
        parts = line.split()
        if len(parts) >= 2:
            origin = parts[1].rstrip('.')
            self.current_origin = origin
            if not zone_info.origin:
                zone_info.origin = origin
            self.logger.debug(f"Set origin to: {origin}")
    
    def _parse_ttl(self, line: str):
        """Parse $TTL directive"""
        parts = line.split()
        if len(parts) >= 2:
            try:
                self.current_ttl = int(parts[1])
                self.logger.debug(f"Set default TTL to: {self.current_ttl}")
            except ValueError:
                self.logger.warning(f"Invalid TTL value in $TTL directive: {parts[1]}")
                pass
    
    def _parse_record_line(self, line: str, zone_info: ZoneInfo) -> Optional[DNSRecord]:
        """Parse a DNS record line"""
        parts = line.split()
        if len(parts) < 3:
            return None
        
        # Determine the format of the record line
        # Format can be: name [ttl] [class] type rdata
        # or: [ttl] [class] type rdata (name inherited from previous)
        
        name = ""
        ttl = self.current_ttl
        record_class = "IN"
        record_type = ""
        rdata = ""
        
        i = 0
        
        # Parse name (if present)
        if not parts[i].isdigit() and parts[i].upper() not in ['IN', 'CH', 'HS']:
            name = parts[i]
            if name == '@':
                name = zone_info.origin or self.current_origin
            elif not name.endswith('.'):
                name = f"{name}.{zone_info.origin or self.current_origin}"
            i += 1
        else:
            # Use previous name (would need state tracking for full implementation)
            name = zone_info.origin or self.current_origin
        
        # Parse TTL (if present)
        if i < len(parts) and parts[i].isdigit():
            try:
                ttl = int(parts[i])
                i += 1
            except ValueError:
                pass
        
        # Parse class (if present)
        if i < len(parts) and parts[i].upper() in ['IN', 'CH', 'HS']:
            record_class = parts[i].upper()
            i += 1
        
        # Parse record type
        if i < len(parts):
            record_type = parts[i].upper()
            i += 1
        
        # Parse rdata (rest of the line)
        if i < len(parts):
            rdata = ' '.join(parts[i:])
        
        if record_type and rdata:
            return DNSRecord(
                name=name.lower(),
                ttl=ttl,
                record_class=record_class,
                record_type=record_type,
                rdata=rdata,
                line_number=self.line_number
            )
        
        return None


class AzureDNSValidator:
    """Validator for Azure DNS compatibility"""
    
    def __init__(self, logger: logging.Logger = None):
        self.validation_results: List[ValidationResult] = []
        self.logger = logger or logging.getLogger('azure_dns_evaluator.validator')
    
    def validate_zone(self, zone_info: ZoneInfo) -> List[ValidationResult]:
        """Validate a zone for Azure DNS compatibility"""
        self.logger.info(f"Starting validation of zone: {zone_info.origin}")
        self.validation_results = []
        
        self._validate_soa_record(zone_info)
        self._validate_record_types(zone_info)
        self._validate_record_limits(zone_info)
        self._validate_record_format(zone_info)
        self._validate_names_and_labels(zone_info)
        self._validate_txt_record_sets(zone_info)
        self._validate_record_set_sizes(zone_info)
        self._validate_import_size_limits(zone_info)
        
        # Log validation summary
        errors = len([r for r in self.validation_results if r.level == ValidationLevel.ERROR])
        warnings = len([r for r in self.validation_results if r.level == ValidationLevel.WARNING])
        infos = len([r for r in self.validation_results if r.level == ValidationLevel.INFO])
        
        self.logger.info(f"Validation completed: {errors} errors, {warnings} warnings, {infos} info messages")
        
        if errors > 0:
            self.logger.warning(f"Zone {zone_info.origin} has {errors} validation errors")
        else:
            self.logger.info(f"Zone {zone_info.origin} passed validation")
        
        return self.validation_results
    
    def _add_result(self, level: ValidationLevel, message: str, 
                   record_name: str = None, record_type: str = None, 
                   line_number: int = None):
        """Add a validation result"""
        result = ValidationResult(
            level=level,
            message=message,
            record_name=record_name,
            record_type=record_type,
            line_number=line_number
        )
        self.validation_results.append(result)
        
        # Log the validation result
        log_message = f"{message}"
        if record_name:
            log_message += f" (record: {record_name})"
        if record_type:
            log_message += f" (type: {record_type})"
        if line_number:
            log_message += f" (line: {line_number})"
        
        if level == ValidationLevel.ERROR:
            self.logger.error(log_message)
        elif level == ValidationLevel.WARNING:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _validate_soa_record(self, zone_info: ZoneInfo):
        """Validate SOA record requirements"""
        if not zone_info.soa_record:
            self._add_result(ValidationLevel.ERROR, "No SOA record found. Azure DNS requires a SOA record.")
            return
        
        soa = zone_info.soa_record
        if soa.ttl < 1 or soa.ttl > AZURE_DNS_LIMITS['max_ttl']:
            self._add_result(
                ValidationLevel.ERROR, 
                f"SOA TTL ({soa.ttl}) is outside Azure DNS limits (1-{AZURE_DNS_LIMITS['max_ttl']})",
                record_name=soa.name,
                record_type=soa.record_type,
                line_number=soa.line_number
            )
    
    def _validate_record_types(self, zone_info: ZoneInfo):
        """Validate record types are supported by Azure DNS"""
        unsupported_types = set(zone_info.record_types.keys()) - AZURE_SUPPORTED_RECORD_TYPES
        
        for record_type in unsupported_types:
            count = zone_info.record_types[record_type]
            self._add_result(
                ValidationLevel.ERROR,
                f"Record type '{record_type}' is not supported by Azure DNS ({count} records found)"
            )
    
    def _validate_record_limits(self, zone_info: ZoneInfo):
        """Validate Azure DNS limits"""
        if zone_info.total_records > AZURE_DNS_LIMITS['max_record_sets']:
            self._add_result(
                ValidationLevel.ERROR,
                f"Too many record sets ({zone_info.total_records}). "
                f"Azure DNS limit is {AZURE_DNS_LIMITS['max_record_sets']}"
            )
    
    def _validate_record_format(self, zone_info: ZoneInfo):
        """Validate record format and content"""
        for record in zone_info.records:
            # Validate TTL
            if record.ttl < AZURE_DNS_LIMITS['min_ttl'] or record.ttl > AZURE_DNS_LIMITS['max_ttl']:
                self._add_result(
                    ValidationLevel.ERROR,
                    f"TTL ({record.ttl}) is outside Azure DNS limits",
                    record_name=record.name,
                    record_type=record.record_type,
                    line_number=record.line_number
                )
            
            # Validate TXT record length
            if record.record_type == 'TXT':
                txt_length = len(record.rdata)
                if txt_length > AZURE_DNS_LIMITS['max_txt_record_length']:
                    self._add_result(
                        ValidationLevel.ERROR,
                        f"TXT record too long ({txt_length} chars). "
                        f"Azure DNS limit is {AZURE_DNS_LIMITS['max_txt_record_length']}",
                        record_name=record.name,
                        record_type=record.record_type,
                        line_number=record.line_number
                    )
    
    def _validate_names_and_labels(self, zone_info: ZoneInfo):
        """Validate DNS names and labels"""
        for record in zone_info.records:
            # Validate domain name length
            if len(record.name) > AZURE_DNS_LIMITS['max_domain_name_length']:
                self._add_result(
                    ValidationLevel.ERROR,
                    f"Domain name too long ({len(record.name)} chars). "
                    f"Azure DNS limit is {AZURE_DNS_LIMITS['max_domain_name_length']}",
                    record_name=record.name,
                    record_type=record.record_type,
                    line_number=record.line_number
                )
            
            # Validate label length
            labels = record.name.split('.')
            for label in labels:
                if len(label) > AZURE_DNS_LIMITS['max_label_length']:
                    self._add_result(
                        ValidationLevel.ERROR,
                        f"Label '{label}' too long ({len(label)} chars). "
                        f"Azure DNS limit is {AZURE_DNS_LIMITS['max_label_length']}",
                        record_name=record.name,
                        record_type=record.record_type,
                        line_number=record.line_number
                    )

    def _validate_txt_record_sets(self, zone_info: ZoneInfo):
        """Validate TXT record sets don't exceed 4KB total size"""
        # Group TXT records by name (record set)
        txt_record_sets = {}
        for record in zone_info.records:
            if record.record_type == 'TXT':
                if record.name not in txt_record_sets:
                    txt_record_sets[record.name] = []
                txt_record_sets[record.name].append(record)
        
        # Check each TXT record set total size
        for record_name, txt_records in txt_record_sets.items():
            total_size = 0
            line_numbers = []
            
            for record in txt_records:
                # Calculate the actual size of the TXT record data
                # Remove quotes if present and calculate UTF-8 byte length
                rdata_clean = record.rdata.strip('"\'')
                total_size += len(rdata_clean.encode('utf-8'))
                line_numbers.append(record.line_number)
            
            if total_size > AZURE_DNS_LIMITS['max_txt_record_set_size']:
                lines_info = f" (lines {', '.join(map(str, line_numbers))})" if line_numbers else ""
                self._add_result(
                    ValidationLevel.ERROR,
                    f"TXT record set '{record_name}' total size ({total_size} bytes) exceeds Azure DNS limit "
                    f"of {AZURE_DNS_LIMITS['max_txt_record_set_size']} bytes{lines_info}",
                    record_name=record_name,
                    record_type='TXT'
                )

    def _validate_record_set_sizes(self, zone_info: ZoneInfo):
        """Validate that record sets don't exceed Azure DNS record count limits"""
        # Group records by name and type (record set)
        record_sets = {}
        for record in zone_info.records:
            # Skip root NS records as Azure DNS will ignore them during import
            if (record.record_type == 'NS' and 
                (record.name == '@' or 
                 record.name == zone_info.origin or 
                 record.name == f"{zone_info.origin}.")):
                continue
                
            key = (record.name, record.record_type)
            if key not in record_sets:
                record_sets[key] = []
            record_sets[key].append(record)
        
        # Check each record set size
        for (record_name, record_type), records in record_sets.items():
            record_count = len(records)
            line_numbers = [str(record.line_number) for record in records]
            
            # Determine the appropriate limit based on record type
            if record_type == 'TXT':
                max_records = AZURE_DNS_LIMITS['max_txt_records_per_set']
            else:
                max_records = AZURE_DNS_LIMITS['max_records_per_set']
            
            if record_count > max_records:
                lines_info = f" (lines {', '.join(line_numbers)})" if line_numbers else ""
                self._add_result(
                    ValidationLevel.ERROR,
                    f"Record set '{record_name}' of type {record_type} has {record_count} records, "
                    f"which exceeds Azure DNS limit of {max_records} records per set{lines_info}",
                    record_name=record_name,
                    record_type=record_type
                )

    def _validate_import_size_limits(self, zone_info: ZoneInfo):
        """Validate zone file size for Azure DNS import API limitations"""
        
        # Check line count limit
        if zone_info.total_lines > AZURE_DNS_LIMITS['max_import_lines']:
            self._add_result(
                ValidationLevel.ERROR,
                f"Zone file has {zone_info.total_lines} lines, which exceeds the Azure DNS "
                f"import API limit of {AZURE_DNS_LIMITS['max_import_lines']} lines. "
                f"RECOMMENDATION: Use --split option to automatically split this file into "
                f"smaller importable files."
            )
        
        # Calculate unique record sets (name + type combinations), excluding root NS records
        record_sets = set()
        for record in zone_info.records:
            # Skip root NS records as Azure DNS will ignore them during import
            if (record.record_type == 'NS' and 
                (record.name == '@' or 
                 record.name == zone_info.origin or 
                 record.name == f"{zone_info.origin}.")):
                continue
            record_sets.add((record.name, record.record_type))
        
        record_set_count = len(record_sets)
        
        # Check record set count limit for import
        if record_set_count > AZURE_DNS_LIMITS['max_import_record_sets']:
            self._add_result(
                ValidationLevel.ERROR,
                f"Zone file has {record_set_count} record sets, which exceeds the Azure DNS "
                f"import API limit of {AZURE_DNS_LIMITS['max_import_record_sets']} record sets. "
                f"RECOMMENDATION: Use --split option to automatically split this file by "
                f"subdomain or record type."
            )
        
        # Provide helpful warnings when approaching limits
        if zone_info.total_lines > AZURE_DNS_LIMITS['max_import_lines'] * 0.8:
            self._add_result(
                ValidationLevel.WARNING,
                f"Zone file has {zone_info.total_lines} lines, approaching the Azure DNS "
                f"import API limit of {AZURE_DNS_LIMITS['max_import_lines']} lines. "
                f"Consider monitoring file size for future imports."
            )
        
        if record_set_count > AZURE_DNS_LIMITS['max_import_record_sets'] * 0.8:
            self._add_result(
                ValidationLevel.WARNING,
                f"Zone file has {record_set_count} record sets, approaching the Azure DNS "
                f"import API limit of {AZURE_DNS_LIMITS['max_import_record_sets']} record sets. "
                f"Consider monitoring record set count for future imports."
            )


class ZoneSplitter:
    """Handle zone file splitting for large files"""
    
    def __init__(self, zone_info: ZoneInfo, original_file_path: str, logger: logging.Logger = None):
        self.zone_info = zone_info
        self.original_file_path = original_file_path
        self.base_name = Path(original_file_path).stem
        self.output_dir = Path(original_file_path).parent / f"{self.base_name}_split"
        self.logger = logger or logging.getLogger('azure_dns_evaluator.splitter')
        # Get TTL from SOA record or use default
        self.default_ttl = 3600
        if zone_info.soa_record:
            self.default_ttl = zone_info.soa_record.ttl
    
    def calculate_optimal_splits(self) -> int:
        """Calculate optimal number of splits based on file size and record sets"""
        total_lines = self.zone_info.total_lines
        max_lines_per_file = AZURE_DNS_LIMITS['max_import_lines']
        
        # Calculate unique record sets (name + type combinations), excluding root NS records
        record_sets = set()
        for record in self.zone_info.records:
            # Skip root NS records as Azure DNS will ignore them during import
            if (record.record_type == 'NS' and 
                (record.name == '@' or 
                 record.name == self.zone_info.origin or 
                 record.name == f"{self.zone_info.origin}.")):
                continue
            record_sets.add((record.name, record.record_type))
        
        total_record_sets = len(record_sets)
        max_record_sets_per_file = AZURE_DNS_LIMITS['max_import_record_sets']
        
        # Calculate minimum splits needed for both constraints
        min_splits_lines = max(1, (total_lines + max_lines_per_file - 1) // max_lines_per_file)
        min_splits_record_sets = max(1, (total_record_sets + max_record_sets_per_file - 1) // max_record_sets_per_file)
        
        # Use the larger of the two requirements
        min_splits = max(min_splits_lines, min_splits_record_sets)
        
        # For very large files (like 200,000 lines), ensure we have at least 20 splits
        if total_lines >= 200000:
            min_splits = max(min_splits, 20)
        
        self.logger.info(f"Calculated optimal splits: {min_splits} files needed")
        self.logger.debug(f"Lines constraint: {min_splits_lines}, Record sets constraint: {min_splits_record_sets}")
        
        return min_splits
    
    def split_by_subdomain(self, num_splits: int) -> List[str]:
        """Split zone file by subdomain prefixes"""
        # Group records by subdomain level
        subdomain_groups = {}
        soa_record = None
        ns_records = []
        
        for record in self.zone_info.records:
            if record.record_type == 'SOA':
                soa_record = record
            elif record.record_type == 'NS' and record.name == '@':
                ns_records.append(record)
            else:
                # Extract subdomain key for grouping
                name_parts = record.name.replace('@', '').strip('.')
                if name_parts:
                    # Use first part of subdomain for grouping
                    key = name_parts.split('.')[0] if '.' in name_parts else name_parts
                else:
                    key = '@'  # Root domain
                
                if key not in subdomain_groups:
                    subdomain_groups[key] = []
                subdomain_groups[key].append(record)
        
        # Sort groups by size (largest first) for better distribution
        sorted_groups = sorted(subdomain_groups.items(), 
                             key=lambda x: len(x[1]), reverse=True)
        
        # Distribute groups across files
        files = [[] for _ in range(num_splits)]
        file_sizes = [0] * num_splits
        
        for group_key, records in sorted_groups:
            # Find file with minimum records
            min_file_idx = min(range(num_splits), key=lambda i: file_sizes[i])
            files[min_file_idx].extend(records)
            file_sizes[min_file_idx] += len(records)
        
        return self._write_split_files(files, soa_record, ns_records)
    
    def split_evenly(self, num_splits: int) -> List[str]:
        """Split zone file evenly by record count"""
        non_essential_records = [r for r in self.zone_info.records 
                               if r.record_type not in ['SOA', 'NS'] or r.name != '@']
        
        soa_record = next((r for r in self.zone_info.records if r.record_type == 'SOA'), None)
        ns_records = [r for r in self.zone_info.records 
                     if r.record_type == 'NS' and r.name == '@']
        
        records_per_file = len(non_essential_records) // num_splits
        remainder = len(non_essential_records) % num_splits
        
        files = []
        start_idx = 0
        
        for i in range(num_splits):
            file_size = records_per_file + (1 if i < remainder else 0)
            end_idx = start_idx + file_size
            files.append(non_essential_records[start_idx:end_idx])
            start_idx = end_idx
        
        return self._write_split_files(files, soa_record, ns_records)
    
    def _write_split_files(self, file_records: List[List], soa_record, ns_records: List) -> List[str]:
        """Write split files to disk"""
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        written_files = []
        
        for i, records in enumerate(file_records):
            if not records:  # Skip empty files
                continue
                
            filename = self.output_dir / f"{self.base_name}_part_{i+1:02d}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                # Write zone header
                f.write(f"$ORIGIN {self.zone_info.origin}\n")
                f.write(f"$TTL {self.default_ttl}\n\n")
                
                # Write SOA record (only in first file)
                if i == 0 and soa_record:
                    f.write(f"{soa_record.name}\t{soa_record.ttl}\t{soa_record.record_class}\t{soa_record.record_type}\t{soa_record.rdata}\n")
                
                # Write NS records (only in first file)
                if i == 0:
                    for ns_record in ns_records:
                        f.write(f"{ns_record.name}\t{ns_record.ttl}\t{ns_record.record_class}\t{ns_record.record_type}\t{ns_record.rdata}\n")
                
                if records and (i == 0 and (soa_record or ns_records)):
                    f.write("\n")  # Add blank line after header records
                
                # Write other records
                for record in records:
                    f.write(f"{record.name}\t{record.ttl}\t{record.record_class}\t{record.record_type}\t{record.rdata}\n")
            
            written_files.append(str(filename))
        
        return written_files
    
    def split_zone_file(self, method: str = "subdomain") -> List[str]:
        """Split the zone file using specified method"""
        self.logger.info(f"Starting zone file split using method: {method}")
        num_splits = self.calculate_optimal_splits()
        
        if method == "subdomain":
            result = self.split_by_subdomain(num_splits)
        else:
            result = self.split_evenly(num_splits)
        
        self.logger.info(f"Successfully split zone file into {len(result)} files")
        return result


class ReportGenerator:
    """Generate evaluation reports"""
    
    def generate_text_report(self, zone_info: ZoneInfo, 
                           validation_results: List[ValidationResult]) -> str:
        """Generate a text report"""
        report_lines = []
        report_lines.append("Azure DNS Zone File Evaluation Report")
        report_lines.append("=" * 50)
        report_lines.append("")
        
        # Zone summary
        report_lines.append("Zone Information:")
        report_lines.append(f"  Origin: {zone_info.origin}")
        report_lines.append(f"  Total Records: {zone_info.total_records}")
        report_lines.append(f"  Total Lines: {zone_info.total_lines}")
        
        # Calculate unique record sets (excluding root NS records that Azure DNS ignores)
        record_sets = set()
        for record in zone_info.records:
            # Skip root NS records as Azure DNS will ignore them during import
            if (record.record_type == 'NS' and 
                (record.name == '@' or 
                 record.name == zone_info.origin or 
                 record.name == f"{zone_info.origin}.")):
                continue
            record_sets.add((record.name, record.record_type))
        record_set_count = len(record_sets)
        report_lines.append(f"  Total Record Sets: {record_set_count}")
        report_lines.append(f"  (Note: Root NS records excluded as Azure DNS manages them automatically)")
        report_lines.append("")
        
        # Record type summary
        report_lines.append("Record Types:")
        for record_type, count in sorted(zone_info.record_types.items()):
            status = "[SUPPORTED]" if record_type in AZURE_SUPPORTED_RECORD_TYPES else "[UNSUPPORTED]"
            report_lines.append(f"  {status} {record_type}: {count}")
        report_lines.append("")
        
        # Validation results
        errors = [r for r in validation_results if r.level == ValidationLevel.ERROR]
        warnings = [r for r in validation_results if r.level == ValidationLevel.WARNING]
        infos = [r for r in validation_results if r.level == ValidationLevel.INFO]
        
        report_lines.append("Validation Summary:")
        report_lines.append(f"  Errors: {len(errors)}")
        report_lines.append(f"  Warnings: {len(warnings)}")
        report_lines.append(f"  Info: {len(infos)}")
        report_lines.append("")
        
        if errors:
            report_lines.append("ERRORS:")
            for error in errors:
                line_info = f" (line {error.line_number})" if error.line_number else ""
                record_info = f" [{error.record_type}]" if error.record_type else ""
                report_lines.append(f"  [ERROR] {error.message}{record_info}{line_info}")
            report_lines.append("")
        
        if warnings:
            report_lines.append("WARNINGS:")
            for warning in warnings:
                line_info = f" (line {warning.line_number})" if warning.line_number else ""
                record_info = f" [{warning.record_type}]" if warning.record_type else ""
                report_lines.append(f"  [WARNING] {warning.message}{record_info}{line_info}")
            report_lines.append("")
        
        # Recommendations
        report_lines.append("Recommendations:")
        if not errors:
            report_lines.append("  [PASS] Zone file appears compatible with Azure DNS!")
            report_lines.append("  [PASS] You can proceed with importing this zone file to Azure DNS.")
        else:
            report_lines.append("  [FAIL] Zone file has compatibility issues that must be resolved.")
            report_lines.append("  [FAIL] Fix all errors before importing to Azure DNS.")
            report_lines.append("")
            report_lines.append("Next Steps:")
            report_lines.append("  1. Review and fix all reported errors")
            report_lines.append("  2. Re-run this evaluation tool")
            report_lines.append("  3. Import to Azure DNS using Azure CLI or PowerShell")
        
        return "\n".join(report_lines)
    
    def generate_json_report(self, zone_info: ZoneInfo, 
                           validation_results: List[ValidationResult]) -> str:
        """Generate a JSON report"""
        report_data = {
            "zone_info": asdict(zone_info),
            "validation_results": [asdict(result) for result in validation_results],
            "summary": {
                "total_records": zone_info.total_records,
                "error_count": len([r for r in validation_results if r.level == ValidationLevel.ERROR]),
                "warning_count": len([r for r in validation_results if r.level == ValidationLevel.WARNING]),
                "is_azure_compatible": len([r for r in validation_results if r.level == ValidationLevel.ERROR]) == 0
            }
        }
        return json.dumps(report_data, indent=2, default=str)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Evaluate BIND zone files for Azure DNS compatibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python azure_dns_evaluator.py zone.txt
  python azure_dns_evaluator.py zone.txt --output report.txt
  python azure_dns_evaluator.py zone.txt --format json --output report.json
  python azure_dns_evaluator.py large_zone.txt --split
  python azure_dns_evaluator.py large_zone.txt --split --split-method even
  python azure_dns_evaluator.py zone.txt --log-file validation.log
        """
    )
    
    parser.add_argument("zone_file", help="Path to the BIND zone file")
    parser.add_argument("-o", "--output", help="Output file for the report")
    parser.add_argument("-f", "--format", choices=["text", "json"], 
                       default="text", help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose output")
    parser.add_argument("--split", action="store_true",
                       help="Automatically split large zone files into smaller files")
    parser.add_argument("--split-method", choices=["subdomain", "even"],
                       default="subdomain", help="Method for splitting files (default: subdomain)")
    parser.add_argument("--log-file", help="Save detailed logs to file")
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose, args.log_file)
    user_output = UserOutput(args.verbose)
    
    logger.info(f"Azure DNS Zone File Evaluator started")
    logger.info(f"Command line args: {' '.join(sys.argv[1:])}")
    
    # Check if zone file exists
    if not os.path.exists(args.zone_file):
        error_msg = f"Zone file '{args.zone_file}' not found."
        logger.error(error_msg)
        user_output.error(error_msg)
        sys.exit(1)
    
    try:
        # Initialize tracking variables
        split_performed = False
        
        # Parse zone file
        user_output.verbose_info(f"Parsing zone file: {args.zone_file}")
        logger.info(f"Starting zone file parsing: {args.zone_file}")
        
        parser_instance = ZoneFileParser(logger)
        zone_info = parser_instance.parse_file(args.zone_file)
        
        user_output.verbose_info(f"Found {zone_info.total_records} records")
        
        # Validate for Azure DNS
        user_output.verbose_info("Validating for Azure DNS compatibility...")
        
        validator = AzureDNSValidator(logger)
        validation_results = validator.validate_zone(zone_info)
        
        # Check if splitting is needed or requested
        needs_splitting = False
        error_count = len([r for r in validation_results if r.level == ValidationLevel.ERROR])
        
        # Check if file exceeds import limits (excluding root NS records)
        record_sets = set()
        for r in zone_info.records:
            # Skip root NS records as Azure DNS will ignore them during import
            if (r.record_type == 'NS' and 
                (r.name == '@' or 
                 r.name == zone_info.origin or 
                 r.name == f"{zone_info.origin}.")):
                continue
            record_sets.add((r.name, r.record_type))
        if (zone_info.total_lines > AZURE_DNS_LIMITS['max_import_lines'] or 
            len(record_sets) > AZURE_DNS_LIMITS['max_import_record_sets']):
            needs_splitting = True
            logger.warning(f"Zone file exceeds import limits: {zone_info.total_lines} lines, {len(record_sets)} record sets")
        
        # Handle splitting
        if args.split and needs_splitting:
            user_output.verbose_info("Zone file exceeds Azure DNS import limits. Splitting...")
            logger.info(f"Starting zone file splitting using method: {args.split_method}")
            
            splitter = ZoneSplitter(zone_info, args.zone_file, logger)
            split_files = splitter.split_zone_file(args.split_method)
            split_performed = True
            
            user_output.info(f"\nZone file has been split into {len(split_files)} files:")
            for split_file in split_files:
                user_output.info(f"  - {split_file}")
            user_output.info(f"\nFiles saved to: {splitter.output_dir}")
            user_output.info("Each split file should now be within Azure DNS import limits.")
            
            # Validate split files to confirm they're within limits
            if args.verbose:
                user_output.info("\nValidating split files...")
                logger.info("Starting validation of split files")
                all_valid = True
                for i, split_file in enumerate(split_files):
                    split_parser = ZoneFileParser(logger)
                    split_zone = split_parser.parse_file(split_file)
                    split_validator = AzureDNSValidator(logger)
                    split_results = split_validator.validate_zone(split_zone)
                    
                    # For non-first files, ignore SOA validation errors (expected)
                    if i > 0:
                        split_results = [r for r in split_results 
                                       if not ("SOA record" in r.message and r.level == ValidationLevel.ERROR)]
                    
                    split_errors = len([r for r in split_results if r.level == ValidationLevel.ERROR])
                    
                    if split_errors > 0:
                        user_output.warning(f"{Path(split_file).name}: {split_errors} errors")
                        all_valid = False
                    else:
                        if i == 0:
                            user_output.info(f"  OK: {Path(split_file).name}: Valid for import (main file with SOA)")
                        else:
                            user_output.info(f"  OK: {Path(split_file).name}: Valid for import (additional records)")
                
                if all_valid:
                    user_output.success("\nSUCCESS: All split files are valid for Azure DNS import!")
                    user_output.info("Import instructions:")
                    user_output.info("1. Import the main file first (part_01.txt)")
                    user_output.info("2. Then import each additional file to add records to the zone")
                    logger.info("All split files validated successfully")
                else:
                    user_output.warning("Some split files still have validation errors.")
                    logger.warning("Some split files failed validation")
        
        elif needs_splitting and not args.split:
            user_output.notice(f"This zone file exceeds Azure DNS import limits.")
            user_output.info(f"Lines: {zone_info.total_lines} (limit: {AZURE_DNS_LIMITS['max_import_lines']})")
            user_output.info(f"Record sets: {len(record_sets)} (limit: {AZURE_DNS_LIMITS['max_import_record_sets']})")
            user_output.info(f"Run with --split to automatically create smaller importable files.")
            logger.info("Zone file exceeds limits but splitting not requested")
        
        # Generate report
        reporter = ReportGenerator()
        
        if args.format == "json":
            report = reporter.generate_json_report(zone_info, validation_results)
        else:
            report = reporter.generate_text_report(zone_info, validation_results)
        
        # Output report
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            user_output.info(f"Report saved to: {args.output}")
            logger.info(f"Report saved to: {args.output}")
        else:
            user_output.info(report)
        
        # Exit with error code if validation failed
        error_count = len([r for r in validation_results if r.level == ValidationLevel.ERROR])
        
        # If splitting was successful, don't exit with error even if original file had issues
        if split_performed:
            user_output.success(f"\nSUCCESS: Zone file successfully split into importable files.")
            logger.info("Zone splitting completed successfully")
            sys.exit(0)
        elif error_count > 0:
            logger.warning(f"Validation failed with {error_count} errors")
            sys.exit(1)
        else:
            logger.info("Validation completed successfully")
    
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        logger.error(error_msg, exc_info=True)
        user_output.error(error_msg)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
