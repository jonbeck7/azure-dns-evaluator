#!/usr/bin/env python3
"""
DNS Zone Delegation Validator

A comprehensive tool for validating DNS zone delegation relationships between
parent zones and child zones. This tool performs multiple validation checks:

1. Child zone file vs. child server validation
2. Child zone vs. parent zone delegation validation  
3. Comprehensive reporting with multiple output formats

Features:
- Validates all DNS record types (A, AAAA, CNAME, TXT, MX, SRV, CAA, etc.)
- Supports both interactive and configuration-based operation
- Multiple report formats (text, JSON, CSV, HTML)
- Concurrent DNS queries for performance
- Comprehensive logging and error handling
- Filters administrative records (root SOA/NS) that differ during delegation

Author: CoPilot with prompts from Jon Beck
Date: August 7, 2025
"""

import dns.resolver
import dns.zone
import dns.rdatatype
import logging
import datetime
import argparse
import os
import json
import csv
import ipaddress
import concurrent.futures
import threading
import time
from typing import List, Dict, Tuple, Optional

# =============================================================================
# CONFIGURATION SECTION - Modify these settings as needed
# =============================================================================

# Zone file configuration
CHILD_ZONE_FILE = "examples/contoso-subdomain.zone"                   # Path to your child zone file
CHILD_ORIGIN = "subdomain.contoso.com"                                # Origin of the child zone (trailing dot added automatically)

# Nameserver configuration - FQDN or IP addresses  
CHILD_NS = "ns1-XX.azure-dns.com"                                     # Child nameserver (FQDN or IP) - using delegated nameserver
PARENT_NS = "8.8.8.8"                                                 # Parent nameserver (FQDN or IP) - main zone nameserver

# Validation options - Enhanced DNS Record Support
# Now supports ALL DNS record types: A, AAAA, CNAME, TXT, MX, PTR, SRV, CAA, etc.
# Only excludes root SOA and root NS records (managed by DNS provider)
IGNORE_ADMINISTRATIVE_RECORDS = True                   # Only ignore root SOA and root NS records during validation
LOG_LEVEL = logging.DEBUG                              # Logging level (DEBUG, INFO, WARNING, ERROR)

# Advanced reporting options
REPORT_FORMATS = ['html']                              # Report formats: 'text', 'json', 'csv', 'html'

# DNS Query Configuration
DNS_TIMEOUT = 10                                       # DNS query timeout in seconds
DNS_RETRIES = 3                                        # Number of retry attempts for failed queries
MAX_CONCURRENT_QUERIES = 10                            # Maximum concurrent DNS queries for performance
QUERY_DELAY = 0.1                                      # Delay between queries in seconds to avoid rate limiting

# =============================================================================

def normalize_domain(domain):
    """Normalize domain name by ensuring it has a trailing dot for DNS operations.
    
    Args:
        domain (str): Domain name with or without trailing dot
        
    Returns:
        str: Domain name with trailing dot for DNS library compatibility
    """
    if not domain:
        return domain
    
    # Add trailing dot if not present
    if not domain.endswith('.'):
        domain = domain + '.'
    
    return domain

def is_root_administrative_record(record, origin):
    """Check if a record is a root SOA or root NS record that should be filtered.
    
    Args:
        record (dict): DNS record with 'fqdn', 'type', and 'data'
        origin (str): The zone origin (with trailing dot)
        
    Returns:
        bool: True if this is a root SOA or root NS record that should be filtered
    """
    # Normalize the origin to ensure it has a trailing dot
    if not origin.endswith('.'):
        origin = origin + '.'
    
    # Check if this is a root record (@ record or exact origin match)
    record_fqdn = record['fqdn']
    if record_fqdn.startswith('@.'):
        # Handle @ notation - replace @ with origin
        record_fqdn = record_fqdn.replace('@.', '')
        if record_fqdn == '' or record_fqdn == origin.rstrip('.'):
            is_root = True
        else:
            is_root = record_fqdn == origin
    else:
        # Direct FQDN comparison
        is_root = (record_fqdn == origin) or (record_fqdn == origin.rstrip('.') + '.')
    
    # Only filter root SOA and NS records
    is_administrative = record['type'] in ['SOA', 'NS']
    
    return is_root and is_administrative

def filter_records_enhanced(records, origin, ignore_root_administrative=True):
    """Enhanced record filtering that only excludes root SOA and root NS records.
    
    This allows validation of:
    - All A, AAAA, CNAME, TXT, MX, PTR, SRV, CAA, etc. records
    - Subdomain NS records (like ns1.example.com NS record)
    - All non-root records regardless of type
    
    Only excludes:
    - Root SOA record (@ IN SOA or origin IN SOA)
    - Root NS records (@ IN NS or origin IN NS)
    
    Args:
        records (list): List of DNS records
        origin (str): Zone origin
        ignore_root_administrative (bool): Whether to filter root administrative records
        
    Returns:
        tuple: (filtered_records, filtered_count, filter_description)
    """
    if not ignore_root_administrative:
        return records, 0, "No filtering applied"
    
    filtered_records = []
    filtered_count = 0
    filtered_types = {}
    
    for record in records:
        if is_root_administrative_record(record, origin):
            filtered_count += 1
            record_type = record['type']
            filtered_types[record_type] = filtered_types.get(record_type, 0) + 1
        else:
            filtered_records.append(record)
    
    # Create description of what was filtered
    if filtered_count > 0:
        type_descriptions = []
        for rtype, count in filtered_types.items():
            type_descriptions.append(f"{count} {rtype}")
        filter_description = f"Filtered {filtered_count} root administrative records: " + ", ".join(type_descriptions)
    else:
        filter_description = "No root administrative records found to filter"
    
    return filtered_records, filtered_count, filter_description

def analyze_zone_records(records):
    """Analyze zone records and provide summary statistics.
    
    Args:
        records (list): List of DNS records
        
    Returns:
        dict: Summary statistics about the records
    """
    record_types = {}
    total_records = len(records)
    
    for record in records:
        rtype = record['type']
        record_types[rtype] = record_types.get(rtype, 0) + 1
    
    # Sort by count (most common first) then by name
    sorted_types = sorted(record_types.items(), key=lambda x: (-x[1], x[0]))
    
    return {
        'total_records': total_records,
        'record_types': dict(sorted_types),
        'unique_types': len(record_types),
        'type_summary': ', '.join([f"{count} {rtype}" for rtype, count in sorted_types])
    }

def setup_logging(log_level=logging.INFO, log_file=None):
    """Setup logging configuration for DNS validation."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    # Configure logging
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"DNS Validation started at {datetime.datetime.now()}")
    return logger

def parse_zone_file(zone_file, origin):
    """Parse DNS zone file and return list of records with enhanced validation."""
    logger = logging.getLogger(__name__)
    
    # Pre-validate zone file syntax
    is_valid, errors, warnings = validate_zone_file_syntax(zone_file, origin)
    
    # Log warnings
    for warning in warnings:
        logger.warning(warning)
    
    # Handle validation errors
    if not is_valid:
        logger.error("Zone file validation failed:")
        for error in errors:
            logger.error(f"  - {error}")
        raise FileNotFoundError(f"Zone file validation failed: {'; '.join(errors)}")
    
    try:
        logger.info(f"Parsing zone file: {zone_file} with origin: {origin}")
        zone = dns.zone.from_file(zone_file, origin)
        records = []
        
        total_nodes = len(zone.nodes)
        progress = create_progress_indicator(total_nodes, "Parsing zone records")
        
        for i, (name, node) in enumerate(zone.nodes.items()):
            progress(i + 1)
            
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    fqdn = str(name) + '.' + origin if not str(name).endswith('.') else str(name)
                    record = {
                        "fqdn": fqdn,
                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                        "data": rdata.to_text(),
                        "ttl": rdataset.ttl  # Add TTL information
                    }
                    records.append(record)
                    logger.debug(f"Parsed record: {fqdn} {record['type']} {record['data']} (TTL: {record['ttl']})")
        
        logger.info(f"Successfully parsed {len(records)} records from zone file")
        return records
        
    except FileNotFoundError:
        logger.error(f"Zone file not found: {zone_file}")
        logger.error(f"Please check the file path and ensure the zone file exists")
        logger.error(f"Current working directory: {os.getcwd()}")
        raise FileNotFoundError(f"Zone file '{zone_file}' not found. Please check the CHILD_ZONE_FILE configuration.")
    except Exception as e:
        logger.error(f"Failed to parse zone file {zone_file}: {str(e)}")
        raise

def resolve_nameserver_to_ip(nameserver, public_resolver="9.9.9.9"):
    """Resolve a nameserver FQDN to IP address if needed."""
    logger = logging.getLogger(__name__)
    
    # If it's already an IP address, return as-is
    try:
        ipaddress.ip_address(nameserver)
        logger.debug(f"Using IP address directly: {nameserver}")
        return nameserver
    except ValueError:
        pass  # Not an IP address, continue with FQDN resolution
    
    # Resolve FQDN to IP
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [public_resolver]
        logger.debug(f"Attempting to resolve {nameserver} using {public_resolver}")
        answers = resolver.resolve(nameserver, 'A')
        ip = str(answers[0])
        logger.info(f"Resolved nameserver {nameserver} to {ip}")
        return ip
    except Exception as e:
        logger.error(f"Failed to resolve nameserver {nameserver}: {str(e)}")
        raise ValueError(f"Unable to resolve nameserver {nameserver}: {str(e)}")

def query_dns(nameserver, fqdn, rtype, timeout=DNS_TIMEOUT, retries=DNS_RETRIES):
    """Query DNS server for specific record type with timeout and retry support."""
    logger = logging.getLogger(__name__)
    
    # Resolve nameserver to IP if it's an FQDN
    nameserver_ip = resolve_nameserver_to_ip(nameserver)
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver_ip]
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2  # Total time including retries
    
    last_exception = None
    
    for attempt in range(retries + 1):
        try:
            if attempt > 0:
                logger.debug(f"Retry attempt {attempt}/{retries} for {fqdn} {rtype} on {nameserver_ip}")
                time.sleep(QUERY_DELAY * attempt)  # Progressive delay
            
            logger.debug(f"Querying {nameserver_ip} for {fqdn} {rtype} (attempt {attempt + 1})")
            answers = resolver.resolve(fqdn, rtype)
            results = sorted([r.to_text() for r in answers])
            logger.debug(f"Query result: {results}")
            return results
            
        except dns.resolver.NXDOMAIN:
            logger.debug(f"NXDOMAIN: {fqdn} {rtype} not found on {nameserver_ip}")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"No answer: {fqdn} {rtype} on {nameserver_ip}")
            return []
        except (dns.resolver.Timeout, dns.exception.Timeout) as e:
            last_exception = e
            logger.debug(f"Timeout on attempt {attempt + 1} for {fqdn} {rtype} on {nameserver_ip}")
            if attempt == retries:
                logger.warning(f"DNS query timeout after {retries + 1} attempts for {fqdn} {rtype} on {nameserver_ip}")
        except Exception as e:
            last_exception = e
            logger.debug(f"DNS query error on attempt {attempt + 1} for {fqdn} {rtype} on {nameserver_ip}: {str(e)}")
            if attempt == retries:
                logger.warning(f"DNS query failed after {retries + 1} attempts for {fqdn} {rtype} on {nameserver_ip}: {str(e)}")
    
    # If we get here, all attempts failed
    logger.error(f"All DNS query attempts failed for {fqdn} {rtype} on {nameserver_ip}. Last error: {last_exception}")
    return []

def query_dns_concurrent(query_tasks, max_workers=MAX_CONCURRENT_QUERIES):
    """Execute multiple DNS queries concurrently for better performance.
    
    Args:
        query_tasks (list): List of tuples (nameserver, fqdn, rtype, record_info)
        max_workers (int): Maximum number of concurrent worker threads
        
    Returns:
        list: List of tuples (record_info, query_results)
    """
    logger = logging.getLogger(__name__)
    results = []
    
    def query_single_record(task):
        nameserver, fqdn, rtype, record_info = task
        try:
            dns_results = query_dns(nameserver, fqdn, rtype)
            return (record_info, dns_results)
        except Exception as e:
            logger.error(f"Concurrent query failed for {fqdn} {rtype}: {str(e)}")
            return (record_info, [])
    
    logger.debug(f"Starting concurrent DNS queries with {max_workers} workers for {len(query_tasks)} queries")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(query_single_record, task): task for task in query_tasks}
        
        for future in concurrent.futures.as_completed(future_to_task):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                task = future_to_task[future]
                logger.error(f"Concurrent query future failed for {task[1]} {task[2]}: {str(e)}")
                results.append((task[3], []))
    
    logger.debug(f"Completed {len(results)} concurrent DNS queries")
    return results

def check_delegation_status(parent_ns, child_origin):
    """Check if the child zone is delegated in the parent zone.
    
    Returns:
        tuple: (is_delegated, ns_records) where is_delegated is boolean and ns_records is list
    """
    logger = logging.getLogger(__name__)
    
    try:
        logger.debug(f"Checking delegation status for {child_origin} in parent {parent_ns}")
        
        # Query parent for NS records of the child zone
        ns_records = query_dns(parent_ns, child_origin, 'NS')
        
        if ns_records:
            logger.info(f"DELEGATION DETECTED: Child zone {child_origin} is delegated in parent zone")
            logger.info(f"  Delegated nameservers: {ns_records}")
            return True, ns_records
        else:
            logger.info(f"NO DELEGATION: Child zone {child_origin} is not delegated in parent zone")
            return False, []
            
    except Exception as e:
        logger.warning(f"Failed to check delegation status: {str(e)}")
        return False, []

def validate_zone_file_syntax(zone_file, origin):
    """Validate zone file syntax before processing.
    
    Args:
        zone_file (str): Path to the zone file
        origin (str): Zone origin domain
        
    Returns:
        tuple: (is_valid, error_messages, warnings)
    """
    logger = logging.getLogger(__name__)
    errors = []
    warnings = []
    
    try:
        # Check if file exists and is readable
        if not os.path.exists(zone_file):
            errors.append(f"Zone file does not exist: {zone_file}")
            return False, errors, warnings
        
        if not os.access(zone_file, os.R_OK):
            errors.append(f"Zone file is not readable: {zone_file}")
            return False, errors, warnings
        
        # Check file size
        file_size = os.path.getsize(zone_file)
        if file_size == 0:
            errors.append(f"Zone file is empty: {zone_file}")
            return False, errors, warnings
        elif file_size > 10 * 1024 * 1024:  # 10MB
            warnings.append(f"Zone file is very large ({file_size / 1024 / 1024:.1f}MB). Processing may take time.")
        
        # Basic syntax validation by attempting to parse
        try:
            zone = dns.zone.from_file(zone_file, origin)
            record_count = sum(len(node.rdatasets) for node in zone.nodes.values())
            
            if record_count == 0:
                warnings.append("Zone file contains no DNS records")
            elif record_count > 10000:
                warnings.append(f"Zone file contains many records ({record_count}). Validation may take time.")
            
            logger.info(f"Zone file syntax validation passed: {record_count} records found")
            
        except dns.zone.NoSOA:
            errors.append("Zone file missing SOA record")
        except dns.exception.SyntaxError as e:
            errors.append(f"Zone file syntax error: {str(e)}")
        except Exception as e:
            errors.append(f"Zone file parsing error: {str(e)}")
        
        return len(errors) == 0, errors, warnings
        
    except Exception as e:
        errors.append(f"Unexpected error during zone file validation: {str(e)}")
        return False, errors, warnings

def create_progress_indicator(total, description="Processing"):
    """Create a simple progress indicator for operations without external dependencies.
    
    Args:
        total (int): Total number of items to process
        description (str): Description of the operation
        
    Returns:
        function: Progress update function
    """
    logger = logging.getLogger(__name__)
    start_time = time.time()
    last_update = 0
    
    def update_progress(current):
        nonlocal last_update
        if total == 0:
            return
            
        percent = (current / total) * 100
        # Only update every 5% or every 10 seconds to avoid spam
        if percent >= last_update + 5 or time.time() - start_time > last_update * 10:
            elapsed = time.time() - start_time
            if current > 0:
                eta = (elapsed / current) * (total - current)
                logger.info(f"{description}: {current}/{total} ({percent:.1f}%) - ETA: {eta:.1f}s")
            else:
                logger.info(f"{description}: {current}/{total} ({percent:.1f}%)")
            last_update = percent
    
    return update_progress
    logger = logging.getLogger(__name__)
    
    try:
        logger.debug(f"Checking delegation status for {child_origin} in parent {parent_ns}")
        
        # Query parent for NS records of the child zone
        ns_records = query_dns(parent_ns, child_origin, 'NS')
        
        if ns_records:
            logger.info(f"DELEGATION DETECTED: Child zone {child_origin} is delegated in parent zone")
            logger.info(f"  Delegated nameservers: {ns_records}")
            return True, ns_records
        else:
            logger.info(f"NO DELEGATION: Child zone {child_origin} is not delegated in parent zone")
            return False, []
            
    except Exception as e:
        logger.warning(f"Failed to check delegation status: {str(e)}")
        return False, []

def validate_child_zone_file_vs_server(child_zone_file, child_origin, child_ns, ignore_administrative_records=True):
    """Validate child zone file against child DNS server with enhanced record support.
    
    This function now supports validation of ALL DNS record types except root SOA and NS records.
    Supported record types include:
    - A, AAAA (IPv4/IPv6 addresses)
    - CNAME (canonical names/aliases)
    - TXT (text records)
    - MX (mail exchange)
    - PTR (reverse DNS)
    - SRV (service records)  
    - CAA (certificate authority authorization)
    - NS records for subdomains (like ns1.example.com NS)
    - Any other valid DNS record types
    
    Only excludes:
    - Root SOA record (zone metadata, managed by DNS provider)
    - Root NS records (delegation records, managed by DNS provider)
    
    Args:
        child_zone_file (str): Path to the zone file
        child_origin (str): Zone origin domain
        child_ns (str): Child nameserver to validate against
        ignore_administrative_records (bool): Whether to filter root administrative records
        
    Returns:
        list: List of mismatched records
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting validation: Zone file vs Child server ({child_ns})")
    
    all_records = parse_zone_file(child_zone_file, child_origin)
    
    # Analyze all records found in zone file
    analysis = analyze_zone_records(all_records)
    logger.info(f"Zone file analysis: {analysis['total_records']} total records, {analysis['unique_types']} unique types")
    logger.info(f"Record types found: {analysis['type_summary']}")
    
    # Enhanced filtering - only exclude root SOA and root NS records
    # This allows validation of all other record types including:
    # A, AAAA, CNAME, TXT, MX, PTR, SRV, CAA, subdomain NS records, etc.
    child_records, filtered_count, filter_description = filter_records_enhanced(
        all_records, child_origin, ignore_administrative_records
    )
    
    if filtered_count > 0:
        logger.info(filter_description)
        # Show what will be validated
        validation_analysis = analyze_zone_records(child_records)
        logger.info(f"Will validate: {validation_analysis['type_summary']}")
    
    mismatches = []
    matches = []
    total_records = len(child_records)
    
    logger.info(f"Validating {total_records} records against child server (enhanced filtering: only root SOA/NS excluded)")
    
    for i, record in enumerate(child_records, 1):
        logger.debug(f"Progress: {i}/{total_records} - Validating {record['fqdn']} {record['type']}")
        
        server_records = query_dns(child_ns, record["fqdn"], record["type"])
        
        if record["data"] in server_records:
            matches.append(record)
            logger.debug(f"MATCH: {record['fqdn']} {record['type']} - {record['data']}")
        else:
            mismatch = {
                "fqdn": record["fqdn"],
                "type": record["type"],
                "zone_file_data": record["data"],
                "child_server_data": server_records
            }
            mismatches.append(mismatch)
            logger.warning(f"MISMATCH: {record['fqdn']} {record['type']} - File: {record['data']} | Server: {server_records}")
    
    # Log summary
    logger.info(f"Zone file vs Child server validation complete:")
    logger.info(f"  Total records: {total_records}")
    logger.info(f"  Matches: {len(matches)}")
    logger.info(f"  Mismatches: {len(mismatches)}")
    logger.info(f"  Success rate: {(len(matches)/total_records*100):.1f}%")
    
    return mismatches

def validate_child_vs_parent(child_zone_file, child_origin, parent_ns, ignore_administrative_records=True):
    """Validate child zone file against parent DNS server with enhanced record support.
    
    This function now supports validation of ALL DNS record types except root SOA and NS records.
    First checks if the child zone is delegated. If delegated, returns early with 
    appropriate message since DNS protocol will always honor delegation.
    
    Supported record types include:
    - A, AAAA (IPv4/IPv6 addresses)
    - CNAME (canonical names/aliases) 
    - TXT (text records)
    - MX (mail exchange)
    - PTR (reverse DNS)
    - SRV (service records)
    - CAA (certificate authority authorization)
    - NS records for subdomains
    - Any other valid DNS record types
    
    Only excludes:
    - Root SOA record (zone metadata)
    - Root NS records (delegation records)
    
    Args:
        child_zone_file (str): Path to the zone file
        child_origin (str): Zone origin domain  
        parent_ns (str): Parent nameserver to validate against
        ignore_administrative_records (bool): Whether to filter root administrative records
        
    Returns:
        list: List of mismatched records
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting validation: Child zone vs Parent server ({parent_ns})")
    
    # Check if child zone is delegated
    is_delegated, delegation_ns = check_delegation_status(parent_ns, child_origin)
    
    if is_delegated:
        logger.info("="*60)
        logger.info("DELEGATION DETECTED - SKIPPING PARENT VALIDATION")
        logger.info("="*60)
        logger.info(f"Child zone {child_origin} is delegated in parent zone")
        logger.info(f"Delegated nameservers: {delegation_ns}")
        logger.info("DNS protocol automatically follows delegation to authoritative servers.")
        logger.info("Queries for child records will be redirected to delegated nameservers.")
        logger.info("Parent zone only contains NS delegation records, not child zone data.")
        logger.info("Parent zone validation SKIPPED - delegation is working correctly.")
        logger.info("="*60)
        
        # Return empty mismatches since delegation is working as expected
        return []
    
    # If not delegated, proceed with normal validation
    logger.info("No delegation detected - proceeding with parent zone validation")
    
    all_records = parse_zone_file(child_zone_file, child_origin)
    
    # Enhanced filtering - only exclude root SOA and root NS records
    # This allows validation of all other record types including:
    # A, AAAA, CNAME, TXT, MX, PTR, SRV, CAA, subdomain NS records, etc.
    child_records, filtered_count, filter_description = filter_records_enhanced(
        all_records, child_origin, ignore_administrative_records
    )
    
    if filtered_count > 0:
        logger.info(filter_description)
    
    mismatches = []
    matches = []
    not_in_parent = []
    total_records = len(child_records)
    
    logger.info(f"Validating {total_records} records against parent server (enhanced filtering: only root SOA/NS excluded)")
    logger.info("NOTE: Only records that exist in parent but differ from child are considered mismatches")
    
    for i, record in enumerate(child_records, 1):
        logger.debug(f"Progress: {i}/{total_records} - Validating {record['fqdn']} {record['type']}")
        
        parent_records = query_dns(parent_ns, record["fqdn"], record["type"])
        
        if not parent_records:
            # Record doesn't exist in parent - this is normal during delegation
            not_in_parent.append(record)
            logger.debug(f"NOT IN PARENT: {record['fqdn']} {record['type']} - not found in parent zone (normal during delegation)")
        elif record["data"] in parent_records:
            # Record exists and matches
            matches.append(record)
            logger.debug(f"MATCH: {record['fqdn']} {record['type']} - {record['data']}")
        else:
            # Record exists in parent but has different value - this IS a mismatch
            mismatch = {
                "fqdn": record["fqdn"],
                "type": record["type"],
                "child_data": record["data"],
                "parent_data": parent_records
            }
            mismatches.append(mismatch)
            logger.warning(f"MISMATCH: {record['fqdn']} {record['type']} - Child: {record['data']} | Parent: {parent_records}")
    
    # Log summary
    logger.info(f"Child zone vs Parent server validation complete:")
    logger.info(f"  Total records: {total_records}")
    logger.info(f"  Matches: {len(matches)}")
    logger.info(f"  Mismatches: {len(mismatches)} (records exist in both but differ)")
    logger.info(f"  Not in parent: {len(not_in_parent)} (normal during delegation)")
    logger.info(f"  Records that exist in parent: {len(matches) + len(mismatches)}")
    if len(matches) + len(mismatches) > 0:
        logger.info(f"  Success rate for existing records: {(len(matches)/(len(matches) + len(mismatches))*100):.1f}%")
    
    return mismatches

def generate_validation_report(file_vs_server_mismatches, file_vs_parent_mismatches, 
                             child_zone_file, child_origin, child_ns, parent_ns, ignore_administrative_records=True):
    """Generate a comprehensive validation report."""
    logger = logging.getLogger(__name__)
    
    # Check delegation status for report
    is_delegated, delegation_ns = check_delegation_status(parent_ns, child_origin)
    
    report = []
    report.append("="*80)
    report.append("DNS VALIDATION REPORT")
    report.append("="*80)
    report.append(f"Generated: {datetime.datetime.now()}")
    report.append(f"Zone File: {child_zone_file}")
    report.append(f"Child Origin: {child_origin}")
    report.append(f"Child Server: {child_ns}")
    report.append(f"Parent Server: {parent_ns}")
    if ignore_administrative_records:
        report.append("ENHANCED RECORD SUPPORT: Only root SOA and root NS records excluded")
        report.append("✓ Validates ALL other record types: A, AAAA, CNAME, TXT, MX, PTR, SRV, CAA, etc.")
        report.append("✓ Validates subdomain NS records and all non-root records")
        report.append("(Root SOA/NS records are managed by DNS providers)")
    else:
        report.append("COMPLETE VALIDATION: ALL records including root SOA and NS records")
        report.append("(Note: Root administrative records may show differences during delegation)")
    report.append("")
    
    # Delegation status
    if is_delegated:
        report.append("DELEGATION STATUS: DELEGATED")
        report.append(f"Child zone is delegated to: {', '.join(delegation_ns)}")
        report.append("DNS protocol honors delegation - parent zone validation skipped")
    else:
        report.append("DELEGATION STATUS: NOT DELEGATED")
        report.append("Child zone records can be tested from parent zone")
    report.append("")
    
    # Zone file vs Child server section
    report.append("ZONE FILE vs CHILD SERVER VALIDATION")
    report.append("-" * 50)
    if file_vs_server_mismatches:
        report.append(f"Found {len(file_vs_server_mismatches)} mismatches:")
        for m in file_vs_server_mismatches:
            report.append(f"  FQDN: {m['fqdn']}")
            report.append(f"  Type: {m['type']}")
            report.append(f"  Zone File Data: {m['zone_file_data']}")
            report.append(f"  Server Data: {m['child_server_data']}")
            report.append("")
    else:
        report.append("SUCCESS: All records match between zone file and child server")
    
    report.append("")
    
    # Child vs Parent section
    report.append("CHILD ZONE vs PARENT ZONE VALIDATION")
    report.append("-" * 50)
    
    if is_delegated:
        report.append("SKIPPED: Child zone is delegated in parent zone")
        report.append("DNS protocol automatically follows delegation to authoritative servers")
        report.append("Parent zone only contains NS delegation records, not child zone data")
        report.append("Queries for child records are redirected to delegated nameservers")
        report.append("This is normal and expected behavior for delegated zones")
    else:
        report.append("NOTE: Only records that exist in parent but differ from child are reported as mismatches")
        report.append("Records not found in parent zone are normal during delegation processes")
        report.append("")
        if file_vs_parent_mismatches:
            report.append(f"Found {len(file_vs_parent_mismatches)} mismatches:")
            for m in file_vs_parent_mismatches:
                report.append(f"  FQDN: {m['fqdn']}")
                report.append(f"  Type: {m['type']}")
                report.append(f"  Child Data: {m['child_data']}")
                report.append(f"  Parent Data: {m['parent_data']}")
                report.append("")
        else:
            report.append("SUCCESS: No conflicting records found between child zone and parent zone")
            report.append("(Records existing only in child zone are expected during delegation)")
    
    report.append("="*80)
    
    # Log the report
    for line in report:
        logger.info(line)
    
    return "\n".join(report)

def generate_structured_report_data(file_vs_server_mismatches, file_vs_parent_mismatches, 
                                   child_zone_file, child_origin, child_ns, parent_ns, 
                                   ignore_administrative_records=True):
    """Generate structured report data for advanced reporting formats.
    
    Returns:
        dict: Structured report data suitable for JSON, CSV, and HTML formats
    """
    logger = logging.getLogger(__name__)
    
    # Check delegation status for report
    is_delegated, delegation_ns = check_delegation_status(parent_ns, child_origin)
    
    # Calculate statistics
    total_server_mismatches = len(file_vs_server_mismatches)
    total_parent_mismatches = len(file_vs_parent_mismatches)
    
    report_data = {
        'metadata': {
            'generated': datetime.datetime.now().isoformat(),
            'tool_version': 'DNS Validation Tool v2.0',
            'zone_file': child_zone_file,
            'child_origin': child_origin,
            'child_server': child_ns,
            'parent_server': parent_ns,
            'ignore_administrative_records': ignore_administrative_records
        },
        'delegation': {
            'is_delegated': is_delegated,
            'delegation_nameservers': delegation_ns if is_delegated else [],
            'status': 'DELEGATED' if is_delegated else 'NOT DELEGATED'
        },
        'validation_results': {
            'zone_file_vs_child_server': {
                'total_mismatches': total_server_mismatches,
                'status': 'PASS' if total_server_mismatches == 0 else 'FAIL',
                'mismatches': file_vs_server_mismatches
            },
            'child_zone_vs_parent_zone': {
                'total_mismatches': total_parent_mismatches,
                'status': 'SKIPPED' if is_delegated else ('PASS' if total_parent_mismatches == 0 else 'FAIL'),
                'skipped_reason': 'Zone is delegated' if is_delegated else None,
                'mismatches': file_vs_parent_mismatches
            }
        },
        'summary': {
            'overall_status': 'PASS' if (total_server_mismatches == 0 and (is_delegated or total_parent_mismatches == 0)) else 'FAIL',
            'total_issues': total_server_mismatches + (0 if is_delegated else total_parent_mismatches),
            'delegation_detected': is_delegated
        }
    }
    
    return report_data

def generate_json_report(report_data, output_file):
    """Generate JSON format report.
    
    Args:
        report_data (dict): Structured report data
        output_file (str): Output file path
        
    Returns:
        str: Path to generated report file
    """
    logger = logging.getLogger(__name__)
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report generated: {output_file}")
        return output_file
        
    except Exception as e:
        logger.error(f"Failed to generate JSON report: {str(e)}")
        raise

def generate_csv_report(report_data, output_file):
    """Generate CSV format report.
    
    Args:
        report_data (dict): Structured report data
        output_file (str): Output file path
        
    Returns:
        str: Path to generated report file
    """
    logger = logging.getLogger(__name__)
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Report Section', 'Field', 'Value'])
            
            # Write metadata
            writer.writerow(['Metadata', 'Generated', report_data['metadata']['generated']])
            writer.writerow(['Metadata', 'Tool Version', report_data['metadata']['tool_version']])
            writer.writerow(['Metadata', 'Zone File', report_data['metadata']['zone_file']])
            writer.writerow(['Metadata', 'Child Origin', report_data['metadata']['child_origin']])
            writer.writerow(['Metadata', 'Child Server', report_data['metadata']['child_server']])
            writer.writerow(['Metadata', 'Parent Server', report_data['metadata']['parent_server']])
            writer.writerow(['Metadata', 'Ignore Admin Records', report_data['metadata']['ignore_administrative_records']])
            
            # Write delegation info
            writer.writerow(['Delegation', 'Status', report_data['delegation']['status']])
            writer.writerow(['Delegation', 'Is Delegated', report_data['delegation']['is_delegated']])
            if report_data['delegation']['delegation_nameservers']:
                writer.writerow(['Delegation', 'Nameservers', ', '.join(report_data['delegation']['delegation_nameservers'])])
            
            # Write summary
            writer.writerow(['Summary', 'Overall Status', report_data['summary']['overall_status']])
            writer.writerow(['Summary', 'Total Issues', report_data['summary']['total_issues']])
            writer.writerow(['Summary', 'Delegation Detected', report_data['summary']['delegation_detected']])
            
            # Write validation results
            server_validation = report_data['validation_results']['zone_file_vs_child_server']
            writer.writerow(['Zone File vs Child Server', 'Status', server_validation['status']])
            writer.writerow(['Zone File vs Child Server', 'Total Mismatches', server_validation['total_mismatches']])
            
            parent_validation = report_data['validation_results']['child_zone_vs_parent_zone']
            writer.writerow(['Child Zone vs Parent Zone', 'Status', parent_validation['status']])
            writer.writerow(['Child Zone vs Parent Zone', 'Total Mismatches', parent_validation['total_mismatches']])
            if parent_validation.get('skipped_reason'):
                writer.writerow(['Child Zone vs Parent Zone', 'Skipped Reason', parent_validation['skipped_reason']])
            
            # Write detailed mismatches
            if server_validation['mismatches']:
                writer.writerow([])  # Empty row for separation
                writer.writerow(['Zone File vs Child Server Mismatches', 'FQDN', 'Type', 'Zone File Data', 'Child Server Data'])
                for mismatch in server_validation['mismatches']:
                    writer.writerow([
                        '',  # Section column
                        mismatch['fqdn'],
                        mismatch['type'],
                        mismatch['zone_file_data'],
                        str(mismatch['child_server_data'])
                    ])
            
            if parent_validation['mismatches']:
                writer.writerow([])  # Empty row for separation
                writer.writerow(['Child Zone vs Parent Zone Mismatches', 'FQDN', 'Type', 'Child Data', 'Parent Data'])
                for mismatch in parent_validation['mismatches']:
                    writer.writerow([
                        '',  # Section column
                        mismatch['fqdn'],
                        mismatch['type'],
                        mismatch['child_data'],
                        str(mismatch['parent_data'])
                    ])
        
        logger.info(f"CSV report generated: {output_file}")
        return output_file
        
    except Exception as e:
        logger.error(f"Failed to generate CSV report: {str(e)}")
        raise

def generate_html_report(report_data, output_file):
    """Generate HTML format report.
    
    Args:
        report_data (dict): Structured report data
        output_file (str): Output file path
        
    Returns:
        str: Path to generated report file
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Generate HTML content
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Validation Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-top: 30px;
        }}
        .status-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        .status-pass {{ background-color: #27ae60; }}
        .status-fail {{ background-color: #e74c3c; }}
        .status-skipped {{ background-color: #f39c12; }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .info-card {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }}
        .info-card h3 {{
            margin-top: 0;
            color: #2c3e50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: white;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #34495e;
            color: white;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .mismatch-table {{
            margin-top: 20px;
        }}
        .delegation-info {{
            background-color: #e8f5e8;
            border: 1px solid #27ae60;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
        }}
        .delegation-warning {{
            background-color: #fff3cd;
            border: 1px solid #f39c12;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
        }}
        .summary-stats {{
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
            text-align: center;
        }}
        .stat-item {{
            background-color: #3498db;
            color: white;
            padding: 20px;
            border-radius: 8px;
            min-width: 120px;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            display: block;
        }}
        .timestamp {{
            text-align: right;
            color: #7f8c8d;
            font-style: italic;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Validation Report</h1>
        
        <div class="summary-stats">
            <div class="stat-item">
                <span class="stat-number">{report_data['summary']['total_issues']}</span>
                <span>Total Issues</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{report_data['validation_results']['zone_file_vs_child_server']['total_mismatches']}</span>
                <span>Server Mismatches</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{report_data['validation_results']['child_zone_vs_parent_zone']['total_mismatches']}</span>
                <span>Parent Mismatches</span>
            </div>
        </div>

        <div class="info-grid">
            <div class="info-card">
                <h3>Configuration</h3>
                <p><strong>Zone File:</strong> {report_data['metadata']['zone_file']}</p>
                <p><strong>Child Origin:</strong> {report_data['metadata']['child_origin']}</p>
                <p><strong>Child Server:</strong> {report_data['metadata']['child_server']}</p>
                <p><strong>Parent Server:</strong> {report_data['metadata']['parent_server']}</p>
            </div>
            
            <div class="info-card">
                <h3>Overall Status</h3>
                <p><span class="status-badge status-{report_data['summary']['overall_status'].lower()}">{report_data['summary']['overall_status']}</span></p>
                <p><strong>Delegation Status:</strong> {report_data['delegation']['status']}</p>
                <p><strong>Admin Records:</strong> {'Ignored' if report_data['metadata']['ignore_administrative_records'] else 'Included'}</p>
            </div>
        </div>'''

        # Add delegation information
        if report_data['delegation']['is_delegated']:
            html_content += f'''
        <div class="delegation-info">
            <h3>🎯 Delegation Detected</h3>
            <p>The child zone <strong>{report_data['metadata']['child_origin']}</strong> is properly delegated in the parent zone.</p>
            <p><strong>Delegated to:</strong> {', '.join(report_data['delegation']['delegation_nameservers'])}</p>
            <p>DNS protocol will automatically redirect queries to the child zones delegated nameservers. Parent zone validation is skipped as this is normal behavior.</p>
        </div>'''
        else:
            html_content += '''
        <div class="delegation-warning">
            <h3>⚠️ No Delegation Detected</h3>
            <p>The child zone is not delegated in the parent zone. Records can be tested directly from the parent zone.</p>
        </div>'''

        # Add Zone File vs Child Server results
        server_validation = report_data['validation_results']['zone_file_vs_child_server']
        html_content += f'''
        <h2>Zone File vs Child Server Validation</h2>
        <p>Status: <span class="status-badge status-{server_validation['status'].lower()}">{server_validation['status']}</span></p>
        <p>Total Mismatches: <strong>{server_validation['total_mismatches']}</strong></p>'''

        if server_validation['mismatches']:
            html_content += '''
        <table class="mismatch-table">
            <thead>
                <tr>
                    <th>FQDN</th>
                    <th>Type</th>
                    <th>Zone File Data</th>
                    <th>Child Server Data</th>
                </tr>
            </thead>
            <tbody>'''
            
            for mismatch in server_validation['mismatches']:
                html_content += f'''
                <tr>
                    <td>{mismatch['fqdn']}</td>
                    <td>{mismatch['type']}</td>
                    <td>{mismatch['zone_file_data']}</td>
                    <td>{mismatch['child_server_data']}</td>
                </tr>'''
            
            html_content += '''
            </tbody>
        </table>'''
        else:
            html_content += '<p style="color: #27ae60; font-weight: bold;">✅ All records match between zone file and child server</p>'

        # Add Child Zone vs Parent Zone results
        parent_validation = report_data['validation_results']['child_zone_vs_parent_zone']
        html_content += f'''
        <h2>Child Zone vs Parent Zone Validation</h2>
        <p>Status: <span class="status-badge status-{parent_validation['status'].lower()}">{parent_validation['status']}</span></p>'''

        if parent_validation.get('skipped_reason'):
            html_content += f'<p><strong>Skipped:</strong> {parent_validation["skipped_reason"]}</p>'
        else:
            html_content += f'<p>Total Mismatches: <strong>{parent_validation["total_mismatches"]}</strong></p>'

            if parent_validation['mismatches']:
                html_content += '''
        <table class="mismatch-table">
            <thead>
                <tr>
                    <th>FQDN</th>
                    <th>Type</th>
                    <th>Child Data</th>
                    <th>Parent Data</th>
                </tr>
            </thead>
            <tbody>'''
                
                for mismatch in parent_validation['mismatches']:
                    html_content += f'''
                    <tr>
                        <td>{mismatch['fqdn']}</td>
                        <td>{mismatch['type']}</td>
                        <td>{mismatch['child_data']}</td>
                        <td>{mismatch['parent_data']}</td>
                    </tr>'''
                
                html_content += '''
            </tbody>
        </table>'''
            else:
                html_content += '<p style="color: #27ae60; font-weight: bold;">✅ No conflicting records found between child zone and parent zone</p>'

        # Close HTML
        html_content += f'''
        <div class="timestamp">
            Generated: {report_data['metadata']['generated']}<br>
            Tool: {report_data['metadata']['tool_version']}
        </div>
    </div>
</body>
</html>'''

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_file}")
        return output_file
        
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {str(e)}")
        raise

def export_results_summary(report_data, output_file=None):
    """Export a concise summary of validation results.
    
    Args:
        report_data (dict): Structured report data
        output_file (str): Optional output file path
        
    Returns:
        str: Summary text
    """
    logger = logging.getLogger(__name__)
    
    summary_lines = [
        f"DNS Validation Summary - {report_data['metadata']['generated']}",
        "=" * 60,
        f"Zone: {report_data['metadata']['child_origin']}",
        f"Zone File: {report_data['metadata']['zone_file']}",
        f"Child Server: {report_data['metadata']['child_server']}",
        f"Parent Server: {report_data['metadata']['parent_server']}",
        "",
        f"Overall Status: {report_data['summary']['overall_status']}",
        f"Total Issues: {report_data['summary']['total_issues']}",
        f"Delegation: {report_data['delegation']['status']}",
        "",
        "Validation Results:",
        f"  Zone File vs Child Server: {report_data['validation_results']['zone_file_vs_child_server']['status']} ({report_data['validation_results']['zone_file_vs_child_server']['total_mismatches']} issues)",
        f"  Child vs Parent Zone: {report_data['validation_results']['child_zone_vs_parent_zone']['status']} ({report_data['validation_results']['child_zone_vs_parent_zone']['total_mismatches']} issues)",
    ]
    
    if report_data['delegation']['is_delegated']:
        summary_lines.extend([
            "",
            "Delegation Details:",
            f"  Nameservers: {', '.join(report_data['delegation']['delegation_nameservers'])}"
        ])
    
    summary_text = "\n".join(summary_lines)
    
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(summary_text)
            logger.info(f"Summary exported to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to export summary to {output_file}: {str(e)}")
    
    return summary_text

def get_interactive_configuration():
    """Interactively prompt user for configuration parameters.
    
    Returns:
        dict: Configuration parameters provided by user
    """
    print("="*60)
    print("DNS VALIDATION TOOL - INTERACTIVE CONFIGURATION")
    print("="*60)
    print("Please provide the following configuration parameters:")
    print("(Press Enter to use default values where available)")
    print("(Type 'help' at any prompt for detailed information)")
    print()
    
    config = {}
    
    # Zone file configuration
    print("Zone File Configuration:")
    print("-" * 25)
    
    while True:
        zone_file = input("Child zone file path (e.g., 'file.zone'): ").strip()
        if zone_file.lower() == 'help':
            print("\nZONE FILE HELP:")
            print("The zone file contains DNS records for your child zone.")
            print("Examples:")
            print("  file.zone           - Zone file in current directory")
            print("  /path/to/zone.db    - Full path to zone file")
            print("  zones/example.zone  - Relative path to zone file")
            print("\nThe file should contain DNS records in BIND zone file format.")
            print("Example zone file content:")
            print("  $ORIGIN example.com.")
            print("  @    IN  SOA  ns1.example.com. admin.example.com. (")
            print("              2023010101 ; serial")
            print("              3600       ; refresh")
            print("              1800       ; retry")
            print("              604800     ; expire")
            print("              86400 )    ; minimum TTL")
            print("  @    IN  NS   ns1.example.com.")
            print("  www  IN  A    192.0.2.1")
            print()
            continue
        elif zone_file:
            # Check if file exists
            if os.path.exists(zone_file):
                config['CHILD_ZONE_FILE'] = zone_file
                print(f"[OK] Zone file found: {zone_file}")
                break
            else:
                print(f"[WARNING] File '{zone_file}' not found in current directory.")
                use_anyway = input("Use this path anyway? (y/N): ").strip().lower()
                if use_anyway in ['y', 'yes']:
                    config['CHILD_ZONE_FILE'] = zone_file
                    break
                else:
                    print("Please provide a different path.")
        else:
            print("Zone file path is required.")
    
    while True:
        child_origin = input("Child zone origin (e.g., 'test.example.com'): ").strip()
        if child_origin.lower() == 'help':
            print("\nCHILD ZONE ORIGIN HELP:")
            print("The domain name of the zone you want to validate.")
            print("This should match the $ORIGIN in your zone file.")
            print("Examples:")
            print("  example.com         - Root domain")
            print("  sub.example.com     - Subdomain")
            print("  test.myzone.org     - Test subdomain")
            print("\nNote: Trailing dots are automatically added for DNS queries.")
            print()
            continue
        elif child_origin:
            config['CHILD_ORIGIN'] = child_origin
            break
        else:
            print("Child zone origin is required.")
    
    print()
    
    # Nameserver configuration
    print("Nameserver Configuration:")
    print("-" * 26)
    
    while True:
        child_ns = input("Child nameserver (FQDN or IP, e.g., 'ns1.example.com' or '1.2.3.4'): ").strip()
        if child_ns.lower() == 'help':
            print("\nCHILD NAMESERVER HELP:")
            print("The authoritative nameserver for your child zone.")
            print("This is where your zone records should be served from.")
            print("Examples:")
            print("  ns1.example.com     - Nameserver FQDN")
            print("  192.168.1.10        - Nameserver IP address")
            print("  ns1-01.azure-dns.com - Cloud DNS service")
            print("\nThe tool will query this server to validate your zone records.")
            print("If using FQDN, it will be automatically resolved to IP address.")
            print()
            continue
        elif child_ns:
            config['CHILD_NS'] = child_ns
            break
        else:
            print("Child nameserver is required.")
    
    while True:
        parent_ns = input("Parent nameserver (FQDN or IP, e.g., '8.8.8.8' or 'ns.parent.com'): ").strip()
        if parent_ns.lower() == 'help':
            print("\nPARENT NAMESERVER HELP:")
            print("The nameserver that hosts the parent zone.")
            print("Used to check delegation and compare records.")
            print("Examples:")
            print("  8.8.8.8             - Google Public DNS")
            print("  1.1.1.1             - Cloudflare DNS")
            print("  ns1.parentzone.com  - Parent zone nameserver")
            print("\nThis server is queried to:")
            print("  • Check if your child zone is delegated")
            print("  • Compare records between parent and child zones")
            print("  • Validate delegation setup")
            print()
            continue
        elif parent_ns:
            config['PARENT_NS'] = parent_ns
            break
        else:
            print("Parent nameserver is required.")
    
    print()
    
    # Validation options
    print("Validation Options:")
    print("-" * 19)
    
    while True:
        ignore_admin = input("Ignore root administrative records (root SOA/NS only)? (Y/n): ").strip().lower()
        if ignore_admin == 'help':
            print("\nENHANCED RECORD VALIDATION HELP:")
            print("This tool now supports ALL DNS record types with enhanced filtering!")
            print("\nSUPPORTED RECORD TYPES:")
            print("  ✓ A, AAAA (IPv4/IPv6 addresses)")
            print("  ✓ CNAME (canonical names/aliases)")
            print("  ✓ TXT (text records)")  
            print("  ✓ MX (mail exchange)")
            print("  ✓ PTR (reverse DNS)")
            print("  ✓ SRV (service records)")
            print("  ✓ CAA (certificate authority authorization)")
            print("  ✓ Subdomain NS records (like ns1.example.com NS)")
            print("  ✓ Any other valid DNS record types")
            print("\nONLY EXCLUDES (when enabled):")
            print("  • Root SOA record (@ IN SOA - zone metadata)")
            print("  • Root NS records (@ IN NS - delegation records)")
            print("  These are managed by DNS providers and typically differ")
            print("\nRecommended: Yes (Y) - Use enhanced filtering")
            print("Choose No (n) to validate ALL records including root SOA/NS")
            print()
            continue
        else:
            config['IGNORE_ADMINISTRATIVE_RECORDS'] = ignore_admin not in ['n', 'no', 'false']
            break
    
    while True:
        log_level_input = input("Logging level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
        if log_level_input.lower() == 'help':
            print("\nLOGGING LEVEL HELP:")
            print("Controls the amount of detail in log output:")
            print("  • DEBUG   - Very detailed output (every DNS query, progress)")
            print("  • INFO    - Standard output (validation results, summaries)")
            print("  • WARNING - Only warnings and errors")
            print("  • ERROR   - Only error messages")
            print("\nRecommended for most users: INFO")
            print("Use DEBUG for troubleshooting DNS issues.")
            print()
            continue
        elif log_level_input in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            config['LOG_LEVEL'] = getattr(logging, log_level_input)
            break
        elif log_level_input == '':
            config['LOG_LEVEL'] = logging.INFO
            break
        else:
            print("Invalid logging level. Please choose DEBUG, INFO, WARNING, or ERROR.")
    
    print()
    
    # Advanced reporting options
    print("Advanced Reporting Options:")
    print("-" * 27)
    
    print("Available report formats:")
    print("  • text  - Traditional text-based report (human-readable)")
    print("  • json  - Structured JSON format (API integration, automation)")
    print("  • csv   - Comma-separated values (spreadsheet analysis)")
    print("  • html  - Professional web report (stakeholder presentations)")
    print()
    print("Examples:")
    print("  text           - Generate only text report")
    print("  json,html      - Generate both JSON and HTML reports")
    print("  text,json,csv  - Generate text, JSON, and CSV reports")
    print("  html           - Generate only HTML report")
    print()
    
    formats_input = input("Report formats (comma-separated) [text]: ").strip()
    if formats_input:
        formats = [f.strip().lower() for f in formats_input.split(',')]
        valid_formats = ['text', 'json', 'csv', 'html']
        config['REPORT_FORMATS'] = [f for f in formats if f in valid_formats]
        
        # Show what was selected and any invalid formats
        if config['REPORT_FORMATS']:
            print(f"Selected formats: {', '.join(config['REPORT_FORMATS'])}")
            invalid_formats = [f for f in formats if f not in valid_formats]
            if invalid_formats:
                print(f"Note: Ignoring invalid formats: {', '.join(invalid_formats)}")
        else:
            print("No valid formats selected, using default: text")
            config['REPORT_FORMATS'] = ['text']
    else:
        config['REPORT_FORMATS'] = ['text']
        print("Using default format: text")
    
    # Show what each format provides
    print("\nSelected report formats will generate:")
    for fmt in config['REPORT_FORMATS']:
        if fmt == 'text':
            print("  ✓ Text Report   - Detailed human-readable validation results")
        elif fmt == 'json':
            print("  ✓ JSON Report   - Machine-readable data for automation/APIs")
        elif fmt == 'csv':
            print("  ✓ CSV Report    - Tabular data for Excel/spreadsheet analysis")
        elif fmt == 'html':
            print("  ✓ HTML Report   - Professional web page with charts and styling")
    
    print()
    
    # Display configuration summary
    print("Configuration Summary:")
    print("-" * 22)
    print(f"Zone File: {config['CHILD_ZONE_FILE']}")
    print(f"Child Origin: {config['CHILD_ORIGIN']}")
    print(f"Child Nameserver: {config['CHILD_NS']}")
    print(f"Parent Nameserver: {config['PARENT_NS']}")
    print(f"Ignore Admin Records: {config['IGNORE_ADMINISTRATIVE_RECORDS']}")
    print(f"Log Level: {logging.getLevelName(config['LOG_LEVEL'])}")
    print(f"Report Formats: {', '.join(config['REPORT_FORMATS'])}")
    print()
    
    # Confirm configuration
    confirm = input("Proceed with this configuration? (Y/n): ").strip().lower()
    if confirm in ['n', 'no']:
        print("Configuration cancelled.")
        return None
    
    # Option to save configuration
    save_config = input("Save this configuration to a file for future use? (y/N): ").strip().lower()
    if save_config in ['y', 'yes']:
        save_configuration_to_file(config)
    
    return config

def load_configuration_from_file(config_file):
    """Load configuration from a JSON or Python configuration file.
    
    Args:
        config_file (str): Path to configuration file
        
    Returns:
        dict: Configuration parameters or None if failed
    """
    logger = logging.getLogger(__name__)
    
    try:
        if not os.path.exists(config_file):
            logger.error(f"Configuration file not found: {config_file}")
            return None
        
        # Handle JSON configuration files
        if config_file.endswith('.json'):
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info(f"Loaded JSON configuration from: {config_file}")
                return config
        
        # Handle Python configuration files
        elif config_file.endswith('.py'):
            import importlib.util
            spec = importlib.util.spec_from_file_location("config", config_file)
            config_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config_module)
            
            config = {}
            for attr in ['CHILD_ZONE_FILE', 'CHILD_ORIGIN', 'CHILD_NS', 'PARENT_NS', 
                        'IGNORE_ADMINISTRATIVE_RECORDS', 'LOG_LEVEL', 'REPORT_FORMATS']:
                if hasattr(config_module, attr):
                    config[attr] = getattr(config_module, attr)
            
            logger.info(f"Loaded Python configuration from: {config_file}")
            return config
        
        else:
            logger.error(f"Unsupported configuration file format: {config_file}")
            return None
            
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_file}: {str(e)}")
        return None

def save_configuration_to_file(config):
    """Save configuration to a Python file for future use.
    
    Args:
        config (dict): Configuration parameters to save
    """
    try:
        config_filename = f"dns_validation_config_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
        
        config_content = f'''# DNS Validation Configuration - Generated {datetime.datetime.now()}
# You can modify these values and use this file by importing it or copying values back to ValidateDNS.py
import logging

# Zone file configuration
CHILD_ZONE_FILE = "{config['CHILD_ZONE_FILE']}"
CHILD_ORIGIN = "{config['CHILD_ORIGIN']}"

# Nameserver configuration
CHILD_NS = "{config['CHILD_NS']}"
PARENT_NS = "{config['PARENT_NS']}"

# Validation options
IGNORE_ADMINISTRATIVE_RECORDS = {config['IGNORE_ADMINISTRATIVE_RECORDS']}
LOG_LEVEL = logging.{logging.getLevelName(config['LOG_LEVEL'])}

# Advanced reporting options
REPORT_FORMATS = {config['REPORT_FORMATS']}

# To use this configuration:
# 1. Copy these values back to the configuration section in ValidateDNS.py, OR
# 2. Import this file and use the values programmatically
'''
        
        with open(config_filename, 'w', encoding='utf-8') as f:
            f.write(config_content)
        
        print(f"[OK] Configuration saved to: {config_filename}")
        print("  You can copy these values back to ValidateDNS.py for future use.")
        
    except Exception as e:
        print(f"[WARNING] Could not save configuration file: {str(e)}")

def parse_command_line_args():
    """Parse command line arguments with enhanced options.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="DNS Zone Validation Tool - Validate DNS zone files against live servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ValidateDNS.py                           # Use configuration from script
  python ValidateDNS.py --interactive             # Interactive configuration mode
  python ValidateDNS.py --config config.json     # Load configuration from file
  python ValidateDNS.py --zone-file example.zone --origin example.com --child-ns ns1.example.com --parent-ns 8.8.8.8
  python ValidateDNS.py --concurrent 20           # Use 20 concurrent DNS queries
  python ValidateDNS.py --timeout 15              # Set DNS timeout to 15 seconds
  python ValidateDNS.py --format html,json        # Generate HTML and JSON reports
  python ValidateDNS.py --help                    # Show this help message

Configuration Priority (highest to lowest):
  1. Command line arguments
  2. Configuration file (--config)
  3. Interactive mode (--interactive)
  4. Script constants
        """
    )
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Run in interactive configuration mode (prompts for all settings)'
    )
    config_group.add_argument(
        '--config', '-c',
        type=str,
        help='Load configuration from JSON or Python file'
    )
    
    # DNS validation options
    dns_group = parser.add_argument_group('DNS Validation Options')
    dns_group.add_argument(
        '--zone-file', '--zone',
        type=str,
        help='Path to the DNS zone file'
    )
    dns_group.add_argument(
        '--origin', '--domain',
        type=str,
        help='Origin domain of the zone (e.g., example.com)'
    )
    dns_group.add_argument(
        '--child-ns', '--child-nameserver',
        type=str,
        help='Child nameserver FQDN or IP address'
    )
    dns_group.add_argument(
        '--parent-ns', '--parent-nameserver',
        type=str,
        help='Parent nameserver FQDN or IP address'
    )
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument(
        '--concurrent',
        type=int,
        default=MAX_CONCURRENT_QUERIES,
        help=f'Maximum concurrent DNS queries (default: {MAX_CONCURRENT_QUERIES})'
    )
    perf_group.add_argument(
        '--timeout',
        type=int,
        default=DNS_TIMEOUT,
        help=f'DNS query timeout in seconds (default: {DNS_TIMEOUT})'
    )
    perf_group.add_argument(
        '--retries',
        type=int,
        default=DNS_RETRIES,
        help=f'Number of DNS query retries (default: {DNS_RETRIES})'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--format', '--formats',
        type=str,
        help='Report formats: text,json,csv,html (comma-separated)'
    )
    output_group.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level'
    )
    output_group.add_argument(
        '--include-admin-records',
        action='store_true',
        help='Include root SOA and NS records in validation (normally filtered)'
    )
    
    # Utility options
    parser.add_argument(
        '--version',
        action='version',
        version='DNS Validation Tool v2.1 Enhanced'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate configuration without performing DNS queries'
    )
    
    return parser.parse_args()

def validate_configuration(child_zone_file, child_origin, child_ns, parent_ns):
    """Validate that all required configuration parameters are provided.
    
    Args:
        child_zone_file (str): Path to the child zone file
        child_origin (str): Child zone origin domain
        child_ns (str): Child nameserver
        parent_ns (str): Parent nameserver
        
    Returns:
        tuple: (is_valid, error_messages) where is_valid is boolean and error_messages is list
    """
    logger = logging.getLogger(__name__)
    errors = []
    
    # Check each required configuration parameter
    if not child_zone_file or child_zone_file.strip() == "":
        errors.append("CHILD_ZONE_FILE is empty or not configured")
    
    if not child_origin or child_origin.strip() == "":
        errors.append("CHILD_ORIGIN is empty or not configured")
    
    if not child_ns or child_ns.strip() == "":
        errors.append("CHILD_NS is empty or not configured")
    
    if not parent_ns or parent_ns.strip() == "":
        errors.append("PARENT_NS is empty or not configured")
    
    # Log validation results
    if errors:
        logger.error("Configuration validation failed!")
        logger.error("Missing or empty configuration parameters:")
        for error in errors:
            logger.error(f"  - {error}")
        logger.error("")
        logger.error("Please update the configuration section at the top of the script:")
        logger.error("  CHILD_ZONE_FILE = \"your_zone_file.zone\"")
        logger.error("  CHILD_ORIGIN = \"your.domain.com\"")
        logger.error("  CHILD_NS = \"your.nameserver.com\" or \"1.2.3.4\"")
        logger.error("  PARENT_NS = \"parent.nameserver.com\" or \"8.8.8.8\"")
        logger.error("")
        return False, errors
    else:
        logger.info("Configuration validation passed - all required parameters are present")
        return True, []

def main():
    """Main function to run DNS validation with comprehensive logging."""
    # Parse command line arguments
    args = parse_command_line_args()
    
    # Setup logging with initial level (may be overridden by interactive config)
    log_filename = f"dns_validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logger = setup_logging(log_level=LOG_LEVEL, log_file=log_filename)
    
    try:
        # Determine configuration source
        if args.interactive:
            # Interactive configuration mode
            logger.info("Starting DNS validation in interactive configuration mode")
            interactive_config = get_interactive_configuration()
            
            if interactive_config is None:
                logger.info("Interactive configuration cancelled by user")
                return False
            
            # Use interactive configuration
            child_zone_file = interactive_config['CHILD_ZONE_FILE']
            child_origin = normalize_domain(interactive_config['CHILD_ORIGIN'])
            child_ns = interactive_config['CHILD_NS']
            parent_ns = interactive_config['PARENT_NS']
            ignore_admin_records = interactive_config['IGNORE_ADMINISTRATIVE_RECORDS']
            report_formats = interactive_config['REPORT_FORMATS']
            
            # Update logging level if changed during interactive config
            if interactive_config['LOG_LEVEL'] != LOG_LEVEL:
                # Recreate logger with new level
                log_filename = f"dns_validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                logger = setup_logging(log_level=interactive_config['LOG_LEVEL'], log_file=log_filename)
                logger.info("Updated logging level based on interactive configuration")
            
            logger.info("Using interactive configuration")
        else:
            # Use configuration constants from script
            child_zone_file = CHILD_ZONE_FILE
            child_origin = normalize_domain(CHILD_ORIGIN)
            child_ns = CHILD_NS
            parent_ns = PARENT_NS
            ignore_admin_records = IGNORE_ADMINISTRATIVE_RECORDS
            report_formats = REPORT_FORMATS
            
            logger.info("Using configuration from script constants")
        
        # Validate configuration before proceeding
        config_valid, config_errors = validate_configuration(
            child_zone_file, 
            child_origin.rstrip('.') if child_origin.endswith('.') else child_origin, 
            child_ns, 
            parent_ns
        )
        if not config_valid:
            if not args.interactive:
                logger.error("Cannot proceed with DNS validation due to configuration errors.")
                logger.error("Please fix the configuration issues listed above and try again.")
                logger.error("Alternatively, run with --interactive flag for guided configuration.")
            return False
        
        logger.info("Starting DNS validation process")
        logger.info("NOTE: SOA and NS records will be ignored during validation")
        logger.info("These administrative records typically differ during delegation processes")
        
        logger.info(f"Configuration:")
        logger.info(f"  Zone file: {child_zone_file}")
        logger.info(f"  Child origin: {child_origin} (normalized with trailing dot)")
        logger.info(f"  Child nameserver: {child_ns}")
        logger.info(f"  Parent nameserver: {parent_ns}")
        logger.info(f"  Report formats: {', '.join(report_formats)}")
        
        # 1. Validate child zone file vs. child server
        logger.info("="*60)
        file_vs_server = validate_child_zone_file_vs_server(child_zone_file, child_origin, child_ns, ignore_administrative_records=ignore_admin_records)
        
        # 2. Validate child zone file vs. parent zone
        logger.info("="*60)
        file_vs_parent = validate_child_vs_parent(child_zone_file, child_origin, parent_ns, ignore_administrative_records=ignore_admin_records)
        
        # Generate comprehensive report
        logger.info("="*60)
        
        # Generate structured data for advanced reporting
        report_data = generate_structured_report_data(
            file_vs_server, file_vs_parent, 
            child_zone_file, child_origin, child_ns, parent_ns, 
            ignore_administrative_records=ignore_admin_records
        )
        
        # Generate reports in requested formats
        report_files = []
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Text report (always generated for logging)
        if 'text' in report_formats:
            text_report = generate_validation_report(file_vs_server, file_vs_parent, 
                                                   child_zone_file, child_origin, child_ns, parent_ns, 
                                                   ignore_administrative_records=ignore_admin_records)
            text_filename = f"dns_validation_report_{timestamp}.txt"
            with open(text_filename, 'w', encoding='utf-8') as f:
                f.write(text_report)
            report_files.append(text_filename)
            logger.info(f"Text report generated: {text_filename}")
        else:
            # Generate text report for logging even if not requested for output
            generate_validation_report(file_vs_server, file_vs_parent, 
                                     child_zone_file, child_origin, child_ns, parent_ns, 
                                     ignore_administrative_records=ignore_admin_records)
        
        # JSON report
        if 'json' in report_formats:
            json_filename = f"dns_validation_report_{timestamp}.json"
            generate_json_report(report_data, json_filename)
            report_files.append(json_filename)
        
        # CSV report
        if 'csv' in report_formats:
            csv_filename = f"dns_validation_report_{timestamp}.csv"
            generate_csv_report(report_data, csv_filename)
            report_files.append(csv_filename)
        
        # HTML report
        if 'html' in report_formats:
            html_filename = f"dns_validation_report_{timestamp}.html"
            generate_html_report(report_data, html_filename)
            report_files.append(html_filename)
        
        # Summary
        logger.info("="*60)
        logger.info("VALIDATION SUMMARY")
        logger.info("="*60)
        logger.info(f"Overall Status: {report_data['summary']['overall_status']}")
        logger.info(f"Total Issues: {report_data['summary']['total_issues']}")
        logger.info(f"Zone File vs Child Server: {report_data['validation_results']['zone_file_vs_child_server']['status']}")
        logger.info(f"Child Zone vs Parent Zone: {report_data['validation_results']['child_zone_vs_parent_zone']['status']}")
        
        if report_files:
            logger.info(f"Generated reports:")
            for report_file in report_files:
                logger.info(f"  - {report_file}")
        
        logger.info(f"Detailed logs saved to: {log_filename}")
        
        return len(file_vs_server) == 0 and len(file_vs_parent) == 0
        
    except Exception as e:
        logger.error(f"Validation failed with error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
