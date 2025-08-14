import os
from datetime import datetime, timezone
#!/usr/bin/env python3
"""
DS Record Cache Verification Script

Checks if DS records for a given domain/zone are still present in the parent zone across major public DNS resolvers.
Use this before disabling DNSSEC zone signing to ensure no public resolver has the DS record cached.

Usage:
  python ds_cache_check.py example.com --output-format html --output results.html

Dependencies:
  pip install dnspython tabulate
"""

import sys
import argparse
import dns.resolver
import dns.name
from tabulate import tabulate
import json
import csv
import concurrent.futures

# List of major public DNS resolvers
PUBLIC_RESOLVERS = [
	("Google", "8.8.8.8"),
	("Google2", "8.8.4.4"),
	("Cloudflare", "1.1.1.1"),
	("Cloudflare2", "1.0.0.1"),
	("Quad9", "9.9.9.9"),
	("OpenDNS", "208.67.222.222"),
	("OpenDNS2", "208.67.220.220"),
	("Comodo", "8.26.56.26"),
	("Level3", "4.2.2.1"),
	("CleanBrowsing", "185.228.168.9"),
	("Verisign", "64.6.64.6"),
	("Verisign2", "64.6.65.6"),
	("AT&T", "165.87.13.129"),
]

def query_ds_record(domain: str, resolver_ip: str) -> tuple[list[str] | str | None, int | None]:
	"""
	Query a DNS resolver for DS records of a domain.
	Returns a tuple: (list of DS records or error string or None, TTL or None)
	"""
	try:
		resolver = dns.resolver.Resolver()
		resolver.nameservers = [resolver_ip]
		answer = resolver.resolve(domain, 'DS', raise_on_no_answer=False)
		if answer.rrset:
			ttl = answer.rrset.ttl
			ds_records = [r.to_text() for r in answer]
			return ds_records, ttl
		else:
			return None, None
	except Exception as e:
		return f"Error: {e}", None

def write_output(
	results: list[list[str]],
	headers: list[str],
	output_format: str,
	output_file: str | None,
	domain: str
) -> None:
	"""
	Write results to output in the specified format, including summary statistics and errors.
	"""
	timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
	present_count = sum(1 for r in results if r[2] == "PRESENT")
	notpresent_count = sum(1 for r in results if r[2] == "NOT PRESENT")
	error_count = sum(1 for r in results if r[2] == "ERROR")
	summary = (
		f"Domain: {domain}\nTimestamp: {timestamp}\n"
		f"PRESENT: {present_count}\nNOT PRESENT: {notpresent_count}\nERROR: {error_count}\n"
	)
	if output_format == "text":
		text = tabulate(results, headers=headers, tablefmt="github")
		error_lines = [f"ERROR: {r[0]} ({r[1]}) - {r[3]}" for r in results if r[2] == "ERROR"]
		output = f"{summary}\n{text}\n"
		if error_lines:
			output += "\nErrors:\n" + "\n".join(error_lines)
		if output_file:
			with open(output_file, "w", encoding="utf-8") as f:
				f.write(output)
		else:
			print(output)
	elif output_format == "csv":
		error_lines = [r for r in results if r[2] == "ERROR"]
		if output_file:
			with open(output_file, "w", newline='', encoding="utf-8") as f:
				f.write(f"# {summary}\n")
				writer = csv.writer(f)
				writer.writerow(headers)
				writer.writerows(results)
				if error_lines:
					f.write("# Errors:\n")
					for r in error_lines:
						f.write(f"# {r[0]} ({r[1]}) - {r[3]}\n")
		else:
			print(f"# {summary}\n")
			writer = csv.writer(sys.stdout)
			writer.writerow(headers)
			writer.writerows(results)
			if error_lines:
				print("# Errors:")
				for r in error_lines:
					print(f"# {r[0]} ({r[1]}) - {r[3]}")
	elif output_format == "json":
		data = {
			"domain": domain,
			"timestamp": timestamp,
			"summary": {
				"present": present_count,
				"not_present": notpresent_count,
				"error": error_count
			},
			"results": [dict(zip(headers, row)) for row in results],
			"errors": [
				{"resolver": r[0], "ip": r[1], "details": r[3]} for r in results if r[2] == "ERROR"
			]
		}
		if output_file:
			with open(output_file, "w", encoding="utf-8") as f:
				json.dump(data, f, indent=2)
		else:
			print(json.dumps(data, indent=2))
	elif output_format == "html":
		style = """
		<style>
		table.ds-table {border-collapse: collapse;}
		table.ds-table th, table.ds-table td {border: 1px solid #333; padding: 6px;}
		table.ds-table th {background: #eee;}
		.ds-present {background: #ffeaea; color: #c00; font-weight: bold;}
		.ds-notpresent {background: #eaffea; color: #080; font-weight: bold;}
		</style>
		"""
		html = ["<html><head>", style, "</head><body>"]
		html.append(f'<h2>DS Record Cache Check</h2><p><b>Domain:</b> {domain}<br><b>Timestamp:</b> {timestamp}</p>')
		html.append(f'<p><b>PRESENT:</b> {present_count} &nbsp; <b>NOT PRESENT:</b> {notpresent_count} &nbsp; <b>ERROR:</b> {error_count}</p>')
		html.append('<table class="ds-table">')
		html.append('<thead><tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr></thead>')
		html.append('<tbody>')
		for row in results:
			row_html = []
			for i, cell in enumerate(row):
				if headers[i] == "DS Record":
					if cell == "PRESENT":
						row_html.append(f'<td class="ds-present">{cell}</td>')
					elif cell == "NOT PRESENT":
						row_html.append(f'<td class="ds-notpresent">{cell}</td>')
					else:
						row_html.append(f'<td>{cell}</td>')
				else:
					row_html.append(f'<td>{cell}</td>')
			html.append('<tr>' + ''.join(row_html) + '</tr>')
		html.append('</tbody></table>')
		# Error section
		error_lines = [f'<li>{r[0]} ({r[1]}) - {r[3]}</li>' for r in results if r[2] == "ERROR"]
		if error_lines:
			html.append('<h3>Errors</h3><ul>' + ''.join(error_lines) + '</ul>')
		html.append('</body></html>')
		html_str = '\n'.join(html)
		if output_file:
			with open(output_file, "w", encoding="utf-8") as f:
				f.write(html_str)
		else:
			print(html_str)
	else:
		print(f"Unknown output format: {output_format}")

def main() -> None:
	"""
	Main entry point for DS record cache verification script.
	Parses arguments, runs checks, and outputs results.
	"""
	parser = argparse.ArgumentParser(
		description="Checks if DS records for a given domain/zone are still present in the parent zone across major public DNS resolvers. Use this before disabling DNSSEC zone signing to ensure no public resolver has the DS record cached.",
		epilog="Example: python ds_cache_check.py example.com --output-format csv --output results.csv --resolver 8.8.8.8 --resolver 1.2.3.4"
	)
	parser.add_argument("domain", help="Domain/zone name to check")
	parser.add_argument("--output-format", choices=["text", "csv", "json", "html"], default="text", help="Output format for results (default: text)")
	parser.add_argument("--output", help="Output file path (if omitted, prints to stdout)")
	parser.add_argument("--output-dir", help="Custom output directory")
	parser.add_argument("--resolver", action="append", help="Additional resolver FQDN or IP to check (can be specified multiple times)")
	parser.add_argument("--error-log", help="Optional file to log error details")
	parser.add_argument("--verbose", action="store_true", help="Enable verbose/debug output")
	args = parser.parse_args()

	import time
	from sys import exit
	start_time = time.time()
	domain: str = args.domain.strip('.').lower()
	print(f"Checking DS record cache for: {domain}\n")

	# Build resolver list
	resolvers: list[tuple[str, str]] = PUBLIC_RESOLVERS.copy()
	if args.resolver:
		for custom in args.resolver:
			resolvers.append(("Custom", custom))
	error_details: list[dict] = []
	total = len(resolvers)
	def check_resolver(idx, name, ip):
		if args.verbose:
			print(f"[{idx}/{total}] Checking resolver: {name} ({ip}) ...", end=" ")
		ds_records, ttl = query_ds_record(domain, ip)
		if isinstance(ds_records, list):
			status = "PRESENT"
			ds_text = " | ".join(ds_records)
			if args.verbose:
				print("PRESENT")
		elif ds_records is None:
			status = "NOT PRESENT"
			ds_text = "-"
			if args.verbose:
				print("NOT PRESENT")
		else:
			status = "ERROR"
			ds_text = ds_records
			# Categorize error
			err_type = "Unknown"
			err_msg = str(ds_text)
			if "timeout" in err_msg.lower():
				err_type = "Timeout"
			elif "nxdomain" in err_msg.lower():
				err_type = "NXDOMAIN"
			elif "servfail" in err_msg.lower():
				err_type = "SERVFAIL"
			elif "connection" in err_msg.lower():
				err_type = "Connection"
			if args.verbose:
				print(f"ERROR [{err_type}]: {err_msg}")
			error_details.append({"resolver": name, "ip": ip, "type": err_type, "message": err_msg})
		return [name, ip, status, ds_text, str(ttl) if ttl else "-"]
	results: list[list[str]] = []
	with concurrent.futures.ThreadPoolExecutor() as executor:
		future_to_idx = {
			executor.submit(check_resolver, idx, name, ip): idx
			for idx, (name, ip) in enumerate(resolvers, 1)
		}
		for future in concurrent.futures.as_completed(future_to_idx):
			result = future.result()
			results.append(result)

	headers: list[str] = ["Resolver", "IP", "DS Record", "Details", "TTL"]

	# Handle output directory
	output_path: str | None = args.output
	if args.output_dir and output_path:
		os.makedirs(args.output_dir, exist_ok=True)
		output_path = os.path.join(args.output_dir, os.path.basename(output_path))

	write_output(results, headers, args.output_format, output_path, domain=domain)

	elapsed = time.time() - start_time
	print(f"\nCompleted in {elapsed:.2f} seconds.")

	present_count = sum(1 for r in results if r[2] == "PRESENT")
	error_count = sum(1 for r in results if r[2] == "ERROR")
	notpresent_count = sum(1 for r in results if r[2] == "NOT PRESENT")

	# Error type summary
	error_type_counts = {}
	for err in error_details:
		error_type_counts[err["type"]] = error_type_counts.get(err["type"], 0) + 1

	print("\nSummary:")
	print(f"  PRESENT: {present_count}")
	print(f"  NOT PRESENT: {notpresent_count}")
	print(f"  ERROR: {error_count}")
	if error_count:
		print("  Error Types:")
		for etype, count in error_type_counts.items():
			print(f"    {etype}: {count}")
		print("\nError Details:")
		for err in error_details:
			print(f"    {err['resolver']} ({err['ip']}): [{err['type']}] {err['message']}")
		# Troubleshooting suggestions
		print("\nTroubleshooting Suggestions:")
		if error_type_counts.get("Timeout"):
			print("  - Timeout: Check your network connection and firewall settings.")
		if error_type_counts.get("NXDOMAIN"):
			print("  - NXDOMAIN: The domain may not exist or is not delegated.")
		if error_type_counts.get("SERVFAIL"):
			print("  - SERVFAIL: Resolver may be misconfigured or unreachable.")
		if error_type_counts.get("Connection"):
			print("  - Connection: Check DNS server IP and connectivity.")

	# Optional: log errors to a file if requested
	if hasattr(args, "error_log") and args.error_log:
		with open(args.error_log, "w", encoding="utf-8") as ef:
			for err in error_details:
				ef.write(f"{err['resolver']} ({err['ip']}): [{err['type']}] {err['message']}\n")

	if error_count == total:
		print("\n⚠️  All resolver queries failed. Please check your network, DNS settings, or try again later.")
	elif present_count > 0:
		print("\n⚠️  At least one public resolver still has the DS record cached. Do NOT disable DNSSEC yet.")
		exit(1)
	else:
		print("\n✅ No public resolver has the DS record cached. Safe to disable DNSSEC zone signing.")
		exit(0)

if __name__ == "__main__":
	main()
