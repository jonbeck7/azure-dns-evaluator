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

def query_ds_record(domain, resolver_ip):
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

def write_output(results, headers, output_format, output_file):
	if output_format == "text":
		text = tabulate(results, headers=headers, tablefmt="github")
		if output_file:
			with open(output_file, "w", encoding="utf-8") as f:
				f.write(text)
		else:
			print(text)
	elif output_format == "csv":
		if output_file:
			with open(output_file, "w", newline='', encoding="utf-8") as f:
				writer = csv.writer(f)
				writer.writerow(headers)
				writer.writerows(results)
		else:
			writer = csv.writer(sys.stdout)
			writer.writerow(headers)
			writer.writerows(results)
	elif output_format == "json":
		data = [dict(zip(headers, row)) for row in results]
		if output_file:
			with open(output_file, "w", encoding="utf-8") as f:
				json.dump(data, f, indent=2)
		else:
			print(json.dumps(data, indent=2))
	elif output_format == "html":
		# Custom HTML table with borders
		style = """
		<style>
		table.ds-table {border-collapse: collapse;}
		table.ds-table th, table.ds-table td {border: 1px solid #333; padding: 6px;}
		table.ds-table th {background: #eee;}
		.ds-present {background: #ffeaea; color: #c00; font-weight: bold;}
		.ds-notpresent {background: #eaffea; color: #080; font-weight: bold;}
		</style>
		"""
		html = [style, '<table class="ds-table">']
		html.append('<thead><tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr></thead>')
		html.append('<tbody>')
		for row in results:
			# Color code the DS Record status cell
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
		html_str = '\n'.join(html)
		if output_file:
			with open(output_file, "w", encoding="utf-8") as f:
				f.write(html_str)
		else:
			print(html_str)
	else:
		print(f"Unknown output format: {output_format}")

def main():
	parser = argparse.ArgumentParser(
		description="Checks if DS records for a given domain/zone are still present in the parent zone across major public DNS resolvers. Use this before disabling DNSSEC zone signing to ensure no public resolver has the DS record cached.",
		epilog="Example: python ds_cache_check.py example.com --output-format csv --output results.csv --resolver 8.8.8.8 --resolver 1.2.3.4"
	)
	parser.add_argument("domain", help="Domain/zone name to check")
	parser.add_argument("--output-format", choices=["text", "csv", "json", "html"], default="text", help="Output format for results (default: text)")
	parser.add_argument("--output", help="Output file path (if omitted, prints to stdout)")
	parser.add_argument("--resolver", action="append", help="Additional resolver FQDN or IP to check (can be specified multiple times)")
	args = parser.parse_args()
	domain = args.domain.strip('.').lower()
	print(f"Checking DS record cache for: {domain}\n")
	# Build resolver list
	resolvers = PUBLIC_RESOLVERS.copy()
	if args.resolver:
		for custom in args.resolver:
			resolvers.append((f"Custom", custom))
	results = []
	for name, ip in resolvers:
		ds_records, ttl = query_ds_record(domain, ip)
		if isinstance(ds_records, list):
			status = "PRESENT"
			ds_text = " | ".join(ds_records)
		elif ds_records is None:
			status = "NOT PRESENT"
			ds_text = "-"
		else:
			status = "ERROR"
			ds_text = ds_records
		results.append([name, ip, status, ds_text, ttl if ttl else "-"])
	headers = ["Resolver", "IP", "DS Record", "Details", "TTL"]
	write_output(results, headers, args.output_format, args.output)
	print("\nRecommendation:")
	if any(r[2] == "PRESENT" for r in results):
		print("⚠️  At least one public resolver still has the DS record cached. Do NOT disable DNSSEC yet.")
	else:
		print("✅ No public resolver has the DS record cached. Safe to disable DNSSEC zone signing.")

if __name__ == "__main__":
	main()
