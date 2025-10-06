#!/usr/bin/env python3
"""
CDN Infrastructure Analyzer for Top US Industries
Analyzes CDN provider configurations and multi-CDN strategies
"""

import socket
import json
import csv
from datetime import datetime
from typing import Dict, List, Set
import sys
import os
from collections import defaultdict
import subprocess

# Mapping of domains to company names
DOMAIN_TO_COMPANY = {
    "unitedhealthgroup.com": "UnitedHealth Group",
    "cvshealth.com": "CVS Health",
    "jnj.com": "Johnson & Johnson",
    "pfizer.com": "Pfizer",
    "cigna.com": "Cigna",
    "apple.com": "Apple",
    "microsoft.com": "Microsoft",
    "amazon.com": "Amazon",
    "google.com": "Google",
    "meta.com": "Meta",
    "walmart.com": "Walmart",
    "costco.com": "Costco",
    "homedepot.com": "Home Depot",
    "target.com": "Target",
    "jpmorganchase.com": "JPMorgan Chase",
    "jpmorgan.com": "JPMorgan",
    "chase.com": "Chase",
    "bankofamerica.com": "Bank of America",
    "wellsfargo.com": "Wells Fargo",
    "citigroup.com": "Citigroup",
    "goldmansachs.com": "Goldman Sachs",
    "paypal.com": "PayPal",
    "visa.com": "Visa",
    "mastercard.com": "Mastercard",
    "stripe.com": "Stripe",
    "block.xyz": "Block (Square)",
    "exxonmobil.com": "ExxonMobil",
    "chevron.com": "Chevron",
    "conocophillips.com": "ConocoPhillips",
    "duke-energy.com": "Duke Energy",
    "nexteraenergy.com": "NextEra Energy"
}

# Company domains organized by industry
COMPANIES = {
    "Healthcare & Pharmaceuticals": [
        "unitedhealthgroup.com",
        "cvshealth.com",
        "jnj.com",
        "pfizer.com",
        "cigna.com"
    ],
    "Technology & Software": [
        "apple.com",
        "microsoft.com",
        "amazon.com",
        "google.com",
        "meta.com"
    ],
    "Retail & E-commerce": [
        "walmart.com",
        "amazon.com",
        "costco.com",
        "homedepot.com",
        "target.com"
    ],
    "Financial Services & Banking": [
        "jpmorganchase.com",
        "jpmorgan.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citigroup.com",
        "goldmansachs.com"
    ],
    "Payment Processing & Fintech": [
        "paypal.com",
        "visa.com",
        "mastercard.com",
        "stripe.com",
        "block.xyz"
    ],
    "Energy & Utilities": [
        "exxonmobil.com",
        "chevron.com",
        "conocophillips.com",
        "duke-energy.com",
        "nexteraenergy.com"
    ]
}

# CDN provider IP ranges
CDN_PATTERNS = {
    'Cloudflare': {
        'ip_prefixes': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.',
                        '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
                        '172.64.', '172.65.', '172.66.', '172.67.', '162.159.', '173.245.', '188.114.'],
        'headers': ['cf-ray', 'cf-cache-status', 'server: cloudflare'],
        'cname_patterns': ['cloudflare']
    },
    'Akamai': {
        'ip_prefixes': ['23.', '104.64.', '104.65.', '104.66.', '104.67.', '104.68.', '104.69.',
                        '104.70.', '104.71.', '104.72.', '104.73.', '104.74.', '104.75.',
                        '2.16.', '2.17.', '2.18.', '2.19.', '2.20.', '2.21.', '2.22.', '2.23.',
                        '96.6.', '96.7.', '184.24.', '184.25.', '184.26.', '184.27.'],
        'headers': ['x-akamai', 'akamai-'],
        'cname_patterns': ['akamai', 'edgesuite', 'edgekey']
    },
    'AWS CloudFront': {
        'ip_prefixes': ['13.32.', '13.33.', '13.35.', '18.64.', '18.65.', '52.46.', '52.84.',
                        '54.182.', '54.192.', '54.230.', '99.84.', '143.204.', '205.251.'],
        'headers': ['x-amz-cf', 'via: cloudfront'],
        'cname_patterns': ['cloudfront']
    },
    'Fastly': {
        'ip_prefixes': ['151.101.', '199.232.', '146.75.', '23.235.'],
        'headers': ['x-fastly', 'fastly-'],
        'cname_patterns': ['fastly']
    },
    'Azure CDN': {
        'ip_prefixes': ['13.107.', '40.', '52.', '104.40.', '104.41.', '104.42.'],
        'headers': ['x-azure-ref', 'x-cache-remote'],
        'cname_patterns': ['azureedge', 'azure-cdn']
    },
    'Google Cloud CDN': {
        'ip_prefixes': ['34.', '35.', '142.250.', '172.217.', '216.239.'],
        'headers': ['x-goog-', 'server: gfe'],
        'cname_patterns': ['googleusercontent', 'ghs.google']
    }
}


def get_http_headers(domain: str) -> Dict[str, str]:
    """Fetch HTTP headers from domain"""
    try:
        result = subprocess.run(['curl', '-sI', '--max-time', '10', f'https://{domain}'],
                                capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            result = subprocess.run(['curl', '-sI', '--max-time', '10', f'http://{domain}'],
                                    capture_output=True, text=True, timeout=15)
        
        headers = {}
        for line in result.stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip().lower()
        return headers
    except:
        return {}


def get_cname_chain(domain: str) -> List[str]:
    """Get CNAME chain for domain"""
    cnames = []
    current = domain
    
    try:
        for _ in range(10):
            result = subprocess.run(['dig', '+short', 'CNAME', current],
                                    capture_output=True, text=True, timeout=5)
            cname = result.stdout.strip().rstrip('.')
            if not cname or cname == current:
                break
            cnames.append(cname)
            current = cname
    except:
        pass
    
    return cnames


def resolve_domain_ips(domain: str) -> List[str]:
    """Resolve domain to IP addresses"""
    try:
        ips = socket.getaddrinfo(domain, None)
        return list(set([ip[4][0] for ip in ips]))
    except:
        return []


def identify_cdn_from_ip(ip: str) -> Set[str]:
    """Identify CDN from IP"""
    cdns = set()
    for cdn_name, cdn_data in CDN_PATTERNS.items():
        for prefix in cdn_data['ip_prefixes']:
            if ip.startswith(prefix):
                cdns.add(cdn_name)
                break
    return cdns


def identify_cdn_from_headers(headers: Dict[str, str]) -> Set[str]:
    """Identify CDN from headers"""
    cdns = set()
    for cdn_name, cdn_data in CDN_PATTERNS.items():
        for pattern in cdn_data['headers']:
            for header_key, header_value in headers.items():
                if pattern.lower() in header_key or pattern.lower() in header_value:
                    cdns.add(cdn_name)
                    break
    return cdns


def identify_cdn_from_cname(cnames: List[str]) -> Set[str]:
    """Identify CDN from CNAME"""
    cdns = set()
    for cname in cnames:
        cname_lower = cname.lower()
        for cdn_name, cdn_data in CDN_PATTERNS.items():
            for pattern in cdn_data['cname_patterns']:
                if pattern in cname_lower:
                    cdns.add(cdn_name)
                    break
    return cdns


def analyze_domain_cdn(domain: str) -> Dict:
    """Analyze CDN for a domain"""
    result = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'status': 'success',
        'cdn_providers': set(),
        'multi_cdn': False,
        'detection_methods': {},
        'ips': [],
        'cnames': [],
        'error': None
    }
    
    try:
        print(f"    Analyzing...", end='', flush=True)
        
        ips = resolve_domain_ips(domain)
        result['ips'] = ips
        
        for ip in ips:
            cdns = identify_cdn_from_ip(ip)
            if cdns:
                result['cdn_providers'].update(cdns)
                result['detection_methods']['ip'] = list(cdns)
        
        cnames = get_cname_chain(domain)
        result['cnames'] = cnames
        
        cdns_from_cname = identify_cdn_from_cname(cnames)
        if cdns_from_cname:
            result['cdn_providers'].update(cdns_from_cname)
            result['detection_methods']['cname'] = list(cdns_from_cname)
        
        headers = get_http_headers(domain)
        cdns_from_headers = identify_cdn_from_headers(headers)
        if cdns_from_headers:
            result['cdn_providers'].update(cdns_from_headers)
            result['detection_methods']['headers'] = list(cdns_from_headers)
        
        result['multi_cdn'] = len(result['cdn_providers']) > 1
        
        if not result['cdn_providers']:
            if any(tech in domain for tech in ['apple', 'microsoft', 'google', 'amazon', 'meta', 'facebook']):
                result['cdn_providers'].add('Internal/Proprietary CDN')
            else:
                result['cdn_providers'].add('Direct/Origin Server')
        
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
    
    result['cdn_providers'] = sorted(list(result['cdn_providers']))
    return result


def generate_summary_stats(results: List[Dict]) -> Dict:
    """Generate summary statistics"""
    stats = {
        'total_domains': len(results),
        'successful': sum(1 for r in results if r['status'] == 'success'),
        'failed': sum(1 for r in results if r['status'] == 'error'),
        'multi_cdn_count': sum(1 for r in results if r.get('multi_cdn', False)),
        'cdn_usage': defaultdict(int)
    }
    
    if stats['successful'] > 0:
        stats['multi_cdn_rate'] = (stats['multi_cdn_count'] / stats['successful']) * 100
    
    for result in results:
        if result['status'] == 'success':
            for provider in result['cdn_providers']:
                stats['cdn_usage'][provider] += 1
    
    return stats


def print_summary_report(results: List[Dict], stats: Dict, by_industry: Dict):
    """Print summary report"""
    print(f"\n{'='*70}")
    print(f"CDN INFRASTRUCTURE ANALYSIS SUMMARY")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")
    
    print(f"\n📈 Overall Statistics:")
    print(f"  Total Domains: {stats['total_domains']}")
    print(f"  Successful: {stats['successful']}")
    print(f"  Failed: {stats['failed']}")
    print(f"  Multi-CDN: {stats['multi_cdn_count']}/{stats['successful']} ({stats.get('multi_cdn_rate', 0):.1f}%)")
    
    print(f"\n🔧 CDN Provider Market Share:")
    sorted_providers = sorted(stats['cdn_usage'].items(), key=lambda x: x[1], reverse=True)
    for provider, count in sorted_providers:
        percentage = (count / stats['successful']) * 100 if stats['successful'] > 0 else 0
        print(f"  {provider}: {count} domains ({percentage:.1f}%)")


def export_to_csv(results: List[Dict], filename: str):
    """Export to CSV"""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Industry', 'Company', 'Domain', 'CDN_Providers', 'Multi_CDN',
                      'Detection_Methods', 'Status', 'Error', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        rows = []
        for result in results:
            industry = 'Unknown'
            for ind, domains in COMPANIES.items():
                if result['domain'] in domains:
                    industry = ind
                    break
            
            company_name = DOMAIN_TO_COMPANY.get(result['domain'], result['domain'])
            detection = '; '.join([f"{k}: {','.join(v)}" for k, v in result.get('detection_methods', {}).items()])
            
            rows.append({
                'Industry': industry,
                'Company': company_name,
                'Domain': result['domain'],
                'CDN_Providers': '; '.join(result.get('cdn_providers', [])),
                'Multi_CDN': 'YES' if result.get('multi_cdn', False) else 'NO',
                'Detection_Methods': detection,
                'Status': result['status'],
                'Error': result.get('error', ''),
                'Timestamp': result['timestamp']
            })
        
        rows.sort(key=lambda x: x['Industry'])
        for row in rows:
            writer.writerow(row)
    
    print(f"\n✅ CSV export saved to: {filename}")


def export_to_json(results: List[Dict], filename: str):
    """Export to JSON"""
    with open(filename, 'w') as jsonfile:
        json.dump(results, jsonfile, indent=2, default=str)
    print(f"✅ JSON export saved to: {filename}")


def export_to_markdown(results: List[Dict], stats: Dict, by_industry: Dict, filename: str):
    """Export to Markdown"""
    with open(filename, 'w') as f:
        f.write("# CDN Infrastructure Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total Domains:** {stats['total_domains']}\n")
        f.write(f"- **Multi-CDN Adoption:** {stats.get('multi_cdn_rate', 0):.1f}%\n\n")
        
        f.write("## CDN Provider Market Share\n\n")
        f.write("| Provider | Count | Percentage |\n")
        f.write("|----------|-------|------------|\n")
        sorted_providers = sorted(stats['cdn_usage'].items(), key=lambda x: x[1], reverse=True)
        for provider, count in sorted_providers:
            percentage = (count / stats['successful']) * 100 if stats['successful'] > 0 else 0
            f.write(f"| {provider} | {count} | {percentage:.1f}% |\n")
    
    print(f"✅ Markdown report saved to: {filename}")


def check_dependencies():
    """Check required commands"""
    missing = []
    for cmd in ['curl', 'dig']:
        try:
            subprocess.run([cmd, '--version'], capture_output=True, timeout=5)
        except:
            missing.append(cmd)
    
    if missing:
        print(f"❌ Error: Missing required commands: {', '.join(missing)}")
        print("\nInstallation:")
        print("  macOS: brew install curl bind")
        print("  Ubuntu: sudo apt-get install curl dnsutils")
        return False
    return True


def main():
    """Main execution"""
    print("="*70)
    print("CDN INFRASTRUCTURE ANALYZER")
    print("Analyzing Top 6 US Industries - 32 Companies")
    print("="*70)
    
    if not check_dependencies():
        sys.exit(1)
    
    # Create output directory
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"\n📁 Created output directory: {output_dir}/")
    
    all_results = []
    by_industry = {}
    
    for industry, domains in COMPANIES.items():
        print(f"\n🏢 Analyzing {industry}...")
        industry_results = []
        
        for domain in domains:
            print(f"  → {domain}...", end='', flush=True)
            result = analyze_domain_cdn(domain)
            all_results.append(result)
            industry_results.append(result)
            
            if result['status'] == 'success':
                providers = ', '.join(result['cdn_providers'])
                mc = '✅' if result['multi_cdn'] else '❌'
                print(f" Done! CDN: {providers}, Multi: {mc}")
            else:
                print(f" ❌ {result['error']}")
        
        successful = [r for r in industry_results if r['status'] == 'success']
        by_industry[industry] = {
            'total': len(successful),
            'multi_cdn': sum(1 for r in successful if r['multi_cdn'])
        }
    
    stats = generate_summary_stats(all_results)
    print_summary_report(all_results, stats, by_industry)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    export_to_csv(all_results, os.path.join(output_dir, f'cdn_analysis_{timestamp}.csv'))
    export_to_json(all_results, os.path.join(output_dir, f'cdn_analysis_{timestamp}.json'))
    export_to_markdown(all_results, stats, by_industry, os.path.join(output_dir, f'cdn_analysis_{timestamp}.md'))
    
    print(f"\n{'='*70}")
    print("✅ Analysis complete!")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    print("\nCDN Infrastructure Analyzer")
    print("=" * 70)
    print("\nAnalyzes CDN configuration for 32 major US companies")
    print("across 6 industries.\n")
    print("Requirements: curl and dig commands\n")
    print("Usage:")
    print("  python3 cdn_analyzer.py")
    print("=" * 70)
    print()
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)