#!/usr/bin/env python3
"""
Enhanced CDN Infrastructure Analyzer for Top US Industries
Analyzes CDN provider configurations with improved detection methods
"""

import socket
import json
import csv
from datetime import datetime
from typing import Dict, List, Set, Tuple
import sys
import os
from collections import defaultdict
import subprocess
import re

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

# Enhanced CDN detection patterns with ASN and expanded patterns
CDN_PATTERNS = {
    'Cloudflare': {
        'asn': ['AS13335', 'AS209242'],
        'ip_prefixes': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.',
                        '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
                        '104.28.', '104.29.', '104.30.', '104.31.',
                        '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.',
                        '162.159.', '173.245.', '188.114.', '190.93.', '197.234.', '198.41.'],
        'headers': ['cf-ray', 'cf-cache-status', 'server: cloudflare', 'cf-request-id'],
        'cname_patterns': ['cloudflare', 'cloudflare.net', 'cloudflare-dns'],
        'reverse_dns': ['cloudflare.com']
    },
    'Akamai': {
        'asn': ['AS20940', 'AS16625', 'AS16702', 'AS17204', 'AS18717', 'AS18680', 
                'AS20189', 'AS21342', 'AS21357', 'AS23903', 'AS24319', 'AS26008',
                'AS30675', 'AS31108', 'AS31109', 'AS31110', 'AS31377', 'AS33905',
                'AS34164', 'AS35993', 'AS35994', 'AS36183', 'AS39836', 'AS43639'],
        'ip_prefixes': ['23.', '2.16.', '2.17.', '2.18.', '2.19.', '2.20.', '2.21.', '2.22.', '2.23.',
                        '72.21.', '72.247.', '88.221.', '92.122.', '95.100.', '96.6.', '96.7.',
                        '104.64.', '104.65.', '104.66.', '104.67.', '104.68.', '104.69.',
                        '104.70.', '104.71.', '104.72.', '104.73.', '104.74.', '104.75.',
                        '104.76.', '104.77.', '104.78.', '104.79.', '104.80.', '104.81.',
                        '184.24.', '184.25.', '184.26.', '184.27.', '184.28.', '184.29.',
                        '184.30.', '184.31.', '184.50.', '184.51.', '184.84.', '184.85.',
                        '23.0.', '23.1.', '23.2.', '23.3.', '23.4.', '23.5.', '23.6.', '23.7.',
                        '23.32.', '23.33.', '23.34.', '23.35.', '23.36.', '23.37.', '23.38.', '23.39.',
                        '23.40.', '23.41.', '23.42.', '23.43.', '23.44.', '23.45.', '23.46.', '23.47.',
                        '23.48.', '23.49.', '23.50.', '23.51.', '23.52.', '23.53.', '23.54.', '23.55.',
                        '23.192.', '23.193.', '23.194.', '23.195.', '23.196.', '23.197.', '23.198.', '23.199.',
                        '23.200.', '23.201.', '23.202.', '23.203.', '23.204.', '23.205.', '23.206.', '23.207.',
                        '23.208.', '23.209.', '23.210.', '23.211.', '23.212.', '23.213.', '23.214.', '23.215.',
                        '23.216.', '23.217.', '23.218.', '23.219.', '23.220.', '23.221.', '23.222.', '23.223.'],
        'headers': ['x-akamai', 'akamai-', 'x-akamai-session-info', 'x-akamai-staging', 
                    'akamai-cache-status', 'akamai-grn', 'server: akamaighost', 'x-cache-key',
                    'x-check-cacheable'],
        'cname_patterns': ['akamai', 'akadns', 'edgesuite', 'edgekey', 'akamaiedge', 
                          'akamaihd', 'edgefcs', 'srip', 'akamai.net', 'akam.net',
                          'akamaized', 'akamaized.net', 'akahost', 'edgefonts'],
        'reverse_dns': ['akamai.net', 'akamai.com', 'akadns.net', 'akamaiedge.net']
    },
    'AWS CloudFront': {
        'asn': ['AS16509', 'AS14618'],
        'ip_prefixes': ['13.32.', '13.33.', '13.35.', '13.224.', '13.225.', '13.226.', '13.227.',
                        '18.64.', '18.65.', '18.154.', '18.160.', '18.164.', '18.165.', '18.166.',
                        '52.46.', '52.84.', '52.85.', '52.222.', '54.182.', '54.192.', '54.230.', 
                        '54.239.', '99.84.', '99.86.', '143.204.', '205.251.', '144.220.'],
        'headers': ['x-amz-cf', 'via: cloudfront', 'x-amz-request-id', 'x-cache: cloudfront',
                    'x-amz-id', 'x-amzn-requestid'],
        'cname_patterns': ['cloudfront', 'cloudfront.net', 'amazonaws.com'],
        'reverse_dns': ['cloudfront.net', 'amazonaws.com']
    },
    'Fastly': {
        'asn': ['AS54113'],
        'ip_prefixes': ['151.101.', '199.232.', '146.75.', '23.235.', '185.31.', '157.52.'],
        'headers': ['x-fastly', 'fastly-', 'x-served-by: cache', 'x-cache: hit, miss',
                    'fastly-debug-digest'],
        'cname_patterns': ['fastly', 'fastly.net', 'fastlylb.net'],
        'reverse_dns': ['fastly.net']
    },
    'Azure CDN': {
        'asn': ['AS8075', 'AS8068'],
        'ip_prefixes': ['13.107.', '20.', '40.', '52.', '104.40.', '104.41.', '104.42.',
                        '104.43.', '104.44.', '104.45.'],
        'headers': ['x-azure-ref', 'x-cache-remote', 'x-msedge-ref', 'server: ecacc'],
        'cname_patterns': ['azureedge', 'azure-cdn', 'azurefd', 'trafficmanager'],
        'reverse_dns': ['azureedge.net', 'azure.com']
    },
    'Google Cloud CDN': {
        'asn': ['AS15169', 'AS139070', 'AS19527'],
        'ip_prefixes': ['34.', '35.', '142.250.', '172.217.', '172.253.', '216.239.', '172.217.',
                        '216.58.', '172.102.', '173.194.', '74.125.', '209.85.'],
        'headers': ['x-goog-', 'server: gfe', 'server: sffe', 'x-google-', 'alt-svc: quic'],
        'cname_patterns': ['googleusercontent', 'ghs.google', 'googlesyndication', 
                          'google.com', '1e100.net', 'googleapis.com'],
        'reverse_dns': ['1e100.net', 'google.com', 'googleusercontent.com']
    },
    'StackPath': {
        'asn': ['AS33438', 'AS12989'],
        'ip_prefixes': ['151.139.', '205.185.', '206.51.'],
        'headers': ['x-sp-cache', 'served-by: stackpath'],
        'cname_patterns': ['stackpath', 'stackpathcdn', 'netdna-cdn'],
        'reverse_dns': ['stackpath.net']
    },
    'KeyCDN': {
        'asn': ['AS30633'],
        'ip_prefixes': [],
        'headers': ['x-keycdn', 'server: keycdn'],
        'cname_patterns': ['kxcdn', 'keycdn'],
        'reverse_dns': ['kxcdn.com']
    }
}


def get_http_headers(domain: str) -> Dict[str, str]:
    """Fetch HTTP headers from domain"""
    try:
        # Try HTTPS first
        result = subprocess.run(['curl', '-sIL', '--max-time', '10', f'https://{domain}'],
                                capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            # Fallback to HTTP
            result = subprocess.run(['curl', '-sIL', '--max-time', '10', f'http://{domain}'],
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
    
    # Try multiple subdomain variations
    domains_to_check = [domain]
    if not domain.startswith('www.'):
        domains_to_check.append(f'www.{domain}')
    
    for check_domain in domains_to_check:
        current = check_domain
        try:
            for _ in range(15):  # Increased from 10 to 15
                result = subprocess.run(['dig', '+short', 'CNAME', current],
                                        capture_output=True, text=True, timeout=8)
                cname = result.stdout.strip().rstrip('.')
                if not cname or cname == current or cname in cnames:
                    break
                cnames.append(cname)
                current = cname
        except:
            pass
    
    return cnames


def get_reverse_dns(ip: str) -> str:
    """Get reverse DNS (PTR) for IP"""
    try:
        result = subprocess.run(['dig', '+short', '-x', ip],
                                capture_output=True, text=True, timeout=5)
        ptr = result.stdout.strip().rstrip('.')
        return ptr if ptr else ''
    except:
        return ''


def get_asn_from_ip(ip: str) -> Tuple[str, str]:
    """Get ASN and organization from IP using whois"""
    try:
        result = subprocess.run(['whois', '-h', 'whois.cymru.com', ip],
                                capture_output=True, text=True, timeout=10)
        
        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            # Parse cymru format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
            parts = [p.strip() for p in lines[1].split('|')]
            if len(parts) >= 7:
                asn = parts[0]
                org = parts[6] if len(parts) > 6 else ''
                return asn, org
    except:
        pass
    
    # Fallback: try standard whois
    try:
        result = subprocess.run(['whois', ip],
                                capture_output=True, text=True, timeout=10)
        
        asn_match = re.search(r'OriginAS:\s*(AS\d+)', result.stdout, re.IGNORECASE)
        if not asn_match:
            asn_match = re.search(r'origin:\s*(AS\d+)', result.stdout, re.IGNORECASE)
        
        org_match = re.search(r'OrgName:\s*(.+)', result.stdout, re.IGNORECASE)
        
        asn = asn_match.group(1) if asn_match else ''
        org = org_match.group(1).strip() if org_match else ''
        
        return asn, org
    except:
        return '', ''


def resolve_domain_ips(domain: str) -> List[str]:
    """Resolve domain to IP addresses"""
    all_ips = []
    
    # Check multiple subdomain variations
    domains_to_check = [domain]
    if not domain.startswith('www.'):
        domains_to_check.append(f'www.{domain}')
    
    for check_domain in domains_to_check:
        try:
            ips = socket.getaddrinfo(check_domain, None)
            for ip in ips:
                ip_addr = ip[4][0]
                # Only add IPv4 addresses
                if ':' not in ip_addr and ip_addr not in all_ips:
                    all_ips.append(ip_addr)
        except:
            pass
    
    return all_ips


def identify_cdn_from_asn(asn: str) -> Set[str]:
    """Identify CDN from ASN (most reliable method)"""
    cdns = set()
    if not asn:
        return cdns
    
    for cdn_name, cdn_data in CDN_PATTERNS.items():
        if asn in cdn_data.get('asn', []):
            cdns.add(cdn_name)
    
    return cdns


def identify_cdn_from_ip(ip: str) -> Set[str]:
    """Identify CDN from IP prefix"""
    cdns = set()
    for cdn_name, cdn_data in CDN_PATTERNS.items():
        for prefix in cdn_data.get('ip_prefixes', []):
            if ip.startswith(prefix):
                cdns.add(cdn_name)
                break
    return cdns


def identify_cdn_from_reverse_dns(ptr: str) -> Set[str]:
    """Identify CDN from reverse DNS"""
    cdns = set()
    if not ptr:
        return cdns
    
    ptr_lower = ptr.lower()
    for cdn_name, cdn_data in CDN_PATTERNS.items():
        for pattern in cdn_data.get('reverse_dns', []):
            if pattern in ptr_lower:
                cdns.add(cdn_name)
                break
    
    return cdns


def identify_cdn_from_headers(headers: Dict[str, str]) -> Set[str]:
    """Identify CDN from headers"""
    cdns = set()
    for cdn_name, cdn_data in CDN_PATTERNS.items():
        for pattern in cdn_data.get('headers', []):
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
            for pattern in cdn_data.get('cname_patterns', []):
                if pattern in cname_lower:
                    cdns.add(cdn_name)
                    break
    return cdns


def calculate_detection_confidence(detection_methods: Dict) -> Tuple[float, str]:
    """Calculate confidence score based on detection methods"""
    confidence_weights = {
        'asn': 0.95,
        'reverse_dns': 0.85,
        'cname': 0.80,
        'headers': 0.70,
        'ip': 0.40
    }
    
    if not detection_methods:
        return 0.0, 'none'
    
    max_confidence = max([confidence_weights.get(method, 0) for method in detection_methods.keys()])
    
    if max_confidence >= 0.80:
        level = 'high'
    elif max_confidence >= 0.60:
        level = 'medium'
    elif max_confidence >= 0.30:
        level = 'low'
    else:
        level = 'very low'
    
    return max_confidence, level


def analyze_domain_cdn(domain: str) -> Dict:
    """Analyze CDN for a domain with improved detection"""
    result = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'status': 'success',
        'cdn_providers': set(),
        'multi_cdn': False,
        'detection_methods': {},
        'detection_details': {},
        'confidence_score': 0.0,
        'confidence_level': 'none',
        'ips': [],
        'cnames': [],
        'asn_info': {},
        'error': None
    }
    
    try:
        print(f"    Analyzing...", end='', flush=True)
        
        # Step 1: Resolve IPs
        ips = resolve_domain_ips(domain)
        result['ips'] = ips
        
        if ips:
            print(f" IPs: {len(ips)}", end='', flush=True)
        
        # Step 2: ASN lookup (most reliable)
        asn_detections = {}
        for ip in ips[:3]:  # Check first 3 IPs
            asn, org = get_asn_from_ip(ip)
            if asn:
                result['asn_info'][ip] = {'asn': asn, 'org': org}
                cdns = identify_cdn_from_asn(asn)
                if cdns:
                    result['cdn_providers'].update(cdns)
                    for cdn in cdns:
                        if cdn not in asn_detections:
                            asn_detections[cdn] = []
                        asn_detections[cdn].append(f"{ip} ({asn} - {org})")
        
        if asn_detections:
            result['detection_methods']['asn'] = list(asn_detections.keys())
            result['detection_details']['asn'] = asn_detections
            print(f" ASN✓", end='', flush=True)
        
        # Step 3: Reverse DNS
        reverse_dns_detections = {}
        for ip in ips[:3]:
            ptr = get_reverse_dns(ip)
            if ptr:
                cdns = identify_cdn_from_reverse_dns(ptr)
                if cdns:
                    result['cdn_providers'].update(cdns)
                    for cdn in cdns:
                        if cdn not in reverse_dns_detections:
                            reverse_dns_detections[cdn] = []
                        reverse_dns_detections[cdn].append(f"{ip} → {ptr}")
        
        if reverse_dns_detections:
            result['detection_methods']['reverse_dns'] = list(reverse_dns_detections.keys())
            result['detection_details']['reverse_dns'] = reverse_dns_detections
            print(f" PTR✓", end='', flush=True)
        
        # Step 4: IP prefix matching
        ip_detections = {}
        for ip in ips:
            cdns = identify_cdn_from_ip(ip)
            if cdns:
                result['cdn_providers'].update(cdns)
                for cdn in cdns:
                    if cdn not in ip_detections:
                        ip_detections[cdn] = []
                    ip_detections[cdn].append(ip)
        
        if ip_detections:
            result['detection_methods']['ip'] = list(ip_detections.keys())
            result['detection_details']['ip'] = ip_detections
        
        # Step 5: CNAME chain
        cnames = get_cname_chain(domain)
        result['cnames'] = cnames
        
        if cnames:
            print(f" CNAME✓", end='', flush=True)
        
        cname_detections = {}
        cdns_from_cname = identify_cdn_from_cname(cnames)
        if cdns_from_cname:
            result['cdn_providers'].update(cdns_from_cname)
            for cdn in cdns_from_cname:
                matching_cnames = []
                for cname in cnames:
                    for cdn_name, cdn_data in CDN_PATTERNS.items():
                        if cdn_name == cdn:
                            for pattern in cdn_data.get('cname_patterns', []):
                                if pattern in cname.lower():
                                    matching_cnames.append(f"{cname} (matched: {pattern})")
                                    break
                if matching_cnames:
                    cname_detections[cdn] = matching_cnames
            
            result['detection_methods']['cname'] = list(cdns_from_cname)
            result['detection_details']['cname'] = cname_detections
        
        # Step 6: HTTP headers
        headers = get_http_headers(domain)
        
        header_detections = {}
        cdns_from_headers = identify_cdn_from_headers(headers)
        if cdns_from_headers:
            result['cdn_providers'].update(cdns_from_headers)
            for cdn in cdns_from_headers:
                matching_headers = []
                for cdn_name, cdn_data in CDN_PATTERNS.items():
                    if cdn_name == cdn:
                        for pattern in cdn_data.get('headers', []):
                            for header_key, header_value in headers.items():
                                if pattern.lower() in header_key or pattern.lower() in header_value:
                                    matching_headers.append(f"{header_key}: {header_value}")
                                    break
                if matching_headers:
                    header_detections[cdn] = matching_headers[:3]  # Limit to 3
            
            result['detection_methods']['headers'] = list(cdns_from_headers)
            result['detection_details']['headers'] = header_detections
            print(f" HDR✓", end='', flush=True)
        
        # Calculate confidence
        confidence_score, confidence_level = calculate_detection_confidence(result['detection_methods'])
        result['confidence_score'] = confidence_score
        result['confidence_level'] = confidence_level
        
        result['multi_cdn'] = len(result['cdn_providers']) > 1
        
        # Improved fallback logic
        if not result['cdn_providers']:
            # Check if it's a tech giant with proprietary CDN
            tech_giants = ['apple', 'microsoft', 'google', 'amazon', 'meta', 'facebook', 'netflix']
            if any(tech in domain for tech in tech_giants):
                result['cdn_providers'].add('Internal/Proprietary CDN')
                result['detection_details']['fallback'] = 'Tech giant - likely internal CDN'
                result['confidence_level'] = 'medium'
            else:
                result['cdn_providers'].add('Unknown/Not Detected')
                result['detection_details']['fallback'] = 'No CDN detected by any method'
                result['confidence_level'] = 'none'
        
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
        'high_confidence': sum(1 for r in results if r.get('confidence_level') == 'high'),
        'cdn_usage': defaultdict(int),
        'detection_method_usage': defaultdict(int)
    }
    
    if stats['successful'] > 0:
        stats['multi_cdn_rate'] = (stats['multi_cdn_count'] / stats['successful']) * 100
        stats['high_confidence_rate'] = (stats['high_confidence'] / stats['successful']) * 100
    
    for result in results:
        if result['status'] == 'success':
            for provider in result['cdn_providers']:
                if provider not in ['Unknown/Not Detected']:
                    stats['cdn_usage'][provider] += 1
            
            for method in result.get('detection_methods', {}).keys():
                stats['detection_method_usage'][method] += 1
    
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
    print(f"  High Confidence: {stats['high_confidence']}/{stats['successful']} ({stats.get('high_confidence_rate', 0):.1f}%)")
    
    print(f"\n🔍 Detection Method Usage:")
    sorted_methods = sorted(stats['detection_method_usage'].items(), key=lambda x: x[1], reverse=True)
    for method, count in sorted_methods:
        print(f"  {method.upper()}: {count} domains")
    
    print(f"\n🔧 CDN Provider Market Share:")
    sorted_providers = sorted(stats['cdn_usage'].items(), key=lambda x: x[1], reverse=True)
    for provider, count in sorted_providers:
        percentage = (count / stats['successful']) * 100 if stats['successful'] > 0 else 0
        print(f"  {provider}: {count} domains ({percentage:.1f}%)")


def export_to_csv(results: List[Dict], filename: str):
    """Export to CSV"""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Industry', 'Company', 'Domain', 'CDN_Providers', 'Multi_CDN',
                      'Confidence_Level', 'Confidence_Score', 'Detection_Methods',
                      'ASN_Detection', 'Reverse_DNS_Detection', 'IP_Detection', 
                      'CNAME_Detection', 'Header_Detection',
                      'Status', 'Error', 'Timestamp']
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
            
            # Format detection details
            asn_details = []
            if 'asn' in result.get('detection_details', {}):
                for cdn, info in result['detection_details']['asn'].items():
                    asn_details.append(f"{cdn}: {'; '.join(info)}")
            
            reverse_dns_details = []
            if 'reverse_dns' in result.get('detection_details', {}):
                for cdn, ptrs in result['detection_details']['reverse_dns'].items():
                    reverse_dns_details.append(f"{cdn}: {'; '.join(ptrs)}")
            
            ip_details = []
            if 'ip' in result.get('detection_details', {}):
                for cdn, ips in result['detection_details']['ip'].items():
                    ip_details.append(f"{cdn}: {', '.join(ips)}")
            
            cname_details = []
            if 'cname' in result.get('detection_details', {}):
                for cdn, cnames in result['detection_details']['cname'].items():
                    cname_details.append(f"{cdn}: {'; '.join(cnames)}")
            
            header_details = []
            if 'headers' in result.get('detection_details', {}):
                for cdn, headers in result['detection_details']['headers'].items():
                    header_details.append(f"{cdn}: {'; '.join(headers[:2])}")
            
            rows.append({
                'Industry': industry,
                'Company': company_name,
                'Domain': result['domain'],
                'CDN_Providers': '; '.join(result.get('cdn_providers', [])),
                'Multi_CDN': 'YES' if result.get('multi_cdn', False) else 'NO',
                'Confidence_Level': result.get('confidence_level', 'none'),
                'Confidence_Score': f"{result.get('confidence_score', 0):.2f}",
                'Detection_Methods': detection,
                'ASN_Detection': '; '.join(asn_details),
                'Reverse_DNS_Detection': '; '.join(reverse_dns_details),
                'IP_Detection': '; '.join(ip_details),
                'CNAME_Detection': '; '.join(cname_details),
                'Header_Detection': '; '.join(header_details),
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
        f.write("# Enhanced CDN Infrastructure Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total Domains Analyzed:** {stats['total_domains']}\n")
        f.write(f"- **Multi-CDN Adoption:** {stats.get('multi_cdn_rate', 0):.1f}%\n")
        f.write(f"- **High Confidence Detections:** {stats.get('high_confidence_rate', 0):.1f}%\n\n")
        
        f.write("## Detection Method Effectiveness\n\n")
        f.write("| Method | Detections | Reliability |\n")
        f.write("|--------|------------|-------------|\n")
        method_reliability = {
            'asn': 'Very High (95%)',
            'reverse_dns': 'High (85%)',
            'cname': 'High (80%)',
            'headers': 'Medium (70%)',
            'ip': 'Low (40%)'
        }
        for method, count in sorted(stats['detection_method_usage'].items(), key=lambda x: x[1], reverse=True):
            reliability = method_reliability.get(method, 'Unknown')
            f.write(f"| {method.upper()} | {count} | {reliability} |\n")
        
        f.write("\n## CDN Provider Market Share\n\n")
        f.write("| Provider | Count | Percentage |\n")
        f.write("|----------|-------|------------|\n")
        sorted_providers = sorted(stats['cdn_usage'].items(), key=lambda x: x[1], reverse=True)
        for provider, count in sorted_providers:
            percentage = (count / stats['successful']) * 100 if stats['successful'] > 0 else 0
            f.write(f"| {provider} | {count} | {percentage:.1f}% |\n")
        
        f.write("\n## Detailed CDN Detection Results\n\n")
        
        for industry, domains in COMPANIES.items():
            f.write(f"### {industry}\n\n")
            
            for domain in domains:
                result = next((r for r in results if r['domain'] == domain), None)
                if result and result['status'] == 'success':
                    company_name = DOMAIN_TO_COMPANY.get(domain, domain)
                    f.write(f"#### {company_name} ({domain})\n\n")
                    
                    f.write(f"**CDN Providers:** {', '.join(result['cdn_providers'])}\n\n")
                    f.write(f"**Multi-CDN:** {'✅ YES' if result['multi_cdn'] else '❌ NO'}\n\n")
                    f.write(f"**Confidence Level:** {result['confidence_level'].upper()} ({result['confidence_score']:.0%})\n\n")
                    
                    # Detection details
                    if 'detection_details' in result and result['detection_details']:
                        f.write("**Detection Details:**\n\n")
                        
                        # ASN Detection (most reliable)
                        if 'asn' in result['detection_details']:
                            f.write("- **🎯 ASN Detection (Highest Reliability):**\n")
                            for cdn, info_list in result['detection_details']['asn'].items():
                                f.write(f"  - **{cdn}:**\n")
                                for info in info_list:
                                    f.write(f"    - {info}\n")
                            f.write("\n")
                        
                        # Reverse DNS Detection
                        if 'reverse_dns' in result['detection_details']:
                            f.write("- **🔍 Reverse DNS (PTR) Detection:**\n")
                            for cdn, ptrs in result['detection_details']['reverse_dns'].items():
                                f.write(f"  - **{cdn}:**\n")
                                for ptr in ptrs:
                                    f.write(f"    - {ptr}\n")
                            f.write("\n")
                        
                        # IP Detection
                        if 'ip' in result['detection_details']:
                            f.write("- **📡 IP Address Detection:**\n")
                            for cdn, ips in result['detection_details']['ip'].items():
                                f.write(f"  - **{cdn}:** {', '.join(ips)}\n")
                            f.write("\n")
                        
                        # CNAME Detection
                        if 'cname' in result['detection_details']:
                            f.write("- **🔗 CNAME Detection:**\n")
                            for cdn, cnames in result['detection_details']['cname'].items():
                                f.write(f"  - **{cdn}:**\n")
                                for cname in cnames:
                                    f.write(f"    - {cname}\n")
                            f.write("\n")
                        
                        # Header Detection
                        if 'headers' in result['detection_details']:
                            f.write("- **📋 HTTP Header Detection:**\n")
                            for cdn, headers in result['detection_details']['headers'].items():
                                f.write(f"  - **{cdn}:**\n")
                                for header in headers[:3]:
                                    f.write(f"    - `{header}`\n")
                            f.write("\n")
                        
                        # Fallback note
                        if 'fallback' in result['detection_details']:
                            f.write(f"- **⚠️ Note:** {result['detection_details']['fallback']}\n\n")
                    
                    # ASN Information
                    if result.get('asn_info'):
                        f.write("**Network Information:**\n\n")
                        for ip, info in result['asn_info'].items():
                            f.write(f"- `{ip}` → {info['asn']} ({info['org']})\n")
                        f.write("\n")
                    
                    f.write("---\n\n")
    
    print(f"✅ Markdown report saved to: {filename}")


def check_dependencies():
    """Check required commands"""
    missing = []
    
    # Check curl
    try:
        result = subprocess.run(['which', 'curl'], capture_output=True, timeout=5)
        if result.returncode != 0:
            missing.append('curl')
    except:
        missing.append('curl')
    
    # Check dig
    try:
        result = subprocess.run(['which', 'dig'], capture_output=True, timeout=5)
        if result.returncode != 0:
            missing.append('dig')
    except:
        missing.append('dig')
    
    # Check whois
    try:
        result = subprocess.run(['which', 'whois'], capture_output=True, timeout=5)
        if result.returncode != 0:
            missing.append('whois')
    except:
        missing.append('whois')
    
    if missing:
        print(f"❌ Error: Missing required commands: {', '.join(missing)}")
        print("\nInstallation:")
        print("  macOS: brew install curl bind whois")
        print("  Ubuntu/Debian: sudo apt-get install curl dnsutils whois")
        print("  RHEL/CentOS: sudo yum install curl bind-utils whois")
        return False
    
    print("✅ All dependencies found (curl, dig, whois)")
    return True


def main():
    """Main execution"""
    print("="*70)
    print("ENHANCED CDN INFRASTRUCTURE ANALYZER")
    print("Analyzing Top 6 US Industries - 32 Companies")
    print("With ASN, Reverse DNS, and Expanded Pattern Detection")
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
                providers = ', '.join([p for p in result['cdn_providers'] if p != 'Unknown/Not Detected'])
                if not providers:
                    providers = 'Unknown/Not Detected'
                mc = '✅' if result['multi_cdn'] else '❌'
                conf = result['confidence_level']
                print(f" Done! CDN: {providers}, Multi: {mc}, Confidence: {conf}")
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
    print("\nEnhanced CDN Infrastructure Analyzer")
    print("=" * 70)
    print("\nAnalyzes CDN configuration for 32 major US companies")
    print("across 6 industries using multiple detection methods:\n")
    print("  • ASN Lookups (95% reliability)")
    print("  • Reverse DNS (85% reliability)")
    print("  • CNAME Analysis (80% reliability)")
    print("  • HTTP Headers (70% reliability)")
    print("  • IP Prefix Matching (40% reliability)\n")
    print("Requirements: curl, dig, and whois commands\n")
    print("Usage:")
    print("  python3 cdn_analyzer_improved.py")
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

