#!/usr/bin/env python3
"""
DNS Discovery Script for RedGravity
Performs basic subdomain enumeration
"""

import sys
import socket

def discover_subdomains(domain):
    """Basic subdomain discovery"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'webdisk', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mail', 'vpn',
        'blog', 'shop', 'api', 'dev', 'staging', 'test', 'admin', 'portal'
    ]
    
    found_domains = [domain]  # Always include the main domain
    
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            found_domains.append(subdomain)
        except socket.gaierror:
            pass  # Subdomain doesn't exist
    
    return found_domains

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: discovery.py <domain>", file=sys.stderr)
        sys.exit(1)
    
    target = sys.argv[1]
    domains = discover_subdomains(target)
    
    for domain in domains:
        print(domain)
