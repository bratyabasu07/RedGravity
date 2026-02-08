#!/usr/bin/env python3
"""
Noise Filter Script for RedGravity
Checks if IP belongs to CDN/Cloud providers
"""

import sys
import ipaddress

# Known CDN/Cloud provider IP ranges (simplified)
CDN_CLOUD_RANGES = [
    # Cloudflare
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    
    # AWS (sample ranges)
    '52.0.0.0/8',
    '54.0.0.0/8',
    
    # Google Cloud
    '34.64.0.0/10',
    '35.184.0.0/13',
    
    # Akamai (sample)
    '23.0.0.0/8',
]

def is_cdn_cloud(ip_str):
    """Check if IP belongs to CDN/Cloud provider"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        for range_str in CDN_CLOUD_RANGES:
            network = ipaddress.ip_network(range_str)
            if ip in network:
                return True
        
        return False
    except ValueError:
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("false")
        sys.exit(0)
    
    ip = sys.argv[1]
    result = is_cdn_cloud(ip)
    print("true" if result else "false")
