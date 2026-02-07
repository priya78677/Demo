# URL Validation & Verification Tool
# Mini Project - January 2025 version

import re
import requests
import urllib.parse
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from requests.exceptions import RequestException, Timeout, SSLError

# ────────────────────────────────────────────────
#          CONFIGURATION
# ────────────────────────────────────────────────
TIMEOUT = 8             # seconds
ALLOW_REDIRECTS = True
MAX_REDIRECTS = 8
USER_AGENT = "Mozilla/5.0 (MiniProject/URLChecker; +https://github.com)"

# Suspicious patterns (very basic phishing/malware indicators)
SUSPICIOUS_PATTERNS = [
    r'\b(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd)\b',           # common shorteners
    r'\d{5,}',                                                     # many numbers in domain
    r'[@|%40]',                                                    # @ in URL (homograph attack)
    r'(login|account|secure|verify|update|password|bank|pay)[a-z0-9-]*\.',  # suspicious subdomains
]

# ────────────────────────────────────────────────
#          HELPER FUNCTIONS
# ────────────────────────────────────────────────

def is_valid_url_syntax(url: str) -> bool:
    """Very practical regex for URL validation (catches most real-world cases)"""
    if not url or len(url) > 2048:
        return False
        
    pattern = re.compile(
        r'^(?:http)s?://'                               # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domain...
        r'(?:[A-Z]{2,63}|[A-Z0-9-]{2,63}(?<!-))|'     # TLD
        r'localhost|' 
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'         # ...or ip
        r'(?::\d+)?'                                    # optional port
        r'(?:/?|[/?]\S*)$', re.IGNORECASE)
    
    return bool(pattern.match(url))


def normalize_url(url: str) -> str:
    """Add https:// if missing, remove trailing /, etc."""
    url = url.strip()
    if not url:
        return ""
        
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    # Remove default ports and fragments
    parsed = urlparse(url)
    if parsed.port in (80, 443, None):
        netloc = parsed.hostname
    else:
        netloc = f"{parsed.hostname}:{parsed.port}"
        
    clean_url = urllib.parse.urlunparse((
        parsed.scheme,
        netloc,
        parsed.path or '/',
        parsed.params,
        parsed.query,
        ''
    ))
    
    return clean_url.rstrip('/')


def check_reachability(url: str) -> dict:
    """Try to make a real HTTP request and return useful info"""
    result = {
        'reachable': False,
        'status_code': None,
        'final_url': url,
        'redirect_count': 0,
        'response_time_ms': None,
        'error': None
    }
    
    try:
        start = datetime.now()
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=ALLOW_REDIRECTS,
            headers={'User-Agent': USER_AGENT},
            verify=True
        )
        end = datetime.now()
        
        result.update({
            'reachable': True,
            'status_code': response.status_code,
            'final_url': response.url,
            'redirect_count': len(response.history),
            'response_time_ms': round((end - start).total_seconds() * 1000, 1)
        })
        
    except Timeout:
        result['error'] = f"Timeout after {TIMEOUT} seconds"
    except SSLError:
        result['error'] = "SSL/TLS certificate error"
    except RequestException as e:
        result['error'] = str(e)
        
    return result


def basic_phishing_score(url: str) -> dict:
    """Very simple suspicious pattern checker"""
    score = 0
    reasons = []
    
    parsed = urlparse(url)
    domain = parsed.hostname.lower() if parsed.hostname else ""
    
    # Shortener usage
    if any(re.search(p, url, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS[:1]):
        score += 30
        reasons.append("Uses URL shortener")
    
    # Many numbers in domain
    if re.search(r'\d{5,}', domain):
        score += 25
        reasons.append("Long number sequence in domain")
    
    # Suspicious keywords in subdomain
    if any(re.search(p, domain) for p in SUSPICIOUS_PATTERNS[3:]):
        score += 35
        reasons.append("Suspicious keyword in subdomain")
    
    return {
        'score': min(score, 100),  # cap at 100
        'risk_level': 'High' if score >= 60 else 'Medium' if score >= 30 else 'Low',
        'reasons': reasons
    }


def get_ssl_info(url: str) -> dict:
    """Basic SSL certificate check"""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return {'has_ssl': False, 'error': 'No hostname'}
            
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'has_ssl': True,
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'expires': cert.get('notAfter')
                }
    except Exception as e:
        return {'has_ssl': False, 'error': str(e)}


# ────────────────────────────────────────────────
#          MAIN FUNCTION
# ────────────────────────────────────────────────

def check_url(url: str) -> dict:
    """Main function to check one URL"""
    result = {
        'original_url': url,
        'normalized_url': None,
        'valid_syntax': False,
        'reachable': False,
        'final_url': None,
        'status': None,
        'risk': None,
        'ssl_info': None,
        'checked_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Step 1 - Syntax validation
    if not is_valid_url_syntax(url):
        result['error'] = "Invalid URL syntax"
        return result
        
    result['valid_syntax'] = True
    result['normalized_url'] = normalize_url(url)
    
    # Step 2 - Reachability check
    reach = check_reachability(result['normalized_url'])
    result.update(reach)
    
    # Step 3 - Risk scoring
    result['risk'] = basic_phishing_score(result['final_url'] or result['normalized_url'])
    
    # Step 4 - SSL info (only if https)
    if result['normalized_url'].startswith('https://'):
        result['ssl_info'] = get_ssl_info(result['normalized_url'])
    
    return result


# ────────────────────────────────────────────────
#          CLI INTERFACE (for mini project demo)
# ────────────────────────────────────────────────

def print_report(data: dict):
    print("\n" + "="*70)
    print("          URL VALIDATION & VERIFICATION REPORT")
    print("="*70)
    print(f"Checked at : {data['checked_at']}")
    print(f"Original   : {data['original_url']}")
    print(f"Normalized : {data['normalized_url']}")
    print(f"Valid syntax : {'✓ Yes' if data['valid_syntax'] else '✗ No'}")
    
    if not data.get('valid_syntax'):
        print("\nError:", data.get('error', 'Invalid URL'))
        return
        
    print(f"Reachable    : {'✓ Yes' if data['reachable'] else '✗ No'}")
    
    if data['reachable']:
        print(f"Status       : {data['status_code']}")
        print(f"Final URL    : {data['final_url']}")
        print(f"Redirects    : {data['redirect_count']}")
        print(f"Response time: {data['response_time_ms']} ms")
        
        risk = data['risk']
        print(f"\nRisk level   : {risk['risk_level']} (score: {risk['score']}/100)")
        if risk['reasons']:
            print("Reasons      :", ", ".join(risk['reasons']))
            
        if data.get('ssl_info', {}).get('has_ssl'):
            print("\nSSL Certificate : Present")
            print(f"  Issuer        : {data['ssl_info'].get('issuer', {}).get('organizationName', 'Unknown')}")
            print(f"  Expires       : {data['ssl_info'].get('expires', 'Unknown')}")
        else:
            print("\nSSL : Not present or failed to verify")
            
    else:
        print("Error:", data.get('error', 'Unknown connection error'))


if __name__ == "__main__":
    print("URL Validation & Verification Tool (Mini Project)")
    print("Enter URLs one by one (empty line to quit)\n")
    
    while True:
        url = input("URL > ").strip()
        if not url:
            break
            
        try:
            report = check_url(url)
            print_report(report)
        except Exception as e:
            print("\nUnexpected error:", str(e))
        print("-"*70)