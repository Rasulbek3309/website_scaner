#!/usr/bin/env python3
import json
import sys
import urllib.request
import urllib.parse
import socket
import ssl
import re
from datetime import datetime
import subprocess
import os

class WebsiteScanner:
    def __init__(self, url):
        self.url = url
        self.domain = urllib.parse.urlparse(url).netloc
        self.results = {}

    def scan(self):
        """Main scanning method"""
        try:
            self.results['basic_info'] = self.get_basic_info()
            self.results['server_info'] = self.get_server_info()
            self.results['domain_info'] = self.get_domain_info()
            self.results['security_info'] = self.get_security_info()
            self.results['performance_info'] = self.get_performance_info()
            self.results['technology_info'] = self.get_technology_info()
            
            return {
                'success': True,
                'data': self.results,
                'scan_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_basic_info(self):
        """Get basic website information"""
        parsed_url = urllib.parse.urlparse(self.url)
        
        try:
            response = urllib.request.urlopen(self.url, timeout=10)
            status_code = response.getcode()
        except Exception:
            status_code = 'Unknown'

        return {
            'url': self.url,
            'domain': self.domain,
            'status_code': status_code,
            'protocol': parsed_url.scheme,
            'port': parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        }

    def get_server_info(self):
        """Get server information"""
        try:
            ip_address = socket.gethostbyname(self.domain)
        except Exception:
            ip_address = 'Unknown'

        try:
            response = urllib.request.urlopen(self.url, timeout=10)
            server = response.headers.get('Server', 'Unknown')
        except Exception:
            server = 'Unknown'

        # Get location info (simplified)
        location_info = self.get_location_info(ip_address)

        return {
            'ip_address': ip_address,
            'server': server,
            'location': location_info.get('country', 'Unknown'),
            'city': location_info.get('city', 'Unknown'),
            'isp': location_info.get('isp', 'Unknown')
        }

    def get_domain_info(self):
        """Get domain information"""
        # Simplified domain info
        # In real implementation, you'd use whois libraries
        return {
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiry_date': 'Unknown',
            'name_servers': self.get_name_servers(),
            'dnssec': 'Unknown'
        }

    def get_security_info(self):
        """Get security information"""
        ssl_info = self.get_ssl_info()
        security_headers = self.get_security_headers()

        return {
            'ssl_certificate': ssl_info,
            'security_headers': security_headers,
            'hsts_enabled': 'Strict-Transport-Security' in security_headers,
            'content_security_policy': 'Content-Security-Policy' in security_headers
        }

    def get_performance_info(self):
        """Get performance information"""
        import time
        
        start_time = time.time()
        try:
            response = urllib.request.urlopen(self.url, timeout=10)
            response_time = (time.time() - start_time) * 1000
            content_length = response.headers.get('Content-Length', 'Unknown')
        except Exception:
            response_time = 'Unknown'
            content_length = 'Unknown'

        return {
            'response_time': f"{response_time:.2f}ms" if response_time != 'Unknown' else 'Unknown',
            'compression': self.check_compression(),
            'caching': self.check_caching(),
            'page_size': f"{int(content_length)/1024:.2f} KB" if content_length != 'Unknown' and content_length.isdigit() else 'Unknown'
        }

    def get_technology_info(self):
        """Get technology stack information"""
        try:
            response = urllib.request.urlopen(self.url, timeout=10)
            content = response.read().decode('utf-8', errors='ignore')
            headers = dict(response.headers)
        except Exception:
            content = ''
            headers = {}

        return {
            'web_server': self.detect_web_server(headers),
            'programming_language': self.detect_programming_language(headers, content),
            'cms': self.detect_cms(content),
            'javascript_frameworks': self.detect_js_frameworks(content),
            'analytics': self.detect_analytics(content)
        }

    def get_location_info(self, ip):
        """Get geolocation information for IP"""
        # Simplified location detection
        # In real implementation, use services like ipapi.co
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }

    def get_name_servers(self):
        """Get domain name servers"""
        try:
            import subprocess
            result = subprocess.run(['nslookup', '-type=ns', self.domain], 
                                  capture_output=True, text=True, timeout=10)
            # Parse nslookup output for nameservers
            nameservers = []
            for line in result.stdout.split('\n'):
                if 'nameserver' in line.lower():
                    ns = line.split()[-1].rstrip('.')
                    nameservers.append(ns)
            return ', '.join(nameservers) if nameservers else 'Unknown'
        except Exception:
            return 'Unknown'

    def get_ssl_info(self):
        """Get SSL certificate information"""
        if not self.url.startswith('https'):
            return {'enabled': False, 'message': 'SSL not enabled'}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'enabled': True,
                        'issuer': cert.get('issuer', [{}])[0].get('commonName', 'Unknown'),
                        'valid_from': cert.get('notBefore', 'Unknown'),
                        'valid_to': cert.get('notAfter', 'Unknown'),
                        'subject': cert.get('subject', [{}])[0].get('commonName', 'Unknown')
                    }
        except Exception as e:
            return {'enabled': False, 'message': f'SSL error: {str(e)}'}

    def get_security_headers(self):
        """Get security headers"""
        try:
            response = urllib.request.urlopen(self.url, timeout=10)
            headers = dict(response.headers)
            
            security_headers = {}
            security_header_names = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy'
            ]
            
            for header_name in security_header_names:
                if header_name in headers:
                    security_headers[header_name] = headers[header_name]
                    
            return security_headers
        except Exception:
            return {}

    def check_compression(self):
        """Check if compression is enabled"""
        try:
            response = urllib.request.urlopen(self.url, timeout=10)
            return 'Enabled' if 'Content-Encoding' in response.headers else 'Disabled'
        except Exception:
            return 'Unknown'

    def check_caching(self):
        """Check caching headers"""
        try:
            response = urllib.request.urlopen(self.url, timeout=10)
            cache_headers = ['Cache-Control', 'Expires', 'ETag', 'Last-Modified']
            
            for header in cache_headers:
                if header in response.headers:
                    return 'Enabled'
            return 'Disabled'
        except Exception:
            return 'Unknown'

    def detect_web_server(self, headers):
        """Detect web server"""
        server = headers.get('Server', 'Unknown')
        return server.split('/')[0] if server != 'Unknown' else 'Unknown'

    def detect_programming_language(self, headers, content):
        """Detect programming language"""
        # Check headers
        powered_by = headers.get('X-Powered-By', '')
        if 'PHP' in powered_by:
            return 'PHP'
        elif 'ASP.NET' in powered_by:
            return 'ASP.NET'
        
        # Check content
        if re.search(r'\.php["\']', content):
            return 'PHP'
        elif re.search(r'\.aspx["\']', content):
            return 'ASP.NET'
        elif re.search(r'\.jsp["\']', content):
            return 'Java'
        elif re.search(r'\.py["\']', content):
            return 'Python'
        
        return 'Unknown'

    def detect_cms(self, content):
        """Detect Content Management System"""
        cms_patterns = {
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Drupal': r'drupal|sites/default',
            'Joomla': r'joomla|option=com_',
            'Magento': r'magento|mage/js',
            'Shopify': r'shopify|cdn\.shopify'
        }
        
        for cms, pattern in cms_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                return cms
                
        return 'Custom/Unknown'

    def detect_js_frameworks(self, content):
        """Detect JavaScript frameworks"""
        frameworks = []
        framework_patterns = {
            'React': r'react|reactjs',
            'Vue.js': r'vue\.js|vuejs',
            'Angular': r'angular|ng-',
            'jQuery': r'jquery'
        }
        
        for framework, pattern in framework_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                frameworks.append(framework)
                
        return ', '.join(frameworks) if frameworks else 'Unknown'

    def detect_analytics(self, content):
        """Detect analytics services"""
        analytics_patterns = {
            'Google Analytics': r'google-analytics|gtag|ga\(',
            'Google Tag Manager': r'googletagmanager',
            'Facebook Pixel': r'facebook\.net/tr|fbq\(',
            'Hotjar': r'hotjar'
        }
        
        for service, pattern in analytics_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                return service
                
        return 'None detected'

def main():
    """Main function for command line usage"""
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <URL>")
        sys.exit(1)
    
    url = sys.argv[1]
    scanner = WebsiteScanner(url)
    result = scanner.scan()
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()