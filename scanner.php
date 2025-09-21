<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class WebsiteScanner {
    private $url;
    private $domain;
    private $results = [];

    public function __construct($url) {
        $this->url = $url;
        $this->domain = parse_url($url, PHP_URL_HOST);
    }

    public function scan() {
        try {
            $this->results['basic_info'] = $this->getBasicInfo();
            $this->results['server_info'] = $this->getServerInfo();
            $this->results['domain_info'] = $this->getDomainInfo();
            $this->results['security_info'] = $this->getSecurityInfo();
            $this->results['performance_info'] = $this->getPerformanceInfo();
            $this->results['technology_info'] = $this->getTechnologyInfo();
            
            return [
                'success' => true,
                'data' => $this->results,
                'scan_time' => date('Y-m-d H:i:s')
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    private function getBasicInfo() {
        $headers = @get_headers($this->url, 1);
        $status_code = $headers ? $this->extractStatusCode($headers[0]) : 'Unknown';
        
        return [
            'url' => $this->url,
            'domain' => $this->domain,
            'status_code' => $status_code,
            'protocol' => parse_url($this->url, PHP_URL_SCHEME),
            'port' => parse_url($this->url, PHP_URL_PORT) ?: (parse_url($this->url, PHP_URL_SCHEME) === 'https' ? 443 : 80)
        ];
    }

    private function getServerInfo() {
        $ip = gethostbyname($this->domain);
        $headers = @get_headers($this->url, 1);
        
        $server = 'Unknown';
        if ($headers && isset($headers['Server'])) {
            $server = is_array($headers['Server']) ? $headers['Server'][0] : $headers['Server'];
        }

        // Get geolocation info (simplified)
        $location_info = $this->getLocationInfo($ip);
        
        return [
            'ip_address' => $ip,
            'server' => $server,
            'location' => $location_info['country'] ?? 'Unknown',
            'city' => $location_info['city'] ?? 'Unknown',
            'isp' => $location_info['isp'] ?? 'Unknown'
        ];
    }

    private function getDomainInfo() {
        // Simplified domain info (in real implementation, you'd use WHOIS API)
        return [
            'registrar' => 'Unknown',
            'creation_date' => 'Unknown',
            'expiry_date' => 'Unknown',
            'name_servers' => $this->getNameServers(),
            'dnssec' => 'Unknown'
        ];
    }

    private function getSecurityInfo() {
        $ssl_info = $this->getSSLInfo();
        $security_headers = $this->getSecurityHeaders();
        
        return [
            'ssl_certificate' => $ssl_info,
            'security_headers' => $security_headers,
            'hsts_enabled' => isset($security_headers['Strict-Transport-Security']),
            'content_security_policy' => isset($security_headers['Content-Security-Policy'])
        ];
    }

    private function getPerformanceInfo() {
        $start_time = microtime(true);
        $headers = @get_headers($this->url, 1);
        $response_time = (microtime(true) - $start_time) * 1000;
        
        return [
            'response_time' => round($response_time, 2) . 'ms',
            'compression' => $this->checkCompression($headers),
            'caching' => $this->checkCaching($headers),
            'page_size' => $this->getPageSize()
        ];
    }

    private function getTechnologyInfo() {
        $headers = @get_headers($this->url, 1);
        $content = @file_get_contents($this->url);
        
        return [
            'web_server' => $this->detectWebServer($headers),
            'programming_language' => $this->detectProgrammingLanguage($headers, $content),
            'cms' => $this->detectCMS($content),
            'javascript_frameworks' => $this->detectJSFrameworks($content),
            'analytics' => $this->detectAnalytics($content)
        ];
    }

    private function extractStatusCode($header) {
        preg_match('/HTTP\/\d\.\d\s+(\d+)/', $header, $matches);
        return isset($matches[1]) ? $matches[1] : 'Unknown';
    }

    private function getLocationInfo($ip) {
        // Simplified location detection
        // In real implementation, use services like ipapi.co or similar
        return [
            'country' => 'Unknown',
            'city' => 'Unknown',
            'isp' => 'Unknown'
        ];
    }

    private function getNameServers() {
        $nameservers = [];
        $dns_records = @dns_get_record($this->domain, DNS_NS);
        
        if ($dns_records) {
            foreach ($dns_records as $record) {
                $nameservers[] = $record['target'];
            }
        }
        
        return implode(', ', $nameservers) ?: 'Unknown';
    }

    private function getSSLInfo() {
        if (parse_url($this->url, PHP_URL_SCHEME) !== 'https') {
            return ['enabled' => false, 'message' => 'SSL not enabled'];
        }

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);

        $stream = @stream_socket_client(
            'ssl://' . $this->domain . ':443',
            $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context
        );

        if (!$stream) {
            return ['enabled' => false, 'message' => 'SSL connection failed'];
        }

        $cert = stream_context_get_params($stream)['options']['ssl']['peer_certificate'];
        $cert_info = openssl_x509_parse($cert);

        fclose($stream);

        return [
            'enabled' => true,
            'issuer' => $cert_info['issuer']['CN'] ?? 'Unknown',
            'valid_from' => date('Y-m-d', $cert_info['validFrom_time_t']),
            'valid_to' => date('Y-m-d', $cert_info['validTo_time_t']),
            'subject' => $cert_info['subject']['CN'] ?? 'Unknown'
        ];
    }

    private function getSecurityHeaders() {
        $headers = @get_headers($this->url, 1);
        $security_headers = [];
        
        $security_header_names = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ];

        foreach ($security_header_names as $header_name) {
            if (isset($headers[$header_name])) {
                $security_headers[$header_name] = is_array($headers[$header_name]) 
                    ? $headers[$header_name][0] 
                    : $headers[$header_name];
            }
        }

        return $security_headers;
    }

    private function checkCompression($headers) {
        return isset($headers['Content-Encoding']) ? 'Enabled' : 'Disabled';
    }

    private function checkCaching($headers) {
        $cache_headers = ['Cache-Control', 'Expires', 'ETag', 'Last-Modified'];
        
        foreach ($cache_headers as $header) {
            if (isset($headers[$header])) {
                return 'Enabled';
            }
        }
        
        return 'Disabled';
    }

    private function getPageSize() {
        $content = @file_get_contents($this->url);
        return $content ? round(strlen($content) / 1024, 2) . ' KB' : 'Unknown';
    }

    private function detectWebServer($headers) {
        if (isset($headers['Server'])) {
            $server = is_array($headers['Server']) ? $headers['Server'][0] : $headers['Server'];
            return explode('/', $server)[0];
        }
        return 'Unknown';
    }

    private function detectProgrammingLanguage($headers, $content) {
        // Check headers for language indicators
        if (isset($headers['X-Powered-By'])) {
            $powered_by = is_array($headers['X-Powered-By']) ? $headers['X-Powered-By'][0] : $headers['X-Powered-By'];
            if (stripos($powered_by, 'PHP') !== false) return 'PHP';
            if (stripos($powered_by, 'ASP.NET') !== false) return 'ASP.NET';
        }

        // Check content for language indicators
        if ($content) {
            if (preg_match('/\.php["\']/', $content)) return 'PHP';
            if (preg_match('/\.aspx["\']/', $content)) return 'ASP.NET';
            if (preg_match('/\.jsp["\']/', $content)) return 'Java';
            if (preg_match('/\.py["\']/', $content)) return 'Python';
        }

        return 'Unknown';
    }

    private function detectCMS($content) {
        if (!$content) return 'Unknown';

        $cms_patterns = [
            'WordPress' => '/wp-content|wp-includes|wordpress/i',
            'Drupal' => '/drupal|sites\/default/i',
            'Joomla' => '/joomla|option=com_/i',
            'Magento' => '/magento|mage\/js/i',
            'Shopify' => '/shopify|cdn\.shopify/i'
        ];

        foreach ($cms_patterns as $cms => $pattern) {
            if (preg_match($pattern, $content)) {
                return $cms;
            }
        }

        return 'Custom/Unknown';
    }

    private function detectJSFrameworks($content) {
        if (!$content) return 'Unknown';

        $frameworks = [];
        $framework_patterns = [
            'React' => '/react|reactjs/i',
            'Vue.js' => '/vue\.js|vuejs/i',
            'Angular' => '/angular|ng-/i',
            'jQuery' => '/jquery/i'
        ];

        foreach ($framework_patterns as $framework => $pattern) {
            if (preg_match($pattern, $content)) {
                $frameworks[] = $framework;
            }
        }

        return empty($frameworks) ? 'Unknown' : implode(', ', $frameworks);
    }

    private function detectAnalytics($content) {
        if (!$content) return 'Unknown';

        $analytics_patterns = [
            'Google Analytics' => '/google-analytics|gtag|ga\(/i',
            'Google Tag Manager' => '/googletagmanager/i',
            'Facebook Pixel' => '/facebook\.net\/tr|fbq\(/i',
            'Hotjar' => '/hotjar/i'
        ];

        foreach ($analytics_patterns as $service => $pattern) {
            if (preg_match($pattern, $content)) {
                return $service;
            }
        }

        return 'None detected';
    }
}

// Handle the request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['url'])) {
        echo json_encode(['success' => false, 'error' => 'URL parameter required']);
        exit;
    }

    $scanner = new WebsiteScanner($input['url']);
    $result = $scanner->scan();
    
    echo json_encode($result);
} else {
    echo json_encode(['success' => false, 'error' => 'Only POST method allowed']);
}
?>