class WebsiteScanner {
    constructor() {
        this.init();
        this.setupEventListeners();
    }

    init() {
        this.urlInput = document.getElementById('urlInput');
        this.scanBtn = document.getElementById('scanBtn');
        this.terminal = document.getElementById('terminal');
        this.terminalBody = document.getElementById('terminalBody');
        this.loadingOverlay = document.getElementById('loadingOverlay');
        this.progressBar = document.getElementById('progressBar');
        this.loadingText = document.getElementById('loadingText');
        this.resultsGrid = document.getElementById('resultsGrid');
        
        this.isScanning = false;
        this.scanSteps = [
            'DNS ma\'lumotlarini olish...',
            'Server ma\'lumotlarini tahlil qilish...',
            'SSL sertifikatini tekshirish...',
            'Whois ma\'lumotlarini olish...',
            'Geolokatsiya ma\'lumotlarini aniqlash...',
            'Texnologiyalarni aniqlash...',
            'Xavfsizlik tahlili...',
            'Performance tahlili...',
            'SEO tahlili...',
            'Natijalarni tayyorlash...'
        ];
    }

    setupEventListeners() {
        this.scanBtn.addEventListener('click', () => this.startScan());
        this.urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.startScan();
            }
        });

        // Smooth scrolling for navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('href');
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    }

    async startScan() {
        if (this.isScanning) return;

        const url = this.urlInput.value.trim();
        if (!url) {
            this.showError('URL kiriting!');
            return;
        }

        if (!this.isValidUrl(url)) {
            this.showError('To\'g\'ri URL formatini kiriting!');
            return;
        }

        this.isScanning = true;
        this.scanBtn.classList.add('loading');
        this.showLoadingOverlay();
        this.showTerminal();
        this.clearResults();

        try {
            await this.performScan(url);
        } catch (error) {
            this.showError('Scan jarayonida xatolik yuz berdi: ' + error.message);
        } finally {
            this.isScanning = false;
            this.scanBtn.classList.remove('loading');
            this.hideLoadingOverlay();
        }
    }

    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    showLoadingOverlay() {
        this.loadingOverlay.classList.add('active');
        this.progressBar.style.width = '0%';
    }

    hideLoadingOverlay() {
        this.loadingOverlay.classList.remove('active');
    }

    showTerminal() {
        this.terminal.classList.add('active');
        this.terminalBody.innerHTML = '<div class="terminal-line"><span class="prompt">cyberscan@pro:~$</span> <span class="cursor">_</span></div>';
    }

    addTerminalLine(text, type = 'info') {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        
        const prompt = document.createElement('span');
        prompt.className = 'prompt';
        prompt.textContent = 'cyberscan@pro:~$';
        
        const content = document.createElement('span');
        content.textContent = ` ${text}`;
        content.style.color = type === 'success' ? '#00ff41' : 
                             type === 'error' ? '#ff0040' : 
                             type === 'warning' ? '#ffbd2e' : '#ffffff';
        
        line.appendChild(prompt);
        line.appendChild(content);
        
        // Remove cursor from previous line
        const cursor = this.terminalBody.querySelector('.cursor');
        if (cursor) cursor.remove();
        
        this.terminalBody.appendChild(line);
        
        // Add new cursor
        const newCursor = document.createElement('span');
        newCursor.className = 'cursor';
        newCursor.textContent = '_';
        line.appendChild(newCursor);
        
        // Scroll to bottom
        this.terminalBody.scrollTop = this.terminalBody.scrollHeight;
    }

    async performScan(url) {
        const totalSteps = this.scanSteps.length;
        
        for (let i = 0; i < totalSteps; i++) {
            this.loadingText.textContent = this.scanSteps[i];
            this.addTerminalLine(this.scanSteps[i], 'info');
            
            // Simulate scanning process
            await this.sleep(800 + Math.random() * 1200);
            
            const progress = ((i + 1) / totalSteps) * 100;
            this.progressBar.style.width = `${progress}%`;
        }

        // Generate scan results
        const results = await this.generateScanResults(url);
        this.displayResults(results);
        
        this.addTerminalLine('Scan muvaffaqiyatli yakunlandi!', 'success');
    }

    async generateScanResults(url) {
        // Simulate API calls and data processing
        const domain = new URL(url).hostname;
        
        return {
            basicInfo: {
                url: url,
                domain: domain,
                protocol: new URL(url).protocol,
                port: new URL(url).port || (new URL(url).protocol === 'https:' ? '443' : '80'),
                status: 'Online'
            },
            serverInfo: {
                server: this.getRandomServer(),
                ip: this.generateRandomIP(),
                location: this.getRandomLocation(),
                provider: this.getRandomProvider(),
                responseTime: Math.floor(Math.random() * 500) + 50 + 'ms'
            },
            domainInfo: {
                registrar: this.getRandomRegistrar(),
                createdDate: this.getRandomDate(2000, 2020),
                expiryDate: this.getRandomDate(2024, 2030),
                nameServers: this.getRandomNameServers(),
                dnssec: Math.random() > 0.5 ? 'Enabled' : 'Disabled'
            },
            security: {
                ssl: Math.random() > 0.2 ? 'Valid' : 'Invalid',
                sslIssuer: this.getRandomSSLIssuer(),
                sslExpiry: this.getRandomDate(2024, 2025),
                hsts: Math.random() > 0.3 ? 'Enabled' : 'Disabled',
                securityHeaders: Math.floor(Math.random() * 8) + 3
            },
            technology: {
                webServer: this.getRandomWebServer(),
                framework: this.getRandomFramework(),
                cms: this.getRandomCMS(),
                analytics: this.getRandomAnalytics(),
                cdn: this.getRandomCDN()
            },
            performance: {
                loadTime: Math.floor(Math.random() * 3000) + 500 + 'ms',
                pageSize: Math.floor(Math.random() * 5000) + 500 + 'KB',
                requests: Math.floor(Math.random() * 100) + 20,
                compression: Math.random() > 0.3 ? 'Enabled' : 'Disabled',
                caching: Math.random() > 0.4 ? 'Optimized' : 'Not Optimized'
            }
        };
    }

    displayResults(results) {
        this.resultsGrid.innerHTML = '';

        // Basic Information Card
        this.createResultCard('🌐 Asosiy Ma\'lumotlar', 'basic-info', [
            { label: 'URL', value: results.basicInfo.url },
            { label: 'Domen', value: results.basicInfo.domain },
            { label: 'Protokol', value: results.basicInfo.protocol },
            { label: 'Port', value: results.basicInfo.port },
            { label: 'Status', value: results.basicInfo.status, class: 'success' }
        ]);

        // Server Information Card
        this.createResultCard('🖥️ Server Ma\'lumotlari', 'server-info', [
            { label: 'Server', value: results.serverInfo.server },
            { label: 'IP Manzil', value: results.serverInfo.ip },
            { label: 'Joylashuv', value: results.serverInfo.location },
            { label: 'Provayder', value: results.serverInfo.provider },
            { label: 'Javob Vaqti', value: results.serverInfo.responseTime, class: 'success' }
        ]);

        // Domain Information Card
        this.createResultCard('📋 Domen Ma\'lumotlari', 'domain-info', [
            { label: 'Registrar', value: results.domainInfo.registrar },
            { label: 'Yaratilgan Sana', value: results.domainInfo.createdDate },
            { label: 'Tugash Sanasi', value: results.domainInfo.expiryDate },
            { label: 'Name Servers', value: results.domainInfo.nameServers },
            { label: 'DNSSEC', value: results.domainInfo.dnssec, class: results.domainInfo.dnssec === 'Enabled' ? 'success' : 'warning' }
        ]);

        // Security Information Card
        this.createResultCard('🔒 Xavfsizlik', 'security-info', [
            { label: 'SSL Sertifikat', value: results.security.ssl, class: results.security.ssl === 'Valid' ? 'success' : 'error' },
            { label: 'SSL Beruvchi', value: results.security.sslIssuer },
            { label: 'SSL Tugash', value: results.security.sslExpiry },
            { label: 'HSTS', value: results.security.hsts, class: results.security.hsts === 'Enabled' ? 'success' : 'warning' },
            { label: 'Xavfsizlik Headers', value: results.security.securityHeaders + '/10', class: results.security.securityHeaders > 6 ? 'success' : 'warning' }
        ]);

        // Technology Stack Card
        this.createResultCard('⚙️ Texnologiyalar', 'technology-info', [
            { label: 'Web Server', value: results.technology.webServer },
            { label: 'Framework', value: results.technology.framework },
            { label: 'CMS', value: results.technology.cms },
            { label: 'Analytics', value: results.technology.analytics },
            { label: 'CDN', value: results.technology.cdn }
        ]);

        // Performance Card
        this.createResultCard('⚡ Performance', 'performance-info', [
            { label: 'Yuklash Vaqti', value: results.performance.loadTime, class: parseInt(results.performance.loadTime) < 2000 ? 'success' : 'warning' },
            { label: 'Sahifa Hajmi', value: results.performance.pageSize },
            { label: 'So\'rovlar Soni', value: results.performance.requests },
            { label: 'Siqish', value: results.performance.compression, class: results.performance.compression === 'Enabled' ? 'success' : 'warning' },
            { label: 'Keshlash', value: results.performance.caching, class: results.performance.caching === 'Optimized' ? 'success' : 'warning' }
        ]);

        // Scroll to results
        document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
    }

    createResultCard(title, id, items) {
        const card = document.createElement('div');
        card.className = 'result-card';
        card.id = id;

        const header = document.createElement('h3');
        header.innerHTML = title;

        card.appendChild(header);

        items.forEach(item => {
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item';

            const label = document.createElement('span');
            label.className = 'result-label';
            label.textContent = item.label;

            const value = document.createElement('span');
            value.className = `result-value ${item.class || ''}`;
            value.textContent = item.value;

            resultItem.appendChild(label);
            resultItem.appendChild(value);
            card.appendChild(resultItem);
        });

        this.resultsGrid.appendChild(card);
    }

    clearResults() {
        this.resultsGrid.innerHTML = '';
    }

    showError(message) {
        this.addTerminalLine(`ERROR: ${message}`, 'error');
        alert(message);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Helper methods for generating random data
    getRandomServer() {
        const servers = ['Apache/2.4.41', 'Nginx/1.18.0', 'Microsoft-IIS/10.0', 'LiteSpeed/5.4', 'Cloudflare'];
        return servers[Math.floor(Math.random() * servers.length)];
    }

    generateRandomIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }

    getRandomLocation() {
        const locations = [
            'United States, California',
            'Germany, Frankfurt',
            'United Kingdom, London',
            'Singapore',
            'Japan, Tokyo',
            'Canada, Toronto',
            'Netherlands, Amsterdam',
            'France, Paris'
        ];
        return locations[Math.floor(Math.random() * locations.length)];
    }

    getRandomProvider() {
        const providers = ['Amazon Web Services', 'Google Cloud', 'Microsoft Azure', 'DigitalOcean', 'Cloudflare', 'Linode', 'Vultr'];
        return providers[Math.floor(Math.random() * providers.length)];
    }

    getRandomRegistrar() {
        const registrars = ['GoDaddy', 'Namecheap', 'Google Domains', 'Cloudflare', 'Network Solutions', 'Hover', 'Name.com'];
        return registrars[Math.floor(Math.random() * registrars.length)];
    }

    getRandomDate(startYear, endYear) {
        const start = new Date(startYear, 0, 1);
        const end = new Date(endYear, 11, 31);
        const date = new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
        return date.toLocaleDateString();
    }

    getRandomNameServers() {
        const ns = ['ns1.example.com', 'ns2.example.com', 'dns1.registrar.com', 'dns2.registrar.com'];
        return ns[Math.floor(Math.random() * ns.length)];
    }

    getRandomSSLIssuer() {
        const issuers = ['Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust', 'Symantec', 'GlobalSign'];
        return issuers[Math.floor(Math.random() * issuers.length)];
    }

    getRandomWebServer() {
        const servers = ['Apache', 'Nginx', 'IIS', 'LiteSpeed', 'Caddy'];
        return servers[Math.floor(Math.random() * servers.length)];
    }

    getRandomFramework() {
        const frameworks = ['React', 'Vue.js', 'Angular', 'Laravel', 'Django', 'Express.js', 'Next.js', 'Nuxt.js'];
        return frameworks[Math.floor(Math.random() * frameworks.length)];
    }

    getRandomCMS() {
        const cms = ['WordPress', 'Drupal', 'Joomla', 'Shopify', 'Magento', 'Custom', 'Ghost'];
        return cms[Math.floor(Math.random() * cms.length)];
    }

    getRandomAnalytics() {
        const analytics = ['Google Analytics', 'Adobe Analytics', 'Matomo', 'Hotjar', 'Mixpanel', 'None'];
        return analytics[Math.floor(Math.random() * analytics.length)];
    }

    getRandomCDN() {
        const cdns = ['Cloudflare', 'Amazon CloudFront', 'Google Cloud CDN', 'Azure CDN', 'KeyCDN', 'None'];
        return cdns[Math.floor(Math.random() * cdns.length)];
    }
}

// Initialize the scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new WebsiteScanner();
    
    // Add some matrix-style background effects
    createMatrixEffect();
});

function createMatrixEffect() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.zIndex = '-1';
    canvas.style.opacity = '0.1';
    canvas.style.pointerEvents = 'none';
    
    document.body.appendChild(canvas);
    
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    const chars = '01';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = [];
    
    for (let i = 0; i < columns; i++) {
        drops[i] = 1;
    }
    
    function draw() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#00ff41';
        ctx.font = fontSize + 'px monospace';
        
        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    setInterval(draw, 100);
}