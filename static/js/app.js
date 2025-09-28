/**
 * CyberAudit Frontend JavaScript
 * Handles user interactions and API communications
 */

class CyberAuditApp {
    constructor() {
        this.currentLanguage = 'ru';
        this.loadingSteps = [
            'Анализируем SSL сертификаты...',
            'Сканируем открытые порты...',
            'Проверяем заголовки безопасности...',
            'Ищем уязвимости CMS...',
            'Тестируем DDoS защиту...',
            'Формируем отчет...'
        ];
        this.currentStep = 0;
        this.currentScanId = null;
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadStats();
        this.setupSmoothScrolling();
    }

    bindEvents() {
        // Scan button
        const scanButton = document.getElementById('scanButton');
        const urlInput = document.getElementById('urlInput');
        
        if (scanButton) {
            scanButton.addEventListener('click', () => this.startScan());
        }
        
        if (urlInput) {
            urlInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.startScan();
                }
            });
        }

        // Language selector
        const languageSelect = document.getElementById('languageSelect');
        if (languageSelect) {
            languageSelect.addEventListener('change', (e) => {
                this.changeLanguage(e.target.value);
            });
        }

        // Modal close
        const closeButtons = document.querySelectorAll('.close');
        closeButtons.forEach(button => {
            button.addEventListener('click', () => this.closeModals());
        });

        // Click outside modal to close
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeModals();
            }
        });

        // Navigation links
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = e.target.getAttribute('href');
                this.scrollToSection(target);
                this.setActiveNavLink(e.target);
            });
        });
    }

    async startScan() {
        const urlInput = document.getElementById('urlInput');
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showError('Пожалуйста, введите URL сайта');
            return;
        }

        // Get selected scan types
        const scanTypes = Array.from(document.querySelectorAll('.scan-types input:checked'))
            .map(input => input.value);
        
        if (scanTypes.length === 0) {
            this.showError('Выберите хотя бы один тип сканирования');
            return;
        }

        // Show loading modal
        this.showLoadingModal();
        this.startLoadingProgress();

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    scan_types: scanTypes,
                    language: this.currentLanguage
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            this.currentScanId = result.scan_id;
            
            // Hide loading modal and show results
            setTimeout(() => {
                this.hideLoadingModal();
                this.showResults(result);
            }, 1000); // Small delay for smooth UX

        } catch (error) {
            console.error('Scan error:', error);
            this.hideLoadingModal();
            this.showError('Произошла ошибка при сканировании. Попробуйте еще раз.');
        }
    }

    showLoadingModal() {
        const modal = document.getElementById('loadingModal');
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    hideLoadingModal() {
        const modal = document.getElementById('loadingModal');
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }

    startLoadingProgress() {
        this.currentStep = 0;
        const progressFill = document.getElementById('progressFill');
        const loadingText = document.getElementById('loadingText');
        
        const updateProgress = () => {
            if (this.currentStep < this.loadingSteps.length) {
                const progress = ((this.currentStep + 1) / this.loadingSteps.length) * 100;
                progressFill.style.width = `${progress}%`;
                loadingText.textContent = this.loadingSteps[this.currentStep];
                this.currentStep++;
                
                setTimeout(updateProgress, 1500); // Update every 1.5 seconds
            }
        };
        
        updateProgress();
    }

    showResults(scanResult) {
        const modal = document.getElementById('resultsModal');
        const resultsContainer = document.getElementById('scanResults');
        
        // Determine score class
        const score = scanResult.score;
        let scoreClass = 'score-critical';
        if (score >= 90) scoreClass = 'score-excellent';
        else if (score >= 80) scoreClass = 'score-good';
        else if (score >= 60) scoreClass = 'score-warning';

        const resultsHTML = `
            <div class="result-header">
                <h2>Результаты сканирования</h2>
                <h3>${scanResult.url}</h3>
                <div class="result-score ${scoreClass}">${score}/100</div>
                <p>Статус: ${scanResult.status === 'completed' ? 'Завершено' : 'В процессе'}</p>
            </div>

            <div class="result-details">
                ${this.generateResultDetails(scanResult.results)}
            </div>

            ${scanResult.recommendations.length > 0 ? `
                <div class="recommendations-section">
                    <h3>🔧 Рекомендации по улучшению безопасности:</h3>
                    <ul>
                        ${scanResult.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            <div class="download-buttons">
                <a href="/api/certificate/${this.currentScanId}" class="download-btn btn-certificate" target="_blank">
                    <i class="fas fa-certificate"></i>
                    Сертификат PDF
                </a>
                <a href="/api/report/${this.currentScanId}" class="download-btn btn-report" target="_blank">
                    <i class="fas fa-file-pdf"></i>
                    Детальный отчет
                </a>
            </div>
        `;
        
        resultsContainer.innerHTML = resultsHTML;
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    generateResultDetails(results) {
        let detailsHTML = '';
        
        const scanTypes = {
            ssl: { name: 'SSL/HTTPS', icon: 'fas fa-lock' },
            ports: { name: 'Порты', icon: 'fas fa-network-wired' },
            headers: { name: 'HTTP заголовки', icon: 'fas fa-shield-virus' },
            cms: { name: 'CMS/CVE', icon: 'fas fa-bug' },
            ddos: { name: 'DDoS защита', icon: 'fas fa-shield-alt' }
        };

        for (const [scanType, scanInfo] of Object.entries(scanTypes)) {
            if (results[scanType]) {
                const result = results[scanType];
                const status = this.getStatusClass(result.score || 0);
                
                detailsHTML += `
                    <div class="result-item ${status}">
                        <h4><i class="${scanInfo.icon}"></i> ${scanInfo.name}</h4>
                        <p>Оценка: <strong>${result.score || 0}/100</strong></p>
                        ${result.error ? `<p class="error">Ошибка: ${result.error}</p>` : ''}
                        ${result.details ? `<p>${result.details}</p>` : ''}
                    </div>
                `;
            }
        }
        
        return detailsHTML;
    }

    getStatusClass(score) {
        if (score >= 80) return 'good';
        if (score >= 60) return 'warning';
        return 'critical';
    }

    closeModals() {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.style.display = 'none';
        });
        document.body.style.overflow = 'auto';
    }

    showError(message) {
        // Simple alert for now, could be replaced with a nice modal
        alert(message);
    }

    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            if (response.ok) {
                const stats = await response.json();
                this.updateStatsDisplay(stats);
            }
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    updateStatsDisplay(stats) {
        const elements = {
            totalScans: document.getElementById('totalScans'),
            certificates: document.getElementById('certificates'),
            activeUsers: document.getElementById('activeUsers')
        };

        if (elements.totalScans) {
            elements.totalScans.textContent = stats.total_scans.toLocaleString();
        }
        if (elements.certificates) {
            elements.certificates.textContent = stats.certificates_issued.toLocaleString();
        }
        if (elements.activeUsers) {
            elements.activeUsers.textContent = stats.active_users.toLocaleString();
        }
    }

    changeLanguage(lang) {
        this.currentLanguage = lang;
        // Implement language switching logic here
        // For now, just store the preference
        localStorage.setItem('cyberaudit_language', lang);
    }

    setupSmoothScrolling() {
        // Enable smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    scrollToSection(selector) {
        const target = document.querySelector(selector);
        if (target) {
            const headerHeight = 80; // Account for fixed header
            const targetPosition = target.offsetTop - headerHeight;
            
            window.scrollTo({
                top: targetPosition,
                behavior: 'smooth'
            });
        }
    }

    setActiveNavLink(activeLink) {
        // Remove active class from all nav links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        
        // Add active class to clicked link
        activeLink.classList.add('active');
    }

    // Utility method to format numbers
    formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        }
        if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }

    // Method to animate counters
    animateCounter(element, target) {
        const start = 0;
        const duration = 2000;
        const startTime = performance.now();
        
        const update = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const current = Math.floor(start + (target - start) * progress);
            
            element.textContent = this.formatNumber(current);
            
            if (progress < 1) {
                requestAnimationFrame(update);
            }
        };
        
        requestAnimationFrame(update);
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CyberAuditApp();
});

// Add some interactive elements for better UX
document.addEventListener('DOMContentLoaded', () => {
    // Add loading animation to buttons
    const buttons = document.querySelectorAll('button, .download-btn');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = 'scale(1)';
            }, 150);
        });
    });

    // Add scroll-based navigation highlighting
    window.addEventListener('scroll', () => {
        const sections = document.querySelectorAll('section[id]');
        const navLinks = document.querySelectorAll('.nav-link');
        
        let current = '';
        
        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.clientHeight;
            if (scrollY >= (sectionTop - 200)) {
                current = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${current}`) {
                link.classList.add('active');
            }
        });
    });

    // Add intersection observer for animation
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
            }
        });
    }, observerOptions);

    // Observe elements for animation
    const animatedElements = document.querySelectorAll('.feature-card, .stat-card');
    animatedElements.forEach(el => observer.observe(el));
});
