"""
CMS и уязвимости Scanner для CyberAudit
Использует Wappalyzer для детекции технологий и проверяет CVE
"""

import httpx
import asyncio
import re
import json
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List
import hashlib

class CMSScanner:
    """Сканер для определения CMS и поиска уязвимостей"""
    
    def __init__(self):
        # Сигнатуры популярных CMS
        self.cms_signatures = {
            'wordpress': {
                'name': 'WordPress',
                'paths': ['/wp-admin/', '/wp-content/', '/wp-includes/'],
                'headers': {'x-powered-by': 'wordpress'},
                'meta': [r'<meta name="generator" content="WordPress ([0-9.]+)"'],
                'files': ['/wp-config.php', '/readme.html'],
                'patterns': [r'/wp-content/themes/', r'/wp-content/plugins/']
            },
            'drupal': {
                'name': 'Drupal',
                'paths': ['/user/login', '/admin/', '/sites/'],
                'headers': {'x-drupal-cache': '', 'x-generator': 'drupal'},
                'meta': [r'<meta name="Generator" content="Drupal ([0-9.]+)"'],
                'files': ['/CHANGELOG.txt', '/install.php'],
                'patterns': [r'/sites/default/files/', r'/modules/']
            },
            'joomla': {
                'name': 'Joomla',
                'paths': ['/administrator/', '/components/', '/modules/'],
                'headers': {},
                'meta': [r'<meta name="generator" content="Joomla! ([0-9.]+)"'],
                'files': ['/configuration.php', '/htaccess.txt'],
                'patterns': [r'/media/system/', r'/templates/']
            },
            'magento': {
                'name': 'Magento',
                'paths': ['/admin/', '/downloader/', '/app/'],
                'headers': {},
                'meta': [],
                'files': ['/app/etc/config.xml', '/downloader/'],
                'patterns': [r'/skin/frontend/', r'/media/catalog/']
            },
            'opencart': {
                'name': 'OpenCart',
                'paths': ['/admin/', '/catalog/', '/system/'],
                'headers': {},
                'meta': [],
                'files': ['/config.php', '/admin/config.php'],
                'patterns': [r'/catalog/view/theme/']
            }
        }
        
        # Известные уязвимости (упрощенная база)
        self.known_vulnerabilities = {
            'wordpress': {
                '5.0': ['CVE-2019-8942', 'CVE-2019-8943'],
                '4.9': ['CVE-2018-6389', 'CVE-2017-17092'],
                '4.8': ['CVE-2017-14723', 'CVE-2017-16510']
            },
            'drupal': {
                '8.5': ['CVE-2018-7600', 'CVE-2018-7602'],
                '7.58': ['CVE-2018-7600', 'CVE-2017-6920'],
                '7.57': ['CVE-2017-6925', 'CVE-2017-6924']
            },
            'joomla': {
                '3.8': ['CVE-2018-6376', 'CVE-2018-6377'],
                '3.7': ['CVE-2017-8917', 'CVE-2017-7985']
            }
        }

    async def scan(self, url: str) -> Dict[str, Any]:
        """Основной метод сканирования CMS и уязвимостей"""
        try:
            # Детекция технологий
            technology_info = await self._detect_technologies(url)
            
            # Определение CMS
            cms_info = await self._detect_cms(url, technology_info)
            
            # Поиск уязвимостей
            vulnerabilities = await self._check_vulnerabilities(cms_info)
            
            # Проверка небезопасных файлов
            exposed_files = await self._check_exposed_files(url, cms_info.get('type'))
            
            # Анализ плагинов (для WordPress)
            plugins_info = await self._analyze_plugins(url, cms_info)
            
            # Расчет оценки безопасности
            score = self._calculate_cms_score(cms_info, vulnerabilities, exposed_files, plugins_info)
            
            # Формирование отчета
            issues = []
            recommendations = []
            
            # Проблемы с уязвимостями
            if vulnerabilities['found']:
                for vuln in vulnerabilities['found']:
                    issues.append(f"Найдена уязвимость {vuln['id']}: {vuln['description']}")
                    recommendations.append(f"Обновите {cms_info.get('name', 'CMS')} до последней версии")
            
            # Проблемы с открытыми файлами
            for file_info in exposed_files['found']:
                issues.append(f"Доступен небезопасный файл: {file_info['path']}")
                recommendations.append(f"Ограничьте доступ к файлу {file_info['path']}")
            
            # Проблемы с плагинами
            if plugins_info['outdated']:
                issues.append(f"Найдены устаревшие плагины: {len(plugins_info['outdated'])}")
                recommendations.append("Обновите устаревшие плагины до последних версий")
            
            status = self._determine_status(score)
            
            return {
                'url': url,
                'technologies': technology_info,
                'cms': cms_info,
                'vulnerabilities': vulnerabilities,
                'exposed_files': exposed_files,
                'plugins': plugins_info,
                'score': score,
                'status': status,
                'issues': issues,
                'recommendations': recommendations,
                'total_checks': 8,
                'passed_checks': max(0, 8 - len(issues))
            }
            
        except Exception as e:
            return {
                'error': f'Ошибка при сканировании CMS: {str(e)}',
                'score': 0,
                'status': 'error'
            }

    async def _detect_technologies(self, url: str) -> Dict[str, Any]:
        """Определение используемых технологий"""
        technologies = {
            'server': None,
            'programming_languages': [],
            'javascript_frameworks': [],
            'css_frameworks': [],
            'analytics': [],
            'others': []
        }
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                response = await client.get(url)
                headers = response.headers
                content = response.text
                
                # Анализ заголовков
                if 'server' in headers:
                    technologies['server'] = headers['server']
                
                if 'x-powered-by' in headers:
                    technologies['programming_languages'].append(headers['x-powered-by'])
                
                # Анализ HTML контента
                technologies.update(self._analyze_html_content(content))
                
        except Exception as e:
            technologies['error'] = f'Ошибка при анализе технологий: {str(e)}'
        
        return technologies

    def _analyze_html_content(self, content: str) -> Dict[str, List]:
        """Анализ HTML контента для определения технологий"""
        result = {
            'javascript_frameworks': [],
            'css_frameworks': [],
            'analytics': [],
            'others': []
        }
        
        # JavaScript фреймворки
        js_patterns = {
            'jQuery': r'jquery[.-]([0-9.]+)',
            'React': r'react[.-]([0-9.]+)',
            'Vue.js': r'vue[.-]([0-9.]+)',
            'Angular': r'angular[.-]([0-9.]+)',
            'Bootstrap': r'bootstrap[.-]([0-9.]+)'
        }
        
        for framework, pattern in js_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                match = re.search(pattern, content, re.IGNORECASE)
                version = match.group(1) if match else 'unknown'
                result['javascript_frameworks'].append(f'{framework} {version}')
        
        # Аналитика
        analytics_patterns = {
            'Google Analytics': r'google-analytics\.com|gtag\(',
            'Yandex Metrica': r'metrica\.yandex\.',
            'Facebook Pixel': r'fbevents\.js'
        }
        
        for service, pattern in analytics_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                result['analytics'].append(service)
        
        return result

    async def _detect_cms(self, url: str, tech_info: Dict) -> Dict[str, Any]:
        """Определение CMS"""
        cms_results = {
            'detected': False,
            'type': None,
            'name': None,
            'version': None,
            'confidence': 0
        }
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                # Получаем главную страницу
                response = await client.get(url)
                content = response.text
                headers = response.headers
                
                best_match = {'cms': None, 'confidence': 0, 'version': None}
                
                for cms_key, cms_data in self.cms_signatures.items():
                    confidence = 0
                    version = None
                    
                    # Проверка заголовков
                    for header, value in cms_data['headers'].items():
                        if header in headers:
                            if not value or value.lower() in headers[header].lower():
                                confidence += 20
                    
                    # Проверка мета-тегов
                    for pattern in cms_data['meta']:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            confidence += 30
                            version = match.group(1) if match.groups() else None
                    
                    # Проверка паттернов в контенте
                    for pattern in cms_data['patterns']:
                        if re.search(pattern, content, re.IGNORECASE):
                            confidence += 15
                    
                    # Проверка путей
                    for path in cms_data['paths'][:2]:  # Ограничиваем для скорости
                        try:
                            path_url = urljoin(url, path)
                            path_response = await client.get(path_url, timeout=5)
                            if path_response.status_code == 200:
                                confidence += 25
                        except:
                            continue
                    
                    if confidence > best_match['confidence']:
                        best_match = {
                            'cms': cms_key,
                            'confidence': confidence,
                            'version': version
                        }
                
                if best_match['confidence'] > 50:
                    cms_results.update({
                        'detected': True,
                        'type': best_match['cms'],
                        'name': self.cms_signatures[best_match['cms']]['name'],
                        'version': best_match['version'],
                        'confidence': best_match['confidence']
                    })
                
        except Exception as e:
            cms_results['error'] = f'Ошибка при определении CMS: {str(e)}'
        
        return cms_results

    async def _check_vulnerabilities(self, cms_info: Dict[str, Any]) -> Dict[str, Any]:
        """Проверка уязвимостей в CMS"""
        vulnerabilities = {
            'found': [],
            'count': 0,
            'risk_level': 'low'
        }
        
        if not cms_info.get('detected') or not cms_info.get('version'):
            return vulnerabilities
        
        cms_type = cms_info['type']
        version = cms_info['version']
        
        if cms_type in self.known_vulnerabilities:
            cms_vulns = self.known_vulnerabilities[cms_type]
            
            for vuln_version, cves in cms_vulns.items():
                # Упрощенная проверка версий
                if self._is_vulnerable_version(version, vuln_version):
                    for cve in cves:
                        vulnerability = {
                            'id': cve,
                            'description': f'Уязвимость в {cms_info["name"]} {version}',
                            'severity': self._get_cve_severity(cve),
                            'affected_version': vuln_version
                        }
                        vulnerabilities['found'].append(vulnerability)
            
            vulnerabilities['count'] = len(vulnerabilities['found'])
            
            # Определение общего уровня риска
            if vulnerabilities['found']:
                severities = [v['severity'] for v in vulnerabilities['found']]
                if 'critical' in severities:
                    vulnerabilities['risk_level'] = 'critical'
                elif 'high' in severities:
                    vulnerabilities['risk_level'] = 'high'
                elif 'medium' in severities:
                    vulnerabilities['risk_level'] = 'medium'
        
        return vulnerabilities

    def _is_vulnerable_version(self, current_version: str, vulnerable_version: str) -> bool:
        """Упрощенная проверка версий на уязвимость"""
        try:
            current_parts = [int(x) for x in current_version.split('.')]
            vulnerable_parts = [int(x) for x in vulnerable_version.split('.')]
            
            # Дополняем нулями до одинаковой длины
            max_len = max(len(current_parts), len(vulnerable_parts))
            current_parts.extend([0] * (max_len - len(current_parts)))
            vulnerable_parts.extend([0] * (max_len - len(vulnerable_parts)))
            
            return current_parts <= vulnerable_parts
        except:
            return False

    def _get_cve_severity(self, cve: str) -> str:
        """Получение уровня серьезности CVE (упрощенная логика)"""
        # В реальном приложении здесь был бы запрос к базе CVE
        severity_map = {
            'CVE-2019-8942': 'high',
            'CVE-2018-7600': 'critical',
            'CVE-2018-6389': 'medium',
            'CVE-2017-8917': 'high'
        }
        return severity_map.get(cve, 'medium')

    async def _check_exposed_files(self, url: str, cms_type: str) -> Dict[str, Any]:
        """Проверка открытых файлов"""
        exposed = {
            'found': [],
            'count': 0
        }
        
        if not cms_type:
            return exposed
        
        # Файлы для проверки в зависимости от CMS
        files_to_check = []
        
        if cms_type == 'wordpress':
            files_to_check = [
                '/wp-config.php',
                '/readme.html',
                '/license.txt',
                '/.htaccess',
                '/wp-admin/install.php',
                '/xmlrpc.php'
            ]
        elif cms_type == 'drupal':
            files_to_check = [
                '/CHANGELOG.txt',
                '/COPYRIGHT.txt',
                '/INSTALL.txt',
                '/LICENSE.txt',
                '/MAINTAINERS.txt',
                '/install.php'
            ]
        elif cms_type == 'joomla':
            files_to_check = [
                '/configuration.php',
                '/htaccess.txt',
                '/LICENSE.txt',
                '/README.txt'
            ]
        
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for file_path in files_to_check:
                    try:
                        file_url = urljoin(url, file_path)
                        response = await client.get(file_url, timeout=5)
                        
                        if response.status_code == 200:
                            # Проверяем, что это не просто редирект на главную
                            if len(response.text) > 100 and 'index' not in response.text.lower()[:200]:
                                exposed['found'].append({
                                    'path': file_path,
                                    'url': file_url,
                                    'size': len(response.text),
                                    'risk': self._assess_file_risk(file_path)
                                })
                    except:
                        continue
                        
        except Exception:
            pass
        
        exposed['count'] = len(exposed['found'])
        return exposed

    def _assess_file_risk(self, file_path: str) -> str:
        """Оценка риска открытого файла"""
        high_risk_files = ['/wp-config.php', '/configuration.php', '/.htaccess']
        medium_risk_files = ['/readme.html', '/license.txt', '/xmlrpc.php']
        
        if file_path in high_risk_files:
            return 'high'
        elif file_path in medium_risk_files:
            return 'medium'
        else:
            return 'low'

    async def _analyze_plugins(self, url: str, cms_info: Dict[str, Any]) -> Dict[str, Any]:
        """Анализ плагинов (упрощенная версия для WordPress)"""
        plugins = {
            'found': [],
            'outdated': [],
            'vulnerable': [],
            'count': 0
        }
        
        if cms_info.get('type') != 'wordpress':
            return plugins
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                response = await client.get(url)
                content = response.text
                
                # Поиск плагинов в HTML
                plugin_pattern = r'/wp-content/plugins/([^/\'"]+)'
                plugin_matches = re.findall(plugin_pattern, content, re.IGNORECASE)
                
                unique_plugins = list(set(plugin_matches))
                
                for plugin_name in unique_plugins[:10]:  # Ограничиваем количество
                    plugin_info = {
                        'name': plugin_name,
                        'path': f'/wp-content/plugins/{plugin_name}/',
                        'version': 'unknown',
                        'status': 'unknown'
                    }
                    
                    # Попытка определить версию плагина
                    try:
                        plugin_readme_url = urljoin(url, f'/wp-content/plugins/{plugin_name}/readme.txt')
                        readme_response = await client.get(plugin_readme_url, timeout=5)
                        
                        if readme_response.status_code == 200:
                            version_match = re.search(r'Stable tag: ([0-9.]+)', readme_response.text)
                            if version_match:
                                plugin_info['version'] = version_match.group(1)
                                plugin_info['status'] = 'active'
                    except:
                        pass
                    
                    plugins['found'].append(plugin_info)
                
                plugins['count'] = len(plugins['found'])
                
        except Exception:
            pass
        
        return plugins

    def _calculate_cms_score(self, cms_info: Dict, vulns: Dict, exposed: Dict, plugins: Dict) -> int:
        """Расчет оценки безопасности CMS"""
        score = 100
        
        # Штрафы за уязвимости
        for vuln in vulns['found']:
            severity = vuln['severity']
            if severity == 'critical':
                score -= 30
            elif severity == 'high':
                score -= 20
            elif severity == 'medium':
                score -= 10
            else:
                score -= 5
        
        # Штрафы за открытые файлы
        for file_info in exposed['found']:
            risk = file_info['risk']
            if risk == 'high':
                score -= 15
            elif risk == 'medium':
                score -= 10
            else:
                score -= 5
        
        # Штрафы за устаревшие плагины
        score -= len(plugins.get('outdated', [])) * 5
        score -= len(plugins.get('vulnerable', [])) * 15
        
        # Бонус за обнаруженную современную CMS
        if cms_info.get('detected') and cms_info.get('version'):
            score += 10
        
        return max(0, min(score, 100))

    def _determine_status(self, score: int) -> str:
        """Определение статуса на основе оценки"""
        if score >= 80:
            return 'good'
        elif score >= 60:
            return 'warning'
        else:
            return 'critical'

# Дополнительные утилиты для анализа CMS
class CMSAnalyzer:
    """Дополнительные методы анализа CMS"""
    
    @staticmethod
    def get_cms_security_recommendations(cms_type: str) -> List[str]:
        """Получение рекомендаций по безопасности для конкретной CMS"""
        recommendations = {
            'wordpress': [
                'Обновите WordPress до последней версии',
                'Обновите все плагины и темы',
                'Установите плагин безопасности (Wordfence, Sucuri)',
                'Измените префикс таблиц БД с wp_ на что-то уникальное',
                'Ограничьте количество попыток входа',
                'Скройте версию WordPress',
                'Отключите xmlrpc.php если не используется',
                'Настройте регулярные резервные копии'
            ],
            'drupal': [
                'Обновите Drupal до последней версии',
                'Обновите все модули',
                'Настройте правильные права доступа к файлам',
                'Включите кэширование для производительности',
                'Регулярно проверяйте логи безопасности',
                'Используйте модули безопасности (Security Kit)'
            ],
            'joomla': [
                'Обновите Joomla до последней версии',
                'Обновите все расширения',
                'Измените стандартную папку administrator',
                'Настройте .htaccess для дополнительной защиты',
                'Отключите отображение ошибок PHP',
                'Используйте расширения безопасности'
            ]
        }
        
        return recommendations.get(cms_type, [
            'Обновите CMS до последней версии',
            'Регулярно делайте резервные копии',
            'Используйте сильные пароли',
            'Ограничьте доступ к административной панели'
        ])
