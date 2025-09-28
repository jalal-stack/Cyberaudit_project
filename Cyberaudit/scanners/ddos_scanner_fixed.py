"""
DDoS Protection Scanner для CyberAudit
Использует dnspython для анализа DNS и базовые нагрузочные тесты
"""

import dns.resolver
import dns.reversename
import httpx
import asyncio
import time
from urllib.parse import urlparse
from typing import Dict, Any, List

class DDoSScanner:
    """Сканер защиты от DDoS атак"""
    
    def __init__(self):
        # Известные CDN провайдеры
        self.cdn_providers = {
            'cloudflare': {
                'name': 'Cloudflare',
                'headers': ['cf-ray', 'cf-cache-status'],
                'protection_level': 'excellent'
            },
            'cloudfront': {
                'name': 'Amazon CloudFront',
                'headers': ['x-amz-cf-id', 'x-cache'],
                'protection_level': 'good'
            },
            'akamai': {
                'name': 'Akamai',
                'headers': ['akamai-origin-hop'],
                'protection_level': 'excellent'
            }
        }

    async def scan(self, url: str) -> Dict[str, Any]:
        """Основной метод сканирования DDoS защиты"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            
            if not hostname:
                return {'error': 'Невозможно извлечь hostname из URL'}
            
            # DNS анализ
            dns_info = await self._analyze_dns(hostname)
            
            # Детекция CDN
            cdn_info = await self._detect_cdn(url, hostname, dns_info)
            
            # Проверка rate limiting
            rate_limit_info = await self._check_rate_limiting(url)
            
            # Расчет общей оценки защиты
            score = self._calculate_protection_score(dns_info, cdn_info, rate_limit_info)
            
            # Определение рекомендаций
            issues = []
            recommendations = []
            
            if not cdn_info['detected']:
                issues.append('CDN/DDoS защита не обнаружена')
                recommendations.append('Настройте CDN для защиты от DDoS')
            
            if dns_info.get('single_ip', False):
                issues.append('Единственная точка отказа')
                recommendations.append('Настройте балансировку нагрузки')
            
            status = self._determine_status(score)
            
            return {
                'url': url,
                'hostname': hostname,
                'dns_info': dns_info,
                'cdn_detection': cdn_info,
                'rate_limiting': rate_limit_info,
                'score': score,
                'status': status,
                'issues': issues,
                'recommendations': recommendations,
                'total_checks': 5,
                'passed_checks': max(0, 5 - len(issues))
            }
            
        except Exception as e:
            return {
                'error': f'Ошибка при анализе DDoS защиты: {str(e)}',
                'score': 0,
                'status': 'error'
            }

    async def _analyze_dns(self, hostname: str) -> Dict[str, Any]:
        """Анализ DNS конфигурации"""
        dns_info = {
            'a_records': [],
            'single_ip': True,
            'geographic_distribution': False
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            # A записи
            try:
                a_records = resolver.resolve(hostname, 'A')
                dns_info['a_records'] = [str(record) for record in a_records]
                
                if len(dns_info['a_records']) > 1:
                    dns_info['single_ip'] = False
                    
            except Exception as e:
                dns_info['error'] = str(e)
            
        except Exception as e:
            dns_info['error'] = f'Ошибка DNS анализа: {str(e)}'
        
        return dns_info

    async def _detect_cdn(self, url: str, hostname: str, dns_info: Dict[str, Any]) -> Dict[str, Any]:
        """Детекция CDN"""
        cdn_result = {
            'detected': False,
            'provider': None,
            'provider_name': None,
            'protection_level': None
        }
        
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                # Поиск CDN по заголовкам
                for cdn_key, cdn_info in self.cdn_providers.items():
                    for header in cdn_info['headers']:
                        if header.lower() in headers:
                            cdn_result.update({
                                'detected': True,
                                'provider': cdn_key,
                                'provider_name': cdn_info['name'],
                                'protection_level': cdn_info['protection_level']
                            })
                            break
                            
        except Exception as e:
            cdn_result['error'] = f'Ошибка при детекции CDN: {str(e)}'
        
        return cdn_result

    async def _check_rate_limiting(self, url: str) -> Dict[str, Any]:
        """Проверка rate limiting"""
        rate_limit_info = {
            'detected': False,
            'method': None
        }
        
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                # Делаем несколько запросов
                for i in range(3):
                    try:
                        response = await client.get(url)
                        
                        # Проверка статус кода 429
                        if response.status_code == 429:
                            rate_limit_info['detected'] = True
                            rate_limit_info['method'] = 'HTTP 429 status'
                            break
                            
                        # Проверка заголовков rate limit
                        headers = response.headers
                        for header in ['x-ratelimit-remaining', 'retry-after']:
                            if header in headers:
                                rate_limit_info['detected'] = True
                                rate_limit_info['method'] = f'Header: {header}'
                                
                    except httpx.TimeoutException:
                        rate_limit_info['detected'] = True
                        rate_limit_info['method'] = 'Request timeout'
                        break
                        
                    await asyncio.sleep(0.5)
                            
        except Exception as e:
            rate_limit_info['error'] = f'Ошибка при проверке rate limiting: {str(e)}'
        
        return rate_limit_info

    def _calculate_protection_score(self, dns_info: Dict, cdn_info: Dict, rate_limit_info: Dict) -> int:
        """Расчет общей оценки защиты от DDoS"""
        score = 0
        
        # Баллы за CDN
        if cdn_info['detected']:
            protection_level = cdn_info.get('protection_level', 'medium')
            if protection_level == 'excellent':
                score += 50
            elif protection_level == 'good':
                score += 35
            else:
                score += 20
        
        # Баллы за множественные IP
        if not dns_info.get('single_ip', True):
            score += 25
        
        # Баллы за rate limiting
        if rate_limit_info['detected']:
            score += 25
        
        return max(0, min(score, 100))

    def _determine_status(self, score: int) -> str:
        """Определение статуса защиты"""
        if score >= 80:
            return 'good'
        elif score >= 60:
            return 'warning'
        else:
            return 'critical'
