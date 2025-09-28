"""
HTTP Security Headers Scanner для CyberAudit
Использует httpx для проверки заголовков безопасности
"""

import httpx
import asyncio
from urllib.parse import urlparse
from typing import Dict, Any, List

class HeadersScanner:
    """Сканер HTTP заголовков безопасности"""
    
    def __init__(self):
        # Критически важные заголовки безопасности
        self.critical_headers = {
            'strict-transport-security': {
                'name': 'Strict-Transport-Security (HSTS)',
                'description': 'Принуждает использование HTTPS',
                'score_weight': 20,
                'required': True
            },
            'content-security-policy': {
                'name': 'Content-Security-Policy (CSP)',
                'description': 'Защита от XSS атак',
                'score_weight': 20,
                'required': True
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': 'Защита от clickjacking',
                'score_weight': 15,
                'required': True
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': 'Предотвращает MIME-sniffing',
                'score_weight': 10,
                'required': True
            }
        }
        
        # Дополнительные заголовки безопасности
        self.additional_headers = {
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'description': 'Контролирует информацию referrer',
                'score_weight': 10,
                'required': False
            },
            'permissions-policy': {
                'name': 'Permissions-Policy',
                'description': 'Контролирует доступ к API браузера',
                'score_weight': 5,
                'required': False
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'description': 'Включает XSS фильтр браузера',
                'score_weight': 5,
                'required': False
            },
            'expect-ct': {
                'name': 'Expect-CT',
                'description': 'Certificate Transparency monitoring',
                'score_weight': 5,
                'required': False
            }
        }
        
        # Опасные заголовки, которых не должно быть
        self.dangerous_headers = {
            'server': 'Раскрывает информацию о сервере',
            'x-powered-by': 'Раскрывает технологии сервера',
            'x-aspnet-version': 'Раскрывает версию ASP.NET',
            'x-aspnetmvc-version': 'Раскрывает версию ASP.NET MVC'
        }

    async def scan(self, url: str) -> Dict[str, Any]:
        """Основной метод сканирования HTTP заголовков"""
        try:
            # Выполнение HTTP запросов для получения заголовков
            headers_info = await self._fetch_headers(url)
            
            if 'error' in headers_info:
                return headers_info
                
            # Анализ заголовков безопасности
            security_analysis = await self._analyze_security_headers(headers_info['headers'])
            
            # Анализ опасных заголовков
            dangerous_analysis = await self._analyze_dangerous_headers(headers_info['headers'])
            
            # Анализ HTTPS редиректов
            https_analysis = await self._analyze_https_redirects(url)
            
            # Расчет общей оценки
            total_score = self._calculate_headers_score(security_analysis, dangerous_analysis, https_analysis)
            
            # Определение статуса и формирование отчета
            issues = []
            recommendations = []
            
            # Проблемы с отсутствующими заголовками
            for header, info in security_analysis['missing'].items():
                if info['required']:
                    issues.append(f"Отсутствует критичный заголовок: {info['name']}")
                    recommendations.append(f"Добавьте заголовок {info['name']} для {info['description'].lower()}")
                else:
                    recommendations.append(f"Рекомендуется добавить заголовок {info['name']} для {info['description'].lower()}")
            
            # Проблемы с неправильными значениями
            for header, details in security_analysis['incorrect'].items():
                issues.append(f"Неправильное значение заголовка {details['name']}: {details['current_value']}")
                recommendations.append(f"Исправьте значение заголовка {details['name']}")
            
            # Опасные заголовки
            for header, value in dangerous_analysis['found'].items():
                issues.append(f"Присутствует небезопасный заголовок {header}: {value}")
                recommendations.append(f"Удалите или скройте заголовок {header}")
            
            status = self._determine_status(total_score)
            
            return {
                'url': url,
                'response_info': headers_info['response_info'],
                'security_headers': security_analysis,
                'dangerous_headers': dangerous_analysis,
                'https_info': https_analysis,
                'score': total_score,
                'status': status,
                'issues': issues,
                'recommendations': recommendations,
                'total_checks': 12,
                'passed_checks': max(0, 12 - len(issues))
            }
            
        except Exception as e:
            return {
                'error': f'Ошибка при сканировании заголовков: {str(e)}',
                'score': 0,
                'status': 'error'
            }

    async def _fetch_headers(self, url: str) -> Dict[str, Any]:
        """Получение HTTP заголовков"""
        try:
            async with httpx.AsyncClient(
                timeout=15,
                follow_redirects=False,
                verify=False  # Игнорируем SSL ошибки для тестирования
            ) as client:
                
                # Выполняем HEAD запрос для получения заголовков
                response = await client.head(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                response_info = {
                    'status_code': response.status_code,
                    'http_version': response.http_version,
                    'reason_phrase': response.reason_phrase
                }
                
                return {
                    'headers': headers,
                    'response_info': response_info
                }
                
        except httpx.TimeoutException:
            return {'error': 'Превышено время ожидания ответа сервера'}
        except httpx.ConnectError:
            return {'error': 'Не удалось подключиться к серверу'}
        except Exception as e:
            return {'error': f'Ошибка при получении заголовков: {str(e)}'}

    async def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Анализ заголовков безопасности"""
        present = {}
        missing = {}
        incorrect = {}
        
        # Проверка всех заголовков безопасности
        all_headers = {**self.critical_headers, **self.additional_headers}
        
        for header_key, header_info in all_headers.items():
            if header_key in headers:
                header_value = headers[header_key]
                
                # Валидация значения заголовка
                validation_result = self._validate_header_value(header_key, header_value)
                
                if validation_result['valid']:
                    present[header_key] = {
                        'name': header_info['name'],
                        'value': header_value,
                        'score': header_info['score_weight'],
                        'strength': validation_result.get('strength', 'good')
                    }
                else:
                    incorrect[header_key] = {
                        'name': header_info['name'],
                        'current_value': header_value,
                        'issue': validation_result['issue'],
                        'recommendation': validation_result['recommendation']
                    }
            else:
                missing[header_key] = header_info
        
        return {
            'present': present,
            'missing': missing,
            'incorrect': incorrect
        }

    def _validate_header_value(self, header: str, value: str) -> Dict[str, Any]:
        """Валидация значений заголовков безопасности"""
        
        if header == 'strict-transport-security':
            # HSTS должен иметь max-age
            if 'max-age=' not in value.lower():
                return {
                    'valid': False,
                    'issue': 'Отсутствует директива max-age',
                    'recommendation': 'Добавьте директиву max-age с подходящим значением'
                }
            
            # Проверяем значение max-age
            try:
                import re
                max_age_match = re.search(r'max-age=(\d+)', value.lower())
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Менее года
                        return {
                            'valid': True,
                            'strength': 'warning',
                            'note': 'Рекомендуется установить max-age не менее 31536000 (1 год)'
                        }
                    else:
                        strength = 'excellent' if 'includesubdomains' in value.lower() else 'good'
                        return {'valid': True, 'strength': strength}
            except:
                pass
                
            return {'valid': True, 'strength': 'good'}
        
        elif header == 'content-security-policy':
            # CSP не должен быть слишком простым
            if value.strip() in ['default-src *', 'default-src \'unsafe-inline\' \'unsafe-eval\'']:
                return {
                    'valid': False,
                    'issue': 'Слишком разрешающий CSP',
                    'recommendation': 'Используйте более строгую политику CSP'
                }
            
            # Проверяем наличие небезопасных директив
            if 'unsafe-inline' in value or 'unsafe-eval' in value:
                return {
                    'valid': True,
                    'strength': 'warning',
                    'note': 'CSP содержит небезопасные директивы'
                }
                
            return {'valid': True, 'strength': 'good'}
        
        elif header == 'x-frame-options':
            valid_values = ['deny', 'sameorigin']
            if value.lower() not in valid_values:
                return {
                    'valid': False,
                    'issue': f'Недопустимое значение: {value}',
                    'recommendation': 'Используйте DENY или SAMEORIGIN'
                }
            
            strength = 'excellent' if value.lower() == 'deny' else 'good'
            return {'valid': True, 'strength': strength}
        
        elif header == 'x-content-type-options':
            if value.lower() != 'nosniff':
                return {
                    'valid': False,
                    'issue': f'Недопустимое значение: {value}',
                    'recommendation': 'Используйте значение nosniff'
                }
                
            return {'valid': True, 'strength': 'good'}
        
        elif header == 'referrer-policy':
            safe_values = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
            if value.lower() in safe_values:
                return {'valid': True, 'strength': 'good'}
            else:
                return {
                    'valid': True,
                    'strength': 'warning',
                    'note': 'Можно использовать более строгую политику referrer'
                }
        
        # Для остальных заголовков - базовая валидация
        return {'valid': True, 'strength': 'good'}

    async def _analyze_dangerous_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Анализ опасных заголовков"""
        found = {}
        
        for dangerous_header, description in self.dangerous_headers.items():
            if dangerous_header in headers:
                found[dangerous_header] = {
                    'value': headers[dangerous_header],
                    'risk': description
                }
        
        return {
            'found': found,
            'count': len(found)
        }

    async def _analyze_https_redirects(self, url: str) -> Dict[str, Any]:
        """Анализ HTTPS редиректов"""
        try:
            parsed_url = urlparse(url)
            
            # Если URL уже HTTPS, проверяем доступность HTTP версии
            if parsed_url.scheme == 'https':
                http_url = url.replace('https://', 'http://')
                
                async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
                    try:
                        response = await client.get(http_url)
                        
                        # Проверяем, есть ли редирект на HTTPS
                        if response.status_code in [301, 302, 308]:
                            location = response.headers.get('location', '')
                            if location.startswith('https://'):
                                return {
                                    'http_to_https_redirect': True,
                                    'redirect_status': response.status_code,
                                    'permanent': response.status_code in [301, 308]
                                }
                        
                        return {
                            'http_to_https_redirect': False,
                            'http_accessible': True
                        }
                    except:
                        return {
                            'http_to_https_redirect': False,
                            'http_accessible': False
                        }
            
            return {'analysis': 'URL is HTTP - HTTPS redirect analysis not applicable'}
            
        except Exception:
            return {'error': 'Failed to analyze HTTPS redirects'}

    def _calculate_headers_score(self, security_analysis: Dict, dangerous_analysis: Dict, https_analysis: Dict) -> int:
        """Расчет общей оценки заголовков безопасности"""
        score = 0
        
        # Баллы за присутствующие заголовки
        for header, info in security_analysis['present'].items():
            header_score = info['score']
            
            # Корректировка на основе качества
            if info.get('strength') == 'excellent':
                header_score = int(header_score * 1.1)
            elif info.get('strength') == 'warning':
                header_score = int(header_score * 0.7)
                
            score += header_score
        
        # Штрафы за отсутствующие критичные заголовки
        for header, info in security_analysis['missing'].items():
            if info['required']:
                score -= info['score_weight'] // 2
        
        # Штрафы за неправильные заголовки
        for header, info in security_analysis['incorrect'].items():
            score -= 10
        
        # Штрафы за опасные заголовки
        score -= dangerous_analysis['count'] * 5
        
        # Бонус за HTTPS редирект
        if https_analysis.get('http_to_https_redirect'):
            score += 5
            if https_analysis.get('permanent'):
                score += 5
        
        return max(0, min(score, 100))

    def _determine_status(self, score: int) -> str:
        """Определение статуса на основе оценки"""
        if score >= 80:
            return 'good'
        elif score >= 60:
            return 'warning'
        else:
            return 'critical'

    async def get_header_recommendations(self) -> Dict[str, str]:
        """Получение рекомендаций по настройке заголовков"""
        return {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': 'default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:',
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'X-XSS-Protection': '1; mode=block'
        }

# Утилиты для детального анализа заголовков
class HeaderAnalyzer:
    """Дополнительные методы анализа заголовков"""
    
    @staticmethod
    def analyze_csp_policy(csp_value: str) -> Dict[str, Any]:
        """Детальный анализ Content Security Policy"""
        directives = {}
        issues = []
        
        # Парсинг директив CSP
        for directive in csp_value.split(';'):
            directive = directive.strip()
            if directive:
                parts = directive.split()
                if parts:
                    directive_name = parts[0]
                    values = parts[1:] if len(parts) > 1 else []
                    directives[directive_name] = values
        
        # Анализ безопасности
        if 'default-src' not in directives:
            issues.append('Отсутствует базовая директива default-src')
        
        for directive, values in directives.items():
            if '*' in values:
                issues.append(f'Директива {directive} разрешает все источники (*)')
            if 'unsafe-inline' in values:
                issues.append(f'Директива {directive} содержит небезопасный \'unsafe-inline\'')
            if 'unsafe-eval' in values:
                issues.append(f'Директива {directive} содержит небезопасный \'unsafe-eval\'')
        
        return {
            'directives': directives,
            'issues': issues,
            'score': max(0, 100 - len(issues) * 15)
        }
    
    @staticmethod
    def get_missing_headers_impact(missing_headers: List[str]) -> Dict[str, str]:
        """Описание влияния отсутствующих заголовков"""
        impact_descriptions = {
            'strict-transport-security': 'Возможны атаки downgrade и man-in-the-middle',
            'content-security-policy': 'Уязвимость к XSS атакам и injection attacks',
            'x-frame-options': 'Уязвимость к clickjacking атакам',
            'x-content-type-options': 'Возможность MIME-type confusion атак',
            'referrer-policy': 'Утечка информации через referrer',
            'permissions-policy': 'Неконтролируемый доступ к API браузера'
        }
        
        return {header: impact_descriptions.get(header, 'Снижение общей безопасности') 
                for header in missing_headers}
