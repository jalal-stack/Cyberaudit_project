"""
Система оценки безопасности для CyberAudit
"""

from typing import Dict, Any, List
import statistics

class SecurityScorer:
    """Класс для расчета общей оценки безопасности"""
    
    def __init__(self):
        # Весовые коэффициенты для разных типов сканирования
        self.weights = {
            'ssl': 0.25,     # 25% - SSL/HTTPS критически важен
            'ports': 0.20,   # 20% - Открытые порты
            'headers': 0.25, # 25% - HTTP заголовки безопасности
            'cms': 0.20,     # 20% - CMS и уязвимости
            'ddos': 0.10     # 10% - DDoS защита
        }
        
        # Критерии для определения уровня безопасности
        self.security_levels = {
            'excellent': {'min_score': 90, 'description': 'Отличная безопасность'},
            'good': {'min_score': 80, 'description': 'Хорошая безопасность'},  
            'warning': {'min_score': 60, 'description': 'Требуется внимание'},
            'critical': {'min_score': 0, 'description': 'Критические проблемы'}
        }

    def calculate_total_score(self, scan_results: Dict[str, Any]) -> int:
        """Расчет общего балла безопасности"""
        try:
            total_score = 0
            total_weight = 0
            
            for scan_type, weight in self.weights.items():
                if scan_type in scan_results and not scan_results[scan_type].get('error'):
                    score = scan_results[scan_type].get('score', 0)
                    total_score += score * weight
                    total_weight += weight
            
            # Нормализация на основе фактически проведенных сканирований
            if total_weight > 0:
                final_score = int(total_score / total_weight)
            else:
                final_score = 0
                
            return max(0, min(final_score, 100))
            
        except Exception:
            return 0

    def generate_recommendations(self, scan_results: Dict[str, Any], translations: Dict[str, Any]) -> List[str]:
        """Генерация персонализированных рекомендаций по безопасности"""
        recommendations = []
        
        try:
            # SSL/HTTPS рекомендации
            if 'ssl' in scan_results:
                ssl_recommendations = self._get_ssl_recommendations(
                    scan_results['ssl'], translations
                )
                recommendations.extend(ssl_recommendations)
            
            # Порты рекомендации
            if 'ports' in scan_results:
                port_recommendations = self._get_port_recommendations(
                    scan_results['ports'], translations
                )
                recommendations.extend(port_recommendations)
            
            # HTTP заголовки рекомендации
            if 'headers' in scan_results:
                header_recommendations = self._get_header_recommendations(
                    scan_results['headers'], translations
                )
                recommendations.extend(header_recommendations)
            
            # CMS рекомендации
            if 'cms' in scan_results:
                cms_recommendations = self._get_cms_recommendations(
                    scan_results['cms'], translations
                )
                recommendations.extend(cms_recommendations)
            
            # DDoS рекомендации
            if 'ddos' in scan_results:
                ddos_recommendations = self._get_ddos_recommendations(
                    scan_results['ddos'], translations
                )
                recommendations.extend(ddos_recommendations)
            
            # Общие рекомендации
            general_recommendations = self._get_general_recommendations(
                scan_results, translations
            )
            recommendations.extend(general_recommendations)
            
            # Удаляем дубликаты и ограничиваем количество
            unique_recommendations = list(dict.fromkeys(recommendations))
            return unique_recommendations[:15]  # Максимум 15 рекомендаций
            
        except Exception:
            return [translations.get('default_recommendation', 
                   'Обратитесь к специалисту по информационной безопасности')]

    def _get_ssl_recommendations(self, ssl_result: Dict[str, Any], translations: Dict) -> List[str]:
        """SSL/HTTPS рекомендации"""
        recommendations = []
        
        if ssl_result.get('error'):
            recommendations.append('Исправьте проблемы с SSL конфигурацией')
            return recommendations
            
        if ssl_result.get('status') == 'critical':
            if ssl_result.get('protocol') == 'HTTP':
                recommendations.append('Установите SSL сертификат и включите HTTPS')
                recommendations.append('Настройте автоматическое перенаправление с HTTP на HTTPS')
            else:
                recommendations.append('Срочно обновите SSL конфигурацию')
                
        elif ssl_result.get('status') == 'warning':
            if ssl_result.get('certificate', {}).get('expires_soon'):
                recommendations.append('Продлите SSL сертификат до истечения срока действия')
            
            protocols = ssl_result.get('protocols', {})
            if protocols.get('weak_protocols'):
                recommendations.append('Отключите устаревшие протоколы TLS/SSL')
                
        return recommendations

    def _get_port_recommendations(self, port_result: Dict[str, Any], translations: Dict) -> List[str]:
        """Рекомендации по портам"""
        recommendations = []
        
        if port_result.get('error'):
            return recommendations
            
        dangerous_ports = port_result.get('dangerous_ports', [])
        
        for port_info in dangerous_ports[:3]:  # Первые 3 самых опасных
            port = port_info.get('port')
            service = port_info.get('service', 'unknown')
            
            if port == 21:  # FTP
                recommendations.append('Замените FTP на SFTP или FTPS для безопасной передачи файлов')
            elif port == 23:  # Telnet
                recommendations.append('Замените Telnet на SSH для безопасного удаленного доступа')
            elif port == 3389:  # RDP
                recommendations.append('Ограничьте доступ к RDP через VPN')
            elif port in [3306, 5432, 1433]:  # Базы данных
                recommendations.append(f'Закройте прямой доступ к базе данных ({service}) из интернета')
            else:
                recommendations.append(f'Закройте неиспользуемый порт {port} ({service})')
        
        if len(dangerous_ports) > 3:
            recommendations.append(f'Проверьте и закройте остальные {len(dangerous_ports)-3} небезопасных портов')
            
        return recommendations

    def _get_header_recommendations(self, header_result: Dict[str, Any], translations: Dict) -> List[str]:
        """Рекомендации по HTTP заголовкам"""
        recommendations = []
        
        if header_result.get('error'):
            return recommendations
            
        security_headers = header_result.get('security_headers', {})
        missing = security_headers.get('missing', {})
        
        # Приоритетные заголовки
        priority_headers = ['strict-transport-security', 'content-security-policy', 'x-frame-options']
        
        for header in priority_headers:
            if header in missing:
                header_name = missing[header].get('name', header)
                recommendations.append(f'Добавьте заголовок {header_name}')
        
        # Опасные заголовки
        dangerous = header_result.get('dangerous_headers', {}).get('found', {})
        if dangerous:
            recommendations.append('Скройте информационные заголовки сервера (Server, X-Powered-By)')
            
        return recommendations

    def _get_cms_recommendations(self, cms_result: Dict[str, Any], translations: Dict) -> List[str]:
        """Рекомендации по CMS"""
        recommendations = []
        
        if cms_result.get('error'):
            return recommendations
            
        cms_info = cms_result.get('cms', {})
        vulnerabilities = cms_result.get('vulnerabilities', {})
        
        if cms_info.get('detected'):
            cms_name = cms_info.get('name', 'CMS')
            
            # Уязвимости
            if vulnerabilities.get('found'):
                recommendations.append(f'Срочно обновите {cms_name} до последней версии')
                
                risk_level = vulnerabilities.get('risk_level', 'medium')
                if risk_level == 'critical':
                    recommendations.append('Найдены критические уязвимости - примените патчи немедленно')
            
            # Открытые файлы
            exposed_files = cms_result.get('exposed_files', {})
            if exposed_files.get('found'):
                recommendations.append('Ограничьте доступ к системным файлам CMS')
            
            # Плагины
            plugins = cms_result.get('plugins', {})
            if plugins.get('outdated'):
                recommendations.append('Обновите устаревшие плагины')
                
        return recommendations

    def _get_ddos_recommendations(self, ddos_result: Dict[str, Any], translations: Dict) -> List[str]:
        """Рекомендации по DDoS защите"""
        recommendations = []
        
        if ddos_result.get('error'):
            return recommendations
            
        cdn_info = ddos_result.get('cdn_detection', {})
        
        if not cdn_info.get('detected'):
            recommendations.append('Настройте CDN (например, Cloudflare) для защиты от DDoS атак')
        
        rate_limiting = ddos_result.get('rate_limiting', {})
        if not rate_limiting.get('detected'):
            recommendations.append('Настройте ограничение скорости запросов (rate limiting)')
            
        dns_info = ddos_result.get('dns_info', {})
        if dns_info.get('single_ip'):
            recommendations.append('Настройте балансировку нагрузки между несколькими серверами')
            
        return recommendations

    def _get_general_recommendations(self, scan_results: Dict[str, Any], translations: Dict) -> List[str]:
        """Общие рекомендации по безопасности"""
        recommendations = []
        
        # Подсчитываем общее количество проблем
        total_issues = 0
        critical_issues = 0
        
        for scan_type, result in scan_results.items():
            if isinstance(result, dict):
                issues = result.get('issues', [])
                total_issues += len(issues)
                
                if result.get('status') == 'critical':
                    critical_issues += 1
        
        # Общие советы на основе анализа
        if critical_issues > 2:
            recommendations.append('Рекомендуется комплексный аудит безопасности')
        
        if total_issues > 10:
            recommendations.append('Создайте план поэтапного устранения уязвимостей')
            recommendations.append('Настройте мониторинг безопасности')
        
        # Всегда актуальные рекомендации
        recommendations.append('Регулярно обновляйте программное обеспечение')
        recommendations.append('Используйте сильные пароли и двухфакторную аутентификацию')
        
        return recommendations

    def get_security_summary(self, scan_results: Dict[str, Any], total_score: int) -> Dict[str, Any]:
        """Получение сводки по безопасности"""
        # Определение уровня безопасности
        security_level = 'critical'
        for level, criteria in sorted(self.security_levels.items(), 
                                    key=lambda x: x[1]['min_score'], reverse=True):
            if total_score >= criteria['min_score']:
                security_level = level
                break
        
        # Подсчет статистики
        stats = {
            'total_checks': 0,
            'passed_checks': 0,
            'failed_checks': 0,
            'issues_found': 0
        }
        
        for scan_type, result in scan_results.items():
            if isinstance(result, dict) and not result.get('error'):
                stats['total_checks'] += result.get('total_checks', 0)
                stats['passed_checks'] += result.get('passed_checks', 0)
                stats['issues_found'] += len(result.get('issues', []))
        
        stats['failed_checks'] = stats['total_checks'] - stats['passed_checks']
        
        return {
            'security_level': security_level,
            'description': self.security_levels[security_level]['description'],
            'total_score': total_score,
            'statistics': stats,
            'certificate_eligible': total_score >= 80
        }

# Дополнительные утилиты для анализа безопасности
class SecurityAnalyzer:
    """Дополнительные методы анализа безопасности"""
    
    @staticmethod
    def categorize_vulnerabilities(scan_results: Dict[str, Any]) -> Dict[str, List]:
        """Категоризация уязвимостей по серьезности"""
        vulnerabilities = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for scan_type, result in scan_results.items():
            if isinstance(result, dict):
                issues = result.get('issues', [])
                status = result.get('status', 'unknown')
                
                for issue in issues:
                    vuln_info = {
                        'scan_type': scan_type,
                        'description': issue,
                        'severity': status
                    }
                    
                    if status == 'critical':
                        vulnerabilities['critical'].append(vuln_info)
                    elif status == 'warning':
                        vulnerabilities['medium'].append(vuln_info)
                    else:
                        vulnerabilities['low'].append(vuln_info)
        
        return vulnerabilities
    
    @staticmethod
    def calculate_risk_score(scan_results: Dict[str, Any]) -> Dict[str, float]:
        """Расчет оценки рисков по категориям"""
        risk_scores = {
            'confidentiality': 0.0,  # Конфиденциальность
            'integrity': 0.0,        # Целостность
            'availability': 0.0      # Доступность
        }
        
        # SSL проблемы влияют на конфиденциальность
        if 'ssl' in scan_results:
            ssl_score = scan_results['ssl'].get('score', 100)
            risk_scores['confidentiality'] += (100 - ssl_score) * 0.4
        
        # CMS уязвимости влияют на целостность
        if 'cms' in scan_results:
            cms_score = scan_results['cms'].get('score', 100) 
            risk_scores['integrity'] += (100 - cms_score) * 0.3
        
        # DDoS защита влияет на доступность
        if 'ddos' in scan_results:
            ddos_score = scan_results['ddos'].get('score', 100)
            risk_scores['availability'] += (100 - ddos_score) * 0.5
        
        # Нормализация до 0-100 диапазона
        for category in risk_scores:
            risk_scores[category] = min(100, max(0, risk_scores[category]))
        
        return risk_scores
