"""
SSL/HTTPS Scanner для CyberAudit
Использует cryptography и ssl модуль для проверки SSL конфигурации
"""

import ssl
import socket
import asyncio
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import httpx

class SSLScanner:
    """Сканер SSL/HTTPS конфигурации"""
    
    def __init__(self):
        self.supported_protocols = [
            'TLSv1.3',
            'TLSv1.2', 
            'TLSv1.1',
            'TLSv1',
            'SSLv3',
            'SSLv2'
        ]
        
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1'
        ]
        
        self.secure_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options'
        ]

    async def scan(self, url: str) -> Dict[str, Any]:
        """Основной метод сканирования SSL"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if not hostname:
                return {"error": "Невозможно извлечь hostname из URL"}
                
            # Если это HTTP, проверим только редирект на HTTPS
            if parsed_url.scheme == 'http':
                https_redirect = await self._check_https_redirect(url)
                return {
                    "protocol": "HTTP",
                    "https_available": https_redirect["available"],
                    "https_redirect": https_redirect["redirect"],
                    "score": 20 if https_redirect["redirect"] else 0,
                    "status": "critical" if not https_redirect["redirect"] else "warning",
                    "issues": ["Сайт использует незащищенный протокол HTTP"] if not https_redirect["redirect"] else ["HTTP трафик не перенаправляется на HTTPS"],
                    "recommendations": ["Настройте автоматическое перенаправление с HTTP на HTTPS", "Получите SSL сертификат"]
                }
            
            # Проверка SSL сертификата и конфигурации
            ssl_info = await self._get_ssl_info(hostname, port)
            cert_info = await self._analyze_certificate(hostname, port)
            protocol_info = await self._check_protocols(hostname, port)
            cipher_info = await self._check_ciphers(hostname, port)
            
            # Расчет оценки
            score = await self._calculate_ssl_score(ssl_info, cert_info, protocol_info, cipher_info)
            
            # Определение статуса и проблем
            issues = []
            recommendations = []
            
            if cert_info.get("expired", False):
                issues.append("SSL сертификат истек")
                recommendations.append("Обновите SSL сертификат")
                
            if cert_info.get("self_signed", False):
                issues.append("Используется самоподписанный сертификат")
                recommendations.append("Получите сертификат от доверенного центра сертификации")
                
            if protocol_info.get("weak_protocols"):
                issues.extend([f"Поддерживается небезопасный протокол: {p}" for p in protocol_info["weak_protocols"]])
                recommendations.append("Отключите поддержку устаревших протоколов (SSLv2, SSLv3, TLSv1.0, TLSv1.1)")
                
            if cipher_info.get("weak_ciphers"):
                issues.extend([f"Поддерживается слабый шифр: {c}" for c in cipher_info["weak_ciphers"][:3]])
                recommendations.append("Настройте использование только современных шифров")
            
            status = self._determine_status(score)
            
            return {
                "protocol": "HTTPS",
                "certificate": cert_info,
                "protocols": protocol_info,
                "ciphers": cipher_info,
                "ssl_info": ssl_info,
                "score": score,
                "status": status,
                "issues": issues,
                "recommendations": recommendations,
                "total_checks": 8,
                "passed_checks": max(0, 8 - len(issues))
            }
            
        except Exception as e:
            return {
                "error": f"Ошибка при сканировании SSL: {str(e)}",
                "score": 0,
                "status": "error"
            }

    async def _check_https_redirect(self, url: str) -> Dict[str, Any]:
        """Проверка редиректа с HTTP на HTTPS"""
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
                response = await client.get(url)
                
                if response.status_code in [301, 302, 308]:
                    location = response.headers.get('location', '')
                    if location.startswith('https://'):
                        return {"available": True, "redirect": True}
                
                # Проверим, доступен ли HTTPS вариант
                https_url = url.replace('http://', 'https://')
                try:
                    response = await client.get(https_url)
                    return {"available": True, "redirect": False}
                except:
                    return {"available": False, "redirect": False}
                    
        except Exception:
            return {"available": False, "redirect": False}

    async def _get_ssl_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Получение базовой информации об SSL"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        "version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "cipher_strength": cipher[2] if cipher else None,
                        "protocol": cipher[1] if cipher else None
                    }
        except Exception as e:
            return {"error": str(e)}

    async def _analyze_certificate(self, hostname: str, port: int) -> Dict[str, Any]:
        """Анализ SSL сертификата"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert_chain()[0].to_cryptography_cert()
                    cert_dict = ssock.getpeercert()
                    
                    # Парсинг дат
                    not_before = datetime.strptime(cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.now()
                    
                    # Проверка срока действия
                    days_until_expiry = (not_after - now).days
                    expired = now > not_after
                    expires_soon = days_until_expiry < 30
                    
                    # Извлечение информации
                    subject = dict(x[0] for x in cert_dict['subject'])
                    issuer = dict(x[0] for x in cert_dict['issuer'])
                    
                    # Проверка на самоподписанный сертификат
                    self_signed = subject.get('commonName') == issuer.get('commonName')
                    
                    # Получение алгоритма подписи
                    signature_algorithm = cert_der.signature_algorithm_oid._name
                    
                    # Размер ключа
                    key_size = cert_der.public_key().key_size
                    
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_until_expiry": days_until_expiry,
                        "expired": expired,
                        "expires_soon": expires_soon,
                        "self_signed": self_signed,
                        "signature_algorithm": signature_algorithm,
                        "key_size": key_size,
                        "san": self._extract_san(cert_der)
                    }
                    
        except Exception as e:
            return {"error": str(e)}

    def _extract_san(self, cert) -> List[str]:
        """Извлечение Subject Alternative Names"""
        try:
            san_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return [name.value for name in san_extension.value]
        except:
            return []

    async def _check_protocols(self, hostname: str, port: int) -> Dict[str, Any]:
        """Проверка поддерживаемых протоколов"""
        supported = []
        weak_protocols = []
        
        protocols_to_check = {
            'TLSv1.3': ssl.PROTOCOL_TLS,
            'TLSv1.2': ssl.PROTOCOL_TLS,
            'TLSv1.1': ssl.PROTOCOL_TLS,
            'TLSv1': ssl.PROTOCOL_TLS,
        }
        
        for protocol_name, protocol_version in protocols_to_check.items():
            try:
                context = ssl.SSLContext(protocol_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Устанавливаем минимальную и максимальную версии
                if protocol_name == 'TLSv1.3':
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                elif protocol_name == 'TLSv1.2':
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif protocol_name == 'TLSv1.1':
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                elif protocol_name == 'TLSv1':
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        supported.append(protocol_name)
                        
                        # Отмечаем слабые протоколы
                        if protocol_name in ['TLSv1', 'TLSv1.1']:
                            weak_protocols.append(protocol_name)
                            
            except:
                continue
        
        return {
            "supported": supported,
            "weak_protocols": weak_protocols,
            "modern_protocols": [p for p in supported if p in ['TLSv1.3', 'TLSv1.2']]
        }

    async def _check_ciphers(self, hostname: str, port: int) -> Dict[str, Any]:
        """Проверка поддерживаемых шифров"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    
                    if not cipher:
                        return {"error": "Не удалось получить информацию о шифрах"}
                    
                    cipher_name = cipher[0]
                    cipher_protocol = cipher[1]
                    cipher_bits = cipher[2]
                    
                    # Проверка на слабые шифры
                    weak_ciphers = []
                    for weak in self.weak_ciphers:
                        if weak.lower() in cipher_name.lower():
                            weak_ciphers.append(weak)
                    
                    return {
                        "current_cipher": cipher_name,
                        "protocol": cipher_protocol,
                        "bits": cipher_bits,
                        "weak_ciphers": weak_ciphers,
                        "strong_cipher": cipher_bits >= 256 and not weak_ciphers
                    }
                    
        except Exception as e:
            return {"error": str(e)}

    async def _calculate_ssl_score(self, ssl_info: Dict, cert_info: Dict, protocol_info: Dict, cipher_info: Dict) -> int:
        """Расчет общей оценки SSL конфигурации"""
        score = 0
        
        # Базовые баллы за наличие SSL
        score += 20
        
        # Сертификат (30 баллов)
        if not cert_info.get("error"):
            if not cert_info.get("expired", False):
                score += 10
            if not cert_info.get("self_signed", False):
                score += 10
            if cert_info.get("key_size", 0) >= 2048:
                score += 5
            if not cert_info.get("expires_soon", False):
                score += 5
                
        # Протоколы (30 баллов)
        if not protocol_info.get("error"):
            modern_protocols = protocol_info.get("modern_protocols", [])
            weak_protocols = protocol_info.get("weak_protocols", [])
            
            if 'TLSv1.3' in modern_protocols:
                score += 15
            elif 'TLSv1.2' in modern_protocols:
                score += 10
                
            if not weak_protocols:
                score += 15
            elif len(weak_protocols) == 1:
                score += 10
            elif len(weak_protocols) == 2:
                score += 5
                
        # Шифры (20 баллов)
        if not cipher_info.get("error"):
            if cipher_info.get("strong_cipher", False):
                score += 15
            elif cipher_info.get("bits", 0) >= 128:
                score += 10
            elif cipher_info.get("bits", 0) >= 64:
                score += 5
                
            if not cipher_info.get("weak_ciphers", []):
                score += 5
        
        return min(score, 100)

    def _determine_status(self, score: int) -> str:
        """Определение статуса на основе оценки"""
        if score >= 80:
            return "good"
        elif score >= 60:
            return "warning" 
        else:
            return "critical"
