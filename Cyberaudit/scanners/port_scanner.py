"""
Port Scanner для CyberAudit
Использует python-nmap для сканирования открытых портов
"""

import nmap
import socket
import asyncio
from urllib.parse import urlparse
from typing import Dict, Any, List

class PortScanner:
    """Сканер открытых портов"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        
        # Стандартные порты для сканирования
        self.common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            993,   # IMAPS
            995,   # POP3S
            1433,  # MSSQL
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            6379,  # Redis
            27017, # MongoDB
        ]
        
        # Опасные/нежелательные открытые порты
        self.dangerous_ports = {
            21: {"service": "FTP", "risk": "high", "reason": "Незащищенная передача данных"},
            23: {"service": "Telnet", "risk": "critical", "reason": "Незащищенный удаленный доступ"},
            25: {"service": "SMTP", "risk": "medium", "reason": "Возможны спам-атаки"},
            110: {"service": "POP3", "risk": "medium", "reason": "Незащищенная электронная почта"},
            143: {"service": "IMAP", "risk": "medium", "reason": "Незащищенная электронная почта"},
            1433: {"service": "MSSQL", "risk": "high", "reason": "База данных доступна извне"},
            3306: {"service": "MySQL", "risk": "high", "reason": "База данных доступна извне"},
            3389: {"service": "RDP", "risk": "high", "reason": "Удаленный рабочий стол доступен извне"},
            5432: {"service": "PostgreSQL", "risk": "high", "reason": "База данных доступна извне"},
            6379: {"service": "Redis", "risk": "critical", "reason": "База данных Redis без аутентификации"},
            27017: {"service": "MongoDB", "risk": "high", "reason": "База данных MongoDB доступна извне"},
        }

    async def scan(self, url: str) -> Dict[str, Any]:
        """Основной метод сканирования портов"""
        try:
            # Извлечение hostname
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            
            if not hostname:
                return {"error": "Невозможно извлечь hostname из URL"}
            
            # Получение IP адреса
            ip_address = await self._resolve_hostname(hostname)
            if not ip_address:
                return {"error": f"Не удалось разрешить hostname: {hostname}"}
            
            # Быстрое сканирование общих портов
            open_ports = await self._scan_common_ports(ip_address)
            
            # Анализ открытых портов
            port_analysis = await self._analyze_ports(open_ports, ip_address)
            
            # Расчет оценки безопасности
            score = self._calculate_port_score(port_analysis)
            
            # Определение статуса и проблем
            issues = []
            recommendations = []
            
            for port_info in port_analysis["dangerous_ports"]:
                port = port_info["port"]
                service = port_info["service"]
                reason = port_info["reason"]
                issues.append(f"Открыт небезопасный порт {port} ({service})")
                recommendations.append(f"Закройте порт {port} или настройте безопасный доступ")
            
            if not open_ports:
                recommendations.append("Проведите более детальное сканирование портов")
            elif len(open_ports) > 10:
                recommendations.append("Слишком много открытых портов - закройте неиспользуемые")
                
            status = self._determine_status(score)
            
            return {
                "target": hostname,
                "ip_address": ip_address,
                "total_ports_scanned": len(self.common_ports),
                "open_ports": port_analysis["open_ports"],
                "dangerous_ports": port_analysis["dangerous_ports"],
                "secure_ports": port_analysis["secure_ports"],
                "score": score,
                "status": status,
                "issues": issues,
                "recommendations": recommendations,
                "total_checks": 10,
                "passed_checks": max(0, 10 - len(port_analysis["dangerous_ports"]))
            }
            
        except Exception as e:
            return {
                "error": f"Ошибка при сканировании портов: {str(e)}",
                "score": 0,
                "status": "error"
            }

    async def _resolve_hostname(self, hostname: str) -> str:
        """Разрешение hostname в IP адрес"""
        try:
            loop = asyncio.get_event_loop()
            ip_address = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            return ip_address
        except Exception:
            return None

    async def _scan_common_ports(self, ip_address: str) -> List[Dict[str, Any]]:
        """Сканирование общих портов"""
        open_ports = []
        
        try:
            # Создаем строку портов для nmap
            port_range = ','.join(map(str, self.common_ports))
            
            # Выполняем сканирование
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, 
                self.nm.scan, 
                ip_address, 
                port_range, 
                '-sS -T4 --max-retries 1 --host-timeout 30s'
            )
            
            # Обработка результатов
            if ip_address in self.nm.all_hosts():
                for protocol in self.nm[ip_address].all_protocols():
                    ports = self.nm[ip_address][protocol].keys()
                    for port in ports:
                        state = self.nm[ip_address][protocol][port]['state']
                        if state == 'open':
                            service_info = self.nm[ip_address][protocol][port]
                            open_ports.append({
                                "port": port,
                                "protocol": protocol,
                                "state": state,
                                "service": service_info.get('name', 'unknown'),
                                "version": service_info.get('version', ''),
                                "product": service_info.get('product', '')
                            })
                            
        except Exception as e:
            # Fallback: простое TCP подключение
            return await self._simple_port_scan(ip_address)
        
        return open_ports

    async def _simple_port_scan(self, ip_address: str) -> List[Dict[str, Any]]:
        """Простое сканирование портов через TCP подключения"""
        open_ports = []
        
        # Сканируем только самые важные порты при fallback
        important_ports = [21, 22, 23, 25, 53, 80, 443, 3389]
        
        for port in important_ports:
            try:
                # Создаем асинхронное подключение
                future = asyncio.open_connection(ip_address, port)
                reader, writer = await asyncio.wait_for(future, timeout=3)
                
                # Порт открыт
                writer.close()
                await writer.wait_closed()
                
                # Определяем сервис по порту
                service_name = self._get_service_by_port(port)
                
                open_ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service_name,
                    "version": "",
                    "product": ""
                })
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Порт закрыт или недоступен
                continue
                
        return open_ports

    def _get_service_by_port(self, port: int) -> str:
        """Определение сервиса по номеру порта"""
        services = {
            21: "ftp",
            22: "ssh", 
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb"
        }
        return services.get(port, "unknown")

    async def _analyze_ports(self, open_ports: List[Dict], ip_address: str) -> Dict[str, Any]:
        """Анализ открытых портов на предмет безопасности"""
        dangerous_ports = []
        secure_ports = []
        all_open_ports = []
        
        for port_info in open_ports:
            port = port_info["port"]
            all_open_ports.append(port_info)
            
            if port in self.dangerous_ports:
                dangerous_info = self.dangerous_ports[port]
                dangerous_ports.append({
                    "port": port,
                    "service": dangerous_info["service"],
                    "risk": dangerous_info["risk"],
                    "reason": dangerous_info["reason"],
                    "detected_service": port_info.get("service", "unknown")
                })
            else:
                # Порты, которые обычно считаются безопасными
                if port in [80, 443, 22, 53]:
                    secure_ports.append(port_info)
                else:
                    # Неизвестный открытый порт - потенциально опасный
                    dangerous_ports.append({
                        "port": port,
                        "service": port_info.get("service", "unknown"),
                        "risk": "medium",
                        "reason": "Неизвестный открытый порт",
                        "detected_service": port_info.get("service", "unknown")
                    })
        
        return {
            "open_ports": all_open_ports,
            "dangerous_ports": dangerous_ports,
            "secure_ports": secure_ports
        }

    def _calculate_port_score(self, analysis: Dict[str, Any]) -> int:
        """Расчет оценки безопасности портов"""
        score = 100  # Начинаем с максимальной оценки
        
        dangerous_ports = analysis["dangerous_ports"]
        open_ports = analysis["open_ports"]
        
        # Штрафы за опасные порты
        for port_info in dangerous_ports:
            risk = port_info["risk"]
            if risk == "critical":
                score -= 25
            elif risk == "high":
                score -= 15
            elif risk == "medium":
                score -= 10
            else:
                score -= 5
        
        # Штраф за слишком много открытых портов
        if len(open_ports) > 10:
            score -= 10
        elif len(open_ports) > 5:
            score -= 5
        
        # Бонус за наличие только безопасных портов
        if not dangerous_ports and len(open_ports) <= 3:
            score += 10
        
        return max(0, min(score, 100))

    def _determine_status(self, score: int) -> str:
        """Определение статуса на основе оценки"""
        if score >= 80:
            return "good"
        elif score >= 60:
            return "warning"
        else:
            return "critical"

    async def _detect_service_versions(self, ip_address: str, port: int) -> Dict[str, str]:
        """Определение версий сервисов (расширенная функция)"""
        try:
            # Подключаемся к порту и пытаемся получить баннер
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip_address, port), 
                timeout=5
            )
            
            # Отправляем простой запрос в зависимости от порта
            if port == 80:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 25:
                writer.write(b"EHLO test\r\n")
            elif port == 21:
                pass  # FTP обычно отправляет баннер сразу
            else:
                writer.write(b"\r\n")
                
            await writer.drain()
            
            # Читаем ответ
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner = response.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                banner = ""
                
            writer.close()
            await writer.wait_closed()
            
            return {"banner": banner}
            
        except Exception:
            return {"banner": ""}

# Дополнительные утилиты для анализа портов
class PortAnalyzer:
    """Дополнительные методы анализа портов"""
    
    @staticmethod
    def get_port_recommendations(open_ports: List[int]) -> List[str]:
        """Получение рекомендаций по открытым портам"""
        recommendations = []
        
        dangerous_found = []
        for port in open_ports:
            if port == 21:
                dangerous_found.append("FTP (21)")
                recommendations.append("Замените FTP на SFTP/FTPS для безопасной передачи файлов")
            elif port == 23:
                dangerous_found.append("Telnet (23)")
                recommendations.append("Замените Telnet на SSH для безопасного удаленного доступа")
            elif port == 3389:
                dangerous_found.append("RDP (3389)")
                recommendations.append("Ограничьте доступ к RDP через VPN или измените стандартный порт")
            elif port in [3306, 5432, 1433, 27017]:
                db_name = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}[port]
                dangerous_found.append(f"{db_name} ({port})")
                recommendations.append(f"Закройте прямой доступ к базе данных {db_name} из интернета")
        
        if not dangerous_found:
            recommendations.append("Конфигурация портов выглядит безопасной")
        else:
            recommendations.insert(0, f"Обнаружены потенциально опасные открытые порты: {', '.join(dangerous_found)}")
            
        return recommendations
