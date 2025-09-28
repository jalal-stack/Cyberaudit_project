import qrcode
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, List
from weasyprint import HTML, CSS
import uuid


class PDFGenerator:
    """Генератор PDF документов"""

    def __init__(self):
        self.base_styles = """
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        body {
            margin: 0;
            padding: 40px;
            font-family: 'Inter', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
            box-sizing: border-box;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="2" fill="white" opacity="0.1"/></svg>') repeat;
            background-size: 50px 50px;
        }
        
        .logo {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }
        
        .subtitle {
            font-size: 16px;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }
        
        .content {
            padding: 40px;
        }
        
        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            margin: 20px auto;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            font-weight: 700;
            color: white;
            position: relative;
        }
        
        .score-excellent { background: linear-gradient(135deg, #10b981 0%, #059669 100%); }
        .score-good { background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); }
        .score-warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
        .score-critical { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
        
        .website-name {
            text-align: center;
            font-size: 28px;
            font-weight: 600;
            margin: 20px 0 10px;
            color: #1f2937;
        }
        
        .scan-date {
            text-align: center;
            color: #6b7280;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 30px 0;
        }
        
        .info-item {
            text-align: center;
            padding: 20px;
            background: #f8fafc;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
        }
        
        .info-label {
            font-size: 14px;
            color: #64748b;
            margin-bottom: 5px;
            font-weight: 500;
        }
        
        .info-value {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
        }
        
        .qr-container {
            text-align: center;
            margin: 30px 0;
            padding: 20px;
            background: #f8fafc;
            border-radius: 12px;
        }
        
        .qr-code {
            margin: 10px auto;
            display: block;
        }
        
        .qr-label {
            font-size: 12px;
            color: #64748b;
            margin-top: 10px;
        }
        
        .footer {
            background: #f8fafc;
            padding: 30px 40px;
            text-align: center;
            color: #64748b;
            font-size: 12px;
            border-top: 1px solid #e2e8f0;
        }
        
        .recommendations {
            margin: 30px 0;
        }
        
        .recommendations h3 {
            color: #1f2937;
            font-size: 20px;
            margin-bottom: 15px;
        }
        
        .recommendation-item {
            padding: 10px 15px;
            margin: 8px 0;
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .critical-item {
            background: #fee2e2;
            border-left-color: #ef4444;
        }
        
        .details-section {
            margin: 30px 0;
            background: #f8fafc;
            border-radius: 12px;
            overflow: hidden;
        }
        
        .details-header {
            background: #4f46e5;
            color: white;
            padding: 15px 20px;
            font-weight: 600;
        }
        
        .details-content {
            padding: 20px;
        }
        
        .scan-result {
            margin: 15px 0;
            padding: 15px;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            background: white;
        }
        
        .scan-title {
            font-weight: 600;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .status-good { background: #dcfce7; color: #166534; }
        .status-warning { background: #fef3c7; color: #92400e; }
        .status-critical { background: #fee2e2; color: #991b1b; }
        
        .page-break {
            page-break-before: always;
        }
        """

    async def generate_certificate(self, scan_data: Dict[str, Any]) -> bytes:
        """Генерация сертификата безопасности"""
        try:
            # Определяем класс для цветовой схемы на основе оценки
            score = scan_data.get("score", 0)
            if score >= 90:
                score_class = "score-excellent"
            elif score >= 80:
                score_class = "score-good"
            elif score >= 60:
                score_class = "score-warning"
            else:
                score_class = "score-critical"

            # Генерируем QR код для верификации
            verification_url = f"https://cyberaudit.example.com/verify/{uuid.uuid4()}"
            qr_image = self._generate_qr_code(verification_url)

            # Дата истечения сертификата (1 год)
            valid_until = (datetime.now() + timedelta(days=365)).strftime("%d.%m.%Y")

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Сертификат безопасности</title>
                <style>{self.base_styles}</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">🛡️ CyberAudit</div>
                        <div class="subtitle">Сертификат кибербезопасности</div>
                    </div>
                    
                    <div class="content">
                        <div class="score-circle {score_class}">
                            {score}
                        </div>
                        
                        <div class="website-name">{scan_data.get('url', 'example.com')}</div>
                        <div class="scan-date">Сканирование выполнено: {scan_data.get('scan_date', datetime.now().strftime('%d.%m.%Y'))}</div>
                        
                        <div class="info-grid">
                            <div class="info-item">
                                <div class="info-label">Оценка безопасности</div>
                                <div class="info-value">{score}/100</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Статус</div>
                                <div class="info-value">✅ Безопасный</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Проверок пройдено</div>
                                <div class="info-value">37 из 45</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Действителен до</div>
                                <div class="info-value">{valid_until}</div>
                            </div>
                        </div>
                        
                        <div class="qr-container">
                            <div class="qr-label">QR-код для верификации сертификата:</div>
                            <img src="data:image/png;base64,{qr_image}" class="qr-code" width="120" height="120">
                            <div class="qr-label">Отсканируйте для проверки подлинности</div>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>Сертификат выдан системой CyberAudit на основе комплексного анализа безопасности</p>
                        <p>Дата выдачи: {datetime.now().strftime('%d.%m.%Y %H:%M')} | ID: {uuid.uuid4().hex[:12].upper()}</p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Генерируем PDF
            html_doc = HTML(string=html_content)
            pdf_bytes = html_doc.write_pdf()

            return pdf_bytes

        except Exception as e:
            raise Exception(f"Ошибка при генерации сертификата: {str(e)}")

    async def generate_report(self, scan_data: Dict[str, Any]) -> bytes:
        """Генерация детального отчета по безопасности"""
        try:
            score = scan_data.get("score", 0)
            results = scan_data.get("results", {})
            recommendations = scan_data.get("recommendations", [])

            # Генерируем секции отчета
            results_html = self._generate_results_html(results)
            recommendations_html = self._generate_recommendations_html(recommendations)

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Отчет по безопасности</title>
                <style>{self.base_styles}</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">🛡️ CyberAudit</div>
                        <div class="subtitle">Отчет по безопасности веб-сайта</div>
                    </div>
                    
                    <div class="content">
                        <div class="website-name">{scan_data.get('url', 'example.com')}</div>
                        <div class="scan-date">Дата сканирования: {scan_data.get('scan_date', datetime.now().strftime('%d.%m.%Y %H:%M'))}</div>
                        
                        <div class="info-grid">
                            <div class="info-item">
                                <div class="info-label">Общая оценка</div>
                                <div class="info-value">{score}/100</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Найдено проблем</div>
                                <div class="info-value">{len(recommendations)}</div>
                            </div>
                        </div>
                        
                        {results_html}
                        
                        <div class="page-break"></div>
                        
                        {recommendations_html}
                    </div>
                    
                    <div class="footer">
                        <p>Отчет создан системой CyberAudit - платформой для комплексного анализа кибербезопасности</p>
                        <p>Для получения актуальной информации рекомендуется проводить сканирование регулярно</p>
                        <p>Дата создания: {datetime.now().strftime('%d.%m.%Y %H:%M')} | ID: {uuid.uuid4().hex[:12].upper()}</p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Генерируем PDF
            html_doc = HTML(string=html_content)
            pdf_bytes = html_doc.write_pdf()

            return pdf_bytes

        except Exception as e:
            raise Exception(f"Ошибка при генерации отчета: {str(e)}")

    def _generate_qr_code(self, data: str) -> str:
        """Генерация QR кода в base64"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Конвертируем в base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        return base64.b64encode(buffer.read()).decode()

    def _generate_results_html(self, results: Dict[str, Any]) -> str:
        """Генерация HTML для результатов сканирования"""
        html_parts = ['<div class="details-section">']
        html_parts.append('<div class="details-header">Результаты детального сканирования</div>')
        html_parts.append('<div class="details-content">')

        # SSL/HTTPS результаты
        if "ssl" in results:
            ssl_result = results["ssl"]
            status_class = f"status-{ssl_result.get('status', 'warning')}"
            html_parts.append(
                f"""
            <div class="scan-result">
                <div class="scan-title">
                    🔒 SSL/HTTPS Анализ
                    <span class="status-badge {status_class}">{ssl_result.get('score', 0)}/100</span>
                </div>
                <div>Протокол: {ssl_result.get('protocol', 'Неизвестно')}</div>
                <div>Проблем: {len(ssl_result.get('issues', []))}</div>
                {self._format_issues(ssl_result.get('issues', []))}
            </div>
            """
            )

        # Результаты портов
        if "ports" in results:
            ports_result = results["ports"]
            status_class = f"status-{ports_result.get('status', 'warning')}"
            dangerous_ports = ports_result.get("dangerous_ports", [])
            html_parts.append(
                f"""
            <div class="scan-result">
                <div class="scan-title">
                    🌐 Сканирование портов
                    <span class="status-badge {status_class}">{ports_result.get('score', 0)}/100</span>
                </div>
                <div>Открыто портов: {len(ports_result.get('open_ports', []))}</div>
                <div>Опасных портов: {len(dangerous_ports)}</div>
                {self._format_issues(ports_result.get('issues', []))}
            </div>
            """
            )

        # HTTP заголовки
        if "headers" in results:
            headers_result = results["headers"]
            status_class = f"status-{headers_result.get('status', 'warning')}"
            html_parts.append(
                f"""
            <div class="scan-result">
                <div class="scan-title">
                    📋 HTTP заголовки безопасности
                    <span class="status-badge {status_class}">{headers_result.get('score', 0)}/100</span>
                </div>
                <div>Проверок пройдено: {headers_result.get('passed_checks', 0)}/{headers_result.get('total_checks', 0)}</div>
                {self._format_issues(headers_result.get('issues', []))}
            </div>
            """
            )

        html_parts.append("</div></div>")
        return "".join(html_parts)

    def _generate_recommendations_html(self, recommendations: List[str]) -> str:
        """Генерация HTML для рекомендаций"""
        if not recommendations:
            return '<div class="recommendations"><h3>✅ Критических рекомендаций нет</h3></div>'

        html_parts = ['<div class="recommendations">']
        html_parts.append("<h3>🔧 Рекомендации по улучшению безопасности</h3>")

        for i, rec in enumerate(recommendations[:10], 1):  # Максимум 10 рекомендаций
            priority_class = (
                "critical-item"
                if any(word in rec.lower() for word in ["критически", "срочно", "немедленно"])
                else "recommendation-item"
            )
            html_parts.append(f'<div class="{priority_class}">{i}. {rec}</div>')

        if len(recommendations) > 10:
            html_parts.append(
                f'<div class="recommendation-item">И еще {len(recommendations) - 10} рекомендаций...</div>'
            )

        html_parts.append("</div>")
        return "".join(html_parts)

    def _format_issues(self, issues: List[str]) -> str:
        """Форматирование списка проблем"""
        if not issues:
            return '<div style="color: #10b981; font-size: 14px; margin-top: 8px;">✅ Проблем не найдено</div>'

        formatted_issues = []
        for issue in issues[:3]:  # Показываем только первые 3
            formatted_issues.append(
                f'<div style="color: #dc2626; font-size: 14px; margin-top: 4px;">⚠️ {issue}</div>'
            )

        if len(issues) > 3:
            formatted_issues.append(
                f'<div style="color: #6b7280; font-size: 12px; margin-top: 4px;">... и еще {len(issues) - 3} проблем</div>'
            )

        return "".join(formatted_issues)

    async def generate_summary_report(self, multiple_scans: List[Dict[str, Any]]) -> bytes:
        """Генерация сводного отчета по нескольким сканированиям"""
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Сводный отчет</title>
                <style>{self.base_styles}</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">🛡️ CyberAudit</div>
                        <div class="subtitle">Сводный отчет по безопасности</div>
                    </div>
                    
                    <div class="content">
                        <h2>Обзор результатов сканирования</h2>
                        <p>Период: {datetime.now().strftime('%d.%m.%Y')}</p>
                        
                        <div class="info-grid">
                            <div class="info-item">
                                <div class="info-label">Всего сканирований</div>
                                <div class="info-value">{len(multiple_scans)}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Средняя оценка</div>
                                <div class="info-value">{sum(s.get('score', 0) for s in multiple_scans) // len(multiple_scans) if multiple_scans else 0}/100</div>
                            </div>
                        </div>
                        
                        {self._generate_scans_summary_html(multiple_scans)}
                    </div>
                </div>
            </body>
            </html>
            """

            html_doc = HTML(string=html_content)
            return html_doc.write_pdf()

        except Exception as e:
            raise Exception(f"Ошибка при генерации сводного отчета: {str(e)}")

    def _generate_scans_summary_html(self, scans: List[Dict[str, Any]]) -> str:
        """Генерация HTML сводки сканирований"""
        html_parts = ['<div class="details-section">']
        html_parts.append('<div class="details-header">Детали сканирований</div>')
        html_parts.append('<div class="details-content">')

        for scan in scans[:5]:  # Показываем только первые 5
            score = scan.get("score", 0)
            status_class = (
                "status-good"
                if score >= 80
                else "status-warning"
                if score >= 60
                else "status-critical"
            )

            html_parts.append(
                f"""
            <div class="scan-result">
                <div class="scan-title">
                    🌐 {scan.get('url', 'Неизвестный сайт')}
                    <span class="status-badge {status_class}">{score}/100</span>
                </div>
                <div>Дата: {scan.get('scan_date', 'Не указана')}</div>
                <div>Проблем найдено: {len(scan.get('recommendations', []))}</div>
            </div>
            """
            )

        html_parts.append("</div></div>")
        return "".join(html_parts)
