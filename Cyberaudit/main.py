"""
CyberAudit - Сканер безопасности веб-сайтов
Основной файл приложения FastAPI
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio

# Импорты модулей сканирования
from .scanners.ssl_scanner import SSLScanner
from .scanners.port_scanner import PortScanner  
from .scanners.headers_scanner import HeadersScanner
from .scanners.cms_scanner import CMSScanner
from .scanners.ddos_scanner import DDoSScanner
from .database.models import ScanResult, init_db
from .reports.pdf_generator import PDFGenerator
from .utils.scoring import SecurityScorer
from .utils.i18n import get_translations

# Создание приложения FastAPI
app = FastAPI(
    title="CyberAudit",
    description="Комплексный сканер безопасности веб-сайтов",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Статические файлы
app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydantic модели для API
class ScanRequest(BaseModel):
    url: str
    scan_types: List[str]  # ['ssl', 'ports', 'headers', 'cms', 'ddos']
    language: str = "ru"

class ScanResponse(BaseModel):
    scan_id: str
    url: str
    score: int
    status: str
    results: Dict[str, Any]
    recommendations: List[str]
    created_at: str

# Инициализация сканеров
ssl_scanner = SSLScanner()
port_scanner = PortScanner()
headers_scanner = HeadersScanner()
cms_scanner = CMSScanner()
ddos_scanner = DDoSScanner()
pdf_generator = PDFGenerator()
scorer = SecurityScorer()

@app.on_event("startup")
async def startup_event():
    """Инициализация при запуске приложения"""
    await init_db()

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Главная страница"""
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Запуск сканирования сайта"""
    try:
        # Валидация URL
        if not request.url.startswith(('http://', 'https://')):
            request.url = f"https://{request.url}"
        
        # Результаты сканирования
        scan_results = {}
        
        # Выполнение сканирований
        tasks = []
        
        if 'ssl' in request.scan_types:
            tasks.append(("ssl", ssl_scanner.scan(request.url)))
        
        if 'ports' in request.scan_types:
            tasks.append(("ports", port_scanner.scan(request.url)))
            
        if 'headers' in request.scan_types:
            tasks.append(("headers", headers_scanner.scan(request.url)))
            
        if 'cms' in request.scan_types:
            tasks.append(("cms", cms_scanner.scan(request.url)))
            
        if 'ddos' in request.scan_types:
            tasks.append(("ddos", ddos_scanner.scan(request.url)))
        
        # Асинхронное выполнение всех сканирований
        for scan_type, task in tasks:
            try:
                result = await task
                scan_results[scan_type] = result
            except Exception as e:
                scan_results[scan_type] = {"error": str(e)}
        
        # Расчет общего балла безопасности
        total_score = scorer.calculate_total_score(scan_results)
        
        # Генерация рекомендаций
        translations = get_translations(request.language)
        recommendations = scorer.generate_recommendations(scan_results, translations)
        
        # Сохранение результатов в базу данных
        from datetime import datetime
        import uuid
        
        scan_id = str(uuid.uuid4())
        scan_result = ScanResult(
            id=scan_id,
            url=request.url,
            score=total_score,
            results=scan_results,
            recommendations=recommendations,
            created_at=datetime.utcnow()
        )
        
        # TODO: Сохранить в базу данных
        
        return ScanResponse(
            scan_id=scan_id,
            url=request.url,
            score=total_score,
            status="completed",
            results=scan_results,
            recommendations=recommendations,
            created_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при сканировании: {str(e)}")

@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Получение результата сканирования по ID"""
    # TODO: Получить из базы данных
    return {"message": "Not implemented yet"}

@app.get("/api/certificate/{scan_id}")
async def download_certificate(scan_id: str):
    """Скачивание сертификата безопасности (PDF)"""
    try:
        # TODO: Получить результат сканирования из БД
        # Для демо создаем фиктивные данные
        sample_data = {
            "url": "example.com",
            "score": 85,
            "scan_date": "25.09.2025",
            "results": {
                "ssl": {"score": 85, "status": "good"},
                "ports": {"score": 70, "status": "warning"},
                "headers": {"score": 90, "status": "good"}
            }
        }
        
        pdf_content = await pdf_generator.generate_certificate(sample_data)
        
        from fastapi.responses import Response
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=certificate_{scan_id}.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при генерации сертификата: {str(e)}")

@app.get("/api/report/{scan_id}")
async def download_report(scan_id: str):
    """Скачивание отчета с рекомендациями (PDF)"""
    try:
        # TODO: Получить результат сканирования из БД
        sample_data = {
            "url": "example.com",
            "score": 67,
            "scan_date": "25.09.2025",
            "results": {
                "ssl": {"score": 85, "status": "good", "issues": []},
                "ports": {"score": 45, "status": "critical", "issues": ["Открыт порт 23 (Telnet)", "Открыт порт 21 (FTP)"]},
                "headers": {"score": 70, "status": "warning", "issues": ["Отсутствует X-Frame-Options"]}
            },
            "recommendations": [
                "Закройте неиспользуемые порты (21, 23)",
                "Добавьте заголовок X-Frame-Options",
                "Настройте Content Security Policy"
            ]
        }
        
        pdf_content = await pdf_generator.generate_report(sample_data)
        
        from fastapi.responses import Response
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при генерации отчета: {str(e)}")

@app.get("/api/stats")
async def get_stats():
    """Статистика платформы"""
    # TODO: Получить реальную статистику из БД
    return {
        "total_scans": 1247,
        "successful_scans": 1089,
        "certificates_issued": 892,
        "active_users": 156,
        "score_distribution": {
            "high": 71,  # 80-100 баллов
            "medium": 21,  # 60-79 баллов
            "low": 8  # 0-59 баллов
        },
        "system_status": {
            "api_server": "online",
            "database": "online", 
            "scanners": "active",
            "queue": "3 in queue"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
