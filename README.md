CyberAudit - Комплексный сканер безопасности веб-сайтов

Описание

CyberAudit - это профессиональная платформа для анализа кибербезопасности веб-сайтов. Система проводит комплексное сканирование и предоставляет детальные отчеты с рекомендациями по улучшению безопасности.

Возможности

🔒 Модули сканирования





SSL/HTTPS анализ - Проверка сертификатов, протоколов шифрования



Сканирование портов - Определение открытых портов и потенциальных уязвимостей



HTTP заголовки - Анализ заголовков безопасности (HSTS, CSP, X-Frame-Options)



CMS и уязвимости - Определение CMS и поиск известных уязвимостей CVE



DDoS защита - Проверка систем защиты от DDoS атак

📊 Система оценки и отчетность





Умная система подсчета баллов безопасности



Генерация PDF сертификатов с QR-кодами для верификации



Детальные отчеты с рекомендациями



Сводные отчеты по нескольким сканированиям

🌐 Многоязычность





Полная поддержка русского языка



Поддержка узбекского языка



Легкое добавление новых языков

🚀 Технологии





Backend: FastAPI + Python 3.10+



Database: PostgreSQL + SQLAlchemy



Frontend: HTML5 + CSS3 + Vanilla JavaScript



PDF Generation: WeasyPrint + QR codes



Security Libraries: cryptography, python-nmap, httpx

Установка и настройка

Системные требования

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install nmap postgresql postgresql-contrib

# CentOS/RHEL
sudo yum install nmap postgresql postgresql-server


Установка зависимостей Python

pip install -r requirements.txt


Настройка базы данных

# Создание базы данных PostgreSQL
sudo -u postgres createdb cyberaudit
sudo -u postgres createuser cyberaudit_user --pwprompt

# Настройка переменных окружения
export DATABASE_URL="postgresql://cyberaudit_user:YOUR_PASSWORD@localhost/cyberaudit"


Запуск приложения

# Режим разработки
uvicorn cyberaudit.main:app --reload --host 0.0.0.0 --port 8000

# Режим продакшена
uvicorn cyberaudit.main:app --host 0.0.0.0 --port 8000 --workers 4


Структура проекта

cyberaudit/
├── main.py              # Основное FastAPI приложение
├── database/
│   └── models.py        # Модели базы данных
├── scanners/
│   ├── ssl_scanner.py   # SSL/HTTPS сканер
│   ├── port_scanner.py  # Сканер портов
│   ├── headers_scanner.py # HTTP заголовки
│   ├── cms_scanner.py   # CMS и уязвимости
│   └── ddos_scanner.py  # DDoS защита
├── utils/
│   ├── scoring.py       # Система оценки
│   └── i18n.py         # Интернационализация
└── reports/
    └── pdf_generator.py # Генерация PDF отчетов

templates/
└── index.html          # Frontend интерфейс

static/
├── css/
│   └── style.css       # Стили
└── js/
    └── app.js         # JavaScript логика


API Endpoints

Основные endpoint'ы





GET / - Главная страница



POST /api/scan - Запуск сканирования



GET /api/scan/{scan_id} - Получение результатов



GET /api/certificate/{scan_id} - Скачивание сертификата (PDF)



GET /api/report/{scan_id} - Скачивание отчета (PDF)



GET /api/stats - Статистика платформы

Пример запроса

{
  "url": "https://example.com",
  "scan_types": ["ssl", "ports", "headers"],
  "language": "ru"
}


Использование





Откройте браузер и перейдите к http://localhost:8000



Введите URL сайта для сканирования



Выберите типы сканирования



Нажмите "Сканировать"



Получите результаты и скачайте PDF отчеты

Безопасность





Все сканирования проводятся в изолированной среде



Поддержка HTTPS и безопасных соединений



Логирование всех операций



Проверка входных данных

Разработка

Установка для разработки

# Клонирование репозитория
git clone <repository-url>
cd cyberaudit

# Создание виртуального окружения
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Установка зависимостей
pip install -r requirements.txt


Тестирование

# Запуск тестов
pytest test_basic.py

# Проверка стиля кода
flake8 cyberaudit/
black cyberaudit/


Roadmap





Интеграция с Shodan API



Поддержка сканирования мобильных приложений



REST API для интеграций



Дашборд администратора



Webhook уведомления



Планировщик сканирований

Лицензия

MIT License

Поддержка

Для получения поддержки:





Создайте issue в GitHub



Напишите на support@cyberaudit.com



Посетите документацию: /docs

Участие в разработке





Fork репозитория



Создайте feature branch



Внесите изменения



Добавьте тесты



Отправьте Pull Request



CyberAudit - Ваш надежный партнер в области кибербезопасности 🛡️
