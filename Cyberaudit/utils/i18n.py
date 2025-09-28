"""
Система интернационализации для CyberAudit
Поддержка русского и узбекского языков
"""

from typing import Dict, Any, List

# Словари переводов
TRANSLATIONS = {
    "ru": {
        # Общие термины
        "security_scan": "Сканирование безопасности",
        "scan_results": "Результаты сканирования",
        "recommendations": "Рекомендации",
        "certificate": "Сертификат",
        "report": "Отчет",
        "score": "Оценка",
        "status": "Статус",
        "issues_found": "Найдено проблем",
        # Статусы безопасности
        "excellent": "Отлично",
        "good": "Хорошо",
        "warning": "Требует внимания",
        "critical": "Критично",
        "error": "Ошибка",
        # Типы сканирования
        "ssl_scan": "SSL/HTTPS анализ",
        "port_scan": "Сканирование портов",
        "headers_scan": "HTTP заголовки",
        "cms_scan": "CMS и уязвимости",
        "ddos_scan": "DDoS защита",
        # SSL/HTTPS
        "ssl_certificate": "SSL сертификат",
        "ssl_protocols": "SSL протоколы",
        "ssl_ciphers": "Шифрование",
        "ssl_expired": "Сертификат истек",
        "ssl_expires_soon": "Сертификат истекает скоро",
        "ssl_self_signed": "Самоподписанный сертификат",
        "ssl_weak_protocol": "Слабый протокол",
        "ssl_strong_encryption": "Сильное шифрование",
        # Порты
        "open_ports": "Открытые порты",
        "dangerous_ports": "Опасные порты",
        "secure_ports": "Безопасные порты",
        "port_closed": "Порт закрыт",
        "port_filtered": "Порт фильтруется",
        # HTTP заголовки
        "security_headers": "Заголовки безопасности",
        "missing_headers": "Отсутствующие заголовки",
        "dangerous_headers": "Опасные заголовки",
        "hsts_header": "HSTS (Strict-Transport-Security)",
        "csp_header": "CSP (Content-Security-Policy)",
        "frame_options": "X-Frame-Options",
        "content_type_options": "X-Content-Type-Options",
        # CMS
        "cms_detected": "CMS обнаружена",
        "cms_version": "Версия CMS",
        "vulnerabilities": "Уязвимости",
        "plugins": "Плагины",
        "exposed_files": "Открытые файлы",
        "security_updates": "Обновления безопасности",
        # DDoS защита
        "ddos_protection": "DDoS защита",
        "cdn_detected": "CDN обнаружена",
        "rate_limiting": "Ограничение скорости",
        "load_balancing": "Балансировка нагрузки",
        "geographic_distribution": "Географическое распределение",
        # Рекомендации
        "install_ssl": "Установите SSL сертификат",
        "update_software": "Обновите программное обеспечение",
        "close_ports": "Закройте неиспользуемые порты",
        "add_security_headers": "Добавьте заголовки безопасности",
        "setup_cdn": "Настройте CDN защиту",
        "enable_rate_limiting": "Включите ограничение скорости запросов",
        "use_strong_passwords": "Используйте сильные пароли",
        "enable_2fa": "Включите двухфакторную аутентификацию",
        "regular_backups": "Делайте регулярные резервные копии",
        "monitor_security": "Настройте мониторинг безопасности",
        # Сообщения об ошибках
        "scan_error": "Ошибка при сканировании",
        "connection_error": "Ошибка подключения",
        "timeout_error": "Превышено время ожидания",
        "invalid_url": "Некорректный URL",
        "default_recommendation": "Обратитесь к специалисту по информационной безопасности",
        # Сертификат
        "certificate_title": "Сертификат безопасности",
        "certificate_subtitle": "Подтверждает соответствие стандартам кибербезопасности",
        "issued_to": "Выдан для",
        "scan_date": "Дата сканирования",
        "security_score": "Оценка безопасности",
        "valid_until": "Действителен до",
        "qr_verification": "QR-код для верификации",
        # Отчет
        "security_report": "Отчет по безопасности",
        "executive_summary": "Краткая сводка",
        "detailed_findings": "Детальные результаты",
        "risk_assessment": "Оценка рисков",
        "action_plan": "План действий",
        "next_scan": "Следующее сканирование",
    },
    "uz": {
        # Общие термины
        "security_scan": "Xavfsizlik skanerlashi",
        "scan_results": "Skanerlash natijalari",
        "recommendations": "Tavsiyalar",
        "certificate": "Sertifikat",
        "report": "Hisobot",
        "score": "Bahosi",
        "status": "Holati",
        "issues_found": "Topilgan muammolar",
        # Статусы безопасности
        "excellent": "Ajoyib",
        "good": "Yaxshi",
        "warning": "Ehtiyot",
        "critical": "Kritik",
        "error": "Xato",
        # Типы сканирования
        "ssl_scan": "SSL/HTTPS tahlili",
        "port_scan": "Portlarni skanerlash",
        "headers_scan": "HTTP sarlavhalar",
        "cms_scan": "CMS va zaifliklar",
        "ddos_scan": "DDoS himoyasi",
        # SSL/HTTPS
        "ssl_certificate": "SSL sertifikat",
        "ssl_protocols": "SSL protokollari",
        "ssl_ciphers": "Shifrlash",
        "ssl_expired": "Sertifikat muddati tugagan",
        "ssl_expires_soon": "Sertifikat muddati tez tugaydi",
        "ssl_self_signed": "O'z-o'zidan imzolangan sertifikat",
        "ssl_weak_protocol": "Zaif protokol",
        "ssl_strong_encryption": "Kuchli shifrlash",
        # Порты
        "open_ports": "Ochiq portlar",
        "dangerous_ports": "Xavfli portlar",
        "secure_ports": "Xavfsiz portlar",
        "port_closed": "Port yopiq",
        "port_filtered": "Port filtrlangan",
        # HTTP заголовки
        "security_headers": "Xavfsizlik sarlavhalari",
        "missing_headers": "Yo'qolgan sarlavhalar",
        "dangerous_headers": "Xavfli sarlavhalar",
        "hsts_header": "HSTS (Strict-Transport-Security)",
        "csp_header": "CSP (Content-Security-Policy)",
        "frame_options": "X-Frame-Options",
        "content_type_options": "X-Content-Type-Options",
        # CMS
        "cms_detected": "CMS aniqlandi",
        "cms_version": "CMS versiyasi",
        "vulnerabilities": "Zaifliklar",
        "plugins": "Plaginlar",
        "exposed_files": "Ochiq fayllar",
        "security_updates": "Xavfsizlik yangilanishlari",
        # DDoS защита
        "ddos_protection": "DDoS himoyasi",
        "cdn_detected": "CDN aniqlandi",
        "rate_limiting": "Tezlikni cheklash",
        "load_balancing": "Yukning balansi",
        "geographic_distribution": "Geografik taqsimot",
        # Рекомендации
        "install_ssl": "SSL sertifikatini o'rnating",
        "update_software": "Dasturiy ta'minotni yangilang",
        "close_ports": "Foydalanilmayotgan portlarni yoping",
        "add_security_headers": "Xavfsizlik sarlavhalarini qo'shing",
        "setup_cdn": "CDN himoyasini sozlang",
        "enable_rate_limiting": "So'rovlar tezligini cheklashni yoqing",
        "use_strong_passwords": "Kuchli parollardan foydalaning",
        "enable_2fa": "Ikki faktorli autentifikatsiyani yoqing",
        "regular_backups": "Muntazam zaxira nusxalarini oling",
        "monitor_security": "Xavfsizlik monitoringini sozlang",
        # Сообщения об ошибках
        "scan_error": "Skanerlashda xato",
        "connection_error": "Ulanish xatosi",
        "timeout_error": "Kutish vaqti tugadi",
        "invalid_url": "Noto'g'ri URL",
        "default_recommendation": "Axborot xavfsizligi mutaxassisiga murojaat qiling",
        # Сертификат
        "certificate_title": "Xavfsizlik sertifikati",
        "certificate_subtitle": "Kiberbezlik standartlariga muvofiqligini tasdiqlaydi",
        "issued_to": "Kimga berilgan",
        "scan_date": "Skanerlash sanasi",
        "security_score": "Xavfsizlik bahosi",
        "valid_until": "Amal qilish muddati",
        "qr_verification": "Tekshirish uchun QR-kod",
        # Отчет
        "security_report": "Xavfsizlik hisoboti",
        "executive_summary": "Qisqacha xulosalar",
        "detailed_findings": "Batafsil natijalar",
        "risk_assessment": "Xavf baholash",
        "action_plan": "Harakat rejasi",
        "next_scan": "Keyingi skanerlash",
    },
}


def get_translations(language: str = "ru") -> Dict[str, str]:
    """
    Получение словаря переводов для указанного языка

    Args:
        language: Код языка ('ru' или 'uz')

    Returns:
        Словарь переводов
    """
    if language not in TRANSLATIONS:
        language = "ru"  # Русский по умолчанию

    return TRANSLATIONS[language]


def translate(key: str, language: str = "ru", default: str = None) -> str:
    """
    Перевод ключа на указанный язык

    Args:
        key: Ключ для перевода
        language: Код языка
        default: Значение по умолчанию, если перевод не найден

    Returns:
        Переведенная строка
    """
    translations = get_translations(language)
    return translations.get(key, default or key)


def translate_scan_results(scan_results: Dict[str, Any], language: str = "ru") -> Dict[str, Any]:
    """
    Перевод результатов сканирования

    Args:
        scan_results: Результаты сканирования
        language: Целевой язык

    Returns:
        Переведенные результаты
    """
    translations = get_translations(language)
    translated = {}

    for scan_type, result in scan_results.items():
        if isinstance(result, dict):
            translated[scan_type] = translate_scan_result(result, translations)
        else:
            translated[scan_type] = result

    return translated


def translate_scan_result(result: Dict[str, Any], translations: Dict[str, str]) -> Dict[str, Any]:
    """
    Перевод результата одного типа сканирования

    Args:
        result: Результат сканирования
        translations: Словарь переводов

    Returns:
        Переведенный результат
    """
    translated = result.copy()

    # Переводим статус
    if "status" in translated:
        status_key = translated["status"]
        translated["status_text"] = translations.get(status_key, status_key)

    # Переводим рекомендации
    if "recommendations" in translated:
        translated_recommendations = []
        for rec in translated["recommendations"]:
            # Пытаемся найти перевод для рекомендации
            translated_rec = translate_recommendation(rec, translations)
            translated_recommendations.append(translated_rec)
        translated["recommendations_translated"] = translated_recommendations

    return translated


def translate_recommendation(recommendation: str, translations: Dict[str, str]) -> str:
    """
    Перевод рекомендации

    Args:
        recommendation: Исходная рекомендация
        translations: Словарь переводов

    Returns:
        Переведенная рекомендация
    """
    # Простое сопоставление ключевых фраз
    recommendation_lower = recommendation.lower()

    if "ssl" in recommendation_lower and "сертификат" in recommendation_lower:
        return translations.get("install_ssl", recommendation)
    elif "обновите" in recommendation_lower:
        return translations.get("update_software", recommendation)
    elif "порт" in recommendation_lower and "закройте" in recommendation_lower:
        return translations.get("close_ports", recommendation)
    elif "заголовк" in recommendation_lower:
        return translations.get("add_security_headers", recommendation)
    elif "cdn" in recommendation_lower:
        return translations.get("setup_cdn", recommendation)
    elif "rate" in recommendation_lower or "скорост" in recommendation_lower:
        return translations.get("enable_rate_limiting", recommendation)
    else:
        return recommendation


def get_security_level_translation(level: str, language: str = "ru") -> str:
    """
    Получение перевода уровня безопасности

    Args:
        level: Уровень безопасности (excellent, good, warning, critical)
        language: Целевой язык

    Returns:
        Переведенный уровень
    """
    translations = get_translations(language)
    return translations.get(level, level)


def format_scan_summary(total_score: int, issues_count: int, language: str = "ru") -> str:
    """
    Форматирование краткой сводки сканирования

    Args:
        total_score: Общая оценка
        issues_count: Количество проблем
        language: Язык

    Returns:
        Отформатированная сводка
    """
    translations = get_translations(language)

    if language == "uz":
        summary = f"Xavfsizlik bahosi: {total_score}/100. "
        if issues_count > 0:
            summary += f"Topildi {issues_count} ta muammo."
        else:
            summary += "Hech qanday muammo topilmadi."
    else:  # ru
        summary = f"Оценка безопасности: {total_score}/100. "
        if issues_count > 0:
            summary += f"Найдено проблем: {issues_count}."
        else:
            summary += "Критических проблем не найдено."

    return summary


# Дополнительные утилиты для локализации
class LocalizationHelper:
    """Помощник для локализации интерфейса"""

    @staticmethod
    def get_month_names(language: str = "ru") -> List[str]:
        """Получение названий месяцев"""
        if language == "uz":
            return [
                "Yanvar",
                "Fevral",
                "Mart",
                "Aprel",
                "May",
                "Iyun",
                "Iyul",
                "Avgust",
                "Sentabr",
                "Oktabr",
                "Noyabr",
                "Dekabr",
            ]
        else:  # ru
            return [
                "Январь",
                "Февраль",
                "Март",
                "Апрель",
                "Май",
                "Июнь",
                "Июль",
                "Август",
                "Сентябрь",
                "Октябрь",
                "Ноябрь",
                "Декабрь",
            ]

    @staticmethod
    def format_date(date_obj, language: str = "ru") -> str:
        """Форматирование даты согласно локали"""
        month_names = LocalizationHelper.get_month_names(language)
        month_name = month_names[date_obj.month - 1]

        if language == "uz":
            return f"{date_obj.day} {month_name} {date_obj.year}"
        else:  # ru
            return f"{date_obj.day} {month_name} {date_obj.year}"

    @staticmethod
    def get_interface_texts(language: str = "ru") -> Dict[str, str]:
        """Получение текстов интерфейса"""
        return get_translations(language)
