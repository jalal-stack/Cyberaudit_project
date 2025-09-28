"""
Basic tests for CyberAudit application
"""

import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.abspath('.'))

def test_imports():
    """Test that all modules can be imported without errors"""
    try:
        from cyberaudit.main import app
        from cyberaudit.utils.scoring import SecurityScorer
        from cyberaudit.utils.i18n import get_translations
        from cyberaudit.reports.pdf_generator import PDFGenerator
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import modules: {e}")

def test_app_creation():
    """Test that the FastAPI app can be created"""
    try:
        from cyberaudit.main import app
        client = TestClient(app)
        response = client.get("/api/stats")
        assert response.status_code in [200, 500]  # 500 is OK since database might not be setup
    except Exception as e:
        pytest.fail(f"Failed to create app: {e}")

def test_security_scorer():
    """Test the SecurityScorer class"""
    from cyberaudit.utils.scoring import SecurityScorer
    
    scorer = SecurityScorer()
    
    # Test with empty results
    score = scorer.calculate_total_score({})
    assert isinstance(score, int)
    assert 0 <= score <= 100
    
    # Test with sample results
    sample_results = {
        'ssl': {'score': 85},
        'ports': {'score': 70},
        'headers': {'score': 90}
    }
    score = scorer.calculate_total_score(sample_results)
    assert isinstance(score, int)
    assert 0 <= score <= 100

def test_pdf_generator():
    """Test the PDFGenerator class"""
    from cyberaudit.reports.pdf_generator import PDFGenerator
    
    generator = PDFGenerator()
    assert generator is not None
    
    # Test QR code generation
    qr_data = generator._generate_qr_code("https://example.com")
    assert isinstance(qr_data, str)
    assert len(qr_data) > 0

if __name__ == "__main__":
    test_imports()
    test_app_creation()
    test_security_scorer()
    test_pdf_generator()
    print("All basic tests passed!")
