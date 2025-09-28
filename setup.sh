#!/bin/bash

# CyberAudit Setup Script
echo "🛡️ Setting up CyberAudit Security Scanner Platform..."

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Please don't run this script as root"
    exit 1
fi

print_step "1. Installing system dependencies..."

# Update package lists
sudo apt-get update

# Install required system packages
sudo apt-get install -y \
    nmap \
    postgresql \
    postgresql-contrib \
    python3-dev \
    libpq-dev \
    pkg-config

print_status "System dependencies installed successfully"

print_step "2. Setting up PostgreSQL database..."

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE cyberaudit;
CREATE USER cyberaudit_user WITH ENCRYPTED PASSWORD 'cyberaudit_secure_password_2024';
GRANT ALL PRIVILEGES ON DATABASE cyberaudit TO cyberaudit_user;
\q
EOF

print_status "PostgreSQL database configured successfully"

print_step "3. Setting up Python environment..."

# Install Python dependencies
pip install -r requirements.txt

print_status "Python dependencies installed successfully"

print_step "4. Setting up environment variables..."

# Create .env file from example
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a random secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    sed -i "s/your-secret-key-here-generate-a-strong-one/$SECRET_KEY/" .env
    sed -i "s/your_password_here/cyberaudit_secure_password_2024/" .env
    print_status "Environment file created: .env"
else
    print_warning ".env file already exists, skipping creation"
fi

print_step "5. Creating required directories..."

# Create directories for logs and certificates
sudo mkdir -p /var/log/cyberaudit
sudo mkdir -p /var/cyberaudit/certificates
sudo mkdir -p /tmp/cyberaudit

# Set permissions
sudo chown $USER:$USER /var/log/cyberaudit
sudo chown $USER:$USER /var/cyberaudit/certificates
sudo chown $USER:$USER /tmp/cyberaudit

print_status "Directories created successfully"

print_step "6. Running database migrations..."

# Initialize database tables
python3 -c "
import asyncio
import sys
sys.path.append('.')
from cyberaudit.database.models import init_db

asyncio.run(init_db())
print('Database initialized successfully')
"

print_status "Database tables created successfully"

print_step "7. Running basic tests..."

# Run basic tests to verify installation
python3 test_basic.py

print_status "Basic tests completed successfully"

echo ""
print_status "✅ CyberAudit setup completed successfully!"
echo ""
print_step "To start the application:"
echo "  uvicorn cyberaudit.main:app --host 0.0.0.0 --port 8000"
echo ""
print_step "For production deployment:"
echo "  uvicorn cyberaudit.main:app --host 0.0.0.0 --port 8000 --workers 4"
echo ""
print_step "Access the application:"
echo "  http://localhost:8000"
echo ""
print_status "🛡️ CyberAudit is ready to scan for security vulnerabilities!"
