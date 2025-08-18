#!/bin/bash

# Professional Phone Intelligence Web Application Deployment Script
# Version: 1.0.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="phone-intelligence-web"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="venv"
LOG_DIR="logs"
BACKUP_DIR="backups"
PORT=${PORT:-5000}
HOST=${HOST:-"0.0.0.0"}
WORKERS=${WORKERS:-4}
ENVIRONMENT=${ENVIRONMENT:-"development"}

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "Professional Phone Intelligence Web Application"
    echo "Deployment Script v1.0.0"
    echo "============================================================"
    echo -e "${NC}"
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed"
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log "Python version: $python_version"
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        error "pip3 is not installed"
    fi
    
    # Check if we're in the right directory
    if [[ ! -f "web_app.py" ]]; then
        error "web_app.py not found. Make sure you're in the correct directory."
    fi
    
    success "System requirements check passed"
}

# Setup virtual environment
setup_venv() {
    log "Setting up virtual environment..."
    
    if [[ -d "$VENV_DIR" ]]; then
        log "Virtual environment already exists"
    else
        python3 -m venv "$VENV_DIR"
        success "Virtual environment created"
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    success "Virtual environment setup complete"
}

# Install dependencies
install_dependencies() {
    log "Installing Python dependencies..."
    
    # Install web application requirements
    if [[ -f "web_requirements.txt" ]]; then
        pip install -r web_requirements.txt
    else
        warn "web_requirements.txt not found, installing minimal requirements"
        pip install flask flask-socketio flask-cors gunicorn eventlet
    fi
    
    # Install base phone intelligence requirements
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
    fi
    
    success "Dependencies installed successfully"
}

# Initialize database
init_database() {
    log "Initializing database..."
    
    python3 init_database.py --create-test-data
    
    if [[ $? -eq 0 ]]; then
        success "Database initialized successfully"
    else
        error "Failed to initialize database"
    fi
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    
    directories=("$LOG_DIR" "$BACKUP_DIR" "uploads" "reports" "web_static/uploads")
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log "Created directory: $dir"
    done
    
    success "Directories created successfully"
}

# Set file permissions
set_permissions() {
    log "Setting file permissions..."
    
    # Make scripts executable
    chmod +x deploy_web_app.sh
    chmod +x init_database.py
    
    # Set permissions for data directories
    chmod 755 uploads reports logs backups
    
    success "Permissions set successfully"
}

# Generate configuration files
generate_config() {
    log "Generating configuration files..."
    
    # Create .env file if it doesn't exist
    if [[ ! -f ".env" ]]; then
        cat > .env << EOF
# Professional Phone Intelligence Web Application Configuration
FLASK_ENV=${ENVIRONMENT}
FLASK_DEBUG=$([[ "$ENVIRONMENT" == "development" ]] && echo "True" || echo "False")
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
MAX_CONTENT_LENGTH=16777216
UPLOAD_FOLDER=uploads
REPORT_FOLDER=reports

# Database Configuration
DATABASE_URL=sqlite:///phone_evidence.db

# External API Keys (Optional)
NUMVERIFY_API_KEY=
TRUECALLER_API_KEY=
GOOGLE_API_KEY=
BING_API_KEY=

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/web_app.log

# Server Configuration
HOST=${HOST}
PORT=${PORT}
WORKERS=${WORKERS}
EOF
        success "Configuration file created: .env"
    else
        log "Configuration file already exists: .env"
    fi
    
    # Create gunicorn configuration
    cat > gunicorn.conf.py << EOF
# Gunicorn configuration for Professional Phone Intelligence Web App

bind = "${HOST}:${PORT}"
workers = ${WORKERS}
worker_class = "eventlet"
worker_connections = 1000
timeout = 60
keepalive = 2
max_requests = 1000
max_requests_jitter = 100

# Process naming
proc_name = "${APP_NAME}"

# Logging
accesslog = "logs/gunicorn_access.log"
errorlog = "logs/gunicorn_error.log"
loglevel = "info"
access_log_format = '%%(h)s %%(l)s %%(u)s %%(t)s "%%(r)s" %%(s)s %%(b)s "%%(f)s" "%%(a)s" %%(D)s'

# Process management
pidfile = "logs/gunicorn.pid"
daemon = False

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Performance
preload_app = True
EOF
    success "Gunicorn configuration created"
    
    # Create systemd service file (for production deployment)
    if [[ "$ENVIRONMENT" == "production" ]]; then
        cat > "${APP_NAME}.service" << EOF
[Unit]
Description=Professional Phone Intelligence Web Application
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=${APP_DIR}
Environment=PATH=${APP_DIR}/${VENV_DIR}/bin
ExecStart=${APP_DIR}/${VENV_DIR}/bin/gunicorn --config gunicorn.conf.py web_app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        log "Systemd service file created: ${APP_NAME}.service"
        log "To install: sudo cp ${APP_NAME}.service /etc/systemd/system/"
        log "To enable: sudo systemctl enable ${APP_NAME}"
        log "To start: sudo systemctl start ${APP_NAME}"
    fi
}

# Test the application
test_application() {
    log "Testing application startup..."
    
    # Test database connection
    python3 -c "
import sqlite3
conn = sqlite3.connect('phone_evidence.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM system_status')
count = cursor.fetchone()[0]
conn.close()
print(f'Database test passed: {count} status entries')
"
    
    # Test Flask app import
    python3 -c "
from web_app import create_app
app = create_app()
if app:
    print('Flask app import test passed')
else:
    raise Exception('Failed to create Flask app')
"
    
    success "Application tests passed"
}

# Start the application
start_application() {
    log "Starting the application..."
    
    if [[ "$ENVIRONMENT" == "development" ]]; then
        log "Starting in development mode..."
        echo -e "${GREEN}"
        echo "============================================================"
        echo "🚀 Professional Phone Intelligence Web Application"
        echo "============================================================"
        echo "📱 Advanced phone number investigation platform"
        echo "🌐 Web-based interface for professional investigators"
        echo "🔒 Secure evidence management and reporting"
        echo "============================================================"
        echo "🌍 Server starting on http://${HOST}:${PORT}"
        echo "📊 Dashboard: http://${HOST}:${PORT}"
        echo "🔍 Investigate: http://${HOST}:${PORT}/investigate"
        echo "============================================================"
        echo -e "${NC}"
        
        # Start with Flask development server
        export FLASK_APP=web_app.py
        export FLASK_ENV=development
        python3 web_app.py
    else
        log "Starting in production mode with Gunicorn..."
        gunicorn --config gunicorn.conf.py web_app:app
    fi
}

# Stop the application
stop_application() {
    log "Stopping the application..."
    
    # Kill gunicorn processes
    if [[ -f "logs/gunicorn.pid" ]]; then
        pid=$(cat logs/gunicorn.pid)
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log "Stopped Gunicorn process (PID: $pid)"
        fi
    fi
    
    # Kill any remaining Flask processes
    pkill -f "web_app.py" || true
    pkill -f "gunicorn.*web_app" || true
    
    success "Application stopped"
}

# Show status
show_status() {
    log "Application status:"
    
    # Check if gunicorn is running
    if pgrep -f "gunicorn.*web_app" > /dev/null; then
        success "Gunicorn is running"
        pgrep -f "gunicorn.*web_app" | while read pid; do
            log "  PID: $pid"
        done
    else
        warn "Gunicorn is not running"
    fi
    
    # Check if Flask dev server is running
    if pgrep -f "web_app.py" > /dev/null; then
        success "Flask development server is running"
    else
        log "Flask development server is not running"
    fi
    
    # Check database
    if [[ -f "phone_evidence.db" ]]; then
        db_size=$(du -h phone_evidence.db | cut -f1)
        success "Database exists (size: $db_size)"
    else
        warn "Database not found"
    fi
    
    # Check log files
    if [[ -d "$LOG_DIR" ]]; then
        log_count=$(find "$LOG_DIR" -name "*.log" | wc -l)
        log "Log files: $log_count"
    fi
}

# Create backup
create_backup() {
    log "Creating backup..."
    
    timestamp=$(date +%Y%m%d_%H%M%S)
    backup_file="$BACKUP_DIR/phone_intelligence_backup_$timestamp.tar.gz"
    
    tar -czf "$backup_file" \
        --exclude="$VENV_DIR" \
        --exclude="__pycache__" \
        --exclude="*.pyc" \
        --exclude="logs/*.log" \
        .
    
    success "Backup created: $backup_file"
}

# Cleanup function
cleanup() {
    log "Performing cleanup..."
    
    # Remove Python cache
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true
    
    # Rotate logs
    if [[ -d "$LOG_DIR" ]]; then
        find "$LOG_DIR" -name "*.log" -size +10M -exec mv {} {}.old \; 2>/dev/null || true
    fi
    
    success "Cleanup completed"
}

# Display help
show_help() {
    echo "Professional Phone Intelligence Web Application Deployment Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  install     - Full installation (setup venv, install deps, init db)"
    echo "  start       - Start the application"
    echo "  stop        - Stop the application"
    echo "  restart     - Restart the application"
    echo "  status      - Show application status"
    echo "  test        - Run application tests"
    echo "  backup      - Create backup"
    echo "  cleanup     - Cleanup cache and logs"
    echo "  help        - Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  ENVIRONMENT - deployment environment (development/production)"
    echo "  HOST        - bind host (default: 0.0.0.0)"
    echo "  PORT        - bind port (default: 5000)"
    echo "  WORKERS     - number of workers (default: 4)"
}

# Main script logic
main() {
    print_banner
    
    case "${1:-install}" in
        "install")
            check_requirements
            create_directories
            setup_venv
            install_dependencies
            init_database
            set_permissions
            generate_config
            test_application
            success "Installation completed successfully!"
            log "Run '$0 start' to start the application"
            ;;
        "start")
            start_application
            ;;
        "stop")
            stop_application
            ;;
        "restart")
            stop_application
            sleep 2
            start_application
            ;;
        "status")
            show_status
            ;;
        "test")
            test_application
            ;;
        "backup")
            create_backup
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            echo "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Handle script interruption
trap 'echo -e "\n${RED}Script interrupted${NC}"; exit 130' INT

# Run main function
main "$@"