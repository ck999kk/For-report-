#!/bin/bash

# Professional Phone Intelligence System Deployment Script
# Comprehensive deployment and setup automation

echo "🔍 PROFESSIONAL PHONE INTELLIGENCE SYSTEM DEPLOYMENT"
echo "======================================================"
echo "Advanced phone number investigation and OSINT collection"
echo "Designed for professional investigators and cybertrace operations"
echo "======================================================"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root for security reasons"
   exit 1
fi

# Detect operating system
OS="Unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    OS="Windows"
fi

log "Detected operating system: $OS"

# Set installation directory
INSTALL_DIR="$HOME/phone_intelligence_system"
BACKUP_DIR="$HOME/phone_intelligence_backup_$(date +%Y%m%d_%H%M%S)"

# Create directories
log "Creating system directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/reports"
mkdir -p "$INSTALL_DIR/evidence"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$BACKUP_DIR"

# Function to install Python dependencies
install_python_deps() {
    log "Installing Python dependencies..."
    
    # Check if Python 3.8+ is available
    if ! command -v python3 &> /dev/null; then
        error "Python 3.8+ is required but not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log "Found Python version: $PYTHON_VERSION"
    
    # Create virtual environment
    if [ ! -d "$INSTALL_DIR/venv" ]; then
        log "Creating Python virtual environment..."
        python3 -m venv "$INSTALL_DIR/venv"
    fi
    
    # Activate virtual environment
    source "$INSTALL_DIR/venv/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "phone_requirements.txt" ]; then
        log "Installing from requirements file..."
        pip install -r phone_requirements.txt
    else
        log "Installing core dependencies manually..."
        pip install aiohttp requests phonenumbers python-whois dnspython
        pip install cryptography pandas numpy matplotlib networkx
        pip install geopy folium beautifulsoup4 PyYAML Jinja2
        pip install scikit-learn tensorflow torch transformers
        pip install nltk spacy Pillow PyPDF2 plotly seaborn
    fi
    
    log "Python dependencies installed successfully"
}

# Function to install system dependencies
install_system_deps() {
    log "Installing system dependencies..."
    
    if [[ "$OS" == "Linux" ]]; then
        if [[ "$DISTRO" == "Ubuntu" || "$DISTRO" == "Debian" ]]; then
            sudo apt-get update
            sudo apt-get install -y build-essential python3-dev python3-pip
            sudo apt-get install -y libssl-dev libffi-dev libxml2-dev libxslt1-dev
            sudo apt-get install -y nmap whois dnsutils curl wget
            sudo apt-get install -y sqlite3 redis-server
        elif [[ "$DISTRO" == "CentOS" || "$DISTRO" == "RHEL" ]]; then
            sudo yum update -y
            sudo yum install -y gcc python3-devel python3-pip
            sudo yum install -y openssl-devel libffi-devel libxml2-devel libxslt-devel
            sudo yum install -y nmap whois bind-utils curl wget
            sudo yum install -y sqlite redis
        fi
    elif [[ "$OS" == "macOS" ]]; then
        # Check if Homebrew is installed
        if ! command -v brew &> /dev/null; then
            log "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        brew update
        brew install python3 nmap whois sqlite redis
        brew install openssl libffi libxml2 libxslt
    fi
    
    log "System dependencies installed successfully"
}

# Function to setup configuration files
setup_config() {
    log "Setting up configuration files..."
    
    # Create main configuration file
    cat > "$INSTALL_DIR/config/phone_intelligence_config.yaml" << 'EOF'
system:
  name: "Professional Phone Intelligence System"
  version: "2.0.0"
  max_concurrent_investigations: 10
  debug_mode: false

apis:
  # Add your API keys here
  numverify_api_key: ""
  truecaller_api_key: ""
  google_api_key: ""
  bing_api_key: ""
  shodan_api_key: ""
  virustotal_api_key: ""
  haveibeenpwned_api_key: ""

investigation:
  default_timeout: 300
  max_osint_sources: 15
  evidence_retention_days: 365
  auto_backup: true
  encryption_enabled: true

reporting:
  default_format: "html"
  include_raw_data: false
  auto_generate_summary: true
  report_directory: "reports"

database:
  type: "sqlite"
  path: "data/phone_intelligence.db"
  backup_enabled: true
  backup_interval_hours: 24

logging:
  level: "INFO"
  file_path: "logs/phone_intelligence.log"
  max_file_size: "100MB"
  backup_count: 5

security:
  encryption_enabled: true
  require_authentication: true
  session_timeout: 3600
  audit_logging: true

osint_sources:
  enabled_sources:
    - "numverify"
    - "truecaller"
    - "reverse_lookup"
    - "social_media"
    - "breach_databases"
    - "search_engines"
  
  source_timeouts:
    default: 30
    search_engines: 60
    social_media: 45

network:
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  request_timeout: 30
  max_retries: 3
  rate_limit_delay: 1

notifications:
  email_enabled: false
  smtp_server: ""
  smtp_port: 587
  smtp_username: ""
  smtp_password: ""
  notification_recipients: []
EOF

    # Create logging configuration
    cat > "$INSTALL_DIR/config/logging.yaml" << 'EOF'
version: 1
formatters:
  default:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  detailed:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s'

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: default
    stream: ext://sys.stdout
  
  file:
    class: logging.handlers.RotatingFileHandler
    level: DEBUG
    formatter: detailed
    filename: logs/phone_intelligence.log
    maxBytes: 104857600  # 100MB
    backupCount: 5

  audit_file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: detailed
    filename: logs/audit.log
    maxBytes: 104857600
    backupCount: 10

loggers:
  PhoneIntelligenceSystem:
    level: INFO
    handlers: [console, file]
    propagate: no
  
  OSINTPhoneCollector:
    level: DEBUG
    handlers: [file, audit_file]
    propagate: no
  
  EvidenceManager:
    level: INFO
    handlers: [file, audit_file]
    propagate: no

root:
  level: INFO
  handlers: [console, file]
EOF

    # Create environment file
    cat > "$INSTALL_DIR/.env" << 'EOF'
# Environment variables for Phone Intelligence System
PHONE_INTEL_HOME="$INSTALL_DIR"
PHONE_INTEL_CONFIG="$INSTALL_DIR/config/phone_intelligence_config.yaml"
PHONE_INTEL_LOG_LEVEL="INFO"
PHONE_INTEL_DEBUG="false"

# Database settings
DATABASE_PATH="$INSTALL_DIR/data/phone_intelligence.db"
EVIDENCE_PATH="$INSTALL_DIR/evidence"
REPORTS_PATH="$INSTALL_DIR/reports"

# Security settings
ENCRYPTION_KEY_FILE="$INSTALL_DIR/config/.encryption_key"
SESSION_SECRET_FILE="$INSTALL_DIR/config/.session_secret"
EOF

    log "Configuration files created successfully"
}

# Function to setup database
setup_database() {
    log "Setting up database..."
    
    # Create database directory
    mkdir -p "$INSTALL_DIR/data"
    
    # Initialize SQLite database
    sqlite3 "$INSTALL_DIR/data/phone_intelligence.db" << 'EOF'
-- Phone Intelligence System Database Schema

-- Investigations table
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    phone_number TEXT NOT NULL,
    investigator TEXT NOT NULL,
    investigation_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    progress REAL DEFAULT 0.0,
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Evidence table
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    data TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    chain_of_custody TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    investigator TEXT NOT NULL,
    integrity_verified BOOLEAN DEFAULT TRUE,
    encryption_status TEXT DEFAULT 'encrypted',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations (id)
);

-- Chain of custody table
CREATE TABLE IF NOT EXISTS chain_of_custody (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    action TEXT NOT NULL,
    investigator TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (id)
);

-- OSINT sources results table
CREATE TABLE IF NOT EXISTS osint_results (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    query TEXT NOT NULL,
    result_data TEXT NOT NULL,
    confidence_score REAL DEFAULT 0.0,
    timestamp DATETIME NOT NULL,
    status TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (investigation_id) REFERENCES investigations (id)
);

-- System audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user_id TEXT,
    event_data TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- System configuration table
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default configuration values
INSERT OR REPLACE INTO system_config (key, value, description) VALUES
('system_version', '2.0.0', 'Current system version'),
('database_version', '1.0', 'Database schema version'),
('installation_date', datetime('now'), 'System installation date'),
('last_maintenance', datetime('now'), 'Last system maintenance date');

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_investigations_phone ON investigations(phone_number);
CREATE INDEX IF NOT EXISTS idx_investigations_investigator ON investigations(investigator);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_osint_investigation ON osint_results(investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

.quit
EOF

    log "Database initialized successfully"
}

# Function to create system scripts
create_scripts() {
    log "Creating system scripts..."
    
    # Create main launcher script
    cat > "$INSTALL_DIR/phone_intel" << 'EOF'
#!/bin/bash

# Phone Intelligence System Launcher
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment
if [ -f "$INSTALL_DIR/.env" ]; then
    source "$INSTALL_DIR/.env"
fi

# Activate virtual environment
source "$INSTALL_DIR/venv/bin/activate"

# Set PYTHONPATH
export PYTHONPATH="$INSTALL_DIR:$PYTHONPATH"

# Launch system
python3 "$INSTALL_DIR/phone_intelligence_system.py" "$@"
EOF

    # Make launcher executable
    chmod +x "$INSTALL_DIR/phone_intel"
    
    # Create system service script
    cat > "$INSTALL_DIR/start_service.sh" << 'EOF'
#!/bin/bash

# Phone Intelligence System Service Starter
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔍 Starting Phone Intelligence System Service..."

# Load environment
source "$INSTALL_DIR/.env"
source "$INSTALL_DIR/venv/bin/activate"

# Start the service
cd "$INSTALL_DIR"
python3 -m phone_intelligence_system --daemon --config "$INSTALL_DIR/config/phone_intelligence_config.yaml"
EOF

    chmod +x "$INSTALL_DIR/start_service.sh"
    
    # Create backup script
    cat > "$INSTALL_DIR/backup_system.sh" << 'EOF'
#!/bin/bash

# Phone Intelligence System Backup Script
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$HOME/phone_intel_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "📦 Creating system backup..."

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup archive
tar -czf "$BACKUP_DIR/phone_intel_backup_$TIMESTAMP.tar.gz" \
    -C "$INSTALL_DIR" \
    --exclude="venv" \
    --exclude="*.pyc" \
    --exclude="__pycache__" \
    .

echo "✅ Backup created: $BACKUP_DIR/phone_intel_backup_$TIMESTAMP.tar.gz"

# Clean old backups (keep last 10)
cd "$BACKUP_DIR"
ls -t phone_intel_backup_*.tar.gz | tail -n +11 | xargs -r rm

echo "🧹 Old backups cleaned"
EOF

    chmod +x "$INSTALL_DIR/backup_system.sh"
    
    # Create update script
    cat > "$INSTALL_DIR/update_system.sh" << 'EOF'
#!/bin/bash

# Phone Intelligence System Update Script
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔄 Updating Phone Intelligence System..."

# Backup current system
"$INSTALL_DIR/backup_system.sh"

# Activate virtual environment
source "$INSTALL_DIR/venv/bin/activate"

# Update Python packages
pip install --upgrade pip
pip install --upgrade -r "$INSTALL_DIR/phone_requirements.txt"

# Update system files (if available)
# This would typically pull from a git repository
# git pull origin main

echo "✅ System updated successfully"
EOF

    chmod +x "$INSTALL_DIR/update_system.sh"
    
    log "System scripts created successfully"
}

# Function to run system tests
run_tests() {
    log "Running system tests..."
    
    # Activate virtual environment
    source "$INSTALL_DIR/venv/bin/activate"
    
    # Copy main system file
    cp phone_intelligence_system.py "$INSTALL_DIR/"
    
    # Test Python import
    cd "$INSTALL_DIR"
    python3 -c "
import sys
sys.path.insert(0, '.')

try:
    from phone_intelligence_system import PhoneIntelligenceSystem, PhoneNumberValidator
    print('✅ Core modules imported successfully')
    
    # Test basic functionality
    validator = PhoneNumberValidator()
    result = validator.validate_and_format('+1234567890')
    print('✅ Phone validation working')
    
    system = PhoneIntelligenceSystem()
    print('✅ Main system initialized')
    
    print('✅ All tests passed')
    
except Exception as e:
    print(f'❌ Test failed: {e}')
    sys.exit(1)
"
    
    if [ $? -eq 0 ]; then
        log "System tests completed successfully"
    else
        error "System tests failed"
        exit 1
    fi
}

# Function to setup systemd service (Linux only)
setup_systemd_service() {
    if [[ "$OS" != "Linux" ]]; then
        return
    fi
    
    log "Setting up systemd service..."
    
    # Create systemd service file
    sudo tee /etc/systemd/system/phone-intelligence.service > /dev/null << EOF
[Unit]
Description=Professional Phone Intelligence System
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/phone_intelligence_system.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable phone-intelligence.service
    
    log "Systemd service configured (use 'sudo systemctl start phone-intelligence' to start)"
}

# Function to create desktop shortcut (Linux/macOS)
create_desktop_shortcut() {
    log "Creating desktop shortcuts..."
    
    if [[ "$OS" == "Linux" ]]; then
        # Create .desktop file
        cat > "$HOME/Desktop/Phone Intelligence System.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Phone Intelligence System
Comment=Professional phone number investigation tool
Exec=gnome-terminal -- $INSTALL_DIR/phone_intel --interactive
Icon=$INSTALL_DIR/assets/icon.png
Terminal=true
Categories=Utility;Security;
EOF
        
        chmod +x "$HOME/Desktop/Phone Intelligence System.desktop"
        
    elif [[ "$OS" == "macOS" ]]; then
        # Create macOS app bundle
        mkdir -p "$HOME/Applications/Phone Intelligence System.app/Contents/MacOS"
        
        cat > "$HOME/Applications/Phone Intelligence System.app/Contents/MacOS/phone_intel" << EOF
#!/bin/bash
exec $INSTALL_DIR/phone_intel --interactive
EOF
        
        chmod +x "$HOME/Applications/Phone Intelligence System.app/Contents/MacOS/phone_intel"
    fi
    
    log "Desktop shortcuts created"
}

# Function to display final instructions
show_final_instructions() {
    echo ""
    echo "🎉 INSTALLATION COMPLETED SUCCESSFULLY!"
    echo "======================================"
    echo ""
    info "📁 Installation Directory: $INSTALL_DIR"
    info "📊 Configuration: $INSTALL_DIR/config/phone_intelligence_config.yaml"
    info "📝 Logs Directory: $INSTALL_DIR/logs"
    info "📄 Reports Directory: $INSTALL_DIR/reports"
    echo ""
    echo "🚀 GETTING STARTED:"
    echo "==================="
    echo ""
    echo "1. Interactive Mode:"
    echo "   $INSTALL_DIR/phone_intel --interactive"
    echo ""
    echo "2. Single Investigation:"
    echo "   $INSTALL_DIR/phone_intel --phone '+1234567890' --investigator 'Detective Smith'"
    echo ""
    echo "3. Check Investigation Status:"
    echo "   $INSTALL_DIR/phone_intel --status <investigation-id>"
    echo ""
    echo "4. List All Investigations:"
    echo "   $INSTALL_DIR/phone_intel --list"
    echo ""
    echo "🔧 SYSTEM MANAGEMENT:"
    echo "====================="
    echo ""
    echo "• Backup System: $INSTALL_DIR/backup_system.sh"
    echo "• Update System: $INSTALL_DIR/update_system.sh"
    echo "• Start Service: $INSTALL_DIR/start_service.sh"
    echo ""
    if [[ "$OS" == "Linux" ]]; then
        echo "• Start as Service: sudo systemctl start phone-intelligence"
        echo "• Enable Auto-start: sudo systemctl enable phone-intelligence"
        echo ""
    fi
    echo "⚙️  CONFIGURATION:"
    echo "=================="
    echo ""
    echo "1. Edit configuration file: $INSTALL_DIR/config/phone_intelligence_config.yaml"
    echo "2. Add API keys for enhanced OSINT capabilities"
    echo "3. Configure notification settings"
    echo "4. Adjust logging and security settings"
    echo ""
    echo "📚 DOCUMENTATION:"
    echo "=================="
    echo ""
    echo "• System logs: $INSTALL_DIR/logs/phone_intelligence.log"
    echo "• Audit logs: $INSTALL_DIR/logs/audit.log"
    echo "• Configuration guide: $INSTALL_DIR/README.md"
    echo ""
    echo "🔒 SECURITY NOTES:"
    echo "=================="
    echo ""
    echo "• All evidence is encrypted and integrity-verified"
    echo "• Comprehensive audit logging is enabled"
    echo "• Regular backups are recommended"
    echo "• Keep API keys secure and regularly rotated"
    echo ""
    echo "⚠️  IMPORTANT:"
    echo "=============="
    echo ""
    echo "This system is designed for legitimate investigative purposes only."
    echo "Ensure compliance with all applicable laws and regulations."
    echo "Respect privacy rights and obtain proper authorization before investigations."
    echo ""
    echo "✅ System is ready for professional use!"
    echo "Happy investigating! 🔍"
    echo ""
}

# Main installation flow
main() {
    log "Starting deployment of Professional Phone Intelligence System..."
    
    # Check prerequisites
    info "Checking system prerequisites..."
    
    # Install system dependencies
    install_system_deps
    
    # Install Python dependencies
    install_python_deps
    
    # Setup configuration
    setup_config
    
    # Setup database
    setup_database
    
    # Create system scripts
    create_scripts
    
    # Run tests
    run_tests
    
    # Setup systemd service (Linux only)
    if [[ "$OS" == "Linux" ]]; then
        setup_systemd_service
    fi
    
    # Create desktop shortcuts
    create_desktop_shortcut
    
    # Final backup
    log "Creating initial system backup..."
    "$INSTALL_DIR/backup_system.sh"
    
    # Show final instructions
    show_final_instructions
}

# Error handling
set -e
trap 'error "Installation failed at line $LINENO"' ERR

# Run main installation
main "$@"

# Success exit
exit 0