#!/bin/bash

# Professional Investigation System - Installation Script
# Installs and configures the investigation system

set -e

echo "Professional Investigation System - Installation"
echo "==============================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "Warning: Running as root. Consider using a dedicated user for security."
fi

# Detect OS
OS="Unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    OS="Windows"
fi

echo "Detected OS: $OS"

# Set installation directory
INSTALL_DIR="${1:-/opt/professional-investigation-system}"
echo "Installation directory: $INSTALL_DIR"

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Copy system files
echo "Copying system files..."
cp -r . "$INSTALL_DIR/"

# Set up Python virtual environment
echo "Setting up Python virtual environment..."
cd "$INSTALL_DIR"

if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python not found. Please install Python 3.8 or higher."
    exit 1
fi

echo "Using Python: $PYTHON_CMD"

# Create virtual environment
$PYTHON_CMD -m venv venv

# Activate virtual environment
if [[ "$OS" == "Windows" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# Upgrade pip
pip install --upgrade pip

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Install optional system tools (if available)
echo "Checking for optional system tools..."

# Check for exiftool
if command -v exiftool &> /dev/null; then
    echo "✓ exiftool found"
else
    echo "○ exiftool not found - install for enhanced metadata extraction"
    if [[ "$OS" == "macOS" ]]; then
        echo "  Install with: brew install exiftool"
    elif [[ "$OS" == "Linux" ]]; then
        echo "  Install with: sudo apt-get install exiftool (Ubuntu/Debian)"
        echo "                sudo yum install perl-Image-ExifTool (CentOS/RHEL)"
    fi
fi

# Check for traceroute
if command -v traceroute &> /dev/null; then
    echo "✓ traceroute found"
else
    echo "○ traceroute not found - install for network tracing"
    if [[ "$OS" == "Linux" ]]; then
        echo "  Install with: sudo apt-get install traceroute (Ubuntu/Debian)"
    fi
fi

# Create directories
echo "Creating system directories..."
mkdir -p logs
mkdir -p evidence_storage
mkdir -p reports
mkdir -p config

# Set permissions
echo "Setting permissions..."
chmod 755 main.py
if [[ "$OS" != "Windows" ]]; then
    chmod 600 config/*.yaml
    chmod 700 evidence_storage
    chmod 755 logs
    chmod 755 reports
fi

# Create startup script
echo "Creating startup script..."
cat > start_investigation_system.sh << 'EOF'
#!/bin/bash
# Professional Investigation System Startup Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
source venv/bin/activate

# Start the investigation system
python main.py "$@"
EOF

chmod +x start_investigation_system.sh

# Create Windows batch file
cat > start_investigation_system.bat << 'EOF'
@echo off
REM Professional Investigation System Startup Script

cd /d "%~dp0"

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Start the investigation system
python main.py %*
EOF

# Test installation
echo "Testing installation..."
source venv/bin/activate
python -c "
import sys
sys.path.insert(0, 'src')
from src.core import InvestigatorCore
print('✓ Core modules imported successfully')
"

echo ""
echo "Installation completed successfully!"
echo ""
echo "Usage:"
echo "  ./start_investigation_system.sh init --investigator 'Your Name'"
echo "  ./start_investigation_system.sh status"
echo "  ./start_investigation_system.sh --help"
echo ""
echo "Or directly:"
echo "  cd $INSTALL_DIR"
echo "  source venv/bin/activate"
echo "  python main.py --help"
echo ""
echo "Configuration files are in: $INSTALL_DIR/config/"
echo "Logs will be written to: $INSTALL_DIR/logs/"
echo "Evidence will be stored in: $INSTALL_DIR/evidence_storage/"
echo "Reports will be generated in: $INSTALL_DIR/reports/"
echo ""

# Security reminder
echo "Security Recommendations:"
echo "- Review and customize configuration files"
echo "- Ensure proper file permissions are set"
echo "- Use dedicated user account for production"
echo "- Configure firewall rules if network access needed"
echo "- Regular backup of evidence and configuration"
echo ""

echo "Installation completed!"