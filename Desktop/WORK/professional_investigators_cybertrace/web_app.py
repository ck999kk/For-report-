#!/usr/bin/env python3
"""
PROFESSIONAL PHONE INTELLIGENCE WEB APPLICATION
==============================================
Complete web-based interface for phone intelligence system
No-code solution for professional investigators

Features:
- Modern responsive web interface
- Real-time investigation progress tracking
- RESTful API endpoints
- WebSocket real-time updates
- Drag-and-drop file uploads
- One-click report generation
- Visual investigation dashboard
- Professional grade security

Author: Professional Investigators Team
Version: 1.0.0 (Production Ready)
"""

import asyncio
import json
import logging
import os
import uuid
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading
from functools import wraps

# Flask and web dependencies
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Import existing phone intelligence system
import sys
sys.path.append(str(Path(__file__).parent))
from phone_intelligence_system import PhoneIntelligenceSystem, PhoneIntelligenceCLI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('web_app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, 
           template_folder='web_templates',
           static_folder='web_static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'phone-intel-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORT_FOLDER'] = 'reports'

# Enable CORS for API endpoints
CORS(app, origins=['http://localhost:5000', 'http://127.0.0.1:5000'])

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Create upload and report directories
Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)
Path(app.config['REPORT_FOLDER']).mkdir(exist_ok=True)

# Global system instance
phone_intel_system = None
active_sessions = {}
investigation_progress = {}

def init_phone_system():
    """Initialize the phone intelligence system"""
    global phone_intel_system
    try:
        phone_intel_system = PhoneIntelligenceSystem()
        logger.info("Phone Intelligence System initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize Phone Intelligence System: {e}")
        return False

def require_session(f):
    """Decorator to require active session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'session_id' not in session:
            return jsonify({'error': 'No active session', 'redirect': '/login'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_session_info():
    """Get current session information"""
    session_id = session.get('session_id')
    if session_id and session_id in active_sessions:
        return active_sessions[session_id]
    return None

def create_session(investigator_name: str) -> str:
    """Create new investigation session"""
    session_id = str(uuid.uuid4())
    session_data = {
        'session_id': session_id,
        'investigator': investigator_name,
        'created_at': datetime.now(),
        'last_activity': datetime.now(),
        'investigations': [],
        'is_active': True
    }
    
    active_sessions[session_id] = session_data
    session['session_id'] = session_id
    session['investigator'] = investigator_name
    
    logger.info(f"Created new session for investigator: {investigator_name}")
    return session_id

# Web Routes
@app.route('/')
def index():
    """Main dashboard page"""
    if 'session_id' not in session:
        return redirect(url_for('login'))
    
    session_info = get_session_info()
    if not session_info:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', session_info=session_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for investigators"""
    if request.method == 'POST':
        investigator_name = request.form.get('investigator_name', '').strip()
        
        if not investigator_name:
            flash('Investigator name is required', 'error')
            return render_template('login.html')
        
        # Create session
        session_id = create_session(investigator_name)
        flash(f'Welcome, {investigator_name}', 'success')
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session_id = session.get('session_id')
    if session_id and session_id in active_sessions:
        active_sessions[session_id]['is_active'] = False
        logger.info(f"Session {session_id} logged out")
    
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/investigate')
def investigate():
    """Phone investigation page"""
    if 'session_id' not in session:
        return redirect(url_for('login'))
    
    session_info = get_session_info()
    if not session_info:
        return redirect(url_for('login'))
    
    return render_template('investigate.html', session_info=session_info)

@app.route('/reports')
def reports():
    """Investigation reports page"""
    if 'session_id' not in session:
        return redirect(url_for('login'))
    
    session_info = get_session_info()
    if not session_info:
        return redirect(url_for('login'))
    
    return render_template('reports.html', session_info=session_info)

@app.route('/history')
def history():
    """Investigation history page"""
    if 'session_id' not in session:
        return redirect(url_for('login'))
    
    session_info = get_session_info()
    if not session_info:
        return redirect(url_for('login'))
    
    return render_template('history.html', session_info=session_info)

# API Endpoints
@app.route('/api/system/status')
def api_system_status():
    """Get system status"""
    try:
        if not phone_intel_system:
            return jsonify({
                'status': 'error',
                'message': 'Phone Intelligence System not initialized'
            }), 500
        
        status = {
            'status': 'operational',
            'active_sessions': len([s for s in active_sessions.values() if s['is_active']]),
            'active_investigations': len(investigation_progress),
            'system_uptime': time.time() - app.start_time if hasattr(app, 'start_time') else 0,
            'version': '1.0.0'
        }
        
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/validate_phone', methods=['POST'])
@require_session
def api_validate_phone():
    """Validate phone number format"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number', '').strip()
        
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400
        
        # Use the existing validator
        validator = phone_intel_system.validator
        validation_result = validator.validate_and_format(phone_number)
        
        return jsonify({
            'status': 'success',
            'validation': validation_result
        })
        
    except Exception as e:
        logger.error(f"Phone validation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start_investigation', methods=['POST'])
@require_session
def api_start_investigation():
    """Start new phone investigation"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number', '').strip()
        investigation_type = data.get('investigation_type', 'comprehensive')
        
        if not phone_number:
            return jsonify({'error': 'Phone number is required'}), 400
        
        session_info = get_session_info()
        if not session_info:
            return jsonify({'error': 'Invalid session'}), 401
        
        investigator = session_info['investigator']
        
        # Start investigation in background thread
        def run_investigation():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                investigation_id = loop.run_until_complete(
                    phone_intel_system.investigate_phone_number(
                        phone_number, investigator, investigation_type
                    )
                )
                
                # Update session with investigation
                session_info['investigations'].append(investigation_id)
                session_info['last_activity'] = datetime.now()
                
                # Notify completion via WebSocket
                socketio.emit('investigation_completed', {
                    'investigation_id': investigation_id,
                    'phone_number': phone_number,
                    'status': 'completed'
                }, room=session_info['session_id'])
                
            except Exception as e:
                logger.error(f"Investigation error: {e}")
                socketio.emit('investigation_error', {
                    'error': str(e),
                    'phone_number': phone_number
                }, room=session_info['session_id'])
            finally:
                loop.close()
        
        # Start investigation thread
        investigation_thread = threading.Thread(target=run_investigation)
        investigation_thread.daemon = True
        investigation_thread.start()
        
        return jsonify({
            'status': 'started',
            'message': 'Investigation started successfully',
            'phone_number': phone_number,
            'investigator': investigator
        })
        
    except Exception as e:
        logger.error(f"Start investigation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/investigation_status/<investigation_id>')
@require_session
def api_investigation_status(investigation_id):
    """Get investigation status"""
    try:
        status = phone_intel_system.get_investigation_status(investigation_id)
        return jsonify(status)
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/investigations')
@require_session
def api_list_investigations():
    """List all investigations for current investigator"""
    try:
        session_info = get_session_info()
        if not session_info:
            return jsonify({'error': 'Invalid session'}), 401
        
        investigator = session_info['investigator']
        investigations = phone_intel_system.list_investigations(investigator)
        
        return jsonify({
            'status': 'success',
            'investigations': investigations,
            'count': len(investigations)
        })
        
    except Exception as e:
        logger.error(f"List investigations error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/download_report/<investigation_id>')
@require_session
def api_download_report(investigation_id):
    """Download investigation report"""
    try:
        # Get investigation record
        if investigation_id not in phone_intel_system.active_investigations:
            return jsonify({'error': 'Investigation not found'}), 404
        
        investigation = phone_intel_system.active_investigations[investigation_id]
        
        if 'report_path' not in investigation.get('results', {}):
            return jsonify({'error': 'Report not available'}), 404
        
        report_path = investigation['results']['report_path']
        
        if not Path(report_path).exists():
            return jsonify({'error': 'Report file not found'}), 404
        
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"investigation_report_{investigation_id[:8]}.html"
        )
        
    except Exception as e:
        logger.error(f"Download report error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload_evidence', methods=['POST'])
@require_session
def api_upload_evidence():
    """Upload evidence files"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        investigation_id = request.form.get('investigation_id')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not investigation_id:
            return jsonify({'error': 'Investigation ID required'}), 400
        
        # Secure filename
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        secure_name = f"{timestamp}_{filename}"
        
        # Save file
        filepath = Path(app.config['UPLOAD_FOLDER']) / secure_name
        file.save(str(filepath))
        
        # Store as evidence
        session_info = get_session_info()
        investigator = session_info['investigator']
        
        evidence_metadata = {
            'original_filename': filename,
            'secure_filename': secure_name,
            'file_size': filepath.stat().st_size,
            'upload_time': datetime.now().isoformat(),
            'file_path': str(filepath)
        }
        
        evidence_id = phone_intel_system.evidence_manager.store_evidence(
            investigation_id, 
            'uploaded_file',
            'file_upload',
            evidence_metadata,
            investigator
        )
        
        return jsonify({
            'status': 'success',
            'evidence_id': evidence_id,
            'filename': filename,
            'file_size': evidence_metadata['file_size']
        })
        
    except Exception as e:
        logger.error(f"Upload evidence error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/session_info')
@require_session
def api_session_info():
    """Get current session information"""
    try:
        session_info = get_session_info()
        if not session_info:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Don't send sensitive data
        safe_info = {
            'session_id': session_info['session_id'],
            'investigator': session_info['investigator'],
            'created_at': session_info['created_at'].isoformat(),
            'last_activity': session_info['last_activity'].isoformat(),
            'investigation_count': len(session_info['investigations']),
            'is_active': session_info['is_active']
        }
        
        return jsonify(safe_info)
        
    except Exception as e:
        logger.error(f"Session info error: {e}")
        return jsonify({'error': str(e)}), 500

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    session_id = session.get('session_id')
    if session_id:
        join_room(session_id)
        emit('connected', {'status': 'Connected to investigation system'})
        logger.info(f"Client connected to session: {session_id}")
    else:
        emit('error', {'message': 'No active session'})
        disconnect()

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    session_id = session.get('session_id')
    if session_id:
        leave_room(session_id)
        logger.info(f"Client disconnected from session: {session_id}")

@socketio.on('join_investigation')
def handle_join_investigation(data):
    """Join investigation room for real-time updates"""
    investigation_id = data.get('investigation_id')
    if investigation_id:
        join_room(f"investigation_{investigation_id}")
        emit('joined_investigation', {'investigation_id': investigation_id})

@socketio.on('leave_investigation')
def handle_leave_investigation(data):
    """Leave investigation room"""
    investigation_id = data.get('investigation_id')
    if investigation_id:
        leave_room(f"investigation_{investigation_id}")
        emit('left_investigation', {'investigation_id': investigation_id})

@socketio.on('request_progress')
def handle_progress_request(data):
    """Request investigation progress update"""
    investigation_id = data.get('investigation_id')
    if investigation_id and investigation_id in phone_intel_system.active_investigations:
        investigation = phone_intel_system.active_investigations[investigation_id]
        emit('progress_update', {
            'investigation_id': investigation_id,
            'progress': investigation.get('progress', 0.0),
            'status': investigation.get('status', 'unknown')
        })

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(413)
def too_large_error(error):
    """Handle file too large errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'File too large (max 16MB)'}), 413
    flash('File too large (maximum 16MB allowed)', 'error')
    return redirect(request.url)

# Initialize system and run
def create_app():
    """Create and configure the Flask app"""
    # Set start time for uptime calculation
    app.start_time = time.time()
    
    # Initialize phone intelligence system
    if not init_phone_system():
        logger.error("Failed to initialize Phone Intelligence System")
        return None
    
    logger.info("Phone Intelligence Web Application initialized successfully")
    return app

if __name__ == '__main__':
    # Create app
    app = create_app()
    if app is None:
        print("Failed to initialize application")
        exit(1)
    
    # Run the application
    print("\n" + "="*60)
    print("🔍 PROFESSIONAL PHONE INTELLIGENCE WEB APPLICATION")
    print("="*60)
    print("📱 Advanced phone number investigation platform")
    print("🌐 Web-based interface for professional investigators")
    print("🔒 Secure evidence management and reporting")
    print("="*60)
    # Find available port
    import socket
    def find_free_port(start_port=5003):
        for port in range(start_port, start_port + 10):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        return None
    
    port = find_free_port()
    if port is None:
        print("❌ No available ports found")
        exit(1)
    
    print(f"🚀 Starting server on http://localhost:{port}")
    print("="*60)
    print(f"📱 ACCESS: http://localhost:{port}")
    print(f"🌐 Open this URL in your web browser")
    print("="*60)
    
    try:
        # Run with SocketIO
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n👋 Server shutdown requested")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        logger.error(f"Server startup error: {e}")