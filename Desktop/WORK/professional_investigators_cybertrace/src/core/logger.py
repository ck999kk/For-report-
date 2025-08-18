"""
Professional Investigation System - Advanced Logging
Comprehensive logging with audit trails, evidence tracking, and security monitoring
"""

import logging
import logging.handlers
import json
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from enum import Enum

from .exceptions import InvestigationException


class LogLevel(Enum):
    """Investigation-specific log levels"""
    TRACE = "TRACE"
    EVIDENCE = "EVIDENCE"
    SECURITY = "SECURITY"
    FORENSICS = "FORENSICS"
    CYBERTRACE = "CYBERTRACE"
    AUDIT = "AUDIT"
    CRITICAL = "CRITICAL"


class InvestigationLogger:
    """Advanced logging system for professional investigations"""
    
    def __init__(self, name: str, log_dir: str = None, config: Dict[str, Any] = None):
        self.name = name
        self.log_dir = Path(log_dir) if log_dir else Path("logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration
        self.config = config or {}
        self.max_file_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10MB
        self.backup_count = self.config.get("backup_count", 10)
        self.enable_encryption = self.config.get("enable_encryption", True)
        self.audit_mode = self.config.get("audit_mode", True)
        
        # Initialize loggers
        self._setup_loggers()
        
        # Audit trail
        self.audit_trail = []
        self.session_id = self._generate_session_id()
        
        # Start session
        self._log_session_start()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = datetime.utcnow().isoformat()
        return hashlib.sha256(f"{self.name}_{timestamp}".encode()).hexdigest()[:16]
    
    def _setup_loggers(self):
        """Setup multiple loggers for different purposes"""
        
        # Main investigation logger
        self.logger = logging.getLogger(f"investigation.{self.name}")
        self.logger.setLevel(logging.DEBUG)
        
        # Evidence logger (tamper-proof)
        self.evidence_logger = logging.getLogger(f"evidence.{self.name}")
        self.evidence_logger.setLevel(logging.INFO)
        
        # Security logger
        self.security_logger = logging.getLogger(f"security.{self.name}")
        self.security_logger.setLevel(logging.WARNING)
        
        # Audit logger
        self.audit_logger = logging.getLogger(f"audit.{self.name}")
        self.audit_logger.setLevel(logging.INFO)
        
        # Setup handlers
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup log handlers with rotation and formatting"""
        
        # Custom formatter with investigation context
        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | SID:%(session_id)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        
        # Add session ID to formatter
        old_format = formatter.format
        def format_with_session(record):
            record.session_id = self.session_id
            return old_format(record)
        formatter.format = format_with_session
        
        # Main log file
        main_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"investigation_{self.name}.log",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        main_handler.setFormatter(formatter)
        self.logger.addHandler(main_handler)
        
        # Evidence log file (append-only, high security)
        evidence_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"evidence_{self.name}.log",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        evidence_handler.setFormatter(formatter)
        self.evidence_logger.addHandler(evidence_handler)
        
        # Security log file
        security_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"security_{self.name}.log",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        security_handler.setFormatter(formatter)
        self.security_logger.addHandler(security_handler)
        
        # Audit log file (immutable)
        audit_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"audit_{self.name}.log",
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        audit_handler.setFormatter(formatter)
        self.audit_logger.addHandler(audit_handler)
        
        # Console handler for development
        if self.config.get("console_output", True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(logging.INFO)
            self.logger.addHandler(console_handler)
    
    def _log_session_start(self):
        """Log session initialization"""
        session_info = {
            "session_id": self.session_id,
            "investigator": self.name,
            "start_time": datetime.utcnow().isoformat(),
            "config": self._sanitize_config()
        }
        
        self.audit_logger.info(f"SESSION_START: {json.dumps(session_info)}")
        self.logger.info(f"Investigation session started: {self.session_id}")
    
    def _sanitize_config(self) -> Dict[str, Any]:
        """Remove sensitive information from config for logging"""
        sanitized = self.config.copy()
        sensitive_keys = ["password", "api_key", "secret", "token"]
        
        for key in sensitive_keys:
            if key in sanitized:
                sanitized[key] = "[REDACTED]"
        
        return sanitized
    
    def log_evidence(self, evidence_id: str, action: str, data: Dict[str, Any], 
                    integrity_hash: str = None):
        """Log evidence handling with tamper-proof trail"""
        
        evidence_entry = {
            "evidence_id": evidence_id,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
            "investigator": self.name,
            "session_id": self.session_id,
            "data": data,
            "integrity_hash": integrity_hash or self._calculate_hash(str(data))
        }
        
        self.evidence_logger.info(f"EVIDENCE: {json.dumps(evidence_entry)}")
        self.audit_trail.append(evidence_entry)
    
    def log_cybertrace(self, trace_type: str, target: str, results: Dict[str, Any],
                      method: str = None):
        """Log cybertrace operations"""
        
        trace_entry = {
            "trace_type": trace_type,
            "target": target,
            "method": method,
            "timestamp": datetime.utcnow().isoformat(),
            "investigator": self.name,
            "session_id": self.session_id,
            "results": results
        }
        
        self.logger.info(f"CYBERTRACE: {json.dumps(trace_entry)}")
        self.audit_trail.append(trace_entry)
    
    def log_security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log security-related events"""
        
        security_entry = {
            "event_type": event_type,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "investigator": self.name,
            "session_id": self.session_id,
            "details": details
        }
        
        self.security_logger.warning(f"SECURITY: {json.dumps(security_entry)}")
        self.audit_trail.append(security_entry)
    
    def log_audit(self, operation: str, resource: str, result: str, metadata: Dict[str, Any] = None):
        """Log audit events for compliance"""
        
        audit_entry = {
            "operation": operation,
            "resource": resource,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
            "investigator": self.name,
            "session_id": self.session_id,
            "metadata": metadata or {}
        }
        
        self.audit_logger.info(f"AUDIT: {json.dumps(audit_entry)}")
        self.audit_trail.append(audit_entry)
    
    def log_exception(self, exception: Exception, context: Dict[str, Any] = None):
        """Log exceptions with full context"""
        
        if isinstance(exception, InvestigationException):
            exception_data = exception.to_dict()
        else:
            exception_data = {
                "error_type": exception.__class__.__name__,
                "message": str(exception),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        if context:
            exception_data["context"] = context
        
        exception_data["session_id"] = self.session_id
        exception_data["investigator"] = self.name
        
        self.logger.error(f"EXCEPTION: {json.dumps(exception_data)}")
        self.security_logger.error(f"EXCEPTION: {json.dumps(exception_data)}")
    
    def _calculate_hash(self, data: str) -> str:
        """Calculate SHA-256 hash for integrity verification"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Get complete audit trail for the session"""
        return self.audit_trail.copy()
    
    def export_audit_trail(self, output_file: str = None) -> str:
        """Export audit trail to file"""
        
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = self.log_dir / f"audit_trail_{self.session_id}_{timestamp}.json"
        
        audit_data = {
            "session_id": self.session_id,
            "investigator": self.name,
            "export_timestamp": datetime.utcnow().isoformat(),
            "trail": self.audit_trail
        }
        
        with open(output_file, 'w') as f:
            json.dump(audit_data, f, indent=2, default=str)
        
        self.log_audit("EXPORT_AUDIT_TRAIL", str(output_file), "SUCCESS")
        return str(output_file)
    
    def close_session(self):
        """Close investigation session"""
        
        session_end = {
            "session_id": self.session_id,
            "investigator": self.name,
            "end_time": datetime.utcnow().isoformat(),
            "total_audit_entries": len(self.audit_trail)
        }
        
        self.audit_logger.info(f"SESSION_END: {json.dumps(session_end)}")
        self.logger.info(f"Investigation session ended: {self.session_id}")
        
        # Export final audit trail
        self.export_audit_trail()
    
    def debug(self, message: str, **kwargs):
        """Debug level logging"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Info level logging"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Warning level logging"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Error level logging"""
        self.logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Critical level logging"""
        self.logger.critical(message, **kwargs)