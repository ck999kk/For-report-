"""
Professional Investigation System - Custom Exceptions
Comprehensive error handling for investigative operations
"""

import traceback
from datetime import datetime
from typing import Optional, Dict, Any


class InvestigationException(Exception):
    """Base exception for investigation system operations"""
    
    def __init__(self, message: str, error_code: str = None, context: Dict[str, Any] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "INV_ERROR"
        self.context = context or {}
        self.timestamp = datetime.utcnow().isoformat()
        self.traceback = traceback.format_exc()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging"""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "context": self.context,
            "timestamp": self.timestamp,
            "traceback": self.traceback
        }


class CybertraceException(InvestigationException):
    """Exception for cybertrace operations"""
    
    def __init__(self, message: str, trace_type: str = None, target: str = None, **kwargs):
        super().__init__(message, error_code="CYBER_ERROR", **kwargs)
        self.trace_type = trace_type
        self.target = target


class EvidenceException(InvestigationException):
    """Exception for evidence handling operations"""
    
    def __init__(self, message: str, evidence_id: str = None, operation: str = None, **kwargs):
        super().__init__(message, error_code="EVIDENCE_ERROR", **kwargs)
        self.evidence_id = evidence_id
        self.operation = operation


class NetworkTraceException(CybertraceException):
    """Exception for network tracing operations"""
    
    def __init__(self, message: str, network_target: str = None, **kwargs):
        super().__init__(message, trace_type="network", target=network_target, **kwargs)
        self.network_target = network_target


class ForensicsException(InvestigationException):
    """Exception for digital forensics operations"""
    
    def __init__(self, message: str, forensics_type: str = None, target_path: str = None, **kwargs):
        super().__init__(message, error_code="FORENSICS_ERROR", **kwargs)
        self.forensics_type = forensics_type
        self.target_path = target_path


class ConfigurationException(InvestigationException):
    """Exception for configuration-related issues"""
    
    def __init__(self, message: str, config_key: str = None, **kwargs):
        super().__init__(message, error_code="CONFIG_ERROR", **kwargs)
        self.config_key = config_key


class SecurityException(InvestigationException):
    """Exception for security-related issues"""
    
    def __init__(self, message: str, security_level: str = "HIGH", **kwargs):
        super().__init__(message, error_code="SECURITY_ERROR", **kwargs)
        self.security_level = security_level


class ValidationException(InvestigationException):
    """Exception for data validation issues"""
    
    def __init__(self, message: str, field: str = None, value: Any = None, **kwargs):
        super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)
        self.field = field
        self.value = value


class ResourceException(InvestigationException):
    """Exception for resource-related issues (memory, disk, network)"""
    
    def __init__(self, message: str, resource_type: str = None, **kwargs):
        super().__init__(message, error_code="RESOURCE_ERROR", **kwargs)
        self.resource_type = resource_type