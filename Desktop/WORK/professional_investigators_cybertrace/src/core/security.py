"""
Professional Investigation System - Security Manager
Comprehensive security management for investigation operations
"""

import hashlib
import hmac
import secrets
import base64
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
import json
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import SecurityException, ValidationException


class SecurityManager:
    """Advanced security management for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Security settings
        self.enable_encryption = self.config.get("enable_encryption", True)
        self.hash_algorithm = self.config.get("hash_algorithm", "sha256")
        self.session_timeout = self.config.get("session_timeout", 3600)  # 1 hour
        self.max_login_attempts = self.config.get("max_login_attempts", 3)
        self.require_mfa = self.config.get("require_mfa", False)
        
        # Initialize security components
        self._initialize_encryption()
        self._initialize_session_management()
        self._initialize_audit_logging()
        
        # Security state
        self.active_sessions = {}
        self.failed_attempts = {}
        self.security_events = []
    
    def _initialize_encryption(self):
        """Initialize encryption components"""
        
        try:
            # Generate or load encryption key
            key_file = Path("config/.security_key")
            
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(self.encryption_key)
                # Secure the key file
                os.chmod(key_file, 0o600)
            
            self.fernet = Fernet(self.encryption_key)
            
        except Exception as e:
            raise SecurityException(
                f"Failed to initialize encryption: {str(e)}",
                security_level="CRITICAL"
            )
    
    def _initialize_session_management(self):
        """Initialize session management"""
        
        self.session_secrets = {}
        self.session_start_times = {}
    
    def _initialize_audit_logging(self):
        """Initialize security audit logging"""
        
        self.audit_log = []
    
    def authenticate_user(self, username: str, password: str, mfa_token: str = None) -> Dict[str, Any]:
        """Authenticate user with optional MFA"""
        
        try:
            # Check for too many failed attempts
            if self._is_account_locked(username):
                self._log_security_event(
                    "AUTHENTICATION_BLOCKED",
                    "HIGH",
                    {"username": username, "reason": "Account locked due to failed attempts"}
                )
                raise SecurityException(
                    "Account is temporarily locked due to multiple failed attempts",
                    security_level="HIGH"
                )
            
            # Validate credentials (in real implementation, check against secure database)
            if not self._validate_credentials(username, password):
                self._record_failed_attempt(username)
                self._log_security_event(
                    "AUTHENTICATION_FAILED",
                    "MEDIUM",
                    {"username": username, "reason": "Invalid credentials"}
                )
                raise SecurityException(
                    "Invalid credentials",
                    security_level="MEDIUM"
                )
            
            # Check MFA if required
            if self.require_mfa:
                if not mfa_token or not self._validate_mfa_token(username, mfa_token):
                    self._log_security_event(
                        "MFA_FAILED",
                        "HIGH",
                        {"username": username}
                    )
                    raise SecurityException(
                        "Multi-factor authentication failed",
                        security_level="HIGH"
                    )
            
            # Create session
            session_id = self.create_session(username)
            
            # Clear failed attempts
            if username in self.failed_attempts:
                del self.failed_attempts[username]
            
            self._log_security_event(
                "AUTHENTICATION_SUCCESS",
                "LOW",
                {"username": username, "session_id": session_id}
            )
            
            return {
                "session_id": session_id,
                "username": username,
                "expires_at": (datetime.utcnow() + timedelta(seconds=self.session_timeout)).isoformat(),
                "permissions": self._get_user_permissions(username)
            }
            
        except SecurityException:
            raise
        except Exception as e:
            self._log_security_event(
                "AUTHENTICATION_ERROR",
                "HIGH",
                {"username": username, "error": str(e)}
            )
            raise SecurityException(
                f"Authentication error: {str(e)}",
                security_level="HIGH"
            )
    
    def _validate_credentials(self, username: str, password: str) -> bool:
        """Validate user credentials (mock implementation)"""
        
        # In production, this would check against a secure user database
        # For demo purposes, accept any non-empty credentials
        return bool(username and password and len(password) >= 8)
    
    def _validate_mfa_token(self, username: str, token: str) -> bool:
        """Validate MFA token (mock implementation)"""
        
        # In production, this would validate against TOTP/SMS/hardware token
        # For demo purposes, accept "123456" as valid token
        return token == "123456"
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts"""
        
        if username not in self.failed_attempts:
            return False
        
        attempts, last_attempt = self.failed_attempts[username]
        
        # Account is locked for 15 minutes after max attempts
        if attempts >= self.max_login_attempts:
            lockout_duration = timedelta(minutes=15)
            if datetime.utcnow() - last_attempt < lockout_duration:
                return True
            else:
                # Reset attempts after lockout period
                del self.failed_attempts[username]
                return False
        
        return False
    
    def _record_failed_attempt(self, username: str):
        """Record failed authentication attempt"""
        
        if username not in self.failed_attempts:
            self.failed_attempts[username] = (0, datetime.utcnow())
        
        attempts, _ = self.failed_attempts[username]
        self.failed_attempts[username] = (attempts + 1, datetime.utcnow())
    
    def _get_user_permissions(self, username: str) -> List[str]:
        """Get user permissions (mock implementation)"""
        
        # In production, this would query user roles and permissions
        return [
            "investigation.read",
            "investigation.write",
            "cybertrace.execute",
            "evidence.manage",
            "reports.generate"
        ]
    
    def create_session(self, username: str) -> str:
        """Create secure session"""
        
        try:
            # Generate secure session ID
            session_id = secrets.token_urlsafe(32)
            
            # Create session data
            session_data = {
                "username": username,
                "created_at": datetime.utcnow().isoformat(),
                "last_activity": datetime.utcnow().isoformat(),
                "ip_address": "127.0.0.1",  # In production, get from request
                "user_agent": "Investigation-System"  # In production, get from request
            }
            
            self.active_sessions[session_id] = session_data
            self.session_secrets[session_id] = secrets.token_bytes(32)
            self.session_start_times[session_id] = datetime.utcnow()
            
            self._log_security_event(
                "SESSION_CREATED",
                "LOW",
                {"session_id": session_id, "username": username}
            )
            
            return session_id
            
        except Exception as e:
            raise SecurityException(
                f"Failed to create session: {str(e)}",
                security_level="HIGH"
            )
    
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session and return session data"""
        
        if session_id not in self.active_sessions:
            self._log_security_event(
                "SESSION_INVALID",
                "MEDIUM",
                {"session_id": session_id}
            )
            return None
        
        session_data = self.active_sessions[session_id]
        
        # Check session timeout
        last_activity = datetime.fromisoformat(session_data["last_activity"])
        if datetime.utcnow() - last_activity > timedelta(seconds=self.session_timeout):
            self.invalidate_session(session_id)
            self._log_security_event(
                "SESSION_EXPIRED",
                "LOW",
                {"session_id": session_id}
            )
            return None
        
        # Update last activity
        session_data["last_activity"] = datetime.utcnow().isoformat()
        
        return session_data
    
    def invalidate_session(self, session_id: str):
        """Invalidate session"""
        
        if session_id in self.active_sessions:
            username = self.active_sessions[session_id]["username"]
            
            del self.active_sessions[session_id]
            if session_id in self.session_secrets:
                del self.session_secrets[session_id]
            if session_id in self.session_start_times:
                del self.session_start_times[session_id]
            
            self._log_security_event(
                "SESSION_INVALIDATED",
                "LOW",
                {"session_id": session_id, "username": username}
            )
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        
        if not self.enable_encryption:
            return data
        
        try:
            encrypted_data = self.fernet.encrypt(data.encode())
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            raise SecurityException(
                f"Encryption failed: {str(e)}",
                security_level="HIGH"
            )
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        
        if not self.enable_encryption:
            return encrypted_data
        
        try:
            decoded_data = base64.b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(decoded_data)
            return decrypted_data.decode()
            
        except Exception as e:
            raise SecurityException(
                f"Decryption failed: {str(e)}",
                security_level="HIGH"
            )
    
    def hash_data(self, data: str, salt: str = None) -> Tuple[str, str]:
        """Hash data with salt"""
        
        if salt is None:
            salt = secrets.token_hex(16)
        
        try:
            if self.hash_algorithm == "sha256":
                hash_obj = hashlib.sha256()
            elif self.hash_algorithm == "sha512":
                hash_obj = hashlib.sha512()
            else:
                raise SecurityException(
                    f"Unsupported hash algorithm: {self.hash_algorithm}",
                    security_level="MEDIUM"
                )
            
            hash_obj.update((data + salt).encode())
            hashed_data = hash_obj.hexdigest()
            
            return hashed_data, salt
            
        except Exception as e:
            raise SecurityException(
                f"Hashing failed: {str(e)}",
                security_level="MEDIUM"
            )
    
    def verify_hash(self, data: str, hashed_data: str, salt: str) -> bool:
        """Verify hashed data"""
        
        try:
            computed_hash, _ = self.hash_data(data, salt)
            return hmac.compare_digest(computed_hash, hashed_data)
            
        except Exception as e:
            raise SecurityException(
                f"Hash verification failed: {str(e)}",
                security_level="MEDIUM"
            )
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode(), salt)
            return hashed.decode()
            
        except Exception as e:
            raise SecurityException(
                f"Password hashing failed: {str(e)}",
                security_level="HIGH"
            )
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        
        try:
            return bcrypt.checkpw(password.encode(), hashed_password.encode())
            
        except Exception as e:
            raise SecurityException(
                f"Password verification failed: {str(e)}",
                security_level="HIGH"
            )
    
    def generate_api_key(self, purpose: str = "general") -> Dict[str, str]:
        """Generate secure API key"""
        
        try:
            api_key = secrets.token_urlsafe(32)
            key_id = secrets.token_hex(8)
            
            key_data = {
                "key_id": key_id,
                "api_key": api_key,
                "purpose": purpose,
                "created_at": datetime.utcnow().isoformat(),
                "status": "active"
            }
            
            self._log_security_event(
                "API_KEY_GENERATED",
                "MEDIUM",
                {"key_id": key_id, "purpose": purpose}
            )
            
            return key_data
            
        except Exception as e:
            raise SecurityException(
                f"API key generation failed: {str(e)}",
                security_level="MEDIUM"
            )
    
    def _log_security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log security event"""
        
        event = {
            "event_type": event_type,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        self.security_events.append(event)
        self.audit_log.append(event)
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        
        return {
            "active_sessions": len(self.active_sessions),
            "failed_attempts": len(self.failed_attempts),
            "recent_events": len([e for e in self.security_events 
                                if datetime.fromisoformat(e["timestamp"]) > 
                                datetime.utcnow() - timedelta(hours=1)]),
            "encryption_enabled": self.enable_encryption,
            "mfa_required": self.require_mfa,
            "hash_algorithm": self.hash_algorithm
        }
    
    def get_security_audit_log(self) -> List[Dict[str, Any]]:
        """Get security audit log"""
        
        return self.audit_log.copy()
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        
        expired_sessions = []
        current_time = datetime.utcnow()
        
        for session_id, session_data in self.active_sessions.items():
            last_activity = datetime.fromisoformat(session_data["last_activity"])
            if current_time - last_activity > timedelta(seconds=self.session_timeout):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.invalidate_session(session_id)
        
        return len(expired_sessions)
    
    def export_security_report(self, file_path: str):
        """Export security report"""
        
        report = {
            "report_timestamp": datetime.utcnow().isoformat(),
            "security_status": self.get_security_status(),
            "audit_log": self.get_security_audit_log(),
            "configuration": {
                "encryption_enabled": self.enable_encryption,
                "hash_algorithm": self.hash_algorithm,
                "session_timeout": self.session_timeout,
                "max_login_attempts": self.max_login_attempts,
                "require_mfa": self.require_mfa
            }
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self._log_security_event(
                "SECURITY_REPORT_EXPORTED",
                "LOW",
                {"file_path": file_path}
            )
            
        except Exception as e:
            raise SecurityException(
                f"Failed to export security report: {str(e)}",
                security_level="MEDIUM"
            )