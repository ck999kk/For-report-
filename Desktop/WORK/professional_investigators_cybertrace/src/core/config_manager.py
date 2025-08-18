"""
Professional Investigation System - Configuration Management
Secure, validated configuration management with environment-specific settings
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
from datetime import datetime
import hashlib

from .exceptions import ConfigurationException, ValidationException


class ConfigurationManager:
    """Advanced configuration management for investigation system"""
    
    def __init__(self, config_dir: str = None, environment: str = None):
        self.config_dir = Path(config_dir) if config_dir else Path("config")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.environment = environment or os.getenv("INVESTIGATION_ENV", "development")
        self.config_cache = {}
        self.config_history = []
        
        # Load configuration
        self._load_configuration()
        
        # Validate configuration
        self._validate_configuration()
    
    def _load_configuration(self):
        """Load configuration from multiple sources with precedence"""
        
        try:
            # Default configuration
            default_config = self._load_default_config()
            
            # Environment-specific configuration
            env_config = self._load_environment_config()
            
            # Local overrides
            local_config = self._load_local_config()
            
            # Environment variables
            env_vars = self._load_environment_variables()
            
            # Merge configurations (later sources override earlier ones)
            self.config = self._merge_configs([
                default_config,
                env_config,
                local_config,
                env_vars
            ])
            
            # Cache the configuration
            self.config_cache = self.config.copy()
            
            # Record configuration load
            self._record_config_change("LOAD", "Configuration loaded successfully")
            
        except Exception as e:
            raise ConfigurationException(
                f"Failed to load configuration: {str(e)}",
                context={"environment": self.environment}
            )
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        
        default_config_file = self.config_dir / "default.yaml"
        
        if default_config_file.exists():
            return self._load_yaml_file(default_config_file)
        
        # Return built-in defaults if no file exists
        return {
            "system": {
                "name": "Professional Investigation System",
                "version": "1.0.0",
                "debug": False,
                "max_workers": 4,
                "timeout": 300
            },
            "logging": {
                "level": "INFO",
                "console_output": True,
                "max_file_size": 10485760,  # 10MB
                "backup_count": 10,
                "enable_encryption": True,
                "audit_mode": True
            },
            "security": {
                "enable_encryption": True,
                "hash_algorithm": "sha256",
                "session_timeout": 3600,
                "max_login_attempts": 3,
                "require_mfa": False
            },
            "cybertrace": {
                "max_concurrent_traces": 5,
                "trace_timeout": 600,
                "enable_deep_scan": True,
                "save_raw_data": True
            },
            "evidence": {
                "storage_path": "evidence_storage",
                "enable_versioning": True,
                "compression": True,
                "encryption": True,
                "backup_enabled": True
            },
            "network": {
                "timeout": 30,
                "retries": 3,
                "user_agent": "Professional-Investigation-System/1.0",
                "rate_limit": 10
            },
            "reporting": {
                "format": "pdf",
                "include_metadata": True,
                "watermark": True,
                "digital_signature": True
            }
        }
    
    def _load_environment_config(self) -> Dict[str, Any]:
        """Load environment-specific configuration"""
        
        env_config_file = self.config_dir / f"{self.environment}.yaml"
        
        if env_config_file.exists():
            return self._load_yaml_file(env_config_file)
        
        return {}
    
    def _load_local_config(self) -> Dict[str, Any]:
        """Load local configuration overrides"""
        
        local_config_file = self.config_dir / "local.yaml"
        
        if local_config_file.exists():
            return self._load_yaml_file(local_config_file)
        
        return {}
    
    def _load_environment_variables(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        
        env_config = {}
        prefix = "INV_"
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                env_config[config_key] = self._parse_env_value(value)
        
        return env_config
    
    def _parse_env_value(self, value: str) -> Union[str, int, float, bool]:
        """Parse environment variable value to appropriate type"""
        
        # Boolean values
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        elif value.lower() in ("false", "no", "0", "off"):
            return False
        
        # Numeric values
        try:
            if "." in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # String value
        return value
    
    def _load_yaml_file(self, file_path: Path) -> Dict[str, Any]:
        """Load YAML configuration file"""
        
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationException(
                f"Invalid YAML in {file_path}: {str(e)}",
                config_key=str(file_path)
            )
        except Exception as e:
            raise ConfigurationException(
                f"Failed to read {file_path}: {str(e)}",
                config_key=str(file_path)
            )
    
    def _merge_configs(self, configs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple configuration dictionaries"""
        
        merged = {}
        
        for config in configs:
            if config:
                merged = self._deep_merge(merged, config)
        
        return merged
    
    def _deep_merge(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries"""
        
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _validate_configuration(self):
        """Validate configuration values"""
        
        validation_rules = {
            "system.name": {"type": str, "required": True},
            "system.version": {"type": str, "required": True},
            "system.max_workers": {"type": int, "min": 1, "max": 50},
            "system.timeout": {"type": int, "min": 1},
            "logging.level": {"type": str, "choices": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
            "logging.max_file_size": {"type": int, "min": 1024},
            "security.session_timeout": {"type": int, "min": 300},
            "security.max_login_attempts": {"type": int, "min": 1, "max": 10},
            "cybertrace.max_concurrent_traces": {"type": int, "min": 1, "max": 20},
            "network.timeout": {"type": int, "min": 1, "max": 300},
            "network.retries": {"type": int, "min": 0, "max": 10}
        }
        
        for key, rules in validation_rules.items():
            self._validate_config_value(key, rules)
    
    def _validate_config_value(self, key: str, rules: Dict[str, Any]):
        """Validate a single configuration value"""
        
        value = self.get(key)
        
        # Check if required
        if rules.get("required", False) and value is None:
            raise ValidationException(
                f"Required configuration key '{key}' is missing",
                field=key
            )
        
        if value is None:
            return
        
        # Check type
        expected_type = rules.get("type")
        if expected_type and not isinstance(value, expected_type):
            raise ValidationException(
                f"Configuration key '{key}' must be of type {expected_type.__name__}",
                field=key,
                value=value
            )
        
        # Check choices
        choices = rules.get("choices")
        if choices and value not in choices:
            raise ValidationException(
                f"Configuration key '{key}' must be one of: {choices}",
                field=key,
                value=value
            )
        
        # Check min/max for numeric values
        if isinstance(value, (int, float)):
            min_val = rules.get("min")
            max_val = rules.get("max")
            
            if min_val is not None and value < min_val:
                raise ValidationException(
                    f"Configuration key '{key}' must be >= {min_val}",
                    field=key,
                    value=value
                )
            
            if max_val is not None and value > max_val:
                raise ValidationException(
                    f"Configuration key '{key}' must be <= {max_val}",
                    field=key,
                    value=value
                )
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        
        keys = key.split(".")
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any, persist: bool = False):
        """Set configuration value using dot notation"""
        
        keys = key.split(".")
        config = self.config
        
        # Navigate to the parent dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        old_value = config.get(keys[-1])
        config[keys[-1]] = value
        
        # Record the change
        self._record_config_change(
            "SET",
            f"Changed {key} from {old_value} to {value}",
            {"key": key, "old_value": old_value, "new_value": value}
        )
        
        # Persist if requested
        if persist:
            self.save_local_config()
    
    def _record_config_change(self, action: str, description: str, metadata: Dict[str, Any] = None):
        """Record configuration change for audit trail"""
        
        change_record = {
            "action": action,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "environment": self.environment,
            "config_hash": self._calculate_config_hash(),
            "metadata": metadata or {}
        }
        
        self.config_history.append(change_record)
    
    def _calculate_config_hash(self) -> str:
        """Calculate hash of current configuration for integrity checking"""
        
        config_str = json.dumps(self.config, sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def save_local_config(self, file_path: str = None):
        """Save current configuration to local file"""
        
        if not file_path:
            file_path = self.config_dir / "local.yaml"
        
        try:
            with open(file_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            
            self._record_config_change("SAVE", f"Configuration saved to {file_path}")
            
        except Exception as e:
            raise ConfigurationException(
                f"Failed to save configuration to {file_path}: {str(e)}",
                config_key=str(file_path)
            )
    
    def reload(self):
        """Reload configuration from files"""
        
        self._load_configuration()
        self._validate_configuration()
        self._record_config_change("RELOAD", "Configuration reloaded")
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get information about the configuration"""
        
        return {
            "environment": self.environment,
            "config_dir": str(self.config_dir),
            "config_hash": self._calculate_config_hash(),
            "last_modified": datetime.utcnow().isoformat(),
            "change_history_count": len(self.config_history)
        }
    
    def get_change_history(self) -> List[Dict[str, Any]]:
        """Get configuration change history"""
        
        return self.config_history.copy()
    
    def export_config(self, file_path: str, include_sensitive: bool = False):
        """Export configuration to file"""
        
        config_to_export = self.config.copy()
        
        if not include_sensitive:
            config_to_export = self._sanitize_config(config_to_export)
        
        try:
            with open(file_path, 'w') as f:
                yaml.dump(config_to_export, f, default_flow_style=False, indent=2)
            
            self._record_config_change(
                "EXPORT",
                f"Configuration exported to {file_path}",
                {"include_sensitive": include_sensitive}
            )
            
        except Exception as e:
            raise ConfigurationException(
                f"Failed to export configuration to {file_path}: {str(e)}",
                config_key=str(file_path)
            )
    
    def _sanitize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from configuration"""
        
        sanitized = {}
        sensitive_keys = ["password", "secret", "key", "token", "credential"]
        
        for key, value in config.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_config(value)
            elif any(sensitive_word in key.lower() for sensitive_word in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def validate_config_integrity(self) -> bool:
        """Validate configuration integrity"""
        
        try:
            current_hash = self._calculate_config_hash()
            cached_hash = self._calculate_config_hash_from_cache()
            
            return current_hash == cached_hash
            
        except Exception:
            return False
    
    def _calculate_config_hash_from_cache(self) -> str:
        """Calculate hash from cached configuration"""
        
        config_str = json.dumps(self.config_cache, sort_keys=True, default=str)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access"""
        return self.get(key)
    
    def __setitem__(self, key: str, value: Any):
        """Allow dictionary-style assignment"""
        self.set(key, value)
    
    def __contains__(self, key: str) -> bool:
        """Allow 'in' operator"""
        return self.get(key) is not None