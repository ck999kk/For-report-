"""
Professional Investigation System - Core Investigator
Main orchestrator for all investigation operations
"""

import asyncio
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import json
import uuid

from .logger import InvestigationLogger
from .config_manager import ConfigurationManager
from .security import SecurityManager
from .exceptions import InvestigationException, SecurityException, ConfigurationException


class InvestigatorCore:
    """Main investigator core system - orchestrates all investigation operations"""
    
    def __init__(self, config_path: str = None, investigator_name: str = None):
        # Initialize system
        self.investigator_name = investigator_name or "Unknown_Investigator"
        self.session_id = str(uuid.uuid4())
        self.start_time = datetime.utcnow()
        
        # Initialize components
        try:
            self.config = ConfigurationManager(config_path)
            self.logger = InvestigationLogger(
                self.investigator_name,
                self.config.get("logging.log_dir", "logs"),
                self.config.get("logging")
            )
            self.security = SecurityManager(self.config.get("security"))
            
        except Exception as e:
            raise InvestigationException(
                f"Failed to initialize investigator core: {str(e)}",
                context={"investigator": self.investigator_name}
            )
        
        # System state
        self.is_initialized = False
        self.active_operations = {}
        self.investigation_cases = {}
        self.system_status = "INITIALIZING"
        
        # Load modules
        self._load_modules()
        
        # Initialize system
        self._initialize_system()
        
        self.logger.info(f"InvestigatorCore initialized for {self.investigator_name}")
    
    def _load_modules(self):
        """Load investigation modules"""
        
        try:
            # Import modules
            from ..cybertrace import CybertraceEngine
            from ..evidence import EvidenceManager
            from ..reporting import ReportGenerator
            
            # Initialize modules
            self.cybertrace = CybertraceEngine(
                config=self.config.get("cybertrace"),
                logger=self.logger,
                security=self.security
            )
            
            self.evidence_manager = EvidenceManager(
                config=self.config.get("evidence"),
                logger=self.logger,
                security=self.security
            )
            
            self.report_generator = ReportGenerator(
                config=self.config.get("reporting"),
                logger=self.logger,
                security=self.security
            )
            
            self.logger.info("All investigation modules loaded successfully")
            
        except ImportError as e:
            raise InvestigationException(
                f"Failed to import investigation modules: {str(e)}",
                error_code="MODULE_IMPORT_ERROR"
            )
        except Exception as e:
            raise InvestigationException(
                f"Failed to initialize investigation modules: {str(e)}",
                error_code="MODULE_INIT_ERROR"
            )
    
    def _initialize_system(self):
        """Initialize the investigation system"""
        
        try:
            self.system_status = "INITIALIZING"
            
            # Validate system requirements
            self._validate_system_requirements()
            
            # Setup workspace
            self._setup_workspace()
            
            # Initialize security context
            self._initialize_security_context()
            
            # Start system monitoring
            self._start_system_monitoring()
            
            self.is_initialized = True
            self.system_status = "READY"
            
            self.logger.log_audit(
                "SYSTEM_INITIALIZATION",
                "InvestigatorCore",
                "SUCCESS",
                {
                    "investigator": self.investigator_name,
                    "session_id": self.session_id,
                    "initialization_time": (datetime.utcnow() - self.start_time).total_seconds()
                }
            )
            
        except Exception as e:
            self.system_status = "ERROR"
            self.logger.log_exception(e)
            raise InvestigationException(
                f"System initialization failed: {str(e)}",
                context={"investigator": self.investigator_name}
            )
    
    def _validate_system_requirements(self):
        """Validate system requirements"""
        
        # Check disk space
        workspace_path = Path(self.config.get("evidence.storage_path", "evidence_storage"))
        
        # Check permissions
        if not os.access(workspace_path.parent, os.W_OK):
            raise InvestigationException(
                "Insufficient permissions for evidence storage",
                error_code="PERMISSION_ERROR"
            )
        
        # Validate configuration
        required_configs = [
            "system.name",
            "logging.level",
            "security.enable_encryption",
            "cybertrace.max_concurrent_traces"
        ]
        
        for config_key in required_configs:
            if self.config.get(config_key) is None:
                raise ConfigurationException(
                    f"Required configuration missing: {config_key}",
                    config_key=config_key
                )
    
    def _setup_workspace(self):
        """Setup investigation workspace"""
        
        # Create directory structure
        base_path = Path(self.config.get("evidence.storage_path", "evidence_storage"))
        
        directories = [
            base_path / "cases",
            base_path / "evidence",
            base_path / "reports",
            base_path / "temp",
            base_path / "backups"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        self.workspace_path = base_path
        self.logger.info(f"Workspace setup complete: {base_path}")
    
    def _initialize_security_context(self):
        """Initialize security context for the session"""
        
        # Create system session
        self.system_session = self.security.create_session(f"system_{self.investigator_name}")
        
        # Log security initialization
        self.logger.log_security_event(
            "SECURITY_CONTEXT_INITIALIZED",
            "LOW",
            {"investigator": self.investigator_name, "session_id": self.system_session}
        )
    
    def _start_system_monitoring(self):
        """Start system monitoring"""
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitor_system,
            daemon=True,
            name="SystemMonitor"
        )
        self.monitoring_thread.start()
        
        self.logger.info("System monitoring started")
    
    def _monitor_system(self):
        """Monitor system health and performance"""
        
        while self.is_initialized:
            try:
                # Check system health
                self._check_system_health()
                
                # Cleanup expired sessions
                self.security.cleanup_expired_sessions()
                
                # Monitor active operations
                self._monitor_active_operations()
                
                # Sleep for monitoring interval
                threading.Event().wait(60)  # Check every minute
                
            except Exception as e:
                self.logger.log_exception(e, {"context": "system_monitoring"})
    
    def _check_system_health(self):
        """Check system health"""
        
        health_status = {
            "timestamp": datetime.utcnow().isoformat(),
            "status": "HEALTHY",
            "components": {}
        }
        
        # Check logger
        try:
            self.logger.debug("Health check")
            health_status["components"]["logger"] = "OK"
        except Exception as e:
            health_status["components"]["logger"] = f"ERROR: {str(e)}"
            health_status["status"] = "DEGRADED"
        
        # Check security
        try:
            security_status = self.security.get_security_status()
            health_status["components"]["security"] = "OK"
            health_status["security_metrics"] = security_status
        except Exception as e:
            health_status["components"]["security"] = f"ERROR: {str(e)}"
            health_status["status"] = "DEGRADED"
        
        # Check cybertrace
        try:
            cybertrace_status = self.cybertrace.get_status()
            health_status["components"]["cybertrace"] = "OK"
            health_status["cybertrace_metrics"] = cybertrace_status
        except Exception as e:
            health_status["components"]["cybertrace"] = f"ERROR: {str(e)}"
            health_status["status"] = "DEGRADED"
        
        # Log health status
        if health_status["status"] != "HEALTHY":
            self.logger.warning(f"System health check: {health_status['status']}")
    
    def _monitor_active_operations(self):
        """Monitor active operations"""
        
        current_time = datetime.utcnow()
        
        for op_id, operation in list(self.active_operations.items()):
            # Check for stuck operations
            if operation.get("timeout"):
                start_time = datetime.fromisoformat(operation["start_time"])
                if (current_time - start_time).total_seconds() > operation["timeout"]:
                    self.logger.warning(f"Operation {op_id} timed out")
                    self._handle_operation_timeout(op_id)
    
    def _handle_operation_timeout(self, operation_id: str):
        """Handle operation timeout"""
        
        operation = self.active_operations.get(operation_id)
        if operation:
            self.logger.log_audit(
                "OPERATION_TIMEOUT",
                operation_id,
                "TIMEOUT",
                operation
            )
            
            # Cancel operation if possible
            if "cancel_callback" in operation:
                try:
                    operation["cancel_callback"]()
                except Exception as e:
                    self.logger.log_exception(e)
            
            # Remove from active operations
            del self.active_operations[operation_id]
    
    def authenticate(self, username: str, password: str, mfa_token: str = None) -> Dict[str, Any]:
        """Authenticate investigator"""
        
        try:
            auth_result = self.security.authenticate_user(username, password, mfa_token)
            
            self.logger.log_audit(
                "INVESTIGATOR_AUTHENTICATION",
                username,
                "SUCCESS",
                {"session_id": auth_result["session_id"]}
            )
            
            return auth_result
            
        except SecurityException as e:
            self.logger.log_exception(e)
            raise
    
    def create_investigation_case(self, case_name: str, case_type: str, 
                                 description: str = None, metadata: Dict[str, Any] = None) -> str:
        """Create new investigation case"""
        
        try:
            case_id = str(uuid.uuid4())
            
            case_data = {
                "case_id": case_id,
                "case_name": case_name,
                "case_type": case_type,
                "description": description,
                "metadata": metadata or {},
                "created_by": self.investigator_name,
                "created_at": datetime.utcnow().isoformat(),
                "status": "ACTIVE",
                "evidence_count": 0,
                "cybertrace_count": 0
            }
            
            # Create case directory
            case_path = self.workspace_path / "cases" / case_id
            case_path.mkdir(parents=True, exist_ok=True)
            
            # Save case file
            case_file = case_path / "case_info.json"
            with open(case_file, 'w') as f:
                json.dump(case_data, f, indent=2, default=str)
            
            # Store in memory
            self.investigation_cases[case_id] = case_data
            
            self.logger.log_audit(
                "CASE_CREATED",
                case_id,
                "SUCCESS",
                case_data
            )
            
            self.logger.info(f"Investigation case created: {case_name} ({case_id})")
            
            return case_id
            
        except Exception as e:
            self.logger.log_exception(e)
            raise InvestigationException(
                f"Failed to create investigation case: {str(e)}",
                context={"case_name": case_name}
            )
    
    def execute_cybertrace(self, case_id: str, trace_type: str, target: str, 
                          options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute cybertrace operation"""
        
        try:
            # Validate case
            if case_id not in self.investigation_cases:
                raise InvestigationException(
                    f"Investigation case not found: {case_id}",
                    error_code="CASE_NOT_FOUND"
                )
            
            # Generate operation ID
            operation_id = str(uuid.uuid4())
            
            # Record operation start
            operation_data = {
                "operation_id": operation_id,
                "case_id": case_id,
                "operation_type": "CYBERTRACE",
                "trace_type": trace_type,
                "target": target,
                "options": options or {},
                "start_time": datetime.utcnow().isoformat(),
                "status": "RUNNING",
                "timeout": self.config.get("cybertrace.trace_timeout", 600)
            }
            
            self.active_operations[operation_id] = operation_data
            
            # Execute cybertrace
            results = self.cybertrace.execute_trace(
                trace_type=trace_type,
                target=target,
                case_id=case_id,
                options=options
            )
            
            # Update operation status
            operation_data["status"] = "COMPLETED"
            operation_data["end_time"] = datetime.utcnow().isoformat()
            operation_data["results"] = results
            
            # Update case
            self.investigation_cases[case_id]["cybertrace_count"] += 1
            
            # Log cybertrace
            self.logger.log_cybertrace(trace_type, target, results)
            
            # Remove from active operations
            del self.active_operations[operation_id]
            
            return {
                "operation_id": operation_id,
                "status": "SUCCESS",
                "results": results
            }
            
        except Exception as e:
            # Update operation status
            if operation_id in self.active_operations:
                self.active_operations[operation_id]["status"] = "FAILED"
                self.active_operations[operation_id]["error"] = str(e)
                del self.active_operations[operation_id]
            
            self.logger.log_exception(e)
            raise InvestigationException(
                f"Cybertrace execution failed: {str(e)}",
                context={"case_id": case_id, "trace_type": trace_type, "target": target}
            )
    
    def collect_evidence(self, case_id: str, evidence_type: str, source: str,
                        metadata: Dict[str, Any] = None) -> str:
        """Collect and store evidence"""
        
        try:
            # Validate case
            if case_id not in self.investigation_cases:
                raise InvestigationException(
                    f"Investigation case not found: {case_id}",
                    error_code="CASE_NOT_FOUND"
                )
            
            # Collect evidence
            evidence_id = self.evidence_manager.collect_evidence(
                case_id=case_id,
                evidence_type=evidence_type,
                source=source,
                metadata=metadata
            )
            
            # Update case
            self.investigation_cases[case_id]["evidence_count"] += 1
            
            self.logger.info(f"Evidence collected: {evidence_id}")
            
            return evidence_id
            
        except Exception as e:
            self.logger.log_exception(e)
            raise InvestigationException(
                f"Evidence collection failed: {str(e)}",
                context={"case_id": case_id, "evidence_type": evidence_type}
            )
    
    def generate_report(self, case_id: str, report_type: str = "comprehensive",
                       output_format: str = "pdf") -> str:
        """Generate investigation report"""
        
        try:
            # Validate case
            if case_id not in self.investigation_cases:
                raise InvestigationException(
                    f"Investigation case not found: {case_id}",
                    error_code="CASE_NOT_FOUND"
                )
            
            # Generate report
            report_path = self.report_generator.generate_report(
                case_id=case_id,
                report_type=report_type,
                output_format=output_format,
                case_data=self.investigation_cases[case_id]
            )
            
            self.logger.log_audit(
                "REPORT_GENERATED",
                case_id,
                "SUCCESS",
                {"report_type": report_type, "output_format": output_format, "report_path": report_path}
            )
            
            return report_path
            
        except Exception as e:
            self.logger.log_exception(e)
            raise InvestigationException(
                f"Report generation failed: {str(e)}",
                context={"case_id": case_id, "report_type": report_type}
            )
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        
        return {
            "system_status": self.system_status,
            "investigator": self.investigator_name,
            "session_id": self.session_id,
            "uptime": (datetime.utcnow() - self.start_time).total_seconds(),
            "active_operations": len(self.active_operations),
            "investigation_cases": len(self.investigation_cases),
            "security_status": self.security.get_security_status(),
            "cybertrace_status": self.cybertrace.get_status(),
            "evidence_status": self.evidence_manager.get_status()
        }
    
    def list_cases(self) -> List[Dict[str, Any]]:
        """List all investigation cases"""
        
        return list(self.investigation_cases.values())
    
    def get_case_details(self, case_id: str) -> Dict[str, Any]:
        """Get detailed information about a case"""
        
        if case_id not in self.investigation_cases:
            raise InvestigationException(
                f"Investigation case not found: {case_id}",
                error_code="CASE_NOT_FOUND"
            )
        
        case_data = self.investigation_cases[case_id].copy()
        
        # Add evidence details
        case_data["evidence"] = self.evidence_manager.list_evidence(case_id)
        
        # Add cybertrace results
        case_data["cybertrace_results"] = self.cybertrace.get_case_results(case_id)
        
        return case_data
    
    def shutdown(self):
        """Shutdown the investigation system"""
        
        try:
            self.logger.info("Shutting down investigation system...")
            
            # Stop monitoring
            self.is_initialized = False
            
            # Cancel active operations
            for operation_id in list(self.active_operations.keys()):
                self._handle_operation_timeout(operation_id)
            
            # Close security sessions
            for session_id in list(self.security.active_sessions.keys()):
                self.security.invalidate_session(session_id)
            
            # Close logger session
            self.logger.close_session()
            
            self.system_status = "SHUTDOWN"
            
            self.logger.log_audit(
                "SYSTEM_SHUTDOWN",
                "InvestigatorCore",
                "SUCCESS",
                {"uptime": (datetime.utcnow() - self.start_time).total_seconds()}
            )
            
        except Exception as e:
            self.logger.log_exception(e)
            raise InvestigationException(
                f"System shutdown failed: {str(e)}",
                context={"investigator": self.investigator_name}
            )