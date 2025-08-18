"""
Professional Investigation System - Cybertrace Engine
Main engine for coordinating all cybertrace operations
"""

import asyncio
import concurrent.futures
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
import threading

from ..core.exceptions import CybertraceException, NetworkTraceException
from .network_tracer import NetworkTracer
from .digital_forensics import DigitalForensicsAnalyzer
from .osint_collector import OSINTCollector
from .metadata_analyzer import MetadataAnalyzer


class CybertraceEngine:
    """Advanced cybertrace engine for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Engine configuration
        self.max_concurrent_traces = self.config.get("max_concurrent_traces", 5)
        self.trace_timeout = self.config.get("trace_timeout", 600)
        self.enable_deep_scan = self.config.get("enable_deep_scan", True)
        self.save_raw_data = self.config.get("save_raw_data", True)
        
        # Initialize components
        self._initialize_components()
        
        # Trace management
        self.active_traces = {}
        self.completed_traces = {}
        self.trace_results = {}
        
        # Thread pool for concurrent operations
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_concurrent_traces,
            thread_name_prefix="CyberTrace"
        )
        
        if self.logger:
            self.logger.info("CybertraceEngine initialized")
    
    def _initialize_components(self):
        """Initialize cybertrace components"""
        
        try:
            self.network_tracer = NetworkTracer(
                config=self.config.get("network_tracer"),
                logger=self.logger,
                security=self.security
            )
            
            self.digital_forensics = DigitalForensicsAnalyzer(
                config=self.config.get("digital_forensics"),
                logger=self.logger,
                security=self.security
            )
            
            self.osint_collector = OSINTCollector(
                config=self.config.get("osint"),
                logger=self.logger,
                security=self.security
            )
            
            self.metadata_analyzer = MetadataAnalyzer(
                config=self.config.get("metadata"),
                logger=self.logger,
                security=self.security
            )
            
            if self.logger:
                self.logger.info("All cybertrace components initialized")
                
        except Exception as e:
            raise CybertraceException(
                f"Failed to initialize cybertrace components: {str(e)}",
                trace_type="initialization"
            )
    
    def execute_trace(self, trace_type: str, target: str, case_id: str = None,
                     options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute cybertrace operation"""
        
        if len(self.active_traces) >= self.max_concurrent_traces:
            raise CybertraceException(
                "Maximum concurrent traces limit reached",
                trace_type=trace_type,
                target=target
            )
        
        # Generate trace ID
        trace_id = f"{trace_type}_{target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        # Create trace record
        trace_record = {
            "trace_id": trace_id,
            "trace_type": trace_type,
            "target": target,
            "case_id": case_id,
            "options": options or {},
            "start_time": datetime.utcnow().isoformat(),
            "status": "RUNNING"
        }
        
        self.active_traces[trace_id] = trace_record
        
        try:
            # Execute trace based on type
            if trace_type == "network":
                results = self._execute_network_trace(target, options)
            elif trace_type == "digital_forensics":
                results = self._execute_digital_forensics(target, options)
            elif trace_type == "osint":
                results = self._execute_osint_collection(target, options)
            elif trace_type == "metadata":
                results = self._execute_metadata_analysis(target, options)
            elif trace_type == "comprehensive":
                results = self._execute_comprehensive_trace(target, options)
            else:
                raise CybertraceException(
                    f"Unknown trace type: {trace_type}",
                    trace_type=trace_type,
                    target=target
                )
            
            # Update trace record
            trace_record["status"] = "COMPLETED"
            trace_record["end_time"] = datetime.utcnow().isoformat()
            trace_record["results"] = results
            
            # Move to completed traces
            self.completed_traces[trace_id] = trace_record
            del self.active_traces[trace_id]
            
            # Store results
            if case_id:
                if case_id not in self.trace_results:
                    self.trace_results[case_id] = []
                self.trace_results[case_id].append(trace_record)
            
            if self.logger:
                self.logger.log_cybertrace(trace_type, target, results)
            
            return results
            
        except Exception as e:
            # Update trace record with error
            trace_record["status"] = "FAILED"
            trace_record["error"] = str(e)
            trace_record["end_time"] = datetime.utcnow().isoformat()
            
            # Move to completed traces
            self.completed_traces[trace_id] = trace_record
            if trace_id in self.active_traces:
                del self.active_traces[trace_id]
            
            if self.logger:
                self.logger.log_exception(e, {"trace_id": trace_id})
            
            raise CybertraceException(
                f"Trace execution failed: {str(e)}",
                trace_type=trace_type,
                target=target,
                context={"trace_id": trace_id}
            )
    
    def _execute_network_trace(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute network trace"""
        
        try:
            results = {}
            
            # DNS lookup
            if options.get("include_dns", True):
                results["dns"] = self.network_tracer.dns_lookup(target)
            
            # Whois lookup
            if options.get("include_whois", True):
                results["whois"] = self.network_tracer.whois_lookup(target)
            
            # Port scan
            if options.get("include_port_scan", False):
                port_range = options.get("port_range", "1-1000")
                results["port_scan"] = self.network_tracer.port_scan(target, port_range)
            
            # Traceroute
            if options.get("include_traceroute", True):
                results["traceroute"] = self.network_tracer.traceroute(target)
            
            # SSL certificate analysis
            if options.get("include_ssl", True):
                results["ssl_certificate"] = self.network_tracer.analyze_ssl_certificate(target)
            
            # HTTP headers analysis
            if options.get("include_http", True):
                results["http_headers"] = self.network_tracer.analyze_http_headers(target)
            
            return {
                "trace_type": "network",
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "results": results,
                "summary": self._generate_network_summary(results)
            }
            
        except Exception as e:
            raise NetworkTraceException(
                f"Network trace failed: {str(e)}",
                network_target=target
            )
    
    def _execute_digital_forensics(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute digital forensics analysis"""
        
        try:
            results = {}
            
            # File analysis
            if options.get("analyze_file", True):
                results["file_analysis"] = self.digital_forensics.analyze_file(target)
            
            # Hash analysis
            if options.get("calculate_hashes", True):
                results["file_hashes"] = self.digital_forensics.calculate_hashes(target)
            
            # Metadata extraction
            if options.get("extract_metadata", True):
                results["metadata"] = self.digital_forensics.extract_metadata(target)
            
            # String analysis
            if options.get("extract_strings", False):
                results["strings"] = self.digital_forensics.extract_strings(target)
            
            # Hex dump
            if options.get("generate_hex_dump", False):
                results["hex_dump"] = self.digital_forensics.generate_hex_dump(target)
            
            return {
                "trace_type": "digital_forensics",
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "results": results,
                "summary": self._generate_forensics_summary(results)
            }
            
        except Exception as e:
            raise CybertraceException(
                f"Digital forensics analysis failed: {str(e)}",
                trace_type="digital_forensics",
                target=target
            )
    
    def _execute_osint_collection(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute OSINT collection"""
        
        try:
            results = {}
            
            # Social media search
            if options.get("search_social_media", True):
                results["social_media"] = self.osint_collector.search_social_media(target)
            
            # Search engine results
            if options.get("search_engines", True):
                results["search_results"] = self.osint_collector.search_engines(target)
            
            # Domain/subdomain enumeration
            if options.get("enumerate_subdomains", True):
                results["subdomains"] = self.osint_collector.enumerate_subdomains(target)
            
            # Email harvesting
            if options.get("harvest_emails", False):
                results["emails"] = self.osint_collector.harvest_emails(target)
            
            # Breach data search
            if options.get("check_breaches", True):
                results["breach_data"] = self.osint_collector.check_breach_databases(target)
            
            return {
                "trace_type": "osint",
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "results": results,
                "summary": self._generate_osint_summary(results)
            }
            
        except Exception as e:
            raise CybertraceException(
                f"OSINT collection failed: {str(e)}",
                trace_type="osint",
                target=target
            )
    
    def _execute_metadata_analysis(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute metadata analysis"""
        
        try:
            results = {}
            
            # File metadata
            if options.get("file_metadata", True):
                results["file_metadata"] = self.metadata_analyzer.extract_file_metadata(target)
            
            # EXIF data
            if options.get("exif_data", True):
                results["exif_data"] = self.metadata_analyzer.extract_exif_data(target)
            
            # Document properties
            if options.get("document_properties", True):
                results["document_properties"] = self.metadata_analyzer.extract_document_properties(target)
            
            # Hidden data
            if options.get("hidden_data", True):
                results["hidden_data"] = self.metadata_analyzer.find_hidden_data(target)
            
            return {
                "trace_type": "metadata",
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "results": results,
                "summary": self._generate_metadata_summary(results)
            }
            
        except Exception as e:
            raise CybertraceException(
                f"Metadata analysis failed: {str(e)}",
                trace_type="metadata",
                target=target
            )
    
    def _execute_comprehensive_trace(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive trace combining all methods"""
        
        try:
            comprehensive_results = {}
            
            # Network analysis
            try:
                comprehensive_results["network"] = self._execute_network_trace(target, options.get("network", {}))
            except Exception as e:
                comprehensive_results["network"] = {"error": str(e)}
            
            # OSINT collection
            try:
                comprehensive_results["osint"] = self._execute_osint_collection(target, options.get("osint", {}))
            except Exception as e:
                comprehensive_results["osint"] = {"error": str(e)}
            
            # If target is a file path, add digital forensics and metadata
            if self._is_file_path(target):
                try:
                    comprehensive_results["digital_forensics"] = self._execute_digital_forensics(target, options.get("digital_forensics", {}))
                except Exception as e:
                    comprehensive_results["digital_forensics"] = {"error": str(e)}
                
                try:
                    comprehensive_results["metadata"] = self._execute_metadata_analysis(target, options.get("metadata", {}))
                except Exception as e:
                    comprehensive_results["metadata"] = {"error": str(e)}
            
            return {
                "trace_type": "comprehensive",
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "results": comprehensive_results,
                "summary": self._generate_comprehensive_summary(comprehensive_results)
            }
            
        except Exception as e:
            raise CybertraceException(
                f"Comprehensive trace failed: {str(e)}",
                trace_type="comprehensive",
                target=target
            )
    
    def _is_file_path(self, target: str) -> bool:
        """Check if target is a file path"""
        
        from pathlib import Path
        return Path(target).exists() and Path(target).is_file()
    
    def _generate_network_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for network trace results"""
        
        summary = {
            "total_checks": len(results),
            "successful_checks": len([r for r in results.values() if not isinstance(r, dict) or "error" not in r]),
            "ip_addresses": [],
            "open_ports": [],
            "technologies": []
        }
        
        # Extract IP addresses
        if "dns" in results and "A" in results["dns"]:
            summary["ip_addresses"] = results["dns"]["A"]
        
        # Extract open ports
        if "port_scan" in results and "open_ports" in results["port_scan"]:
            summary["open_ports"] = results["port_scan"]["open_ports"]
        
        # Extract technologies
        if "http_headers" in results and "server" in results["http_headers"]:
            summary["technologies"].append(results["http_headers"]["server"])
        
        return summary
    
    def _generate_forensics_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for digital forensics results"""
        
        summary = {
            "file_analyzed": True,
            "file_type": None,
            "file_size": None,
            "hash_algorithms": [],
            "metadata_fields": 0
        }
        
        if "file_analysis" in results:
            summary["file_type"] = results["file_analysis"].get("file_type")
            summary["file_size"] = results["file_analysis"].get("file_size")
        
        if "file_hashes" in results:
            summary["hash_algorithms"] = list(results["file_hashes"].keys())
        
        if "metadata" in results:
            summary["metadata_fields"] = len(results["metadata"])
        
        return summary
    
    def _generate_osint_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for OSINT results"""
        
        summary = {
            "sources_checked": len(results),
            "total_results": 0,
            "social_media_profiles": 0,
            "subdomains_found": 0,
            "breach_records": 0
        }
        
        if "social_media" in results:
            summary["social_media_profiles"] = len(results["social_media"])
        
        if "subdomains" in results:
            summary["subdomains_found"] = len(results["subdomains"])
        
        if "breach_data" in results:
            summary["breach_records"] = len(results["breach_data"])
        
        summary["total_results"] = sum([
            summary["social_media_profiles"],
            summary["subdomains_found"],
            summary["breach_records"]
        ])
        
        return summary
    
    def _generate_metadata_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for metadata analysis results"""
        
        summary = {
            "metadata_sources": len(results),
            "total_fields": 0,
            "sensitive_data_found": False,
            "creation_date": None,
            "author_info": None
        }
        
        for source, data in results.items():
            if isinstance(data, dict):
                summary["total_fields"] += len(data)
                
                # Check for sensitive data
                if any(key.lower() in ["author", "creator", "user", "owner"] for key in data.keys()):
                    summary["sensitive_data_found"] = True
                
                # Extract creation date
                for key, value in data.items():
                    if "create" in key.lower() or "date" in key.lower():
                        summary["creation_date"] = value
                        break
        
        return summary
    
    def _generate_comprehensive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for comprehensive trace results"""
        
        summary = {
            "trace_modules": len(results),
            "successful_modules": len([r for r in results.values() if "error" not in r]),
            "total_data_points": 0,
            "risk_indicators": []
        }
        
        # Count total data points
        for module, data in results.items():
            if isinstance(data, dict) and "results" in data:
                if isinstance(data["results"], dict):
                    summary["total_data_points"] += len(data["results"])
        
        # Identify risk indicators
        if "network" in results and "results" in results["network"]:
            network_results = results["network"]["results"]
            if "port_scan" in network_results and network_results["port_scan"].get("open_ports"):
                summary["risk_indicators"].append("Open network ports detected")
        
        if "osint" in results and "results" in results["osint"]:
            osint_results = results["osint"]["results"]
            if "breach_data" in osint_results and osint_results["breach_data"]:
                summary["risk_indicators"].append("Data breach records found")
        
        return summary
    
    def get_status(self) -> Dict[str, Any]:
        """Get cybertrace engine status"""
        
        return {
            "active_traces": len(self.active_traces),
            "completed_traces": len(self.completed_traces),
            "max_concurrent_traces": self.max_concurrent_traces,
            "components_status": {
                "network_tracer": "OK",
                "digital_forensics": "OK",
                "osint_collector": "OK",
                "metadata_analyzer": "OK"
            }
        }
    
    def get_case_results(self, case_id: str) -> List[Dict[str, Any]]:
        """Get all cybertrace results for a case"""
        
        return self.trace_results.get(case_id, [])
    
    def get_trace_history(self) -> List[Dict[str, Any]]:
        """Get trace execution history"""
        
        history = list(self.completed_traces.values())
        return sorted(history, key=lambda x: x["start_time"], reverse=True)
    
    def cancel_trace(self, trace_id: str) -> bool:
        """Cancel active trace"""
        
        if trace_id in self.active_traces:
            # In a real implementation, this would cancel the running operation
            trace_record = self.active_traces[trace_id]
            trace_record["status"] = "CANCELLED"
            trace_record["end_time"] = datetime.utcnow().isoformat()
            
            self.completed_traces[trace_id] = trace_record
            del self.active_traces[trace_id]
            
            if self.logger:
                self.logger.info(f"Trace cancelled: {trace_id}")
            
            return True
        
        return False
    
    def cleanup_old_traces(self, max_age_hours: int = 24):
        """Clean up old trace records"""
        
        cutoff_time = datetime.utcnow().timestamp() - (max_age_hours * 3600)
        
        to_remove = []
        for trace_id, trace_record in self.completed_traces.items():
            trace_time = datetime.fromisoformat(trace_record["start_time"]).timestamp()
            if trace_time < cutoff_time:
                to_remove.append(trace_id)
        
        for trace_id in to_remove:
            del self.completed_traces[trace_id]
        
        if self.logger:
            self.logger.info(f"Cleaned up {len(to_remove)} old trace records")
        
        return len(to_remove)