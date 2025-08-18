"""
Professional Investigation System - Evidence Collector
Automated evidence collection from various sources
"""

import os
import shutil
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import json
import requests

from ..core.exceptions import EvidenceException


class EvidenceCollector:
    """Automated evidence collection for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Configuration
        self.temp_dir = Path(tempfile.gettempdir()) / "evidence_collection"
        self.temp_dir.mkdir(exist_ok=True)
        
        if self.logger:
            self.logger.info("EvidenceCollector initialized")
    
    def collect(self, evidence_type: str, source: str, evidence_id: str,
               metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect evidence based on type and source"""
        
        try:
            collection_result = {
                "evidence_id": evidence_id,
                "evidence_type": evidence_type,
                "source": source,
                "collected_at": datetime.utcnow().isoformat(),
                "metadata": metadata,
                "files": [],
                "data": {},
                "status": "success"
            }
            
            # Dispatch to appropriate collection method
            if evidence_type == "file":
                result = self._collect_file_evidence(source, evidence_id, metadata)
            elif evidence_type == "directory":
                result = self._collect_directory_evidence(source, evidence_id, metadata)
            elif evidence_type == "url":
                result = self._collect_url_evidence(source, evidence_id, metadata)
            elif evidence_type == "network_capture":
                result = self._collect_network_evidence(source, evidence_id, metadata)
            elif evidence_type == "system_info":
                result = self._collect_system_evidence(source, evidence_id, metadata)
            elif evidence_type == "process_list":
                result = self._collect_process_evidence(source, evidence_id, metadata)
            elif evidence_type == "registry":
                result = self._collect_registry_evidence(source, evidence_id, metadata)
            elif evidence_type == "memory_dump":
                result = self._collect_memory_evidence(source, evidence_id, metadata)
            else:
                raise EvidenceException(
                    f"Unknown evidence type: {evidence_type}",
                    operation="collection"
                )
            
            # Merge results
            collection_result.update(result)
            
            if self.logger:
                self.logger.info(f"Evidence collection completed: {evidence_id}")
            
            return collection_result
            
        except Exception as e:
            error_msg = f"Evidence collection failed: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                operation="collection",
                context={"evidence_type": evidence_type, "source": source}
            )
    
    def _collect_file_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect single file evidence"""
        
        try:
            source_path = Path(source)
            
            if not source_path.exists():
                raise EvidenceException(f"Source file not found: {source}")
            
            if not source_path.is_file():
                raise EvidenceException(f"Source is not a file: {source}")
            
            # Create temporary copy
            temp_file = self.temp_dir / f"{evidence_id}_{source_path.name}"
            shutil.copy2(source_path, temp_file)
            
            file_info = {
                "name": source_path.name,
                "path": str(temp_file),
                "original_path": str(source_path),
                "size": source_path.stat().st_size,
                "modified": datetime.fromtimestamp(source_path.stat().st_mtime).isoformat(),
                "created": datetime.fromtimestamp(source_path.stat().st_ctime).isoformat()
            }
            
            return {
                "files": [file_info],
                "data": {
                    "collection_type": "file",
                    "file_metadata": file_info
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"File collection failed: {str(e)}")
    
    def _collect_directory_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect directory evidence"""
        
        try:
            source_path = Path(source)
            
            if not source_path.exists():
                raise EvidenceException(f"Source directory not found: {source}")
            
            if not source_path.is_dir():
                raise EvidenceException(f"Source is not a directory: {source}")
            
            # Create temporary directory
            temp_dir = self.temp_dir / f"{evidence_id}_directory"
            temp_dir.mkdir(exist_ok=True)
            
            # Copy directory contents
            shutil.copytree(source_path, temp_dir / source_path.name, dirs_exist_ok=True)
            
            # Collect file list
            files = []
            for file_path in (temp_dir / source_path.name).rglob('*'):
                if file_path.is_file():
                    relative_path = file_path.relative_to(temp_dir / source_path.name)
                    files.append({
                        "name": file_path.name,
                        "path": str(file_path),
                        "relative_path": str(relative_path),
                        "size": file_path.stat().st_size,
                        "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                    })
            
            return {
                "files": files,
                "data": {
                    "collection_type": "directory",
                    "source_directory": str(source_path),
                    "file_count": len(files),
                    "total_size": sum(f["size"] for f in files)
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"Directory collection failed: {str(e)}")
    
    def _collect_url_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect URL evidence"""
        
        try:
            # Download webpage
            response = requests.get(source, timeout=30)
            response.raise_for_status()
            
            # Save webpage content
            temp_file = self.temp_dir / f"{evidence_id}_webpage.html"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            # Save headers
            headers_file = self.temp_dir / f"{evidence_id}_headers.json"
            with open(headers_file, 'w') as f:
                json.dump(dict(response.headers), f, indent=2)
            
            files = [
                {
                    "name": "webpage.html",
                    "path": str(temp_file),
                    "size": temp_file.stat().st_size,
                    "type": "webpage_content"
                },
                {
                    "name": "headers.json",
                    "path": str(headers_file),
                    "size": headers_file.stat().st_size,
                    "type": "http_headers"
                }
            ]
            
            return {
                "files": files,
                "data": {
                    "collection_type": "url",
                    "url": source,
                    "status_code": response.status_code,
                    "content_type": response.headers.get('Content-Type', ''),
                    "content_length": len(response.content),
                    "response_time": response.elapsed.total_seconds()
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"URL collection failed: {str(e)}")
    
    def _collect_network_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect network evidence (simulated)"""
        
        try:
            # Simulate network capture
            capture_data = {
                "interface": source,
                "captured_at": datetime.utcnow().isoformat(),
                "duration": metadata.get("duration", 60),
                "packet_count": 0,
                "protocols": []
            }
            
            # Save capture data
            capture_file = self.temp_dir / f"{evidence_id}_network_capture.json"
            with open(capture_file, 'w') as f:
                json.dump(capture_data, f, indent=2)
            
            return {
                "files": [{
                    "name": "network_capture.json",
                    "path": str(capture_file),
                    "size": capture_file.stat().st_size,
                    "type": "network_capture"
                }],
                "data": {
                    "collection_type": "network_capture",
                    "interface": source,
                    "capture_summary": capture_data
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"Network evidence collection failed: {str(e)}")
    
    def _collect_system_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect system information evidence"""
        
        try:
            system_info = {
                "collected_at": datetime.utcnow().isoformat(),
                "hostname": os.uname().nodename if hasattr(os, 'uname') else "unknown",
                "platform": os.name,
                "working_directory": os.getcwd(),
                "environment_variables": dict(os.environ),
                "process_id": os.getpid(),
                "user_id": os.getuid() if hasattr(os, 'getuid') else None
            }
            
            # Save system info
            info_file = self.temp_dir / f"{evidence_id}_system_info.json"
            with open(info_file, 'w') as f:
                json.dump(system_info, f, indent=2, default=str)
            
            return {
                "files": [{
                    "name": "system_info.json",
                    "path": str(info_file),
                    "size": info_file.stat().st_size,
                    "type": "system_information"
                }],
                "data": {
                    "collection_type": "system_info",
                    "system_summary": {
                        "hostname": system_info["hostname"],
                        "platform": system_info["platform"],
                        "collected_at": system_info["collected_at"]
                    }
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"System evidence collection failed: {str(e)}")
    
    def _collect_process_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect process list evidence"""
        
        try:
            # Use ps command to get process list (Unix-like systems)
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=30)
                process_list = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Fallback for Windows or if ps is not available
                process_list = "Process collection not available on this system"
            
            # Save process list
            process_file = self.temp_dir / f"{evidence_id}_processes.txt"
            with open(process_file, 'w') as f:
                f.write(process_list)
            
            return {
                "files": [{
                    "name": "processes.txt",
                    "path": str(process_file),
                    "size": process_file.stat().st_size,
                    "type": "process_list"
                }],
                "data": {
                    "collection_type": "process_list",
                    "collected_at": datetime.utcnow().isoformat(),
                    "process_count": len(process_list.split('\n')) - 1 if process_list else 0
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"Process evidence collection failed: {str(e)}")
    
    def _collect_registry_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect Windows registry evidence (simulated)"""
        
        try:
            # Simulated registry collection
            registry_data = {
                "collected_at": datetime.utcnow().isoformat(),
                "registry_path": source,
                "note": "Registry collection requires Windows-specific implementation"
            }
            
            # Save registry data
            registry_file = self.temp_dir / f"{evidence_id}_registry.json"
            with open(registry_file, 'w') as f:
                json.dump(registry_data, f, indent=2)
            
            return {
                "files": [{
                    "name": "registry.json",
                    "path": str(registry_file),
                    "size": registry_file.stat().st_size,
                    "type": "registry_data"
                }],
                "data": {
                    "collection_type": "registry",
                    "registry_path": source,
                    "note": "Simulated registry collection"
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"Registry evidence collection failed: {str(e)}")
    
    def _collect_memory_evidence(self, source: str, evidence_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Collect memory dump evidence (simulated)"""
        
        try:
            # Simulated memory dump
            memory_info = {
                "collected_at": datetime.utcnow().isoformat(),
                "process_id": source,
                "note": "Memory dump collection requires specialized tools"
            }
            
            # Save memory info
            memory_file = self.temp_dir / f"{evidence_id}_memory_info.json"
            with open(memory_file, 'w') as f:
                json.dump(memory_info, f, indent=2)
            
            return {
                "files": [{
                    "name": "memory_info.json",
                    "path": str(memory_file),
                    "size": memory_file.stat().st_size,
                    "type": "memory_dump"
                }],
                "data": {
                    "collection_type": "memory_dump",
                    "process_id": source,
                    "note": "Simulated memory dump collection"
                }
            }
            
        except Exception as e:
            raise EvidenceException(f"Memory evidence collection failed: {str(e)}")
    
    def cleanup_temp_files(self, evidence_id: str):
        """Clean up temporary files for evidence"""
        
        try:
            # Remove temporary files for this evidence
            for file_path in self.temp_dir.glob(f"{evidence_id}_*"):
                if file_path.is_file():
                    file_path.unlink()
                elif file_path.is_dir():
                    shutil.rmtree(file_path)
            
            if self.logger:
                self.logger.info(f"Temporary files cleaned up for evidence: {evidence_id}")
                
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Failed to cleanup temp files: {str(e)}")
    
    def get_supported_evidence_types(self) -> List[str]:
        """Get list of supported evidence types"""
        
        return [
            "file",
            "directory", 
            "url",
            "network_capture",
            "system_info",
            "process_list",
            "registry",
            "memory_dump"
        ]