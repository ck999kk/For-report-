"""
Professional Investigation System - Evidence Manager
Comprehensive evidence management with chain of custody and integrity verification
"""

import os
import json
import hashlib
import shutil
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import uuid

from ..core.exceptions import EvidenceException
from .chain_of_custody import ChainOfCustody
from .evidence_collector import EvidenceCollector
from .evidence_analyzer import EvidenceAnalyzer


class EvidenceManager:
    """Advanced evidence management for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Configuration
        self.storage_path = Path(self.config.get("storage_path", "evidence_storage"))
        self.enable_versioning = self.config.get("enable_versioning", True)
        self.enable_compression = self.config.get("compression", True)
        self.enable_encryption = self.config.get("encryption", True)
        self.backup_enabled = self.config.get("backup_enabled", True)
        self.max_file_size = self.config.get("max_file_size", 1024 * 1024 * 1024)  # 1GB
        
        # Initialize storage structure
        self._initialize_storage()
        
        # Initialize components
        self.chain_of_custody = ChainOfCustody(config, logger, security)
        self.evidence_collector = EvidenceCollector(config, logger, security)
        self.evidence_analyzer = EvidenceAnalyzer(config, logger, security)
        
        # Evidence registry
        self.evidence_registry = {}
        self._load_evidence_registry()
        
        if self.logger:
            self.logger.info("EvidenceManager initialized")
    
    def _initialize_storage(self):
        """Initialize evidence storage structure"""
        
        try:
            # Create directory structure
            directories = [
                self.storage_path,
                self.storage_path / "cases",
                self.storage_path / "evidence",
                self.storage_path / "temp",
                self.storage_path / "backups",
                self.storage_path / "registry"
            ]
            
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
            
            # Create evidence registry file if it doesn't exist
            registry_file = self.storage_path / "registry" / "evidence_registry.json"
            if not registry_file.exists():
                with open(registry_file, 'w') as f:
                    json.dump({}, f, indent=2)
            
            if self.logger:
                self.logger.info(f"Evidence storage initialized at {self.storage_path}")
                
        except Exception as e:
            raise EvidenceException(
                f"Failed to initialize evidence storage: {str(e)}",
                operation="initialization"
            )
    
    def collect_evidence(self, case_id: str, evidence_type: str, source: str,
                        metadata: Dict[str, Any] = None) -> str:
        """Collect and store evidence"""
        
        try:
            # Generate evidence ID
            evidence_id = str(uuid.uuid4())
            
            # Collect evidence based on type
            collection_result = self.evidence_collector.collect(
                evidence_type=evidence_type,
                source=source,
                evidence_id=evidence_id,
                metadata=metadata or {}
            )
            
            # Store evidence
            storage_result = self._store_evidence(
                evidence_id=evidence_id,
                case_id=case_id,
                evidence_type=evidence_type,
                collection_result=collection_result,
                metadata=metadata or {}
            )
            
            # Initialize chain of custody
            self.chain_of_custody.initialize_evidence(
                evidence_id=evidence_id,
                case_id=case_id,
                collector="system",
                initial_metadata=metadata or {}
            )
            
            # Register evidence
            self._register_evidence(evidence_id, case_id, storage_result)
            
            # Log evidence collection
            if self.logger:
                self.logger.log_evidence(
                    evidence_id=evidence_id,
                    action="COLLECTED",
                    data={
                        "case_id": case_id,
                        "evidence_type": evidence_type,
                        "source": source,
                        "storage_result": storage_result
                    }
                )
            
            return evidence_id
            
        except Exception as e:
            error_msg = f"Evidence collection failed: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                operation="collection",
                context={"case_id": case_id, "evidence_type": evidence_type}
            )
    
    def _store_evidence(self, evidence_id: str, case_id: str, evidence_type: str,
                       collection_result: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Store evidence with proper structure and integrity"""
        
        try:
            # Create evidence directory
            evidence_dir = self.storage_path / "evidence" / evidence_id
            evidence_dir.mkdir(parents=True, exist_ok=True)
            
            storage_result = {
                "evidence_id": evidence_id,
                "case_id": case_id,
                "evidence_type": evidence_type,
                "storage_path": str(evidence_dir),
                "stored_at": datetime.utcnow().isoformat(),
                "files": [],
                "integrity": {}
            }
            
            # Store collected data
            if "files" in collection_result:
                for file_info in collection_result["files"]:
                    stored_file = self._store_file(
                        evidence_dir,
                        file_info["path"],
                        file_info.get("name", Path(file_info["path"]).name)
                    )
                    storage_result["files"].append(stored_file)
            
            if "data" in collection_result:
                # Store raw data
                data_file = evidence_dir / "raw_data.json"
                with open(data_file, 'w') as f:
                    json.dump(collection_result["data"], f, indent=2, default=str)
                
                stored_file = self._calculate_file_integrity(data_file)
                storage_result["files"].append(stored_file)
            
            # Store metadata
            metadata_file = evidence_dir / "metadata.json"
            complete_metadata = {
                "evidence_id": evidence_id,
                "case_id": case_id,
                "evidence_type": evidence_type,
                "collection_metadata": metadata,
                "collection_result": collection_result,
                "storage_metadata": storage_result
            }
            
            with open(metadata_file, 'w') as f:
                json.dump(complete_metadata, f, indent=2, default=str)
            
            metadata_integrity = self._calculate_file_integrity(metadata_file)
            storage_result["files"].append(metadata_integrity)
            
            # Calculate overall integrity
            storage_result["integrity"] = self._calculate_evidence_integrity(storage_result)
            
            # Create backup if enabled
            if self.backup_enabled:
                self._create_evidence_backup(evidence_id, evidence_dir)
            
            return storage_result
            
        except Exception as e:
            raise EvidenceException(
                f"Evidence storage failed: {str(e)}",
                evidence_id=evidence_id,
                operation="storage"
            )
    
    def _store_file(self, evidence_dir: Path, source_path: str, file_name: str) -> Dict[str, Any]:
        """Store a single file with integrity verification"""
        
        try:
            source_path = Path(source_path)
            
            if not source_path.exists():
                raise EvidenceException(
                    f"Source file not found: {source_path}",
                    operation="file_storage"
                )
            
            # Check file size
            file_size = source_path.stat().st_size
            if file_size > self.max_file_size:
                raise EvidenceException(
                    f"File too large: {file_size} bytes (max: {self.max_file_size})",
                    operation="file_storage"
                )
            
            # Determine destination path
            dest_path = evidence_dir / file_name
            
            # Copy file
            shutil.copy2(source_path, dest_path)
            
            # Calculate integrity
            file_info = self._calculate_file_integrity(dest_path)
            file_info["original_path"] = str(source_path)
            file_info["stored_name"] = file_name
            
            # Compress if enabled and beneficial
            if self.enable_compression and file_size > 1024:  # > 1KB
                compressed_path = self._compress_file(dest_path)
                if compressed_path:
                    file_info["compressed"] = True
                    file_info["compressed_path"] = str(compressed_path)
                    file_info["compression_ratio"] = compressed_path.stat().st_size / file_size
            
            # Encrypt if enabled
            if self.enable_encryption and self.security:
                encrypted_path = self._encrypt_file(dest_path)
                if encrypted_path:
                    file_info["encrypted"] = True
                    file_info["encrypted_path"] = str(encrypted_path)
            
            return file_info
            
        except Exception as e:
            raise EvidenceException(
                f"File storage failed: {str(e)}",
                operation="file_storage",
                context={"source_path": source_path, "file_name": file_name}
            )
    
    def _calculate_file_integrity(self, file_path: Path) -> Dict[str, Any]:
        """Calculate file integrity hashes"""
        
        try:
            file_info = {
                "path": str(file_path),
                "name": file_path.name,
                "size": file_path.stat().st_size,
                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                "hashes": {}
            }
            
            # Calculate multiple hashes
            hash_algorithms = ["md5", "sha1", "sha256", "sha512"]
            
            with open(file_path, 'rb') as f:
                hash_objects = {alg: hashlib.new(alg) for alg in hash_algorithms}
                
                while chunk := f.read(8192):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
                
                for alg, hash_obj in hash_objects.items():
                    file_info["hashes"][alg] = hash_obj.hexdigest()
            
            return file_info
            
        except Exception as e:
            raise EvidenceException(
                f"Integrity calculation failed: {str(e)}",
                operation="integrity_calculation"
            )
    
    def _calculate_evidence_integrity(self, storage_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall evidence integrity"""
        
        try:
            # Combine all file hashes
            all_hashes = []
            for file_info in storage_result["files"]:
                if "hashes" in file_info:
                    all_hashes.extend(file_info["hashes"].values())
            
            # Create evidence hash from combined file hashes
            evidence_hash = hashlib.sha256()
            for file_hash in sorted(all_hashes):
                evidence_hash.update(file_hash.encode())
            
            integrity = {
                "evidence_hash": evidence_hash.hexdigest(),
                "file_count": len(storage_result["files"]),
                "total_size": sum(f.get("size", 0) for f in storage_result["files"]),
                "calculated_at": datetime.utcnow().isoformat()
            }
            
            return integrity
            
        except Exception as e:
            return {"error": str(e)}
    
    def _compress_file(self, file_path: Path) -> Optional[Path]:
        """Compress file if beneficial"""
        
        try:
            compressed_path = file_path.with_suffix(file_path.suffix + '.zip')
            
            with zipfile.ZipFile(compressed_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(file_path, file_path.name)
            
            # Check if compression was beneficial (>10% reduction)
            original_size = file_path.stat().st_size
            compressed_size = compressed_path.stat().st_size
            
            if compressed_size < original_size * 0.9:
                return compressed_path
            else:
                # Remove compressed file if not beneficial
                compressed_path.unlink()
                return None
                
        except Exception:
            return None
    
    def _encrypt_file(self, file_path: Path) -> Optional[Path]:
        """Encrypt file using security manager"""
        
        try:
            if not self.security:
                return None
            
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Encrypt content
            encrypted_content = self.security.encrypt_data(content.decode('latin-1'))
            
            # Write encrypted file
            encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
            with open(encrypted_path, 'w') as f:
                f.write(encrypted_content)
            
            return encrypted_path
            
        except Exception:
            return None
    
    def _create_evidence_backup(self, evidence_id: str, evidence_dir: Path):
        """Create backup of evidence"""
        
        try:
            backup_dir = self.storage_path / "backups"
            backup_file = backup_dir / f"{evidence_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
            
            with zipfile.ZipFile(backup_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in evidence_dir.rglob('*'):
                    if file_path.is_file():
                        zf.write(file_path, file_path.relative_to(evidence_dir))
            
            if self.logger:
                self.logger.info(f"Evidence backup created: {backup_file}")
                
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Failed to create evidence backup: {str(e)}")
    
    def _register_evidence(self, evidence_id: str, case_id: str, storage_result: Dict[str, Any]):
        """Register evidence in the registry"""
        
        try:
            registry_entry = {
                "evidence_id": evidence_id,
                "case_id": case_id,
                "registered_at": datetime.utcnow().isoformat(),
                "storage_info": storage_result,
                "status": "active"
            }
            
            self.evidence_registry[evidence_id] = registry_entry
            self._save_evidence_registry()
            
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Failed to register evidence: {str(e)}")
    
    def _load_evidence_registry(self):
        """Load evidence registry from file"""
        
        try:
            registry_file = self.storage_path / "registry" / "evidence_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    self.evidence_registry = json.load(f)
            else:
                self.evidence_registry = {}
                
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Failed to load evidence registry: {str(e)}")
            self.evidence_registry = {}
    
    def _save_evidence_registry(self):
        """Save evidence registry to file"""
        
        try:
            registry_file = self.storage_path / "registry" / "evidence_registry.json"
            with open(registry_file, 'w') as f:
                json.dump(self.evidence_registry, f, indent=2, default=str)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to save evidence registry: {str(e)}")
    
    def get_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Retrieve evidence information"""
        
        try:
            if evidence_id not in self.evidence_registry:
                raise EvidenceException(
                    f"Evidence not found: {evidence_id}",
                    evidence_id=evidence_id,
                    operation="retrieval"
                )
            
            evidence_info = self.evidence_registry[evidence_id].copy()
            
            # Add chain of custody information
            evidence_info["chain_of_custody"] = self.chain_of_custody.get_chain(evidence_id)
            
            # Verify integrity
            evidence_info["integrity_check"] = self.verify_evidence_integrity(evidence_id)
            
            return evidence_info
            
        except Exception as e:
            error_msg = f"Evidence retrieval failed: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="retrieval"
            )
    
    def verify_evidence_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """Verify evidence integrity"""
        
        try:
            if evidence_id not in self.evidence_registry:
                return {"status": "error", "message": "Evidence not found"}
            
            evidence_info = self.evidence_registry[evidence_id]
            storage_info = evidence_info["storage_info"]
            
            integrity_check = {
                "evidence_id": evidence_id,
                "checked_at": datetime.utcnow().isoformat(),
                "status": "valid",
                "issues": [],
                "file_checks": []
            }
            
            # Check each file
            for file_info in storage_info["files"]:
                file_path = Path(file_info["path"])
                
                if not file_path.exists():
                    integrity_check["status"] = "invalid"
                    integrity_check["issues"].append(f"Missing file: {file_path}")
                    continue
                
                # Recalculate hash
                current_hash = self._calculate_file_hash(file_path, "sha256")
                stored_hash = file_info["hashes"]["sha256"]
                
                file_check = {
                    "file": str(file_path),
                    "hash_match": current_hash == stored_hash,
                    "stored_hash": stored_hash,
                    "current_hash": current_hash
                }
                
                integrity_check["file_checks"].append(file_check)
                
                if not file_check["hash_match"]:
                    integrity_check["status"] = "invalid"
                    integrity_check["issues"].append(f"Hash mismatch: {file_path}")
            
            # Log integrity check
            if self.logger:
                self.logger.log_evidence(
                    evidence_id=evidence_id,
                    action="INTEGRITY_CHECK",
                    data=integrity_check
                )
            
            return integrity_check
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "checked_at": datetime.utcnow().isoformat()
            }
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate file hash"""
        
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def list_evidence(self, case_id: str = None) -> List[Dict[str, Any]]:
        """List evidence (optionally filtered by case)"""
        
        try:
            evidence_list = []
            
            for evidence_id, evidence_info in self.evidence_registry.items():
                if case_id is None or evidence_info["case_id"] == case_id:
                    # Create summary information
                    summary = {
                        "evidence_id": evidence_id,
                        "case_id": evidence_info["case_id"],
                        "evidence_type": evidence_info["storage_info"]["evidence_type"],
                        "registered_at": evidence_info["registered_at"],
                        "file_count": len(evidence_info["storage_info"]["files"]),
                        "total_size": evidence_info["storage_info"]["integrity"].get("total_size", 0),
                        "status": evidence_info["status"]
                    }
                    evidence_list.append(summary)
            
            return evidence_list
            
        except Exception as e:
            error_msg = f"Evidence listing failed: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(error_msg, operation="listing")
    
    def analyze_evidence(self, evidence_id: str, analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """Analyze evidence using evidence analyzer"""
        
        try:
            if evidence_id not in self.evidence_registry:
                raise EvidenceException(
                    f"Evidence not found: {evidence_id}",
                    evidence_id=evidence_id,
                    operation="analysis"
                )
            
            evidence_info = self.evidence_registry[evidence_id]
            storage_info = evidence_info["storage_info"]
            
            # Perform analysis
            analysis_results = self.evidence_analyzer.analyze(
                evidence_id=evidence_id,
                evidence_files=storage_info["files"],
                analysis_type=analysis_type
            )
            
            # Update chain of custody
            self.chain_of_custody.add_event(
                evidence_id=evidence_id,
                event_type="ANALYZED",
                actor="system",
                details={"analysis_type": analysis_type}
            )
            
            # Log analysis
            if self.logger:
                self.logger.log_evidence(
                    evidence_id=evidence_id,
                    action="ANALYZED",
                    data={
                        "analysis_type": analysis_type,
                        "results_summary": analysis_results.get("summary", {})
                    }
                )
            
            return analysis_results
            
        except Exception as e:
            error_msg = f"Evidence analysis failed: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="analysis"
            )
    
    def export_evidence(self, evidence_id: str, export_path: str, include_analysis: bool = True) -> str:
        """Export evidence package"""
        
        try:
            if evidence_id not in self.evidence_registry:
                raise EvidenceException(
                    f"Evidence not found: {evidence_id}",
                    evidence_id=evidence_id,
                    operation="export"
                )
            
            export_path = Path(export_path)
            export_path.mkdir(parents=True, exist_ok=True)
            
            evidence_info = self.evidence_registry[evidence_id]
            storage_info = evidence_info["storage_info"]
            
            # Create export package
            export_file = export_path / f"evidence_{evidence_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
            
            with zipfile.ZipFile(export_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add evidence files
                for file_info in storage_info["files"]:
                    file_path = Path(file_info["path"])
                    if file_path.exists():
                        zf.write(file_path, f"evidence/{file_path.name}")
                
                # Add chain of custody
                chain = self.chain_of_custody.get_chain(evidence_id)
                chain_json = json.dumps(chain, indent=2, default=str)
                zf.writestr("chain_of_custody.json", chain_json)
                
                # Add evidence information
                evidence_json = json.dumps(evidence_info, indent=2, default=str)
                zf.writestr("evidence_info.json", evidence_json)
                
                # Add analysis if requested
                if include_analysis:
                    try:
                        analysis = self.analyze_evidence(evidence_id)
                        analysis_json = json.dumps(analysis, indent=2, default=str)
                        zf.writestr("analysis_results.json", analysis_json)
                    except Exception as e:
                        zf.writestr("analysis_error.txt", f"Analysis failed: {str(e)}")
            
            # Update chain of custody
            self.chain_of_custody.add_event(
                evidence_id=evidence_id,
                event_type="EXPORTED",
                actor="system",
                details={"export_path": str(export_file)}
            )
            
            # Log export
            if self.logger:
                self.logger.log_evidence(
                    evidence_id=evidence_id,
                    action="EXPORTED",
                    data={"export_file": str(export_file)}
                )
            
            return str(export_file)
            
        except Exception as e:
            error_msg = f"Evidence export failed: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="export"
            )
    
    def get_status(self) -> Dict[str, Any]:
        """Get evidence manager status"""
        
        try:
            total_evidence = len(self.evidence_registry)
            total_size = 0
            active_cases = set()
            
            for evidence_info in self.evidence_registry.values():
                total_size += evidence_info["storage_info"]["integrity"].get("total_size", 0)
                active_cases.add(evidence_info["case_id"])
            
            return {
                "total_evidence": total_evidence,
                "active_cases": len(active_cases),
                "total_storage_size": total_size,
                "storage_size_human": self._format_file_size(total_size),
                "storage_path": str(self.storage_path),
                "configuration": {
                    "versioning_enabled": self.enable_versioning,
                    "compression_enabled": self.enable_compression,
                    "encryption_enabled": self.enable_encryption,
                    "backup_enabled": self.backup_enabled
                }
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size = float(size_bytes)
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.2f} {units[unit_index]}"