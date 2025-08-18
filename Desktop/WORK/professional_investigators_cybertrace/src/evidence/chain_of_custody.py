"""
Professional Investigation System - Chain of Custody
Tamper-proof chain of custody tracking for legal evidence
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from ..core.exceptions import EvidenceException


class ChainOfCustody:
    """Tamper-proof chain of custody management"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Configuration
        self.storage_path = Path(self.config.get("storage_path", "evidence_storage")) / "custody"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Chain storage
        self.custody_chains = {}
        
        if self.logger:
            self.logger.info("ChainOfCustody initialized")
    
    def initialize_evidence(self, evidence_id: str, case_id: str, collector: str,
                           initial_metadata: Dict[str, Any] = None) -> str:
        """Initialize chain of custody for new evidence"""
        
        try:
            chain_data = {
                "evidence_id": evidence_id,
                "case_id": case_id,
                "initialized_at": datetime.utcnow().isoformat(),
                "initialized_by": collector,
                "initial_metadata": initial_metadata or {},
                "events": [],
                "integrity_hash": None
            }
            
            # Add initial event
            initial_event = {
                "event_id": self._generate_event_id(),
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "COLLECTED",
                "actor": collector,
                "details": {"action": "Initial evidence collection"},
                "metadata": initial_metadata or {},
                "hash": None
            }
            
            chain_data["events"].append(initial_event)
            
            # Calculate integrity hash
            chain_data["integrity_hash"] = self._calculate_chain_hash(chain_data)
            initial_event["hash"] = self._calculate_event_hash(initial_event)
            
            # Store chain
            self.custody_chains[evidence_id] = chain_data
            self._save_chain(evidence_id)
            
            if self.logger:
                self.logger.log_audit(
                    "CHAIN_OF_CUSTODY_INITIALIZED",
                    evidence_id,
                    "SUCCESS",
                    {"case_id": case_id, "collector": collector}
                )
            
            return initial_event["event_id"]
            
        except Exception as e:
            error_msg = f"Chain of custody initialization failed: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="chain_initialization"
            )
    
    def add_event(self, evidence_id: str, event_type: str, actor: str,
                 details: Dict[str, Any] = None, metadata: Dict[str, Any] = None) -> str:
        """Add event to chain of custody"""
        
        try:
            if evidence_id not in self.custody_chains:
                # Try to load from storage
                if not self._load_chain(evidence_id):
                    raise EvidenceException(
                        f"Chain of custody not found for evidence: {evidence_id}",
                        evidence_id=evidence_id,
                        operation="add_event"
                    )
            
            chain_data = self.custody_chains[evidence_id]
            
            # Create new event
            event = {
                "event_id": self._generate_event_id(),
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "actor": actor,
                "details": details or {},
                "metadata": metadata or {},
                "previous_hash": chain_data["integrity_hash"],
                "hash": None
            }
            
            # Calculate event hash
            event["hash"] = self._calculate_event_hash(event)
            
            # Add to chain
            chain_data["events"].append(event)
            
            # Update chain integrity hash
            chain_data["integrity_hash"] = self._calculate_chain_hash(chain_data)
            chain_data["last_updated"] = datetime.utcnow().isoformat()
            
            # Save updated chain
            self._save_chain(evidence_id)
            
            if self.logger:
                self.logger.log_audit(
                    "CHAIN_OF_CUSTODY_EVENT_ADDED",
                    evidence_id,
                    "SUCCESS",
                    {"event_type": event_type, "actor": actor, "event_id": event["event_id"]}
                )
            
            return event["event_id"]
            
        except Exception as e:
            error_msg = f"Failed to add chain of custody event: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="add_event"
            )
    
    def get_chain(self, evidence_id: str) -> Dict[str, Any]:
        """Get complete chain of custody"""
        
        try:
            if evidence_id not in self.custody_chains:
                if not self._load_chain(evidence_id):
                    raise EvidenceException(
                        f"Chain of custody not found for evidence: {evidence_id}",
                        evidence_id=evidence_id,
                        operation="get_chain"
                    )
            
            chain_data = self.custody_chains[evidence_id].copy()
            
            # Verify chain integrity
            integrity_check = self.verify_chain_integrity(evidence_id)
            chain_data["integrity_verification"] = integrity_check
            
            return chain_data
            
        except Exception as e:
            error_msg = f"Failed to get chain of custody: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="get_chain"
            )
    
    def verify_chain_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """Verify chain of custody integrity"""
        
        try:
            if evidence_id not in self.custody_chains:
                if not self._load_chain(evidence_id):
                    return {"status": "error", "message": "Chain not found"}
            
            chain_data = self.custody_chains[evidence_id]
            
            integrity_check = {
                "evidence_id": evidence_id,
                "verified_at": datetime.utcnow().isoformat(),
                "status": "valid",
                "issues": [],
                "event_verifications": []
            }
            
            # Verify each event
            previous_hash = None
            for i, event in enumerate(chain_data["events"]):
                event_verification = {
                    "event_id": event["event_id"],
                    "sequence": i,
                    "hash_valid": False,
                    "chain_link_valid": False
                }
                
                # Verify event hash
                calculated_hash = self._calculate_event_hash(event, exclude_hash=True)
                if calculated_hash == event.get("hash"):
                    event_verification["hash_valid"] = True
                else:
                    integrity_check["status"] = "invalid"
                    integrity_check["issues"].append(f"Event {event['event_id']} hash mismatch")
                
                # Verify chain linkage
                if i == 0:
                    # First event should not have previous_hash
                    event_verification["chain_link_valid"] = "previous_hash" not in event
                else:
                    # Subsequent events should link to previous
                    expected_previous = previous_hash
                    actual_previous = event.get("previous_hash")
                    event_verification["chain_link_valid"] = (expected_previous == actual_previous)
                    
                    if not event_verification["chain_link_valid"]:
                        integrity_check["status"] = "invalid"
                        integrity_check["issues"].append(f"Event {event['event_id']} chain link broken")
                
                integrity_check["event_verifications"].append(event_verification)
                previous_hash = event.get("hash")
            
            # Verify overall chain hash
            calculated_chain_hash = self._calculate_chain_hash(chain_data, exclude_hash=True)
            if calculated_chain_hash != chain_data.get("integrity_hash"):
                integrity_check["status"] = "invalid"
                integrity_check["issues"].append("Overall chain hash mismatch")
            
            return integrity_check
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "verified_at": datetime.utcnow().isoformat()
            }
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        
        timestamp = datetime.utcnow().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]
    
    def _calculate_event_hash(self, event: Dict[str, Any], exclude_hash: bool = False) -> str:
        """Calculate event hash for integrity verification"""
        
        # Create copy without hash field
        event_copy = event.copy()
        if exclude_hash and "hash" in event_copy:
            del event_copy["hash"]
        
        # Sort keys for consistent hashing
        event_json = json.dumps(event_copy, sort_keys=True, default=str)
        return hashlib.sha256(event_json.encode()).hexdigest()
    
    def _calculate_chain_hash(self, chain_data: Dict[str, Any], exclude_hash: bool = False) -> str:
        """Calculate chain hash for integrity verification"""
        
        # Create copy without integrity_hash field
        chain_copy = chain_data.copy()
        if exclude_hash and "integrity_hash" in chain_copy:
            del chain_copy["integrity_hash"]
        
        # Sort keys for consistent hashing
        chain_json = json.dumps(chain_copy, sort_keys=True, default=str)
        return hashlib.sha256(chain_json.encode()).hexdigest()
    
    def _save_chain(self, evidence_id: str):
        """Save chain of custody to storage"""
        
        try:
            chain_file = self.storage_path / f"{evidence_id}_custody.json"
            
            with open(chain_file, 'w') as f:
                json.dump(self.custody_chains[evidence_id], f, indent=2, default=str)
            
            # Create backup
            backup_file = self.storage_path / f"{evidence_id}_custody_backup.json"
            with open(backup_file, 'w') as f:
                json.dump(self.custody_chains[evidence_id], f, indent=2, default=str)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to save chain of custody: {str(e)}")
            raise EvidenceException(
                f"Failed to save chain of custody: {str(e)}",
                evidence_id=evidence_id,
                operation="save_chain"
            )
    
    def _load_chain(self, evidence_id: str) -> bool:
        """Load chain of custody from storage"""
        
        try:
            chain_file = self.storage_path / f"{evidence_id}_custody.json"
            
            if chain_file.exists():
                with open(chain_file, 'r') as f:
                    self.custody_chains[evidence_id] = json.load(f)
                return True
            
            return False
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load chain of custody: {str(e)}")
            return False
    
    def export_chain(self, evidence_id: str, output_path: str) -> str:
        """Export chain of custody to file"""
        
        try:
            chain_data = self.get_chain(evidence_id)
            
            output_file = Path(output_path) / f"custody_chain_{evidence_id}.json"
            
            with open(output_file, 'w') as f:
                json.dump(chain_data, f, indent=2, default=str)
            
            if self.logger:
                self.logger.log_audit(
                    "CHAIN_OF_CUSTODY_EXPORTED",
                    evidence_id,
                    "SUCCESS",
                    {"output_file": str(output_file)}
                )
            
            return str(output_file)
            
        except Exception as e:
            error_msg = f"Failed to export chain of custody: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="export_chain"
            )
    
    def get_custody_summary(self, evidence_id: str) -> Dict[str, Any]:
        """Get summary of chain of custody"""
        
        try:
            if evidence_id not in self.custody_chains:
                if not self._load_chain(evidence_id):
                    raise EvidenceException(
                        f"Chain of custody not found for evidence: {evidence_id}",
                        evidence_id=evidence_id,
                        operation="get_summary"
                    )
            
            chain_data = self.custody_chains[evidence_id]
            
            # Count events by type
            event_counts = {}
            actors = set()
            
            for event in chain_data["events"]:
                event_type = event["event_type"]
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
                actors.add(event["actor"])
            
            summary = {
                "evidence_id": evidence_id,
                "case_id": chain_data["case_id"],
                "initialized_at": chain_data["initialized_at"],
                "initialized_by": chain_data["initialized_by"],
                "total_events": len(chain_data["events"]),
                "event_types": event_counts,
                "actors_involved": list(actors),
                "last_event": chain_data["events"][-1] if chain_data["events"] else None,
                "integrity_status": self.verify_chain_integrity(evidence_id)["status"]
            }
            
            return summary
            
        except Exception as e:
            error_msg = f"Failed to get custody summary: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise EvidenceException(
                error_msg,
                evidence_id=evidence_id,
                operation="get_summary"
            )