"""
Professional Investigation System - Evidence Management Module
Comprehensive evidence collection, storage, and chain of custody management
"""

from .evidence_manager import EvidenceManager
from .chain_of_custody import ChainOfCustody
from .evidence_collector import EvidenceCollector
from .evidence_analyzer import EvidenceAnalyzer

__all__ = [
    'EvidenceManager',
    'ChainOfCustody',
    'EvidenceCollector',
    'EvidenceAnalyzer'
]