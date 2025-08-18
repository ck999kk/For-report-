"""
Phone Intelligence Module
Professional Investigators & Cybertrace System

Comprehensive phone number investigation and intelligence gathering system
with legal-grade evidence management and OSINT capabilities.
"""

from .phone_intelligence_engine import PhoneIntelligenceEngine
from .carrier_intelligence import CarrierIntelligence
from .osint_phone_collector import OSINTPhoneCollector
from .social_media_profiler import SocialMediaProfiler
from .breach_database_checker import BreachDatabaseChecker
from .geographic_analyzer import GeographicAnalyzer
from .risk_assessor import RiskAssessor
from .monitoring_engine import MonitoringEngine

__version__ = "1.0.0"
__author__ = "Professional Investigation Team"

__all__ = [
    'PhoneIntelligenceEngine',
    'CarrierIntelligence',
    'OSINTPhoneCollector',
    'SocialMediaProfiler',
    'BreachDatabaseChecker',
    'GeographicAnalyzer',
    'RiskAssessor',
    'MonitoringEngine'
]