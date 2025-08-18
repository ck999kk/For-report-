"""
Professional Investigators & Cybertrace System
Core Framework Module
"""

from .investigator import InvestigatorCore
from .logger import InvestigationLogger
from .config_manager import ConfigurationManager
from .security import SecurityManager
from .exceptions import InvestigationException, CybertraceException

__version__ = "1.0.0"
__author__ = "Professional Investigation Team"

__all__ = [
    'InvestigatorCore',
    'InvestigationLogger', 
    'ConfigurationManager',
    'SecurityManager',
    'InvestigationException',
    'CybertraceException'
]