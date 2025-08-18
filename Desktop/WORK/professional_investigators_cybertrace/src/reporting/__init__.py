"""
Professional Investigation System - Reporting Module
Professional report generation for investigations
"""

from .report_generator import ReportGenerator
from .report_templates import ReportTemplates

__all__ = [
    'ReportGenerator',
    'ReportTemplates'
]