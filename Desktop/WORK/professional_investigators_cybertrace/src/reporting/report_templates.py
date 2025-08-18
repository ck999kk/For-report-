"""
Professional Investigation System - Report Templates
Templates for professional investigation reports
"""

from typing import Dict, Any


class ReportTemplates:
    """Report templates for professional investigations"""
    
    def __init__(self):
        self.templates = {
            "comprehensive": self._comprehensive_template(),
            "executive_summary": self._executive_summary_template(),
            "technical": self._technical_template(),
            "forensics": self._forensics_template(),
            "cybertrace": self._cybertrace_template()
        }
    
    def get_template(self, report_type: str) -> Dict[str, Any]:
        """Get report template by type"""
        
        return self.templates.get(report_type, self._default_template())
    
    def _comprehensive_template(self) -> Dict[str, Any]:
        """Comprehensive investigation report template"""
        
        return {
            "title": "Comprehensive Investigation Report",
            "sections": [
                "Executive Summary",
                "Case Information", 
                "Evidence Summary",
                "Cybertrace Results",
                "Technical Analysis",
                "Findings and Conclusions",
                "Recommendations",
                "Appendices"
            ]
        }
    
    def _executive_summary_template(self) -> Dict[str, Any]:
        """Executive summary template"""
        
        return {
            "title": "Executive Summary",
            "sections": [
                "Overview",
                "Key Findings",
                "Risk Assessment", 
                "Recommendations"
            ]
        }
    
    def _technical_template(self) -> Dict[str, Any]:
        """Technical report template"""
        
        return {
            "title": "Technical Investigation Report",
            "sections": [
                "Technical Overview",
                "Evidence Analysis",
                "Digital Forensics",
                "Network Analysis",
                "Technical Conclusions"
            ]
        }
    
    def _forensics_template(self) -> Dict[str, Any]:
        """Forensics report template"""
        
        return {
            "title": "Digital Forensics Report",
            "sections": [
                "Forensics Summary",
                "Evidence Acquisition",
                "File Analysis",
                "Metadata Analysis",
                "Chain of Custody"
            ]
        }
    
    def _cybertrace_template(self) -> Dict[str, Any]:
        """Cybertrace report template"""
        
        return {
            "title": "Cybertrace Investigation Report", 
            "sections": [
                "Cybertrace Summary",
                "Network Traces",
                "OSINT Results",
                "Digital Footprint",
                "Attribution Analysis"
            ]
        }
    
    def _default_template(self) -> Dict[str, Any]:
        """Default report template"""
        
        return {
            "title": "Investigation Report",
            "sections": [
                "Summary",
                "Analysis",
                "Conclusions"
            ]
        }