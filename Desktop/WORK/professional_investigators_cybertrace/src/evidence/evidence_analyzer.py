"""
Professional Investigation System - Evidence Analyzer
Comprehensive analysis of collected evidence
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from ..core.exceptions import EvidenceException


class EvidenceAnalyzer:
    """Advanced evidence analysis for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        if self.logger:
            self.logger.info("EvidenceAnalyzer initialized")
    
    def analyze(self, evidence_id: str, evidence_files: List[Dict[str, Any]], 
               analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """Analyze evidence files"""
        
        try:
            analysis_results = {
                "evidence_id": evidence_id,
                "analysis_type": analysis_type,
                "analyzed_at": datetime.utcnow().isoformat(),
                "file_analyses": [],
                "summary": {},
                "findings": [],
                "recommendations": []
            }
            
            # Analyze each file
            for file_info in evidence_files:
                file_analysis = self._analyze_file(file_info, analysis_type)
                analysis_results["file_analyses"].append(file_analysis)
            
            # Generate overall summary
            analysis_results["summary"] = self._generate_summary(analysis_results["file_analyses"])
            
            # Extract findings
            analysis_results["findings"] = self._extract_findings(analysis_results["file_analyses"])
            
            # Generate recommendations
            analysis_results["recommendations"] = self._generate_recommendations(analysis_results)
            
            if self.logger:
                self.logger.info(f"Evidence analysis completed: {evidence_id}")
            
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
    
    def _analyze_file(self, file_info: Dict[str, Any], analysis_type: str) -> Dict[str, Any]:
        """Analyze individual file"""
        
        try:
            file_path = Path(file_info["path"])
            
            file_analysis = {
                "file_name": file_info["name"],
                "file_path": str(file_path),
                "file_size": file_info.get("size", 0),
                "analysis_type": analysis_type,
                "analyzed_at": datetime.utcnow().isoformat(),
                "analysis_results": {}
            }
            
            if not file_path.exists():
                file_analysis["error"] = "File not found"
                return file_analysis
            
            # Basic file analysis
            file_analysis["analysis_results"]["basic"] = self._basic_file_analysis(file_path)
            
            # Content analysis based on file type
            if file_path.suffix.lower() == '.json':
                file_analysis["analysis_results"]["json"] = self._analyze_json_file(file_path)
            elif file_path.suffix.lower() == '.txt':
                file_analysis["analysis_results"]["text"] = self._analyze_text_file(file_path)
            elif file_path.suffix.lower() == '.html':
                file_analysis["analysis_results"]["html"] = self._analyze_html_file(file_path)
            
            # Security analysis
            if analysis_type in ["comprehensive", "security"]:
                file_analysis["analysis_results"]["security"] = self._security_analysis(file_path)
            
            return file_analysis
            
        except Exception as e:
            return {
                "file_name": file_info.get("name", "unknown"),
                "error": str(e),
                "analyzed_at": datetime.utcnow().isoformat()
            }
    
    def _basic_file_analysis(self, file_path: Path) -> Dict[str, Any]:
        """Basic file analysis"""
        
        try:
            stat = file_path.stat()
            
            analysis = {
                "file_size": stat.st_size,
                "file_size_human": self._format_file_size(stat.st_size),
                "extension": file_path.suffix.lower(),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "permissions": oct(stat.st_mode)[-3:]
            }
            
            # Read file header for type detection
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(64)
                analysis["header_hex"] = header.hex()
                analysis["detected_type"] = self._detect_file_type(header)
            except Exception:
                analysis["header_hex"] = ""
                analysis["detected_type"] = "unknown"
            
            return analysis
            
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_json_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze JSON file"""
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            analysis = {
                "valid_json": True,
                "structure": self._analyze_json_structure(data),
                "key_count": len(data) if isinstance(data, dict) else 0,
                "array_length": len(data) if isinstance(data, list) else 0,
                "data_types": self._analyze_json_types(data),
                "sensitive_keys": self._find_sensitive_keys(data)
            }
            
            return analysis
            
        except json.JSONDecodeError as e:
            return {
                "valid_json": False,
                "error": str(e)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_text_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze text file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            words = content.split()
            
            analysis = {
                "line_count": len(lines),
                "word_count": len(words),
                "character_count": len(content),
                "encoding": "utf-8",
                "language_indicators": self._detect_language_indicators(content),
                "patterns": self._find_text_patterns(content),
                "suspicious_content": self._find_suspicious_text_content(content)
            }
            
            return analysis
            
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_html_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze HTML file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            analysis = {
                "html_length": len(content),
                "has_doctype": "<!DOCTYPE" in content.upper(),
                "has_html_tag": "<HTML" in content.upper(),
                "has_head_tag": "<HEAD" in content.upper(),
                "has_body_tag": "<BODY" in content.upper(),
                "title": self._extract_html_title(content),
                "meta_tags": self._extract_meta_tags(content),
                "external_links": self._extract_external_links(content),
                "scripts": self._extract_scripts(content),
                "forms": self._extract_forms(content)
            }
            
            return analysis
            
        except Exception as e:
            return {"error": str(e)}
    
    def _security_analysis(self, file_path: Path) -> Dict[str, Any]:
        """Security analysis of file"""
        
        try:
            security_analysis = {
                "risk_level": "LOW",
                "issues": [],
                "suspicious_indicators": []
            }
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > 100 * 1024 * 1024:  # > 100MB
                security_analysis["issues"].append("Large file size")
                security_analysis["risk_level"] = "MEDIUM"
            
            # Check for executable extensions
            executable_extensions = ['.exe', '.bat', '.sh', '.ps1', '.scr', '.com']
            if file_path.suffix.lower() in executable_extensions:
                security_analysis["issues"].append("Executable file type")
                security_analysis["risk_level"] = "HIGH"
            
            # Content analysis for text files
            if file_path.suffix.lower() in ['.txt', '.json', '.html', '.xml']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(8192)  # Read first 8KB
                    
                    # Look for suspicious keywords
                    suspicious_keywords = ['password', 'secret', 'key', 'token', 'credential']
                    for keyword in suspicious_keywords:
                        if keyword in content.lower():
                            security_analysis["suspicious_indicators"].append(f"Contains '{keyword}'")
                            if security_analysis["risk_level"] == "LOW":
                                security_analysis["risk_level"] = "MEDIUM"
                    
                    # Look for URLs
                    if 'http://' in content or 'https://' in content:
                        security_analysis["suspicious_indicators"].append("Contains URLs")
                    
                    # Look for IP addresses
                    import re
                    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                    if re.search(ip_pattern, content):
                        security_analysis["suspicious_indicators"].append("Contains IP addresses")
                
                except Exception:
                    pass
            
            return security_analysis
            
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_json_structure(self, data: Any, max_depth: int = 3, current_depth: int = 0) -> Dict[str, Any]:
        """Analyze JSON structure"""
        
        if current_depth >= max_depth:
            return {"type": type(data).__name__, "truncated": True}
        
        if isinstance(data, dict):
            return {
                "type": "object",
                "keys": list(data.keys())[:10],  # Limit to first 10 keys
                "key_count": len(data),
                "nested": any(isinstance(v, (dict, list)) for v in data.values())
            }
        elif isinstance(data, list):
            return {
                "type": "array",
                "length": len(data),
                "element_types": list(set(type(item).__name__ for item in data[:10]))
            }
        else:
            return {"type": type(data).__name__, "value_preview": str(data)[:100]}
    
    def _analyze_json_types(self, data: Any) -> Dict[str, int]:
        """Analyze data types in JSON"""
        
        type_counts = {}
        
        def count_types(obj):
            obj_type = type(obj).__name__
            type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
            
            if isinstance(obj, dict):
                for value in obj.values():
                    count_types(value)
            elif isinstance(obj, list):
                for item in obj:
                    count_types(item)
        
        count_types(data)
        return type_counts
    
    def _find_sensitive_keys(self, data: Any) -> List[str]:
        """Find sensitive keys in JSON data"""
        
        sensitive_keys = []
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential', 'auth', 'api_key']
        
        def find_keys(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check if key contains sensitive patterns
                    if any(pattern in key.lower() for pattern in sensitive_patterns):
                        sensitive_keys.append(current_path)
                    
                    find_keys(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_keys(item, f"{path}[{i}]")
        
        find_keys(data)
        return sensitive_keys
    
    def _detect_language_indicators(self, content: str) -> List[str]:
        """Detect language indicators in text"""
        
        indicators = []
        
        # Common programming language indicators
        if 'def ' in content or 'import ' in content:
            indicators.append("Python")
        if 'function ' in content or 'var ' in content:
            indicators.append("JavaScript")
        if '#include' in content or 'int main' in content:
            indicators.append("C/C++")
        if 'public class' in content or 'import java.' in content:
            indicators.append("Java")
        
        return indicators
    
    def _find_text_patterns(self, content: str) -> Dict[str, int]:
        """Find patterns in text content"""
        
        import re
        patterns = {}
        
        # Email addresses
        email_count = len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content))
        if email_count > 0:
            patterns["email_addresses"] = email_count
        
        # URLs
        url_count = len(re.findall(r'https?://[^\s]+', content))
        if url_count > 0:
            patterns["urls"] = url_count
        
        # IP addresses
        ip_count = len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content))
        if ip_count > 0:
            patterns["ip_addresses"] = ip_count
        
        # Phone numbers (basic pattern)
        phone_count = len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', content))
        if phone_count > 0:
            patterns["phone_numbers"] = phone_count
        
        return patterns
    
    def _find_suspicious_text_content(self, content: str) -> List[str]:
        """Find suspicious content in text"""
        
        suspicious = []
        
        # Check for common suspicious keywords
        suspicious_keywords = [
            'password', 'secret', 'confidential', 'private key',
            'access token', 'api key', 'credit card', 'ssn'
        ]
        
        content_lower = content.lower()
        for keyword in suspicious_keywords:
            if keyword in content_lower:
                suspicious.append(f"Contains '{keyword}'")
        
        # Check for base64-like patterns
        import re
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', content):
            suspicious.append("Potential base64 encoded data")
        
        return suspicious
    
    def _extract_html_title(self, content: str) -> str:
        """Extract title from HTML content"""
        
        import re
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        return title_match.group(1).strip() if title_match else ""
    
    def _extract_meta_tags(self, content: str) -> List[Dict[str, str]]:
        """Extract meta tags from HTML"""
        
        import re
        meta_tags = []
        
        meta_pattern = r'<meta\s+([^>]+)>'
        for match in re.finditer(meta_pattern, content, re.IGNORECASE):
            meta_content = match.group(1)
            
            # Extract name and content attributes
            name_match = re.search(r'name=["\']([^"\']+)["\']', meta_content, re.IGNORECASE)
            content_match = re.search(r'content=["\']([^"\']+)["\']', meta_content, re.IGNORECASE)
            
            if name_match and content_match:
                meta_tags.append({
                    "name": name_match.group(1),
                    "content": content_match.group(1)
                })
        
        return meta_tags
    
    def _extract_external_links(self, content: str) -> List[str]:
        """Extract external links from HTML"""
        
        import re
        links = []
        
        # Find all href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, content, re.IGNORECASE):
            url = match.group(1)
            if url.startswith(('http://', 'https://')):
                links.append(url)
        
        return list(set(links))  # Remove duplicates
    
    def _extract_scripts(self, content: str) -> List[Dict[str, str]]:
        """Extract script tags from HTML"""
        
        import re
        scripts = []
        
        script_pattern = r'<script\s*([^>]*)>(.*?)</script>'
        for match in re.finditer(script_pattern, content, re.IGNORECASE | re.DOTALL):
            attributes = match.group(1)
            script_content = match.group(2)
            
            # Extract src attribute if present
            src_match = re.search(r'src=["\']([^"\']+)["\']', attributes, re.IGNORECASE)
            
            scripts.append({
                "src": src_match.group(1) if src_match else "",
                "inline": bool(script_content.strip()),
                "content_length": len(script_content)
            })
        
        return scripts
    
    def _extract_forms(self, content: str) -> List[Dict[str, str]]:
        """Extract form tags from HTML"""
        
        import re
        forms = []
        
        form_pattern = r'<form\s+([^>]+)>'
        for match in re.finditer(form_pattern, content, re.IGNORECASE):
            attributes = match.group(1)
            
            # Extract method and action attributes
            method_match = re.search(r'method=["\']([^"\']+)["\']', attributes, re.IGNORECASE)
            action_match = re.search(r'action=["\']([^"\']+)["\']', attributes, re.IGNORECASE)
            
            forms.append({
                "method": method_match.group(1) if method_match else "GET",
                "action": action_match.group(1) if action_match else ""
            })
        
        return forms
    
    def _detect_file_type(self, header: bytes) -> str:
        """Detect file type from header"""
        
        if header.startswith(b'\x89PNG'):
            return "PNG Image"
        elif header.startswith(b'\xff\xd8\xff'):
            return "JPEG Image"
        elif header.startswith(b'%PDF'):
            return "PDF Document"
        elif header.startswith(b'PK\x03\x04'):
            return "ZIP Archive"
        elif header.startswith(b'\x7fELF'):
            return "ELF Executable"
        elif header.startswith(b'MZ'):
            return "PE Executable"
        else:
            return "Unknown"
    
    def _generate_summary(self, file_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate overall analysis summary"""
        
        summary = {
            "total_files": len(file_analyses),
            "successful_analyses": sum(1 for analysis in file_analyses if "error" not in analysis),
            "failed_analyses": sum(1 for analysis in file_analyses if "error" in analysis),
            "file_types": {},
            "total_size": 0,
            "risk_levels": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        }
        
        for analysis in file_analyses:
            if "error" not in analysis:
                # Count file types
                if "analysis_results" in analysis and "basic" in analysis["analysis_results"]:
                    detected_type = analysis["analysis_results"]["basic"].get("detected_type", "unknown")
                    summary["file_types"][detected_type] = summary["file_types"].get(detected_type, 0) + 1
                
                # Sum file sizes
                summary["total_size"] += analysis.get("file_size", 0)
                
                # Count risk levels
                if "analysis_results" in analysis and "security" in analysis["analysis_results"]:
                    risk_level = analysis["analysis_results"]["security"].get("risk_level", "LOW")
                    summary["risk_levels"][risk_level] += 1
        
        summary["total_size_human"] = self._format_file_size(summary["total_size"])
        
        return summary
    
    def _extract_findings(self, file_analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract key findings from analyses"""
        
        findings = []
        
        for analysis in file_analyses:
            if "error" in analysis:
                findings.append({
                    "type": "ERROR",
                    "severity": "MEDIUM",
                    "file": analysis.get("file_name", "unknown"),
                    "description": f"Analysis failed: {analysis['error']}"
                })
                continue
            
            file_name = analysis.get("file_name", "unknown")
            
            # Security findings
            if "analysis_results" in analysis and "security" in analysis["analysis_results"]:
                security = analysis["analysis_results"]["security"]
                
                if security.get("risk_level") == "HIGH":
                    findings.append({
                        "type": "SECURITY",
                        "severity": "HIGH",
                        "file": file_name,
                        "description": f"High-risk file: {', '.join(security.get('issues', []))}"
                    })
                
                for indicator in security.get("suspicious_indicators", []):
                    findings.append({
                        "type": "SUSPICIOUS",
                        "severity": "MEDIUM",
                        "file": file_name,
                        "description": indicator
                    })
            
            # Sensitive data findings
            if "analysis_results" in analysis and "json" in analysis["analysis_results"]:
                json_analysis = analysis["analysis_results"]["json"]
                
                if json_analysis.get("sensitive_keys"):
                    findings.append({
                        "type": "SENSITIVE_DATA",
                        "severity": "HIGH",
                        "file": file_name,
                        "description": f"Contains sensitive keys: {', '.join(json_analysis['sensitive_keys'])}"
                    })
        
        return findings
    
    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        
        recommendations = []
        
        # Based on findings
        high_risk_findings = [f for f in analysis_results["findings"] if f["severity"] == "HIGH"]
        if high_risk_findings:
            recommendations.append("Review and secure high-risk files immediately")
        
        sensitive_data_findings = [f for f in analysis_results["findings"] if f["type"] == "SENSITIVE_DATA"]
        if sensitive_data_findings:
            recommendations.append("Remove or encrypt sensitive data in evidence files")
        
        # Based on summary
        summary = analysis_results["summary"]
        if summary["failed_analyses"] > 0:
            recommendations.append("Investigate files that failed analysis")
        
        if summary["risk_levels"]["HIGH"] > 0:
            recommendations.append("Implement additional security measures for high-risk evidence")
        
        # General recommendations
        recommendations.append("Maintain chain of custody documentation")
        recommendations.append("Store evidence in secure, access-controlled environment")
        recommendations.append("Regular integrity verification of evidence files")
        
        return recommendations
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size = float(size_bytes)
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.2f} {units[unit_index]}"