"""
Professional Investigation System - Metadata Analyzer
Advanced metadata extraction and analysis for digital evidence
"""

import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import mimetypes
import struct
import binascii

from ..core.exceptions import CybertraceException


class MetadataAnalyzer:
    """Advanced metadata analysis for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Configuration
        self.max_file_size = self.config.get("max_file_size", 100 * 1024 * 1024)  # 100MB
        self.extract_hidden_data = self.config.get("extract_hidden_data", True)
        self.analyze_structure = self.config.get("analyze_structure", True)
        
        if self.logger:
            self.logger.info("MetadataAnalyzer initialized")
    
    def extract_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract comprehensive file metadata"""
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise CybertraceException(
                    f"File not found: {file_path}",
                    trace_type="metadata",
                    target=str(file_path)
                )
            
            results = {
                "file_path": str(file_path.absolute()),
                "timestamp": datetime.utcnow().isoformat(),
                "file_info": {},
                "system_metadata": {},
                "format_metadata": {},
                "embedded_metadata": {},
                "structure_analysis": {}
            }
            
            # Basic file information
            results["file_info"] = self._get_basic_file_info(file_path)
            
            # System-level metadata
            results["system_metadata"] = self._extract_system_metadata(file_path)
            
            # Format-specific metadata
            results["format_metadata"] = self._extract_format_metadata(file_path)
            
            # Embedded metadata (EXIF, document properties, etc.)
            results["embedded_metadata"] = self._extract_embedded_metadata(file_path)
            
            # Structure analysis
            if self.analyze_structure:
                results["structure_analysis"] = self._analyze_file_structure(file_path)
            
            if self.logger:
                self.logger.info(f"File metadata extraction completed for {file_path}")
            
            return results
            
        except Exception as e:
            error_msg = f"File metadata extraction failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="metadata", target=str(file_path))
    
    def extract_exif_data(self, file_path: str) -> Dict[str, Any]:
        """Extract EXIF data from images"""
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise CybertraceException(
                    f"File not found: {file_path}",
                    trace_type="metadata",
                    target=str(file_path)
                )
            
            results = {
                "file_path": str(file_path.absolute()),
                "timestamp": datetime.utcnow().isoformat(),
                "exif_data": {},
                "gps_data": {},
                "camera_data": {},
                "software_data": {}
            }
            
            # Check if file is an image
            if not self._is_image_file(file_path):
                results["error"] = "File is not an image"
                return results
            
            # Extract EXIF using multiple methods
            exif_data = self._extract_exif_pillow(file_path)
            if not exif_data:
                exif_data = self._extract_exif_exiftool(file_path)
            
            results["exif_data"] = exif_data
            
            # Categorize EXIF data
            results["gps_data"] = self._extract_gps_from_exif(exif_data)
            results["camera_data"] = self._extract_camera_from_exif(exif_data)
            results["software_data"] = self._extract_software_from_exif(exif_data)
            
            # Privacy risk assessment
            results["privacy_assessment"] = self._assess_privacy_risk(results)
            
            if self.logger:
                self.logger.info(f"EXIF data extraction completed for {file_path}")
            
            return results
            
        except Exception as e:
            error_msg = f"EXIF data extraction failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="metadata", target=str(file_path))
    
    def extract_document_properties(self, file_path: str) -> Dict[str, Any]:
        """Extract document properties and metadata"""
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise CybertraceException(
                    f"File not found: {file_path}",
                    trace_type="metadata",
                    target=str(file_path)
                )
            
            results = {
                "file_path": str(file_path.absolute()),
                "timestamp": datetime.utcnow().isoformat(),
                "document_properties": {},
                "author_information": {},
                "creation_data": {},
                "modification_history": {},
                "application_data": {}
            }
            
            # Extract using exiftool
            properties = self._extract_document_exiftool(file_path)
            results["document_properties"] = properties
            
            # Categorize document metadata
            results["author_information"] = self._extract_author_info(properties)
            results["creation_data"] = self._extract_creation_data(properties)
            results["modification_history"] = self._extract_modification_history(properties)
            results["application_data"] = self._extract_application_data(properties)
            
            # Office document specific analysis
            if self._is_office_document(file_path):
                results["office_metadata"] = self._extract_office_metadata(file_path)
            
            # PDF specific analysis
            if file_path.suffix.lower() == '.pdf':
                results["pdf_metadata"] = self._extract_pdf_metadata(file_path)
            
            if self.logger:
                self.logger.info(f"Document properties extraction completed for {file_path}")
            
            return results
            
        except Exception as e:
            error_msg = f"Document properties extraction failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="metadata", target=str(file_path))
    
    def find_hidden_data(self, file_path: str) -> Dict[str, Any]:
        """Find hidden data and steganography indicators"""
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise CybertraceException(
                    f"File not found: {file_path}",
                    trace_type="metadata",
                    target=str(file_path)
                )
            
            results = {
                "file_path": str(file_path.absolute()),
                "timestamp": datetime.utcnow().isoformat(),
                "hidden_data_indicators": {},
                "steganography_analysis": {},
                "alternate_data_streams": {},
                "embedded_files": {},
                "suspicious_patterns": {}
            }
            
            # Check for alternate data streams (Windows)
            results["alternate_data_streams"] = self._check_alternate_data_streams(file_path)
            
            # Look for embedded files
            results["embedded_files"] = self._find_embedded_files(file_path)
            
            # Steganography analysis
            if self._is_image_file(file_path):
                results["steganography_analysis"] = self._analyze_steganography(file_path)
            
            # Look for suspicious patterns
            results["suspicious_patterns"] = self._find_suspicious_patterns(file_path)
            
            # Entropy analysis for hidden data
            results["entropy_analysis"] = self._analyze_entropy_for_hidden_data(file_path)
            
            if self.logger:
                self.logger.info(f"Hidden data analysis completed for {file_path}")
            
            return results
            
        except Exception as e:
            error_msg = f"Hidden data analysis failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="metadata", target=str(file_path))
    
    def _get_basic_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get basic file information"""
        
        try:
            stat = file_path.stat()
            
            return {
                "name": file_path.name,
                "size": stat.st_size,
                "size_human": self._format_file_size(stat.st_size),
                "extension": file_path.suffix.lower(),
                "mime_type": mimetypes.guess_type(str(file_path))[0],
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_system_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract system-level metadata"""
        
        try:
            stat = file_path.stat()
            
            metadata = {
                "inode": stat.st_ino,
                "device": stat.st_dev,
                "hard_links": stat.st_nlink,
                "permissions": oct(stat.st_mode)[-3:],
                "owner_uid": stat.st_uid,
                "group_gid": stat.st_gid
            }
            
            # Extended attributes (macOS/Linux)
            try:
                import xattr
                metadata["extended_attributes"] = {}
                for attr in xattr.listxattr(str(file_path)):
                    try:
                        value = xattr.getxattr(str(file_path), attr)
                        metadata["extended_attributes"][attr] = value.decode('utf-8', errors='ignore')
                    except Exception:
                        metadata["extended_attributes"][attr] = "<binary data>"
            except ImportError:
                metadata["extended_attributes"] = {"error": "xattr module not available"}
            except Exception as e:
                metadata["extended_attributes"] = {"error": str(e)}
            
            return metadata
            
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_format_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract format-specific metadata"""
        
        try:
            file_type = self._detect_file_type(file_path)
            
            metadata = {
                "detected_type": file_type,
                "format_analysis": {}
            }
            
            # Format-specific analysis
            if self._is_image_file(file_path):
                metadata["format_analysis"] = self._analyze_image_format(file_path)
            elif self._is_audio_file(file_path):
                metadata["format_analysis"] = self._analyze_audio_format(file_path)
            elif self._is_video_file(file_path):
                metadata["format_analysis"] = self._analyze_video_format(file_path)
            elif self._is_document_file(file_path):
                metadata["format_analysis"] = self._analyze_document_format(file_path)
            
            return metadata
            
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_embedded_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract embedded metadata using exiftool"""
        
        try:
            # Use exiftool for comprehensive metadata extraction
            result = subprocess.run(
                ["exiftool", "-j", "-all", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                metadata_list = json.loads(result.stdout)
                if metadata_list and len(metadata_list) > 0:
                    return metadata_list[0]
            
            return {"error": "Could not extract embedded metadata"}
            
        except subprocess.TimeoutExpired:
            return {"error": "Metadata extraction timeout"}
        except FileNotFoundError:
            return {"error": "exiftool not available"}
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_file_structure(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file structure"""
        
        try:
            structure = {
                "header_analysis": {},
                "file_signature": {},
                "structure_integrity": {}
            }
            
            # Read file header
            with open(file_path, 'rb') as f:
                header = f.read(512)  # Read first 512 bytes
            
            structure["header_analysis"] = {
                "header_hex": binascii.hexlify(header[:64]).decode(),
                "magic_number": self._identify_magic_number(header),
                "possible_formats": self._identify_possible_formats(header)
            }
            
            # File signature verification
            structure["file_signature"] = self._verify_file_signature(file_path, header)
            
            # Structure integrity check
            structure["structure_integrity"] = self._check_structure_integrity(file_path)
            
            return structure
            
        except Exception as e:
            return {"error": str(e)}
    
    def _is_image_file(self, file_path: Path) -> bool:
        """Check if file is an image"""
        
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp']
        return file_path.suffix.lower() in image_extensions
    
    def _is_audio_file(self, file_path: Path) -> bool:
        """Check if file is audio"""
        
        audio_extensions = ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma']
        return file_path.suffix.lower() in audio_extensions
    
    def _is_video_file(self, file_path: Path) -> bool:
        """Check if file is video"""
        
        video_extensions = ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v']
        return file_path.suffix.lower() in video_extensions
    
    def _is_document_file(self, file_path: Path) -> bool:
        """Check if file is a document"""
        
        doc_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp']
        return file_path.suffix.lower() in doc_extensions
    
    def _is_office_document(self, file_path: Path) -> bool:
        """Check if file is an Office document"""
        
        office_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        return file_path.suffix.lower() in office_extensions
    
    def _extract_exif_pillow(self, file_path: Path) -> Dict[str, Any]:
        """Extract EXIF using Pillow"""
        
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            image = Image.open(file_path)
            exif_data = {}
            
            if hasattr(image, '_getexif'):
                exif = image._getexif()
                if exif is not None:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_data[tag] = str(value)
            
            return exif_data
            
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_exif_exiftool(self, file_path: Path) -> Dict[str, Any]:
        """Extract EXIF using exiftool"""
        
        try:
            result = subprocess.run(
                ["exiftool", "-j", "-EXIF:all", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                exif_list = json.loads(result.stdout)
                if exif_list and len(exif_list) > 0:
                    return exif_list[0]
            
            return {}
            
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return {}
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_gps_from_exif(self, exif_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract GPS data from EXIF"""
        
        gps_data = {}
        
        gps_keys = [
            'GPS Latitude', 'GPS Longitude', 'GPS Altitude', 'GPS Timestamp',
            'GPS Date Stamp', 'GPS Speed', 'GPS Track', 'GPS Satellites'
        ]
        
        for key in gps_keys:
            if key in exif_data:
                gps_data[key] = exif_data[key]
        
        # Check for GPS coordinates in various formats
        for key in exif_data:
            if 'gps' in key.lower() or 'latitude' in key.lower() or 'longitude' in key.lower():
                gps_data[key] = exif_data[key]
        
        return gps_data
    
    def _extract_camera_from_exif(self, exif_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract camera data from EXIF"""
        
        camera_data = {}
        
        camera_keys = [
            'Make', 'Model', 'Camera Model Name', 'Lens Model', 'Lens Info',
            'Focal Length', 'F Number', 'Exposure Time', 'ISO', 'Flash',
            'White Balance', 'Exposure Mode', 'Scene Type'
        ]
        
        for key in camera_keys:
            if key in exif_data:
                camera_data[key] = exif_data[key]
        
        return camera_data
    
    def _extract_software_from_exif(self, exif_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract software data from EXIF"""
        
        software_data = {}
        
        software_keys = [
            'Software', 'Processing Software', 'Creator Tool', 'Application',
            'Photoshop Timestamp', 'History', 'Document ID'
        ]
        
        for key in software_keys:
            if key in exif_data:
                software_data[key] = exif_data[key]
        
        return software_data
    
    def _assess_privacy_risk(self, exif_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess privacy risk based on EXIF data"""
        
        risk_assessment = {
            "risk_level": "LOW",
            "risk_factors": [],
            "recommendations": []
        }
        
        # Check for GPS data
        if exif_results.get("gps_data"):
            risk_assessment["risk_level"] = "HIGH"
            risk_assessment["risk_factors"].append("GPS location data present")
            risk_assessment["recommendations"].append("Remove GPS data before sharing")
        
        # Check for camera serial numbers
        exif_data = exif_results.get("exif_data", {})
        for key, value in exif_data.items():
            if 'serial' in key.lower():
                risk_assessment["risk_level"] = "MEDIUM"
                risk_assessment["risk_factors"].append("Camera serial number present")
                risk_assessment["recommendations"].append("Remove camera serial number")
        
        # Check for personal software
        software_data = exif_results.get("software_data", {})
        if software_data:
            risk_assessment["risk_factors"].append("Software information present")
            risk_assessment["recommendations"].append("Consider removing software metadata")
        
        return risk_assessment
    
    def _extract_document_exiftool(self, file_path: Path) -> Dict[str, Any]:
        """Extract document metadata using exiftool"""
        
        try:
            result = subprocess.run(
                ["exiftool", "-j", "-all", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                metadata_list = json.loads(result.stdout)
                if metadata_list and len(metadata_list) > 0:
                    return metadata_list[0]
            
            return {}
            
        except Exception:
            return {}
    
    def _extract_author_info(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Extract author information from document properties"""
        
        author_info = {}
        
        author_keys = [
            'Author', 'Creator', 'Last Modified By', 'Company', 'Manager',
            'Title', 'Subject', 'Keywords', 'Comments'
        ]
        
        for key in author_keys:
            if key in properties:
                author_info[key] = properties[key]
        
        return author_info
    
    def _extract_creation_data(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Extract creation data from document properties"""
        
        creation_data = {}
        
        creation_keys = [
            'Create Date', 'Creation Date', 'Date Created', 'Modify Date',
            'Last Modified', 'Application', 'Producer', 'Template'
        ]
        
        for key in creation_keys:
            if key in properties:
                creation_data[key] = properties[key]
        
        return creation_data
    
    def _extract_modification_history(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Extract modification history from document properties"""
        
        mod_history = {}
        
        history_keys = [
            'Revision Number', 'Total Edit Time', 'Last Printed',
            'Security', 'Shared', 'Doc Security'
        ]
        
        for key in history_keys:
            if key in properties:
                mod_history[key] = properties[key]
        
        return mod_history
    
    def _extract_application_data(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Extract application data from document properties"""
        
        app_data = {}
        
        app_keys = [
            'Application', 'Producer', 'Creator Tool', 'Generator',
            'Software', 'Version', 'Build'
        ]
        
        for key in app_keys:
            if key in properties:
                app_data[key] = properties[key]
        
        return app_data
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size = float(size_bytes)
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.2f} {units[unit_index]}"
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type using multiple methods"""
        
        try:
            # Try using python-magic
            import magic
            return magic.from_file(str(file_path))
        except ImportError:
            # Fallback to extension-based detection
            return f"File with extension: {file_path.suffix}"
        except Exception as e:
            return f"Unknown ({str(e)})"
    
    def _identify_magic_number(self, header: bytes) -> str:
        """Identify magic number in file header"""
        
        magic_numbers = {
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF87a': 'GIF87a',
            b'GIF89a': 'GIF89a',
            b'%PDF': 'PDF',
            b'PK\x03\x04': 'ZIP',
            b'\x1f\x8b\x08': 'GZIP',
            b'\x7fELF': 'ELF',
            b'MZ': 'PE'
        }
        
        for magic, file_type in magic_numbers.items():
            if header.startswith(magic):
                return file_type
        
        return "Unknown"
    
    def _identify_possible_formats(self, header: bytes) -> List[str]:
        """Identify possible file formats based on header"""
        
        formats = []
        
        # Check common signatures
        if header.startswith(b'\xff\xd8\xff'):
            formats.append("JPEG")
        if header.startswith(b'\x89PNG'):
            formats.append("PNG")
        if header.startswith(b'%PDF'):
            formats.append("PDF")
        if header.startswith(b'PK'):
            formats.extend(["ZIP", "Office Document", "JAR"])
        
        return formats if formats else ["Unknown"]
    
    def _verify_file_signature(self, file_path: Path, header: bytes) -> Dict[str, Any]:
        """Verify file signature against extension"""
        
        extension = file_path.suffix.lower()
        detected_type = self._identify_magic_number(header)
        
        return {
            "extension": extension,
            "detected_type": detected_type,
            "signature_match": self._signature_matches_extension(extension, detected_type),
            "potential_spoofing": not self._signature_matches_extension(extension, detected_type)
        }
    
    def _signature_matches_extension(self, extension: str, detected_type: str) -> bool:
        """Check if file signature matches extension"""
        
        matches = {
            '.jpg': ['JPEG'], '.jpeg': ['JPEG'],
            '.png': ['PNG'],
            '.gif': ['GIF87a', 'GIF89a'],
            '.pdf': ['PDF'],
            '.zip': ['ZIP']
        }
        
        expected_types = matches.get(extension, [])
        return detected_type in expected_types
    
    def _check_structure_integrity(self, file_path: Path) -> Dict[str, Any]:
        """Check file structure integrity"""
        
        integrity = {
            "valid_structure": True,
            "issues": []
        }
        
        try:
            # Basic checks based on file type
            if self._is_image_file(file_path):
                integrity = self._check_image_integrity(file_path)
            elif file_path.suffix.lower() == '.pdf':
                integrity = self._check_pdf_integrity(file_path)
            
        except Exception as e:
            integrity["valid_structure"] = False
            integrity["issues"].append(f"Structure check failed: {str(e)}")
        
        return integrity
    
    def _check_image_integrity(self, file_path: Path) -> Dict[str, Any]:
        """Check image file integrity"""
        
        integrity = {"valid_structure": True, "issues": []}
        
        try:
            from PIL import Image
            image = Image.open(file_path)
            image.verify()  # Verify image integrity
        except Exception as e:
            integrity["valid_structure"] = False
            integrity["issues"].append(f"Image verification failed: {str(e)}")
        
        return integrity
    
    def _check_pdf_integrity(self, file_path: Path) -> Dict[str, Any]:
        """Check PDF file integrity"""
        
        integrity = {"valid_structure": True, "issues": []}
        
        try:
            # Basic PDF structure check
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                
                if not content.startswith(b'%PDF'):
                    integrity["valid_structure"] = False
                    integrity["issues"].append("Invalid PDF header")
                
                # Check for PDF trailer
                f.seek(-1024, 2)  # Read last 1KB
                trailer = f.read()
                
                if b'%%EOF' not in trailer:
                    integrity["valid_structure"] = False
                    integrity["issues"].append("Missing PDF trailer")
                    
        except Exception as e:
            integrity["valid_structure"] = False
            integrity["issues"].append(f"PDF check failed: {str(e)}")
        
        return integrity
    
    def _check_alternate_data_streams(self, file_path: Path) -> Dict[str, Any]:
        """Check for alternate data streams (Windows)"""
        
        # This is a placeholder - actual implementation would require
        # Windows-specific APIs or tools
        return {"note": "Alternate data stream checking not implemented"}
    
    def _find_embedded_files(self, file_path: Path) -> Dict[str, Any]:
        """Find embedded files within the target file"""
        
        # Basic implementation - look for common file signatures
        embedded = {"files_found": [], "analysis": "basic"}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Look for common file signatures
            signatures = [
                (b'%PDF', 'PDF'),
                (b'\x89PNG', 'PNG'),
                (b'\xff\xd8\xff', 'JPEG'),
                (b'PK\x03\x04', 'ZIP/Office')
            ]
            
            for signature, file_type in signatures:
                offset = 0
                while True:
                    pos = content.find(signature, offset)
                    if pos == -1:
                        break
                    
                    if pos > 0:  # Not at the beginning
                        embedded["files_found"].append({
                            "type": file_type,
                            "offset": pos,
                            "signature": signature.hex()
                        })
                    
                    offset = pos + 1
            
        except Exception as e:
            embedded["error"] = str(e)
        
        return embedded
    
    def _analyze_steganography(self, file_path: Path) -> Dict[str, Any]:
        """Basic steganography analysis for images"""
        
        stego_analysis = {
            "suspicious_indicators": [],
            "analysis_type": "basic",
            "recommendation": "Use specialized steganography tools for detailed analysis"
        }
        
        try:
            # Basic checks for steganography indicators
            stat = file_path.stat()
            
            # Check file size vs typical size for image type
            if stat.st_size > 10 * 1024 * 1024:  # > 10MB
                stego_analysis["suspicious_indicators"].append("Unusually large file size")
            
            # Check for suspicious metadata
            exif_data = self._extract_exif_pillow(file_path)
            if "error" not in exif_data and exif_data:
                if any("comment" in key.lower() for key in exif_data.keys()):
                    stego_analysis["suspicious_indicators"].append("Custom comments in metadata")
            
        except Exception as e:
            stego_analysis["error"] = str(e)
        
        return stego_analysis
    
    def _find_suspicious_patterns(self, file_path: Path) -> Dict[str, Any]:
        """Find suspicious patterns in file"""
        
        patterns = {
            "patterns_found": [],
            "analysis": "basic"
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
            
            # Look for suspicious patterns
            if b'password' in content.lower():
                patterns["patterns_found"].append("Contains 'password' string")
            
            if b'secret' in content.lower():
                patterns["patterns_found"].append("Contains 'secret' string")
            
            if b'key' in content.lower():
                patterns["patterns_found"].append("Contains 'key' string")
            
            # Check for base64-like patterns
            import re
            base64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
            if base64_pattern.search(content):
                patterns["patterns_found"].append("Potential base64 encoded data")
            
        except Exception as e:
            patterns["error"] = str(e)
        
        return patterns
    
    def _analyze_entropy_for_hidden_data(self, file_path: Path) -> Dict[str, Any]:
        """Analyze entropy to detect potential hidden data"""
        
        entropy_analysis = {
            "segments": [],
            "overall_entropy": 0.0,
            "suspicious_segments": []
        }
        
        try:
            with open(file_path, 'rb') as f:
                chunk_size = 8192
                chunk_num = 0
                
                while chunk_num < 10:  # Analyze first 10 chunks
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Calculate entropy for this chunk
                    entropy = self._calculate_chunk_entropy(chunk)
                    
                    segment_info = {
                        "chunk": chunk_num,
                        "offset": chunk_num * chunk_size,
                        "entropy": entropy
                    }
                    
                    entropy_analysis["segments"].append(segment_info)
                    
                    # High entropy might indicate encrypted/compressed data
                    if entropy > 7.5:
                        entropy_analysis["suspicious_segments"].append(segment_info)
                    
                    chunk_num += 1
                
                # Calculate overall entropy
                if entropy_analysis["segments"]:
                    entropies = [s["entropy"] for s in entropy_analysis["segments"]]
                    entropy_analysis["overall_entropy"] = sum(entropies) / len(entropies)
            
        except Exception as e:
            entropy_analysis["error"] = str(e)
        
        return entropy_analysis
    
    def _calculate_chunk_entropy(self, chunk: bytes) -> float:
        """Calculate Shannon entropy for a chunk of data"""
        
        if not chunk:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in chunk:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        chunk_len = len(chunk)
        
        for count in byte_counts:
            if count > 0:
                probability = count / chunk_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _extract_office_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract Office document metadata"""
        
        # Placeholder for Office-specific metadata extraction
        return {"note": "Office metadata extraction requires specialized libraries"}
    
    def _extract_pdf_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract PDF-specific metadata"""
        
        # Placeholder for PDF-specific metadata extraction
        return {"note": "PDF metadata extraction requires specialized libraries"}
    
    def _analyze_image_format(self, file_path: Path) -> Dict[str, Any]:
        """Analyze image format specifics"""
        
        try:
            from PIL import Image
            image = Image.open(file_path)
            
            return {
                "format": image.format,
                "mode": image.mode,
                "size": image.size,
                "has_transparency": image.mode in ('RGBA', 'LA') or 'transparency' in image.info
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_audio_format(self, file_path: Path) -> Dict[str, Any]:
        """Analyze audio format specifics"""
        
        return {"note": "Audio format analysis requires specialized libraries"}
    
    def _analyze_video_format(self, file_path: Path) -> Dict[str, Any]:
        """Analyze video format specifics"""
        
        return {"note": "Video format analysis requires specialized libraries"}
    
    def _analyze_document_format(self, file_path: Path) -> Dict[str, Any]:
        """Analyze document format specifics"""
        
        return {"note": "Document format analysis requires specialized libraries"}