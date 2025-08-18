"""
Professional Investigation System - Digital Forensics Analyzer
Advanced digital forensics capabilities for file and system analysis
"""

import os
import hashlib
import magic
import struct
import binascii
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import json
import mimetypes
import subprocess

from ..core.exceptions import ForensicsException


class DigitalForensicsAnalyzer:
    """Advanced digital forensics analysis for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Configuration
        self.max_file_size = self.config.get("max_file_size", 100 * 1024 * 1024)  # 100MB
        self.hash_algorithms = self.config.get("hash_algorithms", ["md5", "sha1", "sha256", "sha512"])
        self.extract_strings_min_length = self.config.get("strings_min_length", 4)
        self.hex_dump_bytes = self.config.get("hex_dump_bytes", 512)
        
        if self.logger:
            self.logger.info("DigitalForensicsAnalyzer initialized")
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file analysis"""
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise ForensicsException(
                    f"File not found: {file_path}",
                    forensics_type="file_analysis",
                    target_path=str(file_path)
                )
            
            if not file_path.is_file():
                raise ForensicsException(
                    f"Path is not a file: {file_path}",
                    forensics_type="file_analysis",
                    target_path=str(file_path)
                )
            
            results = {
                "file_path": str(file_path.absolute()),
                "file_name": file_path.name,
                "timestamp": datetime.utcnow().isoformat(),
                "basic_info": {},
                "file_type": {},
                "timestamps": {},
                "permissions": {},
                "signature_analysis": {},
                "entropy_analysis": {}
            }
            
            # Basic file information
            file_stat = file_path.stat()
            results["basic_info"] = {
                "size_bytes": file_stat.st_size,
                "size_human": self._format_file_size(file_stat.st_size),
                "inode": file_stat.st_ino,
                "device": file_stat.st_dev,
                "links": file_stat.st_nlink,
                "uid": file_stat.st_uid,
                "gid": file_stat.st_gid
            }
            
            # File type analysis
            results["file_type"] = self._analyze_file_type(file_path)
            
            # Timestamps
            results["timestamps"] = {
                "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(file_stat.st_atime).isoformat()
            }
            
            # Permissions
            results["permissions"] = self._analyze_permissions(file_stat)
            
            # File signature analysis
            results["signature_analysis"] = self._analyze_file_signature(file_path)
            
            # Entropy analysis (for detecting encryption/compression)
            if file_stat.st_size <= self.max_file_size:
                results["entropy_analysis"] = self._calculate_entropy(file_path)
            
            if self.logger:
                self.logger.info(f"File analysis completed for {file_path}")
            
            return results
            
        except Exception as e:
            error_msg = f"File analysis failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise ForensicsException(
                error_msg,
                forensics_type="file_analysis",
                target_path=str(file_path)
            )
    
    def calculate_hashes(self, file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
        """Calculate file hashes"""
        
        try:
            file_path = Path(file_path)
            algorithms = algorithms or self.hash_algorithms
            
            if not file_path.exists():
                raise ForensicsException(
                    f"File not found: {file_path}",
                    forensics_type="hash_calculation",
                    target_path=str(file_path)
                )
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                raise ForensicsException(
                    f"File too large for hash calculation: {file_size} bytes",
                    forensics_type="hash_calculation",
                    target_path=str(file_path)
                )
            
            hashes = {}
            hash_objects = {}
            
            # Initialize hash objects
            for algorithm in algorithms:
                try:
                    hash_objects[algorithm] = hashlib.new(algorithm)
                except ValueError:
                    if self.logger:
                        self.logger.warning(f"Unsupported hash algorithm: {algorithm}")
                    continue
            
            # Read file and update hashes
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for algorithm, hash_obj in hash_objects.items():
                        hash_obj.update(chunk)
            
            # Get final hash values
            for algorithm, hash_obj in hash_objects.items():
                hashes[algorithm] = hash_obj.hexdigest()
            
            if self.logger:
                self.logger.info(f"Hash calculation completed for {file_path}")
            
            return hashes
            
        except Exception as e:
            error_msg = f"Hash calculation failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise ForensicsException(
                error_msg,
                forensics_type="hash_calculation",
                target_path=str(file_path)
            )
    
    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract file metadata"""
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise ForensicsException(
                    f"File not found: {file_path}",
                    forensics_type="metadata_extraction",
                    target_path=str(file_path)
                )
            
            metadata = {
                "file_path": str(file_path.absolute()),
                "timestamp": datetime.utcnow().isoformat(),
                "exif_data": {},
                "extended_attributes": {},
                "file_system_metadata": {}
            }
            
            # Try to extract EXIF data for images
            if self._is_image_file(file_path):
                metadata["exif_data"] = self._extract_exif_data(file_path)
            
            # Extract extended attributes (macOS/Linux)
            metadata["extended_attributes"] = self._extract_extended_attributes(file_path)
            
            # File system metadata
            metadata["file_system_metadata"] = self._extract_filesystem_metadata(file_path)
            
            # Document metadata (for Office documents, PDFs, etc.)
            if self._is_document_file(file_path):
                metadata["document_metadata"] = self._extract_document_metadata(file_path)
            
            if self.logger:
                self.logger.info(f"Metadata extraction completed for {file_path}")
            
            return metadata
            
        except Exception as e:
            error_msg = f"Metadata extraction failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise ForensicsException(
                error_msg,
                forensics_type="metadata_extraction",
                target_path=str(file_path)
            )
    
    def extract_strings(self, file_path: str, min_length: int = None) -> List[str]:
        """Extract printable strings from file"""
        
        try:
            file_path = Path(file_path)
            min_length = min_length or self.extract_strings_min_length
            
            if not file_path.exists():
                raise ForensicsException(
                    f"File not found: {file_path}",
                    forensics_type="string_extraction",
                    target_path=str(file_path)
                )
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                raise ForensicsException(
                    f"File too large for string extraction: {file_size} bytes",
                    forensics_type="string_extraction",
                    target_path=str(file_path)
                )
            
            strings = []
            current_string = ""
            
            with open(file_path, 'rb') as f:
                while byte := f.read(1):
                    char = byte[0]
                    
                    # Check if character is printable ASCII
                    if 32 <= char <= 126:
                        current_string += chr(char)
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
                
                # Don't forget the last string
                if len(current_string) >= min_length:
                    strings.append(current_string)
            
            if self.logger:
                self.logger.info(f"String extraction completed for {file_path}: {len(strings)} strings found")
            
            return strings
            
        except Exception as e:
            error_msg = f"String extraction failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise ForensicsException(
                error_msg,
                forensics_type="string_extraction",
                target_path=str(file_path)
            )
    
    def generate_hex_dump(self, file_path: str, max_bytes: int = None) -> str:
        """Generate hex dump of file"""
        
        try:
            file_path = Path(file_path)
            max_bytes = max_bytes or self.hex_dump_bytes
            
            if not file_path.exists():
                raise ForensicsException(
                    f"File not found: {file_path}",
                    forensics_type="hex_dump",
                    target_path=str(file_path)
                )
            
            hex_dump = []
            
            with open(file_path, 'rb') as f:
                offset = 0
                while offset < max_bytes:
                    chunk = f.read(16)
                    if not chunk:
                        break
                    
                    # Format hex representation
                    hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
                    hex_part = hex_part.ljust(47)  # Pad to consistent width
                    
                    # Format ASCII representation
                    ascii_part = ''.join(
                        chr(byte) if 32 <= byte <= 126 else '.'
                        for byte in chunk
                    )
                    
                    # Format line
                    line = f"{offset:08x}  {hex_part}  |{ascii_part}|"
                    hex_dump.append(line)
                    
                    offset += 16
            
            if self.logger:
                self.logger.info(f"Hex dump generated for {file_path}")
            
            return '\n'.join(hex_dump)
            
        except Exception as e:
            error_msg = f"Hex dump generation failed for {file_path}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise ForensicsException(
                error_msg,
                forensics_type="hex_dump",
                target_path=str(file_path)
            )
    
    def _analyze_file_type(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file type using multiple methods"""
        
        file_type_info = {}
        
        # MIME type detection
        try:
            mime_type, encoding = mimetypes.guess_type(str(file_path))
            file_type_info["mime_type"] = mime_type
            file_type_info["encoding"] = encoding
        except Exception:
            pass
        
        # Magic number detection
        try:
            file_type_info["magic_type"] = magic.from_file(str(file_path))
            file_type_info["magic_mime"] = magic.from_file(str(file_path), mime=True)
        except Exception as e:
            file_type_info["magic_error"] = str(e)
        
        # File extension
        file_type_info["extension"] = file_path.suffix.lower()
        
        # Manual signature detection
        file_type_info["signature"] = self._detect_file_signature(file_path)
        
        return file_type_info
    
    def _analyze_permissions(self, file_stat) -> Dict[str, Any]:
        """Analyze file permissions"""
        
        mode = file_stat.st_mode
        
        permissions = {
            "octal": oct(mode)[-3:],
            "symbolic": self._mode_to_symbolic(mode),
            "owner": {
                "read": bool(mode & 0o400),
                "write": bool(mode & 0o200),
                "execute": bool(mode & 0o100)
            },
            "group": {
                "read": bool(mode & 0o040),
                "write": bool(mode & 0o020),
                "execute": bool(mode & 0o010)
            },
            "other": {
                "read": bool(mode & 0o004),
                "write": bool(mode & 0o002),
                "execute": bool(mode & 0o001)
            },
            "special_bits": {
                "setuid": bool(mode & 0o4000),
                "setgid": bool(mode & 0o2000),
                "sticky": bool(mode & 0o1000)
            }
        }
        
        return permissions
    
    def _analyze_file_signature(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file signature/magic numbers"""
        
        signature_info = {}
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(64)  # Read first 64 bytes
            
            signature_info["header_hex"] = binascii.hexlify(header).decode()
            signature_info["detected_type"] = self._identify_by_signature(header)
            signature_info["is_executable"] = self._is_executable_signature(header)
            signature_info["is_compressed"] = self._is_compressed_signature(header)
            signature_info["is_encrypted"] = self._appears_encrypted(header)
            
        except Exception as e:
            signature_info["error"] = str(e)
        
        return signature_info
    
    def _calculate_entropy(self, file_path: Path) -> Dict[str, Any]:
        """Calculate file entropy (measure of randomness)"""
        
        try:
            byte_counts = [0] * 256
            total_bytes = 0
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for byte in chunk:
                        byte_counts[byte] += 1
                        total_bytes += 1
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * (probability.bit_length() - 1)
            
            # Normalize to 0-8 scale
            if total_bytes > 0:
                entropy = entropy / 8.0 * 8.0
            
            entropy_info = {
                "shannon_entropy": entropy,
                "total_bytes": total_bytes,
                "unique_bytes": sum(1 for count in byte_counts if count > 0),
                "interpretation": self._interpret_entropy(entropy)
            }
            
            return entropy_info
            
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
    
    def _mode_to_symbolic(self, mode: int) -> str:
        """Convert file mode to symbolic representation"""
        
        # File type
        if os.path.stat.S_ISREG(mode):
            result = '-'
        elif os.path.stat.S_ISDIR(mode):
            result = 'd'
        elif os.path.stat.S_ISLNK(mode):
            result = 'l'
        else:
            result = '?'
        
        # Owner permissions
        result += 'r' if mode & 0o400 else '-'
        result += 'w' if mode & 0o200 else '-'
        result += 'x' if mode & 0o100 else '-'
        
        # Group permissions
        result += 'r' if mode & 0o040 else '-'
        result += 'w' if mode & 0o020 else '-'
        result += 'x' if mode & 0o010 else '-'
        
        # Other permissions
        result += 'r' if mode & 0o004 else '-'
        result += 'w' if mode & 0o002 else '-'
        result += 'x' if mode & 0o001 else '-'
        
        return result
    
    def _detect_file_signature(self, file_path: Path) -> str:
        """Detect file type by signature/magic numbers"""
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            return self._identify_by_signature(header)
            
        except Exception:
            return "Unknown"
    
    def _identify_by_signature(self, header: bytes) -> str:
        """Identify file type by header signature"""
        
        # Common file signatures
        signatures = {
            b'\x89PNG\r\n\x1a\n': 'PNG Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'GIF87a': 'GIF87a Image',
            b'GIF89a': 'GIF89a Image',
            b'RIFF': 'RIFF (WAV/AVI)',
            b'%PDF': 'PDF Document',
            b'PK\x03\x04': 'ZIP Archive',
            b'PK\x05\x06': 'ZIP Archive (empty)',
            b'PK\x07\x08': 'ZIP Archive (spanned)',
            b'\x1f\x8b\x08': 'GZIP Archive',
            b'BZh': 'BZIP2 Archive',
            b'\x7fELF': 'ELF Executable',
            b'MZ': 'PE Executable',
            b'\xfe\xed\xfa': 'Mach-O Executable (32-bit)',
            b'\xfe\xed\xfa\xce': 'Mach-O Executable (64-bit)',
            b'\xca\xfe\xba\xbe': 'Java Class File',
            b'\xd0\xcf\x11\xe0': 'Microsoft Office Document'
        }
        
        for signature, file_type in signatures.items():
            if header.startswith(signature):
                return file_type
        
        return "Unknown"
    
    def _is_executable_signature(self, header: bytes) -> bool:
        """Check if file appears to be executable"""
        
        executable_signatures = [
            b'\x7fELF',  # ELF
            b'MZ',       # PE
            b'\xfe\xed\xfa',  # Mach-O 32-bit
            b'\xfe\xed\xfa\xce',  # Mach-O 64-bit
            b'\xca\xfe\xba\xbe',  # Java Class
        ]
        
        return any(header.startswith(sig) for sig in executable_signatures)
    
    def _is_compressed_signature(self, header: bytes) -> bool:
        """Check if file appears to be compressed"""
        
        compressed_signatures = [
            b'PK\x03\x04',  # ZIP
            b'\x1f\x8b\x08',  # GZIP
            b'BZh',         # BZIP2
            b'\x5d\x00\x00',  # LZMA
        ]
        
        return any(header.startswith(sig) for sig in compressed_signatures)
    
    def _appears_encrypted(self, header: bytes) -> bool:
        """Basic check if file might be encrypted (high entropy in header)"""
        
        if len(header) < 16:
            return False
        
        # Calculate entropy of first 16 bytes
        byte_counts = [0] * 256
        for byte in header[:16]:
            byte_counts[byte] += 1
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / 16
                entropy -= probability * (probability.bit_length() - 1)
        
        # High entropy might indicate encryption
        return entropy > 6.0
    
    def _interpret_entropy(self, entropy: float) -> str:
        """Interpret entropy value"""
        
        if entropy < 1.0:
            return "Very low entropy - highly structured data"
        elif entropy < 3.0:
            return "Low entropy - structured data with patterns"
        elif entropy < 5.0:
            return "Medium entropy - mixed structured/random data"
        elif entropy < 7.0:
            return "High entropy - mostly random data or compressed"
        else:
            return "Very high entropy - likely encrypted or highly compressed"
    
    def _is_image_file(self, file_path: Path) -> bool:
        """Check if file is an image"""
        
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif']
        return file_path.suffix.lower() in image_extensions
    
    def _is_document_file(self, file_path: Path) -> bool:
        """Check if file is a document"""
        
        doc_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp']
        return file_path.suffix.lower() in doc_extensions
    
    def _extract_exif_data(self, file_path: Path) -> Dict[str, Any]:
        """Extract EXIF data from images"""
        
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
    
    def _extract_extended_attributes(self, file_path: Path) -> Dict[str, Any]:
        """Extract extended file attributes"""
        
        try:
            import xattr
            
            attributes = {}
            for attr in xattr.listxattr(str(file_path)):
                try:
                    value = xattr.getxattr(str(file_path), attr)
                    attributes[attr] = value.decode('utf-8', errors='ignore')
                except Exception:
                    attributes[attr] = "<binary data>"
            
            return attributes
            
        except ImportError:
            return {"error": "xattr module not available"}
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_filesystem_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract file system metadata"""
        
        try:
            stat = file_path.stat()
            
            metadata = {
                "inode": stat.st_ino,
                "device": stat.st_dev,
                "hard_links": stat.st_nlink,
                "user_id": stat.st_uid,
                "group_id": stat.st_gid,
                "size": stat.st_size,
                "block_size": getattr(stat, 'st_blksize', None),
                "blocks": getattr(stat, 'st_blocks', None),
                "created_timestamp": stat.st_ctime,
                "modified_timestamp": stat.st_mtime,
                "accessed_timestamp": stat.st_atime
            }
            
            return metadata
            
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_document_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract document metadata using exiftool or similar"""
        
        try:
            # Try using exiftool if available
            result = subprocess.run(
                ["exiftool", "-json", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                metadata = json.loads(result.stdout)
                if metadata and len(metadata) > 0:
                    return metadata[0]
            
            return {"error": "Could not extract document metadata"}
            
        except subprocess.TimeoutExpired:
            return {"error": "Document metadata extraction timeout"}
        except FileNotFoundError:
            return {"error": "exiftool not available"}
        except Exception as e:
            return {"error": str(e)}