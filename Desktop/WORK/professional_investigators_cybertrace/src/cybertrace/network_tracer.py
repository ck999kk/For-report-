"""
Professional Investigation System - Network Tracer
Advanced network analysis and reconnaissance capabilities
"""

import socket
import ssl
import subprocess
import requests
import dns.resolver
import whois
import concurrent.futures
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import json
import ipaddress
import threading
import time

from ..core.exceptions import NetworkTraceException


class NetworkTracer:
    """Advanced network tracing for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Configuration
        self.timeout = self.config.get("timeout", 30)
        self.retries = self.config.get("retries", 3)
        self.user_agent = self.config.get("user_agent", "Professional-Investigation-System/1.0")
        self.rate_limit = self.config.get("rate_limit", 10)  # requests per second
        
        # Rate limiting
        self._last_request_time = 0
        self._request_lock = threading.Lock()
        
        if self.logger:
            self.logger.info("NetworkTracer initialized")
    
    def _rate_limit(self):
        """Apply rate limiting to requests"""
        
        with self._request_lock:
            current_time = time.time()
            time_since_last = current_time - self._last_request_time
            min_interval = 1.0 / self.rate_limit
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
            
            self._last_request_time = time.time()
    
    def dns_lookup(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive DNS lookup"""
        
        try:
            self._rate_limit()
            
            results = {
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "records": {}
            }
            
            # Record types to query
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR']
            
            for record_type in record_types:
                try:
                    if record_type == 'PTR':
                        # Special handling for PTR records (reverse DNS)
                        if self._is_ip_address(target):
                            resolver = dns.resolver.Resolver()
                            resolver.timeout = self.timeout
                            reversed_ip = dns.reversename.from_address(target)
                            answers = resolver.resolve(reversed_ip, record_type)
                            results["records"][record_type] = [str(answer) for answer in answers]
                    else:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = self.timeout
                        answers = resolver.resolve(target, record_type)
                        
                        if record_type == 'MX':
                            results["records"][record_type] = [
                                {"priority": answer.preference, "exchange": str(answer.exchange)}
                                for answer in answers
                            ]
                        elif record_type == 'SOA':
                            soa = answers[0]
                            results["records"][record_type] = {
                                "mname": str(soa.mname),
                                "rname": str(soa.rname),
                                "serial": soa.serial,
                                "refresh": soa.refresh,
                                "retry": soa.retry,
                                "expire": soa.expire,
                                "minimum": soa.minimum
                            }
                        else:
                            results["records"][record_type] = [str(answer) for answer in answers]
                            
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    results["records"][record_type] = []
                except Exception as e:
                    results["records"][record_type] = {"error": str(e)}
            
            # Additional DNS information
            results["nameservers"] = self._get_authoritative_nameservers(target)
            results["reverse_dns"] = self._get_reverse_dns_info(target)
            
            if self.logger:
                self.logger.info(f"DNS lookup completed for {target}")
            
            return results
            
        except Exception as e:
            error_msg = f"DNS lookup failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise NetworkTraceException(error_msg, network_target=target)
    
    def whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        
        try:
            self._rate_limit()
            
            results = {
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "whois_data": {}
            }
            
            # Perform WHOIS lookup
            try:
                whois_data = whois.whois(target)
                
                # Convert to serializable format
                results["whois_data"] = {}
                for key, value in whois_data.items():
                    if value is not None:
                        if isinstance(value, list):
                            results["whois_data"][key] = [str(v) for v in value if v is not None]
                        else:
                            results["whois_data"][key] = str(value)
                
                # Extract key information
                results["registrar"] = whois_data.registrar
                results["creation_date"] = str(whois_data.creation_date) if whois_data.creation_date else None
                results["expiration_date"] = str(whois_data.expiration_date) if whois_data.expiration_date else None
                results["name_servers"] = whois_data.name_servers if whois_data.name_servers else []
                results["emails"] = whois_data.emails if whois_data.emails else []
                
            except Exception as e:
                results["whois_data"] = {"error": str(e)}
            
            if self.logger:
                self.logger.info(f"WHOIS lookup completed for {target}")
            
            return results
            
        except Exception as e:
            error_msg = f"WHOIS lookup failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise NetworkTraceException(error_msg, network_target=target)
    
    def port_scan(self, target: str, port_range: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        
        try:
            results = {
                "target": target,
                "port_range": port_range,
                "timestamp": datetime.utcnow().isoformat(),
                "open_ports": [],
                "closed_ports": [],
                "filtered_ports": []
            }
            
            # Parse port range
            if "-" in port_range:
                start_port, end_port = map(int, port_range.split("-"))
                ports = list(range(start_port, end_port + 1))
            else:
                ports = [int(port_range)]
            
            # Resolve hostname to IP
            try:
                target_ip = socket.gethostbyname(target)
                results["target_ip"] = target_ip
            except socket.gaierror:
                if self._is_ip_address(target):
                    target_ip = target
                    results["target_ip"] = target_ip
                else:
                    raise NetworkTraceException(f"Cannot resolve hostname: {target}")
            
            # Scan ports
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)  # 2 second timeout for port scan
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    
                    if result == 0:
                        # Try to get service banner
                        banner = self._get_service_banner(target_ip, port)
                        return {"port": port, "status": "open", "banner": banner}
                    else:
                        return {"port": port, "status": "closed"}
                        
                except Exception:
                    return {"port": port, "status": "filtered"}
            
            # Use thread pool for concurrent scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                scan_results = list(executor.map(scan_port, ports))
            
            # Categorize results
            for result in scan_results:
                if result["status"] == "open":
                    results["open_ports"].append(result)
                elif result["status"] == "closed":
                    results["closed_ports"].append({"port": result["port"]})
                else:
                    results["filtered_ports"].append({"port": result["port"]})
            
            # Add service identification for open ports
            results["services"] = self._identify_services(results["open_ports"])
            
            if self.logger:
                self.logger.info(f"Port scan completed for {target}: {len(results['open_ports'])} open ports")
            
            return results
            
        except Exception as e:
            error_msg = f"Port scan failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise NetworkTraceException(error_msg, network_target=target)
    
    def traceroute(self, target: str) -> Dict[str, Any]:
        """Perform traceroute"""
        
        try:
            results = {
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "hops": []
            }
            
            # Use system traceroute command
            try:
                # Try different traceroute commands based on the system
                cmd = ["traceroute", "-n", "-m", "30", target]
                
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if process.returncode == 0:
                    lines = process.stdout.strip().split('\n')[1:]  # Skip header
                    
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                hop_num = parts[0]
                                if '*' in line:
                                    results["hops"].append({
                                        "hop": hop_num,
                                        "ip": "*",
                                        "hostname": "*",
                                        "rtt": ["*", "*", "*"]
                                    })
                                else:
                                    # Extract IP and timing information
                                    ip = parts[1] if len(parts) > 1 else "*"
                                    rtt_times = []
                                    
                                    for part in parts[2:]:
                                        if "ms" in part:
                                            rtt_times.append(part.replace("ms", ""))
                                    
                                    results["hops"].append({
                                        "hop": hop_num,
                                        "ip": ip,
                                        "hostname": self._reverse_dns_lookup(ip) if ip != "*" else "*",
                                        "rtt": rtt_times
                                    })
                else:
                    results["error"] = process.stderr
                    
            except subprocess.TimeoutExpired:
                results["error"] = "Traceroute timeout"
            except FileNotFoundError:
                # Fallback to custom traceroute implementation
                results = self._custom_traceroute(target)
            
            if self.logger:
                self.logger.info(f"Traceroute completed for {target}")
            
            return results
            
        except Exception as e:
            error_msg = f"Traceroute failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise NetworkTraceException(error_msg, network_target=target)
    
    def analyze_ssl_certificate(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        
        try:
            results = {
                "target": target,
                "port": port,
                "timestamp": datetime.utcnow().isoformat(),
                "certificate": {}
            }
            
            # Get SSL certificate
            context = ssl.create_default_context()
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    # Extract certificate information
                    results["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_name": cert.get("subjectAltName", []),
                        "signature_algorithm": cert.get("signatureAlgorithm"),
                        "public_key_algorithm": self._get_public_key_algorithm(cert_der),
                        "key_size": self._get_key_size(cert_der)
                    }
                    
                    # SSL/TLS protocol information
                    results["ssl_info"] = {
                        "protocol": ssock.version(),
                        "cipher": ssock.cipher(),
                        "compression": ssock.compression(),
                        "server_hostname": ssock.server_hostname
                    }
                    
                    # Certificate validation
                    results["validation"] = self._validate_certificate(cert)
            
            if self.logger:
                self.logger.info(f"SSL certificate analysis completed for {target}:{port}")
            
            return results
            
        except Exception as e:
            error_msg = f"SSL certificate analysis failed for {target}:{port}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            return {
                "target": target,
                "port": port,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }
    
    def analyze_http_headers(self, target: str, port: int = 80, use_https: bool = None) -> Dict[str, Any]:
        """Analyze HTTP headers"""
        
        try:
            # Determine protocol
            if use_https is None:
                use_https = port == 443
            
            protocol = "https" if use_https else "http"
            url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
            
            results = {
                "target": target,
                "url": url,
                "timestamp": datetime.utcnow().isoformat(),
                "headers": {},
                "server_info": {},
                "security_headers": {},
                "technologies": []
            }
            
            # Make HTTP request
            headers = {"User-Agent": self.user_agent}
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False  # For investigation purposes
            )
            
            # Extract headers
            results["headers"] = dict(response.headers)
            results["status_code"] = response.status_code
            results["final_url"] = response.url
            
            # Extract server information
            server = response.headers.get("Server", "")
            results["server_info"] = {
                "server": server,
                "powered_by": response.headers.get("X-Powered-By", ""),
                "generator": response.headers.get("Generator", ""),
                "technology": response.headers.get("X-Technology", "")
            }
            
            # Analyze security headers
            security_headers = {
                "content_security_policy": response.headers.get("Content-Security-Policy"),
                "strict_transport_security": response.headers.get("Strict-Transport-Security"),
                "x_frame_options": response.headers.get("X-Frame-Options"),
                "x_content_type_options": response.headers.get("X-Content-Type-Options"),
                "x_xss_protection": response.headers.get("X-XSS-Protection"),
                "referrer_policy": response.headers.get("Referrer-Policy"),
                "feature_policy": response.headers.get("Feature-Policy"),
                "permissions_policy": response.headers.get("Permissions-Policy")
            }
            
            results["security_headers"] = {k: v for k, v in security_headers.items() if v is not None}
            results["security_score"] = self._calculate_security_score(security_headers)
            
            # Technology detection
            results["technologies"] = self._detect_technologies(response)
            
            # Redirect chain analysis
            if response.history:
                results["redirect_chain"] = [
                    {"url": r.url, "status_code": r.status_code}
                    for r in response.history
                ]
            
            if self.logger:
                self.logger.info(f"HTTP headers analysis completed for {url}")
            
            return results
            
        except Exception as e:
            error_msg = f"HTTP headers analysis failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            return {
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _get_authoritative_nameservers(self, domain: str) -> List[str]:
        """Get authoritative nameservers for domain"""
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            answers = resolver.resolve(domain, 'NS')
            return [str(answer) for answer in answers]
        except Exception:
            return []
    
    def _get_reverse_dns_info(self, target: str) -> Dict[str, Any]:
        """Get reverse DNS information"""
        
        try:
            if self._is_ip_address(target):
                hostname = socket.gethostbyaddr(target)[0]
                return {"hostname": hostname}
            else:
                ip = socket.gethostbyname(target)
                return {"ip": ip}
        except Exception:
            return {}
    
    def _get_service_banner(self, ip: str, port: int) -> Optional[str]:
        """Get service banner from open port"""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def _identify_services(self, open_ports: List[Dict[str, Any]]) -> Dict[int, str]:
        """Identify services running on open ports"""
        
        # Common service ports
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL"
        }
        
        services = {}
        for port_info in open_ports:
            port = port_info["port"]
            service = common_services.get(port, "Unknown")
            
            # Try to identify from banner
            if port_info.get("banner"):
                banner = port_info["banner"].lower()
                if "http" in banner:
                    service = "HTTP"
                elif "ssh" in banner:
                    service = "SSH"
                elif "ftp" in banner:
                    service = "FTP"
                elif "smtp" in banner:
                    service = "SMTP"
            
            services[port] = service
        
        return services
    
    def _reverse_dns_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup"""
        
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip
    
    def _custom_traceroute(self, target: str) -> Dict[str, Any]:
        """Custom traceroute implementation using ICMP"""
        
        results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "hops": [],
            "method": "custom_icmp"
        }
        
        try:
            # This is a simplified implementation
            # In production, you'd need proper ICMP socket handling
            results["error"] = "Custom traceroute not implemented - requires raw socket privileges"
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _get_public_key_algorithm(self, cert_der: bytes) -> str:
        """Extract public key algorithm from certificate"""
        
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(cert_der)
            return cert.public_key().__class__.__name__
        except Exception:
            return "Unknown"
    
    def _get_key_size(self, cert_der: bytes) -> Optional[int]:
        """Extract key size from certificate"""
        
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
            
            if hasattr(public_key, 'key_size'):
                return public_key.key_size
        except Exception:
            pass
        
        return None
    
    def _validate_certificate(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SSL certificate"""
        
        validation = {
            "is_valid": True,
            "issues": []
        }
        
        try:
            # Check expiration
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            if datetime.utcnow() > not_after:
                validation["is_valid"] = False
                validation["issues"].append("Certificate is expired")
            
            # Check if certificate is valid yet
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            if datetime.utcnow() < not_before:
                validation["is_valid"] = False
                validation["issues"].append("Certificate is not yet valid")
            
            # Check for self-signed (basic check)
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            
            if subject == issuer:
                validation["issues"].append("Certificate appears to be self-signed")
            
        except Exception as e:
            validation["issues"].append(f"Validation error: {str(e)}")
        
        return validation
    
    def _calculate_security_score(self, security_headers: Dict[str, Any]) -> int:
        """Calculate security score based on headers"""
        
        score = 0
        max_score = 100
        
        # Security headers scoring
        header_weights = {
            "content_security_policy": 25,
            "strict_transport_security": 20,
            "x_frame_options": 15,
            "x_content_type_options": 15,
            "x_xss_protection": 10,
            "referrer_policy": 10,
            "permissions_policy": 5
        }
        
        for header, weight in header_weights.items():
            if security_headers.get(header):
                score += weight
        
        return min(score, max_score)
    
    def _detect_technologies(self, response) -> List[str]:
        """Detect technologies from HTTP response"""
        
        technologies = []
        
        # Server header analysis
        server = response.headers.get("Server", "").lower()
        if "apache" in server:
            technologies.append("Apache")
        if "nginx" in server:
            technologies.append("Nginx")
        if "iis" in server:
            technologies.append("IIS")
        
        # Powered-by header
        powered_by = response.headers.get("X-Powered-By", "").lower()
        if "php" in powered_by:
            technologies.append("PHP")
        if "asp.net" in powered_by:
            technologies.append("ASP.NET")
        
        # Content analysis
        content = response.text.lower()
        if "wordpress" in content:
            technologies.append("WordPress")
        if "drupal" in content:
            technologies.append("Drupal")
        if "joomla" in content:
            technologies.append("Joomla")
        
        return list(set(technologies))