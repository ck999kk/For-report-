"""
Professional Investigation System - OSINT Collector
Open Source Intelligence gathering for professional investigations
"""

import requests
import re
import dns.resolver
import time
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
import socket
from urllib.parse import urljoin, urlparse
import base64

from ..core.exceptions import CybertraceException


class OSINTCollector:
    """Advanced OSINT collection for professional investigations"""
    
    def __init__(self, config: Dict[str, Any] = None, logger=None, security=None):
        self.config = config or {}
        self.logger = logger
        self.security = security
        
        # Configuration
        self.timeout = self.config.get("timeout", 30)
        self.retries = self.config.get("retries", 3)
        self.user_agent = self.config.get("user_agent", "Mozilla/5.0 (Investigation-System/1.0)")
        self.rate_limit = self.config.get("rate_limit", 5)  # requests per second
        self.max_results = self.config.get("max_results", 100)
        
        # Rate limiting
        self._last_request_time = 0
        self._request_lock = threading.Lock()
        
        # Session for connection reuse
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if self.logger:
            self.logger.info("OSINTCollector initialized")
    
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
    
    def search_social_media(self, target: str) -> List[Dict[str, Any]]:
        """Search for social media profiles"""
        
        try:
            self._rate_limit()
            
            results = []
            
            # Define social media platforms to search
            platforms = {
                "twitter": f"https://twitter.com/{target}",
                "facebook": f"https://facebook.com/{target}",
                "instagram": f"https://instagram.com/{target}",
                "linkedin": f"https://linkedin.com/in/{target}",
                "github": f"https://github.com/{target}",
                "reddit": f"https://reddit.com/user/{target}",
                "youtube": f"https://youtube.com/user/{target}",
                "tiktok": f"https://tiktok.com/@{target}",
                "snapchat": f"https://snapchat.com/add/{target}",
                "telegram": f"https://t.me/{target}"
            }
            
            for platform, url in platforms.items():
                try:
                    # Check if profile exists
                    response = self.session.head(
                        url,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                    
                    if response.status_code == 200:
                        # Get additional information
                        profile_info = self._analyze_social_profile(platform, url)
                        
                        results.append({
                            "platform": platform,
                            "url": url,
                            "status": "found",
                            "status_code": response.status_code,
                            "profile_info": profile_info,
                            "checked_at": datetime.utcnow().isoformat()
                        })
                    elif response.status_code == 404:
                        results.append({
                            "platform": platform,
                            "url": url,
                            "status": "not_found",
                            "status_code": response.status_code,
                            "checked_at": datetime.utcnow().isoformat()
                        })
                    else:
                        results.append({
                            "platform": platform,
                            "url": url,
                            "status": "unknown",
                            "status_code": response.status_code,
                            "checked_at": datetime.utcnow().isoformat()
                        })
                
                except Exception as e:
                    results.append({
                        "platform": platform,
                        "url": url,
                        "status": "error",
                        "error": str(e),
                        "checked_at": datetime.utcnow().isoformat()
                    })
                
                # Rate limiting between requests
                self._rate_limit()
            
            if self.logger:
                found_profiles = sum(1 for r in results if r["status"] == "found")
                self.logger.info(f"Social media search completed for {target}: {found_profiles} profiles found")
            
            return results
            
        except Exception as e:
            error_msg = f"Social media search failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="osint", target=target)
    
    def search_engines(self, target: str) -> List[Dict[str, Any]]:
        """Search for target in search engines"""
        
        try:
            results = []
            
            # Search queries to try
            search_queries = [
                f'"{target}"',
                f'{target} site:linkedin.com',
                f'{target} site:facebook.com',
                f'{target} site:twitter.com',
                f'{target} site:instagram.com',
                f'{target} filetype:pdf',
                f'{target} inurl:profile',
                f'{target} contact email'
            ]
            
            for query in search_queries:
                try:
                    self._rate_limit()
                    
                    # Use DuckDuckGo for search (more privacy-friendly)
                    search_results = self._duckduckgo_search(query)
                    
                    results.append({
                        "query": query,
                        "results": search_results,
                        "result_count": len(search_results),
                        "searched_at": datetime.utcnow().isoformat()
                    })
                    
                except Exception as e:
                    results.append({
                        "query": query,
                        "error": str(e),
                        "searched_at": datetime.utcnow().isoformat()
                    })
            
            if self.logger:
                total_results = sum(r.get("result_count", 0) for r in results)
                self.logger.info(f"Search engine queries completed for {target}: {total_results} total results")
            
            return results
            
        except Exception as e:
            error_msg = f"Search engine search failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="osint", target=target)
    
    def enumerate_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Enumerate subdomains for a domain"""
        
        try:
            subdomains = []
            
            # Common subdomain wordlist
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'test', 'dev', 'staging',
                'api', 'admin', 'blog', 'shop', 'store', 'support', 'help', 'forum', 'chat',
                'mobile', 'm', 'cdn', 'static', 'img', 'images', 'css', 'js', 'media',
                'video', 'secure', 'ssl', 'vpn', 'remote', 'intranet', 'extranet', 'portal',
                'demo', 'beta', 'alpha', 'stage', 'prod', 'production', 'app', 'apps',
                'old', 'new', 'beta', 'test2', 'dev2', 'staging2', 'backup', 'backups'
            ]
            
            # DNS enumeration
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    
                    # Try to resolve the subdomain
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    
                    try:
                        answers = resolver.resolve(full_domain, 'A')
                        ip_addresses = [str(answer) for answer in answers]
                        
                        # Get additional information
                        subdomain_info = self._analyze_subdomain(full_domain, ip_addresses)
                        
                        subdomains.append({
                            "subdomain": full_domain,
                            "ip_addresses": ip_addresses,
                            "status": "active",
                            "info": subdomain_info,
                            "checked_at": datetime.utcnow().isoformat()
                        })
                        
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        # Subdomain doesn't exist
                        pass
                    except dns.resolver.Timeout:
                        subdomains.append({
                            "subdomain": full_domain,
                            "status": "timeout",
                            "checked_at": datetime.utcnow().isoformat()
                        })
                
                except Exception as e:
                    subdomains.append({
                        "subdomain": f"{subdomain}.{domain}",
                        "status": "error",
                        "error": str(e),
                        "checked_at": datetime.utcnow().isoformat()
                    })
            
            # Certificate Transparency logs search (simplified)
            ct_subdomains = self._search_certificate_transparency(domain)
            subdomains.extend(ct_subdomains)
            
            if self.logger:
                active_subdomains = sum(1 for s in subdomains if s.get("status") == "active")
                self.logger.info(f"Subdomain enumeration completed for {domain}: {active_subdomains} active subdomains found")
            
            return subdomains
            
        except Exception as e:
            error_msg = f"Subdomain enumeration failed for {domain}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="osint", target=domain)
    
    def harvest_emails(self, target: str) -> List[Dict[str, Any]]:
        """Harvest email addresses related to target"""
        
        try:
            emails = []
            
            # Search for emails in web pages
            if self._is_domain(target):
                web_emails = self._harvest_emails_from_web(target)
                emails.extend(web_emails)
            
            # Search for emails in search engine results
            search_emails = self._harvest_emails_from_search(target)
            emails.extend(search_emails)
            
            # Common email patterns
            if self._is_domain(target):
                pattern_emails = self._generate_email_patterns(target)
                emails.extend(pattern_emails)
            
            # Remove duplicates
            unique_emails = []
            seen_emails = set()
            
            for email_info in emails:
                email = email_info.get("email", "").lower()
                if email and email not in seen_emails:
                    seen_emails.add(email)
                    unique_emails.append(email_info)
            
            if self.logger:
                self.logger.info(f"Email harvesting completed for {target}: {len(unique_emails)} unique emails found")
            
            return unique_emails
            
        except Exception as e:
            error_msg = f"Email harvesting failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="osint", target=target)
    
    def check_breach_databases(self, target: str) -> List[Dict[str, Any]]:
        """Check for target in breach databases (simulated)"""
        
        try:
            # Note: This is a simulated implementation
            # In a real system, you would integrate with actual breach databases
            # like HaveIBeenPwned API, security vendor APIs, etc.
            
            results = []
            
            # Simulated breach check
            breach_info = {
                "target": target,
                "checked_at": datetime.utcnow().isoformat(),
                "breaches_found": 0,
                "breach_details": [],
                "note": "This is a simulated breach check. Integrate with actual breach APIs for real data."
            }
            
            # Check if target looks like an email
            if "@" in target and "." in target:
                # Simulate email breach check
                breach_info["type"] = "email"
                # In real implementation, call HaveIBeenPwned API or similar
                breach_info["breach_details"] = [
                    {
                        "service": "Simulated Service",
                        "breach_date": "2020-01-01",
                        "data_types": ["emails", "passwords"],
                        "verified": False,
                        "note": "Simulated breach data"
                    }
                ]
                breach_info["breaches_found"] = len(breach_info["breach_details"])
            
            elif self._is_domain(target):
                # Simulate domain breach check
                breach_info["type"] = "domain"
                breach_info["breach_details"] = []
                breach_info["breaches_found"] = 0
            
            else:
                # Simulate username breach check
                breach_info["type"] = "username"
                breach_info["breach_details"] = []
                breach_info["breaches_found"] = 0
            
            results.append(breach_info)
            
            if self.logger:
                self.logger.info(f"Breach database check completed for {target}: {breach_info['breaches_found']} breaches found")
            
            return results
            
        except Exception as e:
            error_msg = f"Breach database check failed for {target}: {str(e)}"
            if self.logger:
                self.logger.error(error_msg)
            raise CybertraceException(error_msg, trace_type="osint", target=target)
    
    def _analyze_social_profile(self, platform: str, url: str) -> Dict[str, Any]:
        """Analyze social media profile for additional information"""
        
        try:
            self._rate_limit()
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                info = {
                    "title": self._extract_title(content),
                    "description": self._extract_description(content),
                    "has_profile_image": "profile" in content and ("image" in content or "avatar" in content),
                    "follower_indicators": any(word in content for word in ["followers", "following", "friends"]),
                    "post_indicators": any(word in content for word in ["posts", "tweets", "photos", "videos"]),
                    "verified_indicators": any(word in content for word in ["verified", "badge", "checkmark"])
                }
                
                return info
            
            return {"status_code": response.status_code}
            
        except Exception as e:
            return {"error": str(e)}
    
    def _duckduckgo_search(self, query: str) -> List[Dict[str, Any]]:
        """Perform search using DuckDuckGo"""
        
        try:
            # DuckDuckGo Instant Answer API (limited but doesn't require API key)
            url = "https://api.duckduckgo.com/"
            params = {
                "q": query,
                "format": "json",
                "no_html": "1",
                "skip_disambig": "1"
            }
            
            response = self.session.get(url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                results = []
                
                # Process instant answer
                if data.get("Answer"):
                    results.append({
                        "type": "instant_answer",
                        "title": "DuckDuckGo Instant Answer",
                        "content": data["Answer"],
                        "url": data.get("AnswerURL", "")
                    })
                
                # Process abstract
                if data.get("Abstract"):
                    results.append({
                        "type": "abstract",
                        "title": data.get("Heading", "Abstract"),
                        "content": data["Abstract"],
                        "url": data.get("AbstractURL", "")
                    })
                
                # Process related topics
                for topic in data.get("RelatedTopics", [])[:5]:  # Limit to 5
                    if isinstance(topic, dict) and topic.get("Text"):
                        results.append({
                            "type": "related_topic",
                            "title": topic.get("FirstURL", "Related Topic"),
                            "content": topic["Text"],
                            "url": topic.get("FirstURL", "")
                        })
                
                return results
            
            return []
            
        except Exception as e:
            if self.logger:
                self.logger.warning(f"DuckDuckGo search failed: {str(e)}")
            return []
    
    def _analyze_subdomain(self, subdomain: str, ip_addresses: List[str]) -> Dict[str, Any]:
        """Analyze subdomain for additional information"""
        
        try:
            info = {
                "ip_count": len(ip_addresses),
                "http_status": None,
                "https_status": None,
                "technologies": [],
                "titles": []
            }
            
            # Check HTTP and HTTPS
            for protocol in ["http", "https"]:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.head(url, timeout=10, allow_redirects=True)
                    
                    if protocol == "http":
                        info["http_status"] = response.status_code
                    else:
                        info["https_status"] = response.status_code
                    
                    # Get page title if status is 200
                    if response.status_code == 200:
                        try:
                            page_response = self.session.get(url, timeout=10)
                            title = self._extract_title(page_response.text)
                            if title:
                                info["titles"].append({"protocol": protocol, "title": title})
                        except Exception:
                            pass
                
                except Exception:
                    pass
            
            return info
            
        except Exception as e:
            return {"error": str(e)}
    
    def _search_certificate_transparency(self, domain: str) -> List[Dict[str, Any]]:
        """Search Certificate Transparency logs for subdomains"""
        
        try:
            # This is a simplified implementation
            # In production, you would use services like crt.sh API
            
            subdomains = []
            
            # Simulated CT log search
            # In real implementation, query crt.sh or similar service
            simulated_ct_domains = [
                f"api.{domain}",
                f"cdn.{domain}",
                f"blog.{domain}",
                f"admin.{domain}"
            ]
            
            for ct_domain in simulated_ct_domains:
                try:
                    # Try to resolve to verify it exists
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    answers = resolver.resolve(ct_domain, 'A')
                    ip_addresses = [str(answer) for answer in answers]
                    
                    subdomains.append({
                        "subdomain": ct_domain,
                        "ip_addresses": ip_addresses,
                        "status": "active",
                        "source": "certificate_transparency",
                        "checked_at": datetime.utcnow().isoformat()
                    })
                    
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    pass
            
            return subdomains
            
        except Exception:
            return []
    
    def _is_domain(self, target: str) -> bool:
        """Check if target appears to be a domain"""
        
        return "." in target and not "@" in target and not "/" in target
    
    def _harvest_emails_from_web(self, domain: str) -> List[Dict[str, Any]]:
        """Harvest emails from web pages"""
        
        try:
            emails = []
            
            # Common pages to check for emails
            pages = [
                f"http://{domain}",
                f"https://{domain}",
                f"http://{domain}/contact",
                f"https://{domain}/contact",
                f"http://{domain}/about",
                f"https://{domain}/about"
            ]
            
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            
            for page_url in pages:
                try:
                    self._rate_limit()
                    response = self.session.get(page_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        found_emails = email_pattern.findall(response.text)
                        
                        for email in found_emails:
                            emails.append({
                                "email": email.lower(),
                                "source": "web_page",
                                "source_url": page_url,
                                "found_at": datetime.utcnow().isoformat()
                            })
                
                except Exception:
                    continue
            
            return emails
            
        except Exception:
            return []
    
    def _harvest_emails_from_search(self, target: str) -> List[Dict[str, Any]]:
        """Harvest emails from search engine results"""
        
        try:
            emails = []
            
            # Search for email patterns
            search_query = f'{target} "@" email contact'
            search_results = self._duckduckgo_search(search_query)
            
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            
            for result in search_results:
                content = result.get("content", "")
                found_emails = email_pattern.findall(content)
                
                for email in found_emails:
                    emails.append({
                        "email": email.lower(),
                        "source": "search_result",
                        "source_title": result.get("title", ""),
                        "found_at": datetime.utcnow().isoformat()
                    })
            
            return emails
            
        except Exception:
            return []
    
    def _generate_email_patterns(self, domain: str) -> List[Dict[str, Any]]:
        """Generate common email patterns for a domain"""
        
        try:
            emails = []
            
            # Common email patterns
            common_patterns = [
                f"info@{domain}",
                f"contact@{domain}",
                f"admin@{domain}",
                f"support@{domain}",
                f"sales@{domain}",
                f"marketing@{domain}",
                f"help@{domain}",
                f"webmaster@{domain}",
                f"postmaster@{domain}",
                f"noreply@{domain}"
            ]
            
            for email in common_patterns:
                emails.append({
                    "email": email,
                    "source": "pattern_generation",
                    "verified": False,
                    "generated_at": datetime.utcnow().isoformat()
                })
            
            return emails
            
        except Exception:
            return []
    
    def _extract_title(self, html_content: str) -> Optional[str]:
        """Extract title from HTML content"""
        
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
                # Clean up title
                title = re.sub(r'\s+', ' ', title)
                return title[:200]  # Limit length
            return None
        except Exception:
            return None
    
    def _extract_description(self, html_content: str) -> Optional[str]:
        """Extract description from HTML content"""
        
        try:
            desc_pattern = r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\'][^>]*>'
            desc_match = re.search(desc_pattern, html_content, re.IGNORECASE)
            if desc_match:
                description = desc_match.group(1).strip()
                return description[:500]  # Limit length
            return None
        except Exception:
            return None