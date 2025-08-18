"""
OSINT Phone Collector Module
Advanced Open Source Intelligence gathering for phone numbers
"""

import re
import json
import time
import hashlib
import logging
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import quote, urlencode
import random

from ..core.logger import get_logger
from ..core.exceptions import InvestigationException


@dataclass
class OSINTResult:
    """OSINT collection result"""
    source: str
    data_type: str
    content: Dict[str, Any]
    confidence: float
    timestamp: datetime
    evidence_hash: str = None


class OSINTPhoneCollector:
    """
    Advanced OSINT collection system for phone number intelligence
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize OSINT Phone Collector
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config.get('osint_phone', {})
        self.logger = logger or get_logger(__name__)
        
        # Search engines and services configuration
        self.search_engines = {
            'google': {
                'enabled': self.config.get('google_enabled', True),
                'base_url': 'https://www.google.com/search',
                'rate_limit': 10,  # requests per minute
                'user_agents': [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                ]
            },
            'bing': {
                'enabled': self.config.get('bing_enabled', True),
                'base_url': 'https://www.bing.com/search',
                'rate_limit': 15,
                'user_agents': [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
                ]
            },
            'duckduckgo': {
                'enabled': self.config.get('duckduckgo_enabled', True),
                'base_url': 'https://duckduckgo.com/',
                'rate_limit': 20
            }
        }
        
        # Directory services configuration
        self.directory_services = {
            'truecaller': {
                'enabled': self.config.get('truecaller_enabled', False),
                'api_key': self.config.get('truecaller_api_key'),
                'base_url': 'https://api.truecaller.com/v1/lookup',
                'rate_limit': 100
            },
            'whitepages': {
                'enabled': self.config.get('whitepages_enabled', False),
                'api_key': self.config.get('whitepages_api_key'),
                'base_url': 'https://api.whitepages.com/api/v1/phone',
                'rate_limit': 50
            }
        }
        
        # Social media patterns
        self.social_patterns = {
            'telegram': r'(?:t\.me|telegram\.me)\/(?:joinchat\/)?([A-Za-z0-9_]+)',
            'whatsapp': r'(?:wa\.me|whatsapp\.com\/send\?phone=)([0-9]+)',
            'viber': r'viber://(?:chat|add)\?number=([0-9+]+)',
            'signal': r'signal\.me\/#p\/([0-9+]+)',
            'facebook': r'facebook\.com\/([A-Za-z0-9.]+)',
            'instagram': r'instagram\.com\/([A-Za-z0-9_.]+)',
            'twitter': r'twitter\.com\/([A-Za-z0-9_]+)',
            'linkedin': r'linkedin\.com\/in\/([A-Za-z0-9-]+)'
        }
        
        # Rate limiting tracking
        self.request_history = {}
        
        # Session for connection pooling
        self.session = requests.Session()
        
        self.logger.info("OSINT Phone Collector initialized")
    
    def collect_intelligence(self, phone_number: str) -> Dict[str, Any]:
        """
        Collect comprehensive OSINT intelligence for phone number
        
        Args:
            phone_number: Phone number to investigate
            
        Returns:
            Dict containing all OSINT intelligence
        """
        try:
            self.logger.info(f"Starting OSINT collection for: {phone_number[:3]}***{phone_number[-3:]}")
            
            results = {
                'phone_number': phone_number,
                'search_engine_results': [],
                'directory_lookups': [],
                'social_media_mentions': [],
                'business_listings': [],
                'spam_reports': [],
                'public_records': [],
                'analysis_summary': {},
                'collection_timestamp': datetime.now(timezone.utc),
                'total_sources': 0,
                'confidence_score': 0.0
            }
            
            # Search engine intelligence
            search_results = self._collect_search_engine_intel(phone_number)
            results['search_engine_results'] = search_results
            
            # Directory service lookups
            directory_results = self._collect_directory_intel(phone_number)
            results['directory_lookups'] = directory_results
            
            # Social media mentions analysis
            social_mentions = self._analyze_social_media_mentions(phone_number, search_results)
            results['social_media_mentions'] = social_mentions
            
            # Business listings search
            business_listings = self._search_business_listings(phone_number)
            results['business_listings'] = business_listings
            
            # Spam/scam database checks
            spam_reports = self._check_spam_databases(phone_number)
            results['spam_reports'] = spam_reports
            
            # Public records search (where legal)
            public_records = self._search_public_records(phone_number)
            results['public_records'] = public_records
            
            # Generate analysis summary
            results['analysis_summary'] = self._generate_analysis_summary(results)
            results['total_sources'] = self._count_total_sources(results)
            results['confidence_score'] = self._calculate_confidence_score(results)
            
            self.logger.info(f"OSINT collection completed. Found {results['total_sources']} sources")
            return results
            
        except Exception as e:
            self.logger.error(f"Error in OSINT collection: {e}")
            return {
                'error': str(e),
                'phone_number': phone_number,
                'collection_timestamp': datetime.now(timezone.utc)
            }
    
    def _collect_search_engine_intel(self, phone_number: str) -> List[OSINTResult]:
        """
        Collect intelligence from search engines
        
        Args:
            phone_number: Phone number to search
            
        Returns:
            List of OSINT results from search engines
        """
        results = []
        
        # Format variations of the phone number for searching
        search_formats = self._generate_search_formats(phone_number)
        
        for engine_name, engine_config in self.search_engines.items():
            if not engine_config['enabled']:
                continue
                
            try:
                self.logger.debug(f"Searching {engine_name} for phone number")
                
                for phone_format in search_formats[:3]:  # Limit to top 3 formats per engine
                    if not self._check_rate_limit(engine_name):
                        self.logger.warning(f"Rate limit exceeded for {engine_name}")
                        break
                    
                    engine_results = self._search_engine(engine_name, phone_format, engine_config)
                    if engine_results:
                        results.extend(engine_results)
                    
                    # Delay between requests
                    time.sleep(random.uniform(2, 5))
                    
            except Exception as e:
                self.logger.error(f"Error searching {engine_name}: {e}")
        
        return results
    
    def _generate_search_formats(self, phone_number: str) -> List[str]:
        """
        Generate different search format variations of the phone number
        
        Args:
            phone_number: Original phone number
            
        Returns:
            List of phone number format variations
        """
        # Clean the number first
        clean_number = re.sub(r'[^\d+]', '', phone_number)
        
        formats = []
        
        # Original format
        formats.append(f'"{phone_number}"')
        
        # E.164 format
        if clean_number.startswith('+'):
            formats.append(f'"{clean_number}"')
        
        # With parentheses (US format)
        if len(clean_number) >= 10:
            if clean_number.startswith('+1') or clean_number.startswith('1'):
                number_part = clean_number.lstrip('+1')
                if len(number_part) == 10:
                    formatted = f"({number_part[:3]}) {number_part[3:6]}-{number_part[6:]}"
                    formats.append(f'"{formatted}"')
        
        # With dashes
        if len(clean_number) >= 10:
            number_part = clean_number.lstrip('+')
            if len(number_part) >= 10:
                last_10 = number_part[-10:]
                formatted = f"{last_10[:3]}-{last_10[3:6]}-{last_10[6:]}"
                formats.append(f'"{formatted}"')
        
        # With dots
        if len(clean_number) >= 10:
            number_part = clean_number.lstrip('+')
            if len(number_part) >= 10:
                last_10 = number_part[-10:]
                formatted = f"{last_10[:3]}.{last_10[3:6]}.{last_10[6:]}"
                formats.append(f'"{formatted}"')
        
        # With spaces
        if len(clean_number) >= 10:
            number_part = clean_number.lstrip('+')
            if len(number_part) >= 10:
                last_10 = number_part[-10:]
                formatted = f"{last_10[:3]} {last_10[3:6]} {last_10[6:]}"
                formats.append(f'"{formatted}"')
        
        return list(set(formats))  # Remove duplicates
    
    def _search_engine(self, engine_name: str, query: str, config: Dict[str, Any]) -> List[OSINTResult]:
        """
        Search specific search engine for phone number mentions
        
        Args:
            engine_name: Name of search engine
            query: Search query
            config: Engine configuration
            
        Returns:
            List of OSINT results
        """
        results = []
        
        try:
            headers = {
                'User-Agent': random.choice(config.get('user_agents', [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                ]))
            }
            
            if engine_name == 'google':
                results.extend(self._search_google(query, headers))
            elif engine_name == 'bing':
                results.extend(self._search_bing(query, headers))
            elif engine_name == 'duckduckgo':
                results.extend(self._search_duckduckgo(query, headers))
            
        except Exception as e:
            self.logger.error(f"Error searching {engine_name}: {e}")
        
        return results
    
    def _search_google(self, query: str, headers: Dict[str, str]) -> List[OSINTResult]:
        """Search Google for phone number mentions"""
        results = []
        
        try:
            params = {
                'q': query,
                'num': 20,
                'hl': 'en'
            }
            
            response = self.session.get(
                'https://www.google.com/search',
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                # Basic parsing of search results
                # In production, would use more sophisticated parsing
                mentions = self._extract_mentions_from_html(response.text, 'google')
                
                for mention in mentions:
                    result = OSINTResult(
                        source='google_search',
                        data_type='search_result',
                        content=mention,
                        confidence=0.6,
                        timestamp=datetime.now(timezone.utc)
                    )
                    result.evidence_hash = self._generate_evidence_hash(result)
                    results.append(result)
            
        except Exception as e:
            self.logger.error(f"Google search error: {e}")
        
        return results
    
    def _search_bing(self, query: str, headers: Dict[str, str]) -> List[OSINTResult]:
        """Search Bing for phone number mentions"""
        results = []
        
        try:
            params = {
                'q': query,
                'count': 20
            }
            
            response = self.session.get(
                'https://www.bing.com/search',
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                mentions = self._extract_mentions_from_html(response.text, 'bing')
                
                for mention in mentions:
                    result = OSINTResult(
                        source='bing_search',
                        data_type='search_result',
                        content=mention,
                        confidence=0.6,
                        timestamp=datetime.now(timezone.utc)
                    )
                    result.evidence_hash = self._generate_evidence_hash(result)
                    results.append(result)
            
        except Exception as e:
            self.logger.error(f"Bing search error: {e}")
        
        return results
    
    def _search_duckduckgo(self, query: str, headers: Dict[str, str]) -> List[OSINTResult]:
        """Search DuckDuckGo for phone number mentions"""
        results = []
        
        try:
            params = {
                'q': query,
                'format': 'json',
                'no_html': '1',
                'skip_disambig': '1'
            }
            
            response = self.session.get(
                'https://api.duckduckgo.com/',
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Process results
                for item in data.get('Results', [])[:10]:
                    mention = {
                        'title': item.get('Text', ''),
                        'url': item.get('FirstURL', ''),
                        'snippet': item.get('Result', '')
                    }
                    
                    result = OSINTResult(
                        source='duckduckgo_search',
                        data_type='search_result',
                        content=mention,
                        confidence=0.5,
                        timestamp=datetime.now(timezone.utc)
                    )
                    result.evidence_hash = self._generate_evidence_hash(result)
                    results.append(result)
            
        except Exception as e:
            self.logger.error(f"DuckDuckGo search error: {e}")
        
        return results
    
    def _collect_directory_intel(self, phone_number: str) -> List[OSINTResult]:
        """
        Collect intelligence from phone directory services
        
        Args:
            phone_number: Phone number to lookup
            
        Returns:
            List of directory lookup results
        """
        results = []
        
        for service_name, service_config in self.directory_services.items():
            if not service_config['enabled']:
                continue
                
            try:
                self.logger.debug(f"Looking up {service_name} directory")
                
                if not self._check_rate_limit(service_name):
                    self.logger.warning(f"Rate limit exceeded for {service_name}")
                    continue
                
                if service_name == 'truecaller':
                    service_results = self._lookup_truecaller(phone_number, service_config)
                elif service_name == 'whitepages':
                    service_results = self._lookup_whitepages(phone_number, service_config)
                
                if service_results:
                    results.extend(service_results)
                    
            except Exception as e:
                self.logger.error(f"Error with {service_name} lookup: {e}")
        
        return results
    
    def _lookup_truecaller(self, phone_number: str, config: Dict[str, Any]) -> List[OSINTResult]:
        """Lookup phone number on TrueCaller"""
        results = []
        
        try:
            if not config.get('api_key'):
                self.logger.warning("TrueCaller API key not configured")
                return results
            
            headers = {
                'Authorization': f'Bearer {config["api_key"]}',
                'Content-Type': 'application/json'
            }
            
            params = {
                'phone': phone_number,
                'countryCode': 'US'  # Default, should be dynamic
            }
            
            response = self.session.get(
                config['base_url'],
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result = OSINTResult(
                    source='truecaller',
                    data_type='directory_lookup',
                    content=data,
                    confidence=0.8,
                    timestamp=datetime.now(timezone.utc)
                )
                result.evidence_hash = self._generate_evidence_hash(result)
                results.append(result)
            
        except Exception as e:
            self.logger.error(f"TrueCaller lookup error: {e}")
        
        return results
    
    def _lookup_whitepages(self, phone_number: str, config: Dict[str, Any]) -> List[OSINTResult]:
        """Lookup phone number on WhitePages"""
        results = []
        
        try:
            if not config.get('api_key'):
                self.logger.warning("WhitePages API key not configured")
                return results
            
            params = {
                'api_key': config['api_key'],
                'phone': phone_number
            }
            
            response = self.session.get(
                config['base_url'],
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result = OSINTResult(
                    source='whitepages',
                    data_type='directory_lookup',
                    content=data,
                    confidence=0.7,
                    timestamp=datetime.now(timezone.utc)
                )
                result.evidence_hash = self._generate_evidence_hash(result)
                results.append(result)
            
        except Exception as e:
            self.logger.error(f"WhitePages lookup error: {e}")
        
        return results
    
    def _analyze_social_media_mentions(self, phone_number: str, search_results: List[OSINTResult]) -> List[Dict[str, Any]]:
        """
        Analyze search results for social media mentions
        
        Args:
            phone_number: Phone number being analyzed
            search_results: Search engine results to analyze
            
        Returns:
            List of social media mentions found
        """
        mentions = []
        
        try:
            for result in search_results:
                content = result.content
                text_content = f"{content.get('title', '')} {content.get('snippet', '')} {content.get('url', '')}"
                
                for platform, pattern in self.social_patterns.items():
                    matches = re.findall(pattern, text_content, re.IGNORECASE)
                    
                    for match in matches:
                        mention = {
                            'platform': platform,
                            'identifier': match,
                            'source_url': content.get('url', ''),
                            'context': content.get('snippet', ''),
                            'confidence': 0.6,
                            'found_in': result.source,
                            'timestamp': datetime.now(timezone.utc)
                        }
                        mentions.append(mention)
        
        except Exception as e:
            self.logger.error(f"Error analyzing social media mentions: {e}")
        
        return mentions
    
    def _search_business_listings(self, phone_number: str) -> List[Dict[str, Any]]:
        """
        Search business directories and listings for phone number
        
        Args:
            phone_number: Phone number to search
            
        Returns:
            List of business listings found
        """
        listings = []
        
        try:
            # Google Business search
            business_query = f'"{phone_number}" business'
            headers = {'User-Agent': random.choice(self.search_engines['google']['user_agents'])}
            
            params = {
                'q': business_query,
                'num': 10
            }
            
            response = self.session.get(
                'https://www.google.com/search',
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                # Extract business listings from response
                business_mentions = self._extract_business_mentions(response.text)
                listings.extend(business_mentions)
        
        except Exception as e:
            self.logger.error(f"Error searching business listings: {e}")
        
        return listings
    
    def _check_spam_databases(self, phone_number: str) -> List[Dict[str, Any]]:
        """
        Check phone number against spam/scam databases
        
        Args:
            phone_number: Phone number to check
            
        Returns:
            List of spam reports found
        """
        spam_reports = []
        
        try:
            # Free spam database checks
            spam_sources = [
                'whocalld.com',
                'truecaller.com',
                'scammer.info',
                'robokiller.com'
            ]
            
            for source in spam_sources:
                try:
                    # Note: This is a simplified example
                    # In production, would use proper APIs where available
                    spam_query = f'site:{source} "{phone_number}" spam OR scam OR robocall'
                    
                    headers = {'User-Agent': random.choice(self.search_engines['google']['user_agents'])}
                    params = {'q': spam_query, 'num': 5}
                    
                    response = self.session.get(
                        'https://www.google.com/search',
                        params=params,
                        headers=headers,
                        timeout=30
                    )
                    
                    if response.status_code == 200 and phone_number in response.text:
                        spam_report = {
                            'source': source,
                            'type': 'potential_spam',
                            'confidence': 0.5,
                            'details': f'Found mentions on {source}',
                            'timestamp': datetime.now(timezone.utc)
                        }
                        spam_reports.append(spam_report)
                    
                    time.sleep(random.uniform(1, 3))  # Rate limiting
                    
                except Exception as e:
                    self.logger.debug(f"Error checking {source}: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Error checking spam databases: {e}")
        
        return spam_reports
    
    def _search_public_records(self, phone_number: str) -> List[Dict[str, Any]]:
        """
        Search public records for phone number (where legally permitted)
        
        Args:
            phone_number: Phone number to search
            
        Returns:
            List of public records found
        """
        records = []
        
        try:
            # This would include searches of publicly available records
            # Must comply with local privacy laws and regulations
            
            # Example: Court records, business registrations, etc.
            # Implementation depends on jurisdiction and legal requirements
            
            self.logger.info("Public records search - ensuring legal compliance")
            
            # Placeholder for legal public records search
            # In production, would integrate with authorized databases
            
        except Exception as e:
            self.logger.error(f"Error searching public records: {e}")
        
        return records
    
    def _extract_mentions_from_html(self, html_content: str, source: str) -> List[Dict[str, Any]]:
        """Extract phone number mentions from HTML content"""
        mentions = []
        
        try:
            # Basic HTML parsing for search result extraction
            # In production, would use proper HTML parsing libraries
            
            # Look for result blocks (simplified)
            if 'google' in source:
                # Extract Google search result snippets
                import re
                patterns = [
                    r'<h3[^>]*>([^<]+)</h3>',
                    r'<span[^>]*class="[^"]*st[^"]*"[^>]*>([^<]+)</span>',
                    r'<cite[^>]*>([^<]+)</cite>'
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
                    for match in matches[:5]:  # Limit results
                        if len(match.strip()) > 10:  # Filter out very short matches
                            mentions.append({
                                'title': match.strip()[:200],
                                'snippet': match.strip()[:500],
                                'url': '',  # Would extract from actual HTML
                                'source': source
                            })
        
        except Exception as e:
            self.logger.error(f"Error extracting mentions: {e}")
        
        return mentions
    
    def _extract_business_mentions(self, html_content: str) -> List[Dict[str, Any]]:
        """Extract business mentions from search results"""
        business_mentions = []
        
        try:
            # Look for business-related patterns in search results
            business_keywords = ['business', 'company', 'service', 'store', 'office', 'contact']
            
            # Simplified extraction - in production would be more sophisticated
            if any(keyword in html_content.lower() for keyword in business_keywords):
                business_mentions.append({
                    'type': 'potential_business',
                    'source': 'google_business_search',
                    'confidence': 0.4,
                    'details': 'Found in business-related search results'
                })
        
        except Exception as e:
            self.logger.error(f"Error extracting business mentions: {e}")
        
        return business_mentions
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate summary of OSINT analysis
        
        Args:
            results: Complete OSINT results
            
        Returns:
            Dict containing analysis summary
        """
        try:
            summary = {
                'total_mentions': len(results.get('search_engine_results', [])),
                'directory_hits': len(results.get('directory_lookups', [])),
                'social_media_associations': len(results.get('social_media_mentions', [])),
                'business_associations': len(results.get('business_listings', [])),
                'spam_indicators': len(results.get('spam_reports', [])),
                'public_record_matches': len(results.get('public_records', [])),
                'risk_indicators': [],
                'notable_findings': []
            }
            
            # Identify risk indicators
            if summary['spam_indicators'] > 0:
                summary['risk_indicators'].append('spam_reports_found')
            
            if summary['social_media_associations'] > 3:
                summary['risk_indicators'].append('high_social_media_exposure')
            
            # Notable findings
            if summary['business_associations'] > 0:
                summary['notable_findings'].append('business_registration_found')
            
            if summary['directory_hits'] > 1:
                summary['notable_findings'].append('multiple_directory_listings')
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating analysis summary: {e}")
            return {'error': str(e)}
    
    def _count_total_sources(self, results: Dict[str, Any]) -> int:
        """Count total number of sources found"""
        total = 0
        for key in ['search_engine_results', 'directory_lookups', 'business_listings', 'spam_reports', 'public_records']:
            total += len(results.get(key, []))
        return total
    
    def _calculate_confidence_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall confidence score for OSINT results"""
        try:
            total_sources = self._count_total_sources(results)
            
            if total_sources == 0:
                return 0.0
            
            # Weight different source types
            weights = {
                'directory_lookups': 0.8,
                'search_engine_results': 0.6,
                'business_listings': 0.7,
                'spam_reports': 0.5,
                'public_records': 0.9
            }
            
            weighted_score = 0.0
            total_weight = 0.0
            
            for source_type, weight in weights.items():
                count = len(results.get(source_type, []))
                if count > 0:
                    weighted_score += weight * min(count / 5.0, 1.0)  # Normalize to max 5 sources per type
                    total_weight += weight
            
            if total_weight > 0:
                return min(weighted_score / total_weight, 1.0)
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence score: {e}")
            return 0.0
    
    def _generate_evidence_hash(self, result: OSINTResult) -> str:
        """Generate evidence hash for OSINT result"""
        try:
            result_dict = asdict(result)
            result_dict.pop('evidence_hash', None)  # Remove hash field for hashing
            result_json = json.dumps(result_dict, default=str, sort_keys=True)
            return hashlib.sha256(result_json.encode()).hexdigest()
        except Exception:
            return hashlib.sha256(str(datetime.now()).encode()).hexdigest()
    
    def _check_rate_limit(self, service: str) -> bool:
        """Check if service rate limit allows another request"""
        current_time = time.time()
        
        if service not in self.request_history:
            self.request_history[service] = []
        
        # Clean old requests (older than 1 hour)
        self.request_history[service] = [
            req_time for req_time in self.request_history[service]
            if current_time - req_time < 3600
        ]
        
        # Check rate limit
        rate_limit = self.search_engines.get(service, {}).get('rate_limit', 10)
        if service in self.directory_services:
            rate_limit = self.directory_services[service].get('rate_limit', 10)
        
        if len(self.request_history[service]) >= rate_limit:
            return False
        
        # Record this request
        self.request_history[service].append(current_time)
        return True