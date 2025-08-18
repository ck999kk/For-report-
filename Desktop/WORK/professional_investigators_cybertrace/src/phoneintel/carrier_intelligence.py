"""
Carrier Intelligence Module
Advanced carrier and network information gathering for phone numbers
"""

import json
import time
import hashlib
import logging
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

from ..core.logger import get_logger
from ..core.exceptions import InvestigationException


@dataclass
class CarrierInfo:
    """Structured carrier information"""
    carrier_name: str = None
    network_type: str = None
    country_code: str = None
    country_name: str = None
    network_code: str = None
    is_ported: bool = None
    original_carrier: str = None
    roaming_status: str = None
    hlr_status: str = None
    mcc: str = None  # Mobile Country Code
    mnc: str = None  # Mobile Network Code
    source: str = None
    confidence: float = 0.0
    timestamp: datetime = None


@dataclass
class NetworkInfo:
    """Network infrastructure information"""
    network_name: str = None
    network_type: str = None
    technology: str = None  # 2G, 3G, 4G, 5G
    coverage_area: List[str] = None
    parent_company: str = None
    regulatory_info: Dict[str, Any] = None


class CarrierIntelligence:
    """
    Advanced carrier and network intelligence gathering system
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize Carrier Intelligence
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config.get('carrier_intelligence', {})
        self.logger = logger or get_logger(__name__)
        
        # API configurations
        self.apis = {
            'twilio': {
                'enabled': self.config.get('twilio_enabled', False),
                'account_sid': self.config.get('twilio_account_sid'),
                'auth_token': self.config.get('twilio_auth_token'),
                'base_url': 'https://lookups.twilio.com/v1/PhoneNumbers/',
                'rate_limit': 100  # requests per hour
            },
            'numverify': {
                'enabled': self.config.get('numverify_enabled', False),
                'api_key': self.config.get('numverify_api_key'),
                'base_url': 'http://apilayer.net/api/validate',
                'rate_limit': 250  # requests per month for free tier
            },
            'abstractapi': {
                'enabled': self.config.get('abstractapi_enabled', False),
                'api_key': self.config.get('abstractapi_api_key'),
                'base_url': 'https://phonevalidation.abstractapi.com/v1/',
                'rate_limit': 100  # requests per month for free tier
            }
        }
        
        # MCC/MNC database (subset - in production, load from comprehensive database)
        self.mcc_mnc_db = self._load_mcc_mnc_database()
        
        # Rate limiting
        self.api_calls = {}
        
        self.logger.info("Carrier Intelligence module initialized")
    
    def analyze_number(self, phone_number: str) -> Dict[str, Any]:
        """
        Perform comprehensive carrier analysis
        
        Args:
            phone_number: Phone number to analyze
            
        Returns:
            Dict containing carrier intelligence
        """
        try:
            self.logger.info(f"Analyzing carrier information for: {phone_number[:3]}***{phone_number[-3:]}")
            
            results = {
                'carrier_info': None,
                'network_info': None,
                'hlr_lookup': None,
                'portability_info': None,
                'multiple_sources': [],
                'analysis_timestamp': datetime.now(timezone.utc),
                'confidence_score': 0.0
            }
            
            # Try multiple API sources
            api_results = []
            
            # Twilio Lookup
            twilio_result = self._twilio_lookup(phone_number)
            if twilio_result:
                api_results.append(twilio_result)
            
            # NumVerify Lookup
            numverify_result = self._numverify_lookup(phone_number)
            if numverify_result:
                api_results.append(numverify_result)
            
            # AbstractAPI Lookup
            abstractapi_result = self._abstractapi_lookup(phone_number)
            if abstractapi_result:
                api_results.append(abstractapi_result)
            
            # Consolidate results
            if api_results:
                results['carrier_info'] = self._consolidate_carrier_info(api_results)
                results['multiple_sources'] = api_results
                results['confidence_score'] = self._calculate_confidence(api_results)
            
            # MCC/MNC Analysis
            mcc_mnc_info = self._analyze_mcc_mnc(phone_number, results.get('carrier_info'))
            if mcc_mnc_info:
                results['network_info'] = mcc_mnc_info
            
            # Number portability analysis
            portability_info = self._analyze_portability(phone_number, results.get('carrier_info'))
            results['portability_info'] = portability_info
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in carrier analysis: {e}")
            return {
                'error': str(e),
                'analysis_timestamp': datetime.now(timezone.utc),
                'confidence_score': 0.0
            }
    
    def basic_lookup(self, phone_number: str) -> Dict[str, Any]:
        """
        Perform basic carrier lookup (faster, minimal API calls)
        
        Args:
            phone_number: Phone number to lookup
            
        Returns:
            Dict containing basic carrier information
        """
        try:
            # Try the most reliable free source first
            result = self._numverify_lookup(phone_number)
            if not result:
                result = self._abstractapi_lookup(phone_number)
            
            if result:
                return {
                    'carrier_name': result.get('carrier_name'),
                    'country_name': result.get('country_name'),
                    'network_type': result.get('network_type'),
                    'source': result.get('source'),
                    'confidence': result.get('confidence', 0.5),
                    'timestamp': datetime.now(timezone.utc)
                }
            
            return {
                'error': 'No carrier information available',
                'timestamp': datetime.now(timezone.utc)
            }
            
        except Exception as e:
            self.logger.error(f"Error in basic lookup: {e}")
            return {'error': str(e), 'timestamp': datetime.now(timezone.utc)}
    
    def _twilio_lookup(self, phone_number: str) -> Optional[Dict[str, Any]]:
        """
        Perform Twilio carrier lookup
        
        Args:
            phone_number: Phone number to lookup
            
        Returns:
            Dict containing Twilio lookup results
        """
        if not self.apis['twilio']['enabled']:
            return None
        
        try:
            # Rate limiting check
            if not self._check_rate_limit('twilio'):
                self.logger.warning("Twilio rate limit exceeded")
                return None
            
            import base64
            
            # Prepare credentials
            credentials = f"{self.apis['twilio']['account_sid']}:{self.apis['twilio']['auth_token']}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Make API request
            url = f"{self.apis['twilio']['base_url']}{phone_number}"
            params = {'Type': 'carrier'}
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                carrier_info = data.get('carrier', {})
                
                return {
                    'source': 'twilio',
                    'carrier_name': carrier_info.get('name'),
                    'network_type': carrier_info.get('type'),
                    'country_code': data.get('country_code'),
                    'national_format': data.get('national_format'),
                    'is_valid': True,
                    'confidence': 0.9,
                    'raw_response': data
                }
            else:
                self.logger.warning(f"Twilio lookup failed: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Twilio lookup error: {e}")
            return None
    
    def _numverify_lookup(self, phone_number: str) -> Optional[Dict[str, Any]]:
        """
        Perform NumVerify lookup
        
        Args:
            phone_number: Phone number to lookup
            
        Returns:
            Dict containing NumVerify lookup results
        """
        if not self.apis['numverify']['enabled']:
            return None
        
        try:
            # Rate limiting check
            if not self._check_rate_limit('numverify'):
                self.logger.warning("NumVerify rate limit exceeded")
                return None
            
            params = {
                'access_key': self.apis['numverify']['api_key'],
                'number': phone_number,
                'country_code': '',
                'format': '1'
            }
            
            response = requests.get(self.apis['numverify']['base_url'], params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('valid'):
                    return {
                        'source': 'numverify',
                        'carrier_name': data.get('carrier'),
                        'country_name': data.get('country_name'),
                        'country_code': data.get('country_code'),
                        'network_type': data.get('line_type'),
                        'international_format': data.get('international_format'),
                        'national_format': data.get('local_format'),
                        'location': data.get('location'),
                        'is_valid': data.get('valid'),
                        'confidence': 0.8,
                        'raw_response': data
                    }
            
            return None
                
        except Exception as e:
            self.logger.error(f"NumVerify lookup error: {e}")
            return None
    
    def _abstractapi_lookup(self, phone_number: str) -> Optional[Dict[str, Any]]:
        """
        Perform AbstractAPI phone validation
        
        Args:
            phone_number: Phone number to lookup
            
        Returns:
            Dict containing AbstractAPI lookup results
        """
        if not self.apis['abstractapi']['enabled']:
            return None
        
        try:
            # Rate limiting check
            if not self._check_rate_limit('abstractapi'):
                self.logger.warning("AbstractAPI rate limit exceeded")
                return None
            
            params = {
                'api_key': self.apis['abstractapi']['api_key'],
                'phone': phone_number
            }
            
            response = requests.get(self.apis['abstractapi']['base_url'], params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'source': 'abstractapi',
                    'carrier_name': data.get('carrier'),
                    'country_name': data.get('country', {}).get('name'),
                    'country_code': data.get('country', {}).get('code'),
                    'network_type': data.get('type'),
                    'is_valid': data.get('valid'),
                    'international_format': data.get('format', {}).get('international'),
                    'national_format': data.get('format', {}).get('local'),
                    'confidence': 0.7,
                    'raw_response': data
                }
            
            return None
                
        except Exception as e:
            self.logger.error(f"AbstractAPI lookup error: {e}")
            return None
    
    def _consolidate_carrier_info(self, api_results: List[Dict[str, Any]]) -> CarrierInfo:
        """
        Consolidate information from multiple API sources
        
        Args:
            api_results: List of API results
            
        Returns:
            CarrierInfo: Consolidated carrier information
        """
        try:
            # Priority weighting for sources
            source_weights = {
                'twilio': 0.9,
                'numverify': 0.8,
                'abstractapi': 0.7
            }
            
            # Consolidate data with confidence weighting
            consolidated = CarrierInfo(timestamp=datetime.now(timezone.utc))
            
            # Carrier name - use most confident source
            carriers = [(r.get('carrier_name'), source_weights.get(r.get('source'), 0.5)) 
                       for r in api_results if r.get('carrier_name')]
            if carriers:
                consolidated.carrier_name = max(carriers, key=lambda x: x[1])[0]
            
            # Network type
            types = [(r.get('network_type'), source_weights.get(r.get('source'), 0.5)) 
                    for r in api_results if r.get('network_type')]
            if types:
                consolidated.network_type = max(types, key=lambda x: x[1])[0]
            
            # Country information
            countries = [(r.get('country_name'), source_weights.get(r.get('source'), 0.5)) 
                        for r in api_results if r.get('country_name')]
            if countries:
                consolidated.country_name = max(countries, key=lambda x: x[1])[0]
            
            country_codes = [(r.get('country_code'), source_weights.get(r.get('source'), 0.5)) 
                           for r in api_results if r.get('country_code')]
            if country_codes:
                consolidated.country_code = max(country_codes, key=lambda x: x[1])[0]
            
            # Source tracking
            consolidated.source = ', '.join([r.get('source', 'unknown') for r in api_results])
            
            # Confidence calculation
            consolidated.confidence = sum([source_weights.get(r.get('source'), 0.5) 
                                          for r in api_results]) / len(api_results)
            
            return consolidated
            
        except Exception as e:
            self.logger.error(f"Error consolidating carrier info: {e}")
            return CarrierInfo(timestamp=datetime.now(timezone.utc))
    
    def _analyze_mcc_mnc(self, phone_number: str, carrier_info: Optional[CarrierInfo]) -> Optional[NetworkInfo]:
        """
        Analyze MCC/MNC codes for network information
        
        Args:
            phone_number: Phone number
            carrier_info: Carrier information if available
            
        Returns:
            NetworkInfo: Network infrastructure information
        """
        try:
            if not carrier_info or not carrier_info.country_code:
                return None
            
            # Extract country code from phone number
            country_code = carrier_info.country_code
            
            # Look up MCC for country
            mcc_info = self.mcc_mnc_db.get('countries', {}).get(country_code)
            if not mcc_info:
                return None
            
            network_info = NetworkInfo()
            network_info.network_name = carrier_info.carrier_name
            network_info.network_type = carrier_info.network_type
            network_info.coverage_area = [carrier_info.country_name] if carrier_info.country_name else []
            
            # Add MCC information
            if mcc_info:
                carrier_info.mcc = mcc_info.get('mcc')
                # Look up MNC if carrier name matches
                for operator in mcc_info.get('operators', []):
                    if (carrier_info.carrier_name and 
                        carrier_info.carrier_name.lower() in operator.get('name', '').lower()):
                        carrier_info.mnc = operator.get('mnc')
                        network_info.parent_company = operator.get('parent_company')
                        network_info.technology = operator.get('technology')
                        break
            
            return network_info
            
        except Exception as e:
            self.logger.error(f"Error analyzing MCC/MNC: {e}")
            return None
    
    def _analyze_portability(self, phone_number: str, carrier_info: Optional[CarrierInfo]) -> Dict[str, Any]:
        """
        Analyze number portability status
        
        Args:
            phone_number: Phone number
            carrier_info: Current carrier information
            
        Returns:
            Dict containing portability analysis
        """
        try:
            # This is a simplified analysis - in production, would use dedicated portability APIs
            portability_info = {
                'is_portable': True,  # Most modern networks support portability
                'likely_ported': False,
                'original_carrier': None,
                'portability_date': None,
                'confidence': 0.3  # Low confidence without dedicated API
            }
            
            # Basic heuristics for detecting potential porting
            if carrier_info:
                # If we have conflicting carrier information from different sources,
                # it might indicate porting
                if hasattr(carrier_info, 'source') and ',' in carrier_info.source:
                    portability_info['likely_ported'] = True
                    portability_info['confidence'] = 0.6
            
            return portability_info
            
        except Exception as e:
            self.logger.error(f"Error analyzing portability: {e}")
            return {'error': str(e)}
    
    def _calculate_confidence(self, api_results: List[Dict[str, Any]]) -> float:
        """
        Calculate overall confidence score based on multiple API results
        
        Args:
            api_results: List of API results
            
        Returns:
            float: Confidence score (0.0 - 1.0)
        """
        if not api_results:
            return 0.0
        
        # Weight by source reliability and agreement
        total_confidence = 0.0
        agreement_bonus = 0.0
        
        # Base confidence from sources
        for result in api_results:
            total_confidence += result.get('confidence', 0.5)
        
        # Agreement bonus - if multiple sources agree, increase confidence
        if len(api_results) > 1:
            carriers = [r.get('carrier_name') for r in api_results if r.get('carrier_name')]
            if len(set(carriers)) == 1 and len(carriers) > 1:
                agreement_bonus = 0.2
        
        final_confidence = min(1.0, (total_confidence / len(api_results)) + agreement_bonus)
        return final_confidence
    
    def _check_rate_limit(self, api_name: str) -> bool:
        """
        Check if API rate limit allows for another request
        
        Args:
            api_name: Name of the API to check
            
        Returns:
            bool: True if request is allowed
        """
        current_time = time.time()
        
        if api_name not in self.api_calls:
            self.api_calls[api_name] = []
        
        # Clean old calls (older than 1 hour)
        self.api_calls[api_name] = [
            call_time for call_time in self.api_calls[api_name]
            if current_time - call_time < 3600
        ]
        
        # Check against rate limit
        rate_limit = self.apis[api_name]['rate_limit']
        if len(self.api_calls[api_name]) >= rate_limit:
            return False
        
        # Record this call
        self.api_calls[api_name].append(current_time)
        return True
    
    def _load_mcc_mnc_database(self) -> Dict[str, Any]:
        """
        Load MCC/MNC database (simplified version)
        In production, this would load from a comprehensive database
        
        Returns:
            Dict containing MCC/MNC information
        """
        return {
            'countries': {
                'US': {
                    'mcc': '310',
                    'operators': [
                        {'name': 'Verizon', 'mnc': '004', 'technology': '5G', 'parent_company': 'Verizon Communications'},
                        {'name': 'AT&T', 'mnc': '030', 'technology': '5G', 'parent_company': 'AT&T Inc.'},
                        {'name': 'T-Mobile', 'mnc': '260', 'technology': '5G', 'parent_company': 'Deutsche Telekom'},
                        {'name': 'Sprint', 'mnc': '120', 'technology': '4G', 'parent_company': 'T-Mobile US'},
                    ]
                },
                'AU': {
                    'mcc': '505',
                    'operators': [
                        {'name': 'Telstra', 'mnc': '001', 'technology': '5G', 'parent_company': 'Telstra Corporation'},
                        {'name': 'Optus', 'mnc': '002', 'technology': '5G', 'parent_company': 'Singapore Telecommunications'},
                        {'name': 'Vodafone', 'mnc': '003', 'technology': '4G', 'parent_company': 'Vodafone Group'},
                    ]
                },
                'GB': {
                    'mcc': '234',
                    'operators': [
                        {'name': 'EE', 'mnc': '030', 'technology': '5G', 'parent_company': 'BT Group'},
                        {'name': 'O2', 'mnc': '010', 'technology': '5G', 'parent_company': 'Telefónica'},
                        {'name': 'Vodafone', 'mnc': '015', 'technology': '5G', 'parent_company': 'Vodafone Group'},
                        {'name': 'Three', 'mnc': '020', 'technology': '5G', 'parent_company': 'CK Hutchison'},
                    ]
                }
            }
        }