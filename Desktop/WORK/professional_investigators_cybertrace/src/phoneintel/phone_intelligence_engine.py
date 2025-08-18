"""
Phone Intelligence Engine
Core phone number analysis and intelligence gathering system
"""

import re
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_timezone
    from phonenumbers.phonenumberutil import NumberParseException
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False
    logging.warning("phonenumbers library not available. Install with: pip install phonenumbers")

from ..core.logger import get_logger
from ..core.exceptions import InvestigationException


@dataclass
class PhoneNumberInfo:
    """Structured phone number information"""
    original_number: str
    parsed_number: Optional[str] = None
    country_code: int = None
    national_number: str = None
    international_format: str = None
    national_format: str = None
    e164_format: str = None
    is_valid: bool = False
    is_possible: bool = False
    number_type: str = None
    carrier_name: str = None
    country_name: str = None
    region: str = None
    timezone: List[str] = None
    analysis_timestamp: datetime = None
    confidence_score: float = 0.0
    source: str = "phone_intelligence_engine"


@dataclass
class PhoneIntelligenceResult:
    """Complete phone intelligence analysis result"""
    phone_info: PhoneNumberInfo
    osint_data: Dict[str, Any]
    carrier_intelligence: Dict[str, Any]
    geographic_analysis: Dict[str, Any]
    social_media_profiles: List[Dict[str, Any]]
    breach_data: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    evidence_hash: str = None
    investigation_id: str = None
    created_at: datetime = None


class PhoneIntelligenceEngine:
    """
    Core engine for comprehensive phone number intelligence gathering
    with legal-grade evidence management
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize Phone Intelligence Engine
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger(__name__)
        
        # Initialize components
        self._init_components()
        
        # Validation patterns
        self.phone_patterns = [
            r'[\+]?[1-9]?[\d\s\-\(\)\.]{7,15}',  # General international
            r'^[\+]?[1-9]\d{1,14}$',             # E.164 format
            r'^\d{10}$',                         # US/AU 10-digit
            r'^\d{11}$',                         # 11-digit with country code
            r'^0\d{9,10}$',                      # National format with leading 0
        ]
        
        self.logger.info("Phone Intelligence Engine initialized")
    
    def _init_components(self):
        """Initialize intelligence gathering components"""
        try:
            # Import components dynamically to handle missing dependencies
            from .carrier_intelligence import CarrierIntelligence
            from .osint_phone_collector import OSINTPhoneCollector
            from .geographic_analyzer import GeographicAnalyzer
            from .social_media_profiler import SocialMediaProfiler
            from .breach_database_checker import BreachDatabaseChecker
            from .risk_assessor import RiskAssessor
            
            self.carrier_intel = CarrierIntelligence(self.config, self.logger)
            self.osint_collector = OSINTPhoneCollector(self.config, self.logger)
            self.geographic_analyzer = GeographicAnalyzer(self.config, self.logger)
            self.social_profiler = SocialMediaProfiler(self.config, self.logger)
            self.breach_checker = BreachDatabaseChecker(self.config, self.logger)
            self.risk_assessor = RiskAssessor(self.config, self.logger)
            
            self.logger.info("All intelligence components initialized successfully")
            
        except ImportError as e:
            self.logger.warning(f"Some components not available: {e}")
            # Initialize stub components
            self.carrier_intel = None
            self.osint_collector = None
            self.geographic_analyzer = None
            self.social_profiler = None
            self.breach_checker = None
            self.risk_assessor = None
    
    def analyze_phone_number(self, phone_number: str, investigation_id: str = None,
                           deep_analysis: bool = True) -> PhoneIntelligenceResult:
        """
        Perform comprehensive analysis of a phone number
        
        Args:
            phone_number: Phone number to analyze
            investigation_id: Investigation case ID
            deep_analysis: Whether to perform deep OSINT analysis
            
        Returns:
            PhoneIntelligenceResult: Complete analysis result
        """
        try:
            self.logger.info(f"Starting phone number analysis: {phone_number[:3]}***{phone_number[-3:]}")
            
            # Parse and validate phone number
            phone_info = self._parse_phone_number(phone_number)
            
            # Initialize result structure
            result = PhoneIntelligenceResult(
                phone_info=phone_info,
                osint_data={},
                carrier_intelligence={},
                geographic_analysis={},
                social_media_profiles=[],
                breach_data=[],
                risk_assessment={},
                investigation_id=investigation_id,
                created_at=datetime.now(timezone.utc)
            )
            
            if not phone_info.is_valid:
                self.logger.warning(f"Invalid phone number format: {phone_number}")
                result.risk_assessment = {"risk_level": "unknown", "reason": "invalid_format"}
                return self._finalize_result(result)
            
            # Gather intelligence from various sources
            if deep_analysis:
                result = self._perform_deep_analysis(result)
            else:
                result = self._perform_basic_analysis(result)
            
            return self._finalize_result(result)
            
        except Exception as e:
            self.logger.error(f"Error analyzing phone number: {e}")
            raise InvestigationException(f"Phone analysis failed: {e}")
    
    def _parse_phone_number(self, phone_number: str) -> PhoneNumberInfo:
        """
        Parse and validate phone number using multiple methods
        
        Args:
            phone_number: Raw phone number string
            
        Returns:
            PhoneNumberInfo: Parsed phone number information
        """
        info = PhoneNumberInfo(
            original_number=phone_number,
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
        try:
            # Clean input
            cleaned_number = re.sub(r'[^\d\+]', '', phone_number)
            
            if PHONENUMBERS_AVAILABLE:
                # Try parsing with different region hints
                regions_to_try = ['US', 'AU', 'GB', 'CA', None]
                
                for region in regions_to_try:
                    try:
                        parsed = phonenumbers.parse(cleaned_number, region)
                        
                        if phonenumbers.is_valid_number(parsed):
                            info.parsed_number = str(parsed)
                            info.country_code = parsed.country_code
                            info.national_number = str(parsed.national_number)
                            info.international_format = phonenumbers.format_number(
                                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                            )
                            info.national_format = phonenumbers.format_number(
                                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                            )
                            info.e164_format = phonenumbers.format_number(
                                parsed, phonenumbers.PhoneNumberFormat.E164
                            )
                            info.is_valid = True
                            info.is_possible = phonenumbers.is_possible_number(parsed)
                            
                            # Get number type
                            number_type = phonenumbers.number_type(parsed)
                            info.number_type = self._get_number_type_string(number_type)
                            
                            # Get carrier (if available)
                            try:
                                info.carrier_name = carrier.name_for_number(parsed, 'en')
                            except:
                                pass
                            
                            # Get location
                            try:
                                info.country_name = geocoder.country_name_for_number(parsed, 'en')
                                info.region = geocoder.description_for_number(parsed, 'en')
                            except:
                                pass
                            
                            # Get timezone
                            try:
                                timezones = pn_timezone.time_zones_for_number(parsed)
                                info.timezone = list(timezones)
                            except:
                                pass
                            
                            info.confidence_score = 0.9
                            break
                            
                    except NumberParseException:
                        continue
            
            # Fallback parsing for basic validation
            if not info.is_valid:
                info = self._basic_phone_parsing(info, cleaned_number)
            
        except Exception as e:
            self.logger.error(f"Error parsing phone number: {e}")
            info.confidence_score = 0.0
        
        return info
    
    def _basic_phone_parsing(self, info: PhoneNumberInfo, cleaned_number: str) -> PhoneNumberInfo:
        """
        Basic phone number parsing without phonenumbers library
        
        Args:
            info: PhoneNumberInfo object to update
            cleaned_number: Cleaned phone number string
            
        Returns:
            PhoneNumberInfo: Updated phone number information
        """
        try:
            # Basic validation patterns
            for pattern in self.phone_patterns:
                if re.match(pattern, cleaned_number):
                    info.is_possible = True
                    break
            
            # Extract country code (basic detection)
            if cleaned_number.startswith('+'):
                if len(cleaned_number) >= 4:
                    # Try common country codes
                    if cleaned_number.startswith('+1'):
                        info.country_code = 1
                        info.country_name = "United States/Canada"
                        info.national_number = cleaned_number[2:]
                    elif cleaned_number.startswith('+61'):
                        info.country_code = 61
                        info.country_name = "Australia"
                        info.national_number = cleaned_number[3:]
                    elif cleaned_number.startswith('+44'):
                        info.country_code = 44
                        info.country_name = "United Kingdom"
                        info.national_number = cleaned_number[3:]
                    elif cleaned_number.startswith('+86'):
                        info.country_code = 86
                        info.country_name = "China"
                        info.national_number = cleaned_number[3:]
                    
                    info.e164_format = cleaned_number
                    info.international_format = cleaned_number
            
            # Basic validation
            if len(cleaned_number) >= 7 and len(cleaned_number) <= 15:
                info.is_valid = True
                info.confidence_score = 0.5
            
        except Exception as e:
            self.logger.error(f"Error in basic phone parsing: {e}")
        
        return info
    
    def _get_number_type_string(self, number_type) -> str:
        """Convert phonenumbers number type to string"""
        if not PHONENUMBERS_AVAILABLE:
            return "unknown"
        
        type_mapping = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
            phonenumbers.PhoneNumberType.VOIP: "voip",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
            phonenumbers.PhoneNumberType.PAGER: "pager",
            phonenumbers.PhoneNumberType.UAN: "uan",
            phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
        }
        return type_mapping.get(number_type, "unknown")
    
    def _perform_deep_analysis(self, result: PhoneIntelligenceResult) -> PhoneIntelligenceResult:
        """
        Perform deep intelligence analysis
        
        Args:
            result: Initial analysis result
            
        Returns:
            PhoneIntelligenceResult: Enhanced result with deep analysis
        """
        phone_number = result.phone_info.e164_format or result.phone_info.original_number
        
        try:
            # Carrier intelligence
            if self.carrier_intel:
                self.logger.info("Gathering carrier intelligence")
                result.carrier_intelligence = self.carrier_intel.analyze_number(phone_number)
            
            # Geographic analysis
            if self.geographic_analyzer:
                self.logger.info("Performing geographic analysis")
                result.geographic_analysis = self.geographic_analyzer.analyze_location(phone_number)
            
            # OSINT collection
            if self.osint_collector:
                self.logger.info("Collecting OSINT data")
                result.osint_data = self.osint_collector.collect_intelligence(phone_number)
            
            # Social media profiling
            if self.social_profiler:
                self.logger.info("Analyzing social media associations")
                result.social_media_profiles = self.social_profiler.find_profiles(phone_number)
            
            # Breach database checking
            if self.breach_checker:
                self.logger.info("Checking breach databases")
                result.breach_data = self.breach_checker.check_breaches(phone_number)
            
            # Risk assessment
            if self.risk_assessor:
                self.logger.info("Performing risk assessment")
                result.risk_assessment = self.risk_assessor.assess_risk(result)
            
        except Exception as e:
            self.logger.error(f"Error in deep analysis: {e}")
            result.risk_assessment = {
                "risk_level": "error",
                "reason": f"analysis_error: {str(e)}"
            }
        
        return result
    
    def _perform_basic_analysis(self, result: PhoneIntelligenceResult) -> PhoneIntelligenceResult:
        """
        Perform basic analysis without deep OSINT
        
        Args:
            result: Initial analysis result
            
        Returns:
            PhoneIntelligenceResult: Result with basic analysis
        """
        try:
            # Basic carrier lookup if available
            if self.carrier_intel:
                result.carrier_intelligence = self.carrier_intel.basic_lookup(
                    result.phone_info.e164_format or result.phone_info.original_number
                )
            
            # Basic risk assessment
            result.risk_assessment = {
                "risk_level": "low" if result.phone_info.is_valid else "unknown",
                "confidence": result.phone_info.confidence_score,
                "analysis_type": "basic"
            }
            
        except Exception as e:
            self.logger.error(f"Error in basic analysis: {e}")
        
        return result
    
    def _finalize_result(self, result: PhoneIntelligenceResult) -> PhoneIntelligenceResult:
        """
        Finalize analysis result with evidence hash and metadata
        
        Args:
            result: Analysis result to finalize
            
        Returns:
            PhoneIntelligenceResult: Finalized result
        """
        try:
            # Create evidence hash
            result_dict = asdict(result)
            result_json = json.dumps(result_dict, default=str, sort_keys=True)
            result.evidence_hash = hashlib.sha256(result_json.encode()).hexdigest()
            
            self.logger.info(f"Phone analysis completed. Evidence hash: {result.evidence_hash[:16]}...")
            
        except Exception as e:
            self.logger.error(f"Error finalizing result: {e}")
        
        return result
    
    def batch_analyze_numbers(self, phone_numbers: List[str], investigation_id: str = None,
                            deep_analysis: bool = True) -> List[PhoneIntelligenceResult]:
        """
        Analyze multiple phone numbers in batch
        
        Args:
            phone_numbers: List of phone numbers to analyze
            investigation_id: Investigation case ID
            deep_analysis: Whether to perform deep analysis
            
        Returns:
            List[PhoneIntelligenceResult]: Analysis results
        """
        results = []
        
        self.logger.info(f"Starting batch analysis of {len(phone_numbers)} numbers")
        
        for i, number in enumerate(phone_numbers, 1):
            try:
                self.logger.info(f"Analyzing number {i}/{len(phone_numbers)}")
                result = self.analyze_phone_number(number, investigation_id, deep_analysis)
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error analyzing number {number}: {e}")
                # Create error result
                error_result = PhoneIntelligenceResult(
                    phone_info=PhoneNumberInfo(
                        original_number=number,
                        analysis_timestamp=datetime.now(timezone.utc),
                        confidence_score=0.0
                    ),
                    osint_data={},
                    carrier_intelligence={},
                    geographic_analysis={},
                    social_media_profiles=[],
                    breach_data=[],
                    risk_assessment={
                        "risk_level": "error",
                        "reason": f"analysis_error: {str(e)}"
                    },
                    investigation_id=investigation_id,
                    created_at=datetime.now(timezone.utc)
                )
                results.append(error_result)
        
        self.logger.info(f"Batch analysis completed. {len(results)} results generated")
        return results
    
    def get_supported_features(self) -> Dict[str, bool]:
        """
        Get list of supported features based on available dependencies
        
        Returns:
            Dict[str, bool]: Feature availability mapping
        """
        return {
            "phonenumbers_parsing": PHONENUMBERS_AVAILABLE,
            "carrier_intelligence": self.carrier_intel is not None,
            "osint_collection": self.osint_collector is not None,
            "geographic_analysis": self.geographic_analyzer is not None,
            "social_media_profiling": self.social_profiler is not None,
            "breach_database_checking": self.breach_checker is not None,
            "risk_assessment": self.risk_assessor is not None,
        }