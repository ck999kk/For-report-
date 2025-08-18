"""
Professional Investigators & Cybertrace System
Main Application Entry Point
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core import InvestigatorCore
from src.core.exceptions import InvestigationException


class InvestigationSystemCLI:
    """Command Line Interface for the Investigation System"""
    
    def __init__(self):
        self.investigator = None
    
    def run(self):
        """Main entry point"""
        
        parser = argparse.ArgumentParser(
            description="Professional Investigators & Cybertrace System",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python main.py init --investigator "Detective Smith"
  python main.py create-case --name "Security Breach Investigation" --type "cybersecurity"
  python main.py cybertrace --case-id "abc-123" --type "network" --target "example.com"
  python main.py collect-evidence --case-id "abc-123" --type "file" --source "/path/to/file"
  python main.py generate-report --case-id "abc-123" --type "comprehensive" --format "pdf"
  python main.py status
            """
        )
        
        # Global arguments
        parser.add_argument('--config', help='Configuration file path')
        parser.add_argument('--investigator', help='Investigator name')
        parser.add_argument('--debug', action='store_true', help='Enable debug mode')
        
        # Subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Initialize system
        init_parser = subparsers.add_parser('init', help='Initialize investigation system')
        init_parser.add_argument('--investigator', required=True, help='Investigator name')
        
        # Create case
        case_parser = subparsers.add_parser('create-case', help='Create new investigation case')
        case_parser.add_argument('--name', required=True, help='Case name')
        case_parser.add_argument('--type', required=True, help='Case type')
        case_parser.add_argument('--description', help='Case description')
        
        # Cybertrace operations
        cyber_parser = subparsers.add_parser('cybertrace', help='Execute cybertrace operation')
        cyber_parser.add_argument('--case-id', required=True, help='Case ID')
        cyber_parser.add_argument('--type', required=True, 
                                choices=['network', 'digital_forensics', 'osint', 'metadata', 'comprehensive'],
                                help='Cybertrace type')
        cyber_parser.add_argument('--target', required=True, help='Target for cybertrace')
        cyber_parser.add_argument('--options', help='JSON options for cybertrace')
        
        # Evidence collection
        evidence_parser = subparsers.add_parser('collect-evidence', help='Collect evidence')
        evidence_parser.add_argument('--case-id', required=True, help='Case ID')
        evidence_parser.add_argument('--type', required=True,
                                   choices=['file', 'directory', 'url', 'network_capture', 'system_info'],
                                   help='Evidence type')
        evidence_parser.add_argument('--source', required=True, help='Evidence source')
        evidence_parser.add_argument('--metadata', help='JSON metadata for evidence')
        
        # Report generation
        report_parser = subparsers.add_parser('generate-report', help='Generate investigation report')
        report_parser.add_argument('--case-id', required=True, help='Case ID')
        report_parser.add_argument('--type', default='comprehensive',
                                 choices=['comprehensive', 'executive_summary', 'technical', 'forensics', 'cybertrace'],
                                 help='Report type')
        report_parser.add_argument('--format', default='html',
                                 choices=['html', 'pdf', 'json', 'txt'],
                                 help='Output format')
        
        # System status
        status_parser = subparsers.add_parser('status', help='Show system status')
        
        # List cases
        list_parser = subparsers.add_parser('list-cases', help='List investigation cases')
        
        # Case details
        details_parser = subparsers.add_parser('case-details', help='Show case details')
        details_parser.add_argument('--case-id', required=True, help='Case ID')
        
        # Parse arguments
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            # Execute command
            if args.command == 'init':
                self._init_system(args)
            elif args.command == 'create-case':
                self._create_case(args)
            elif args.command == 'cybertrace':
                self._execute_cybertrace(args)
            elif args.command == 'collect-evidence':
                self._collect_evidence(args)
            elif args.command == 'generate-report':
                self._generate_report(args)
            elif args.command == 'status':
                self._show_status(args)
            elif args.command == 'list-cases':
                self._list_cases(args)
            elif args.command == 'case-details':
                self._show_case_details(args)
            
        except Exception as e:
            print(f"Error: {str(e)}")
            if args.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    
    def _init_system(self, args):
        """Initialize investigation system"""
        
        print("Initializing Professional Investigation System...")
        
        try:
            self.investigator = InvestigatorCore(
                config_path=args.config,
                investigator_name=args.investigator
            )
            
            print(f"✓ System initialized successfully")
            print(f"✓ Investigator: {args.investigator}")
            print(f"✓ Session ID: {self.investigator.session_id}")
            print(f"✓ System Status: {self.investigator.system_status}")
            
        except Exception as e:
            print(f"✗ System initialization failed: {str(e)}")
            raise
    
    def _create_case(self, args):
        """Create new investigation case"""
        
        if not self.investigator:
            self._init_system(args)
        
        print(f"Creating new investigation case: {args.name}")
        
        case_id = self.investigator.create_investigation_case(
            case_name=args.name,
            case_type=args.type,
            description=args.description
        )
        
        print(f"✓ Case created successfully")
        print(f"✓ Case ID: {case_id}")
        print(f"✓ Case Name: {args.name}")
        print(f"✓ Case Type: {args.type}")
    
    def _execute_cybertrace(self, args):
        """Execute cybertrace operation"""
        
        if not self.investigator:
            self._init_system(args)
        
        print(f"Executing cybertrace operation...")
        print(f"Case ID: {args.case_id}")
        print(f"Type: {args.type}")
        print(f"Target: {args.target}")
        
        import json
        options = json.loads(args.options) if args.options else {}
        
        result = self.investigator.execute_cybertrace(
            case_id=args.case_id,
            trace_type=args.type,
            target=args.target,
            options=options
        )
        
        print(f"✓ Cybertrace operation completed")
        print(f"✓ Operation ID: {result['operation_id']}")
        print(f"✓ Status: {result['status']}")
        
        if args.debug and 'results' in result:
            print("\nResults Summary:")
            print(json.dumps(result['results'], indent=2, default=str))
    
    def _collect_evidence(self, args):
        """Collect evidence"""
        
        if not self.investigator:
            self._init_system(args)
        
        print(f"Collecting evidence...")
        print(f"Case ID: {args.case_id}")
        print(f"Type: {args.type}")
        print(f"Source: {args.source}")
        
        import json
        metadata = json.loads(args.metadata) if args.metadata else {}
        
        evidence_id = self.investigator.collect_evidence(
            case_id=args.case_id,
            evidence_type=args.type,
            source=args.source,
            metadata=metadata
        )
        
        print(f"✓ Evidence collected successfully")
        print(f"✓ Evidence ID: {evidence_id}")
    
    def _generate_report(self, args):
        """Generate investigation report"""
        
        if not self.investigator:
            self._init_system(args)
        
        print(f"Generating investigation report...")
        print(f"Case ID: {args.case_id}")
        print(f"Type: {args.type}")
        print(f"Format: {args.format}")
        
        report_path = self.investigator.generate_report(
            case_id=args.case_id,
            report_type=args.type,
            output_format=args.format
        )
        
        print(f"✓ Report generated successfully")
        print(f"✓ Report Path: {report_path}")
    
    def _show_status(self, args):
        """Show system status"""
        
        if not self.investigator:
            self._init_system(args)
        
        status = self.investigator.get_system_status()
        
        print("System Status")
        print("=" * 50)
        print(f"System Status: {status['system_status']}")
        print(f"Investigator: {status['investigator']}")
        print(f"Session ID: {status['session_id']}")
        print(f"Uptime: {status['uptime']:.2f} seconds")
        print(f"Active Operations: {status['active_operations']}")
        print(f"Investigation Cases: {status['investigation_cases']}")
        
        print("\nComponent Status:")
        print(f"Security: {status['security_status']}")
        print(f"Cybertrace: {status['cybertrace_status']}")
        print(f"Evidence: {status['evidence_status']}")
    
    def _list_cases(self, args):
        """List investigation cases"""
        
        if not self.investigator:
            self._init_system(args)
        
        cases = self.investigator.list_cases()
        
        print("Investigation Cases")
        print("=" * 50)
        
        if not cases:
            print("No cases found.")
            return
        
        for case in cases:
            print(f"\nCase ID: {case['case_id']}")
            print(f"Name: {case['case_name']}")
            print(f"Type: {case['case_type']}")
            print(f"Status: {case['status']}")
            print(f"Created: {case['created_at']}")
            print(f"Evidence: {case['evidence_count']} items")
            print(f"Cybertrace: {case['cybertrace_count']} operations")
    
    def _show_case_details(self, args):
        """Show detailed case information"""
        
        if not self.investigator:
            self._init_system(args)
        
        case_details = self.investigator.get_case_details(args.case_id)
        
        print(f"Case Details: {case_details['case_name']}")
        print("=" * 50)
        print(f"Case ID: {case_details['case_id']}")
        print(f"Name: {case_details['case_name']}")
        print(f"Type: {case_details['case_type']}")
        print(f"Status: {case_details['status']}")
        print(f"Created: {case_details['created_at']}")
        print(f"Created By: {case_details['created_by']}")
        
        if case_details.get('description'):
            print(f"Description: {case_details['description']}")
        
        # Evidence summary
        evidence = case_details.get('evidence', [])
        print(f"\nEvidence ({len(evidence)} items):")
        for item in evidence[:5]:  # Show first 5
            print(f"  - {item.get('evidence_id', 'Unknown')}: {item.get('evidence_type', 'Unknown')}")
        if len(evidence) > 5:
            print(f"  ... and {len(evidence) - 5} more items")
        
        # Cybertrace summary
        cybertrace = case_details.get('cybertrace_results', [])
        print(f"\nCybertrace Operations ({len(cybertrace)} operations):")
        for op in cybertrace[:5]:  # Show first 5
            print(f"  - {op.get('trace_id', 'Unknown')}: {op.get('trace_type', 'Unknown')} -> {op.get('target', 'Unknown')}")
        if len(cybertrace) > 5:
            print(f"  ... and {len(cybertrace) - 5} more operations")


def main():
    """Main entry point"""
    
    print("Professional Investigators & Cybertrace System v1.0.0")
    print("Copyright (c) 2025 Professional Investigation Team")
    print("=" * 60)
    
    try:
        cli = InvestigationSystemCLI()
        cli.run()
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()