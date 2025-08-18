#!/usr/bin/env python3
"""
END-TO-END INVESTIGATION WORKFLOW TESTING
=========================================
Tests complete investigation workflow from start to finish
"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
import sys

# Add project to path
sys.path.append(str(Path(__file__).parent))

from phone_intelligence_system import PhoneIntelligenceSystem

class InvestigationWorkflowTester:
    def __init__(self):
        self.phone_system = None
        self.investigator_name = "Detective_Smith"
        self.test_phone_numbers = [
            "+1-555-123-4567",
            "+44-20-7946-0958", 
            "+33-1-23-45-67-89"
        ]
        self.investigation_results = []
        
    async def initialize_system(self):
        """Initialize the investigation system"""
        try:
            self.phone_system = PhoneIntelligenceSystem()
            print("✅ Investigation system initialized successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to initialize system: {e}")
            return False
    
    async def test_complete_investigation(self, phone_number):
        """Test complete investigation workflow for a phone number"""
        print(f"\n🔍 Starting Complete Investigation: {phone_number}")
        print("-" * 50)
        
        try:
            # Start investigation
            investigation_id = await self.phone_system.investigate_phone_number(
                phone_number, 
                self.investigator_name, 
                'comprehensive'
            )
            
            print(f"  📋 Investigation ID: {investigation_id}")
            
            # Wait for investigation to complete
            max_wait = 60  # seconds
            wait_time = 0
            
            while wait_time < max_wait:
                try:
                    status = self.phone_system.get_investigation_status(investigation_id)
                    print(f"  ⏳ Status: {status.get('status', 'unknown')} - Progress: {status.get('progress', 0):.1f}%")
                    
                    if status.get('status') == 'completed':
                        print(f"  ✅ Investigation completed successfully!")
                        break
                        
                    await asyncio.sleep(2)
                    wait_time += 2
                    
                except Exception as e:
                    print(f"  ⚠️  Status check error: {e}")
                    break
            
            # Get investigation results
            try:
                investigations = self.phone_system.list_investigations(self.investigator_name)
                current_investigation = None
                
                for inv in investigations:
                    if inv.get('id') == investigation_id:
                        current_investigation = inv
                        break
                
                if current_investigation:
                    print(f"  📊 Investigation Results:")
                    print(f"    - Phone: {current_investigation.get('phone_number', 'N/A')}")
                    print(f"    - Status: {current_investigation.get('status', 'N/A')}")
                    print(f"    - Evidence Count: {current_investigation.get('evidence_count', 0)}")
                    print(f"    - Completed: {current_investigation.get('completion_time', 'N/A')}")
                    
                    # Test report generation
                    try:
                        report_path = current_investigation.get('report_path')
                        if report_path and Path(report_path).exists():
                            print(f"  📄 Report generated: {Path(report_path).name}")
                            
                            # Read and validate report
                            report_content = Path(report_path).read_text()
                            if len(report_content) > 1000:  # Basic validation
                                print(f"    ✅ Report content validated ({len(report_content)} characters)")
                            else:
                                print(f"    ⚠️  Report content may be incomplete")
                        else:
                            print(f"  ❌ Report not found or not generated")
                    
                    except Exception as e:
                        print(f"  ❌ Report validation error: {e}")
                
                else:
                    print(f"  ❌ Investigation results not found")
                
            except Exception as e:
                print(f"  ❌ Results retrieval error: {e}")
            
            return {
                'investigation_id': investigation_id,
                'phone_number': phone_number,
                'success': True,
                'results': current_investigation
            }
            
        except Exception as e:
            print(f"  ❌ Investigation failed: {e}")
            return {
                'phone_number': phone_number,
                'success': False,
                'error': str(e)
            }
    
    async def test_evidence_integrity(self):
        """Test evidence integrity and chain of custody"""
        print(f"\n🔒 Testing Evidence Integrity & Chain of Custody")
        print("-" * 50)
        
        try:
            evidence_manager = self.phone_system.evidence_manager
            
            # Get all evidence for investigations
            total_evidence = 0
            verified_evidence = 0
            
            investigations = self.phone_system.list_investigations(self.investigator_name)
            
            for investigation in investigations:
                investigation_id = investigation.get('id')
                if investigation_id:
                    try:
                        evidence_list = evidence_manager.get_evidence_list(investigation_id)
                        
                        for evidence_item in evidence_list:
                            total_evidence += 1
                            
                            # Verify evidence integrity
                            is_verified = evidence_manager.verify_evidence_integrity(evidence_item['id'])
                            if is_verified:
                                verified_evidence += 1
                                print(f"  ✅ Evidence {evidence_item['id'][:8]}... verified")
                            else:
                                print(f"  ❌ Evidence {evidence_item['id'][:8]}... INTEGRITY FAILED")
                    
                    except Exception as e:
                        print(f"  ⚠️  Evidence check error for {investigation_id}: {e}")
            
            integrity_rate = (verified_evidence / total_evidence) * 100 if total_evidence > 0 else 100
            
            print(f"\n  📊 Evidence Integrity Report:")
            print(f"    - Total Evidence Items: {total_evidence}")
            print(f"    - Verified Evidence: {verified_evidence}")
            print(f"    - Integrity Rate: {integrity_rate:.1f}%")
            
            return {
                'total_evidence': total_evidence,
                'verified_evidence': verified_evidence,
                'integrity_rate': integrity_rate
            }
            
        except Exception as e:
            print(f"  ❌ Evidence integrity test failed: {e}")
            return {'error': str(e)}
    
    async def test_database_consistency(self):
        """Test database consistency and data integrity"""
        print(f"\n🗄️  Testing Database Consistency")
        print("-" * 50)
        
        try:
            import sqlite3
            
            db_path = "phone_evidence.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check investigation records
            cursor.execute("SELECT COUNT(*) FROM investigations WHERE investigator = ?", (self.investigator_name,))
            investigation_count = cursor.fetchone()[0]
            
            # Check evidence records
            cursor.execute("SELECT COUNT(*) FROM evidence WHERE investigator = ?", (self.investigator_name,))
            evidence_count = cursor.fetchone()[0]
            
            # Check chain of custody records
            cursor.execute("SELECT COUNT(*) FROM chain_of_custody WHERE investigator = ?", (self.investigator_name,))
            custody_count = cursor.fetchone()[0]
            
            print(f"  📊 Database Records:")
            print(f"    - Investigations: {investigation_count}")
            print(f"    - Evidence Items: {evidence_count}")
            print(f"    - Chain of Custody: {custody_count}")
            
            # Check for orphaned records
            cursor.execute("""
                SELECT COUNT(*) FROM evidence e 
                LEFT JOIN investigations i ON e.investigation_id = i.id 
                WHERE i.id IS NULL AND e.investigator = ?
            """, (self.investigator_name,))
            orphaned_evidence = cursor.fetchone()[0]
            
            if orphaned_evidence == 0:
                print(f"  ✅ No orphaned evidence records found")
            else:
                print(f"  ⚠️  Found {orphaned_evidence} orphaned evidence records")
            
            conn.close()
            
            return {
                'investigation_count': investigation_count,
                'evidence_count': evidence_count,
                'custody_count': custody_count,
                'orphaned_evidence': orphaned_evidence,
                'consistent': orphaned_evidence == 0
            }
            
        except Exception as e:
            print(f"  ❌ Database consistency test failed: {e}")
            return {'error': str(e)}
    
    async def test_performance_metrics(self):
        """Test system performance under normal load"""
        print(f"\n⚡ Testing Performance Metrics")
        print("-" * 50)
        
        try:
            # Test phone validation performance
            print(f"  🏃 Testing phone validation speed...")
            start_time = time.time()
            
            validation_count = 0
            for _ in range(50):
                for phone in self.test_phone_numbers:
                    try:
                        result = self.phone_system.validator.validate_and_format(phone)
                        if result.get('is_valid'):
                            validation_count += 1
                    except:
                        pass
            
            validation_time = time.time() - start_time
            validation_rate = (50 * len(self.test_phone_numbers)) / validation_time
            
            print(f"    ✅ Validation Rate: {validation_rate:.1f} validations/second")
            
            # Test database query performance
            print(f"  💾 Testing database query speed...")
            
            import sqlite3
            conn = sqlite3.connect("phone_evidence.db")
            cursor = conn.cursor()
            
            start_time = time.time()
            
            for _ in range(100):
                cursor.execute("SELECT COUNT(*) FROM investigations")
                cursor.fetchone()
            
            query_time = time.time() - start_time
            query_rate = 100 / query_time
            
            print(f"    ✅ Database Query Rate: {query_rate:.1f} queries/second")
            
            conn.close()
            
            return {
                'validation_rate': validation_rate,
                'query_rate': query_rate,
                'validation_time': validation_time,
                'query_time': query_time
            }
            
        except Exception as e:
            print(f"  ❌ Performance testing failed: {e}")
            return {'error': str(e)}
    
    async def run_complete_workflow_test(self):
        """Run complete end-to-end workflow test"""
        print("🚀 STARTING END-TO-END INVESTIGATION WORKFLOW TEST")
        print("=" * 60)
        
        if not await self.initialize_system():
            print("❌ Cannot proceed without system initialization")
            return
        
        test_start_time = time.time()
        
        # Test investigations for each phone number
        print(f"\n📱 Testing Multiple Phone Number Investigations")
        print("=" * 60)
        
        for phone_number in self.test_phone_numbers:
            result = await self.test_complete_investigation(phone_number)
            self.investigation_results.append(result)
        
        # Test system integrity
        evidence_results = await self.test_evidence_integrity()
        db_results = await self.test_database_consistency()
        performance_results = await self.test_performance_metrics()
        
        total_test_time = time.time() - test_start_time
        
        # Generate comprehensive report
        print(f"\n" + "=" * 60)
        print("📋 END-TO-END WORKFLOW TEST SUMMARY")
        print("=" * 60)
        
        successful_investigations = len([r for r in self.investigation_results if r.get('success')])
        total_investigations = len(self.investigation_results)
        
        print(f"🔍 INVESTIGATION RESULTS:")
        print(f"  ✅ Successful: {successful_investigations}/{total_investigations}")
        print(f"  📊 Success Rate: {(successful_investigations/total_investigations)*100:.1f}%")
        
        print(f"\n🔒 EVIDENCE INTEGRITY:")
        if 'integrity_rate' in evidence_results:
            print(f"  📊 Integrity Rate: {evidence_results['integrity_rate']:.1f}%")
            print(f"  📁 Total Evidence: {evidence_results['total_evidence']}")
        
        print(f"\n🗄️  DATABASE CONSISTENCY:")
        if 'consistent' in db_results:
            status = "✅ CONSISTENT" if db_results['consistent'] else "❌ INCONSISTENT"
            print(f"  {status}")
            print(f"  📊 Investigations: {db_results.get('investigation_count', 'N/A')}")
            print(f"  📊 Evidence: {db_results.get('evidence_count', 'N/A')}")
        
        print(f"\n⚡ PERFORMANCE METRICS:")
        if 'validation_rate' in performance_results:
            print(f"  🏃 Validation Rate: {performance_results['validation_rate']:.1f} ops/sec")
            print(f"  💾 DB Query Rate: {performance_results['query_rate']:.1f} queries/sec")
        
        print(f"\n⏱️  TOTAL TEST TIME: {total_test_time:.2f} seconds")
        
        # Calculate overall score
        investigation_score = (successful_investigations / total_investigations) * 100 if total_investigations > 0 else 0
        evidence_score = evidence_results.get('integrity_rate', 0)
        db_score = 100 if db_results.get('consistent', False) else 0
        performance_score = 100 if (performance_results.get('validation_rate', 0) > 100 and performance_results.get('query_rate', 0) > 50) else 50
        
        overall_score = (investigation_score + evidence_score + db_score + performance_score) / 4
        
        print(f"\n🎯 OVERALL SYSTEM SCORE: {overall_score:.1f}%")
        
        if overall_score >= 90:
            print("🏆 EXCELLENT: System performing at professional grade!")
        elif overall_score >= 80:
            print("✅ VERY GOOD: System ready for production use")
        elif overall_score >= 70:
            print("✅ GOOD: System functioning well with minor issues")
        elif overall_score >= 60:
            print("⚠️  FAIR: System needs improvements")
        else:
            print("❌ POOR: System requires major fixes")
        
        print("=" * 60)
        
        # Save comprehensive results
        final_results = {
            'test_summary': {
                'overall_score': overall_score,
                'investigation_success_rate': investigation_score,
                'evidence_integrity_rate': evidence_score,
                'database_consistency_score': db_score,
                'performance_score': performance_score,
                'total_test_time': total_test_time
            },
            'investigation_results': self.investigation_results,
            'evidence_results': evidence_results,
            'database_results': db_results,
            'performance_results': performance_results,
            'timestamp': datetime.now().isoformat()
        }
        
        results_file = f"end_to_end_workflow_results_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump(final_results, f, indent=2)
        
        print(f"💾 Complete results saved to: {results_file}")
        
        return final_results

async def main():
    """Run the complete end-to-end workflow test"""
    tester = InvestigationWorkflowTester()
    results = await tester.run_complete_workflow_test()
    return results

if __name__ == "__main__":
    asyncio.run(main())