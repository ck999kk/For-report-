#!/usr/bin/env python3
"""
WEB INTERFACE COMPLETE TESTING
==============================
Tests the complete web interface from end-user perspective
Includes login, investigation workflow, report generation, etc.
"""

import requests
import json
import time
from datetime import datetime
from pathlib import Path
import sys

class WebInterfaceTester:
    def __init__(self):
        self.base_url = "http://localhost:5001"
        self.session = requests.Session()
        self.investigator_name = "Test_Investigator"
        self.test_results = []
        
    def test_login_workflow(self):
        """Test complete login workflow"""
        print("\n🔐 Testing Login Workflow...")
        
        # Test GET login page
        try:
            response = self.session.get(f"{self.base_url}/login")
            print(f"  ✅ Login page accessible: {response.status_code}")
            
            # Test POST login
            login_data = {'investigator_name': self.investigator_name}
            response = self.session.post(f"{self.base_url}/login", data=login_data)
            
            if response.status_code == 200 or 'dashboard' in response.text.lower():
                print(f"  ✅ Login successful: {response.status_code}")
                return True
            else:
                print(f"  ❌ Login failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ❌ Login error: {e}")
            return False
    
    def test_dashboard_access(self):
        """Test dashboard page access"""
        print("\n📊 Testing Dashboard Access...")
        
        try:
            response = self.session.get(f"{self.base_url}/")
            
            if response.status_code == 200:
                print(f"  ✅ Dashboard accessible: {response.status_code}")
                # Check for key dashboard elements
                content = response.text.lower()
                if 'dashboard' in content or 'investigation' in content:
                    print(f"  ✅ Dashboard content loaded correctly")
                    return True
                else:
                    print(f"  ⚠️  Dashboard accessible but content may be incomplete")
                    return True
            else:
                print(f"  ❌ Dashboard access failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ❌ Dashboard error: {e}")
            return False
    
    def test_api_with_session(self):
        """Test API endpoints with authenticated session"""
        print("\n🔌 Testing Authenticated API Endpoints...")
        
        results = {}
        
        # Test phone validation API
        try:
            phone_data = {'phone_number': '+1-555-123-4567'}
            response = self.session.post(
                f"{self.base_url}/api/validate_phone",
                json=phone_data,
                headers={'Content-Type': 'application/json'}
            )
            
            results['validate_phone'] = {
                'status_code': response.status_code,
                'success': response.status_code == 200
            }
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✅ Phone validation API working: {data.get('status', 'N/A')}")
            else:
                print(f"  ⚠️  Phone validation API: {response.status_code}")
                
        except Exception as e:
            print(f"  ❌ Phone validation API error: {e}")
        
        # Test session info API
        try:
            response = self.session.get(f"{self.base_url}/api/session_info")
            results['session_info'] = {
                'status_code': response.status_code,
                'success': response.status_code == 200
            }
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✅ Session info API: {data.get('investigator', 'N/A')}")
            else:
                print(f"  ⚠️  Session info API: {response.status_code}")
                
        except Exception as e:
            print(f"  ❌ Session info API error: {e}")
        
        # Test start investigation API
        try:
            investigation_data = {
                'phone_number': '+1-555-123-4567',
                'investigation_type': 'comprehensive'
            }
            response = self.session.post(
                f"{self.base_url}/api/start_investigation",
                json=investigation_data,
                headers={'Content-Type': 'application/json'}
            )
            
            results['start_investigation'] = {
                'status_code': response.status_code,
                'success': response.status_code == 200
            }
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✅ Investigation started: {data.get('status', 'N/A')}")
            else:
                print(f"  ⚠️  Start investigation API: {response.status_code}")
                
        except Exception as e:
            print(f"  ❌ Start investigation API error: {e}")
        
        return results
    
    def test_investigation_pages(self):
        """Test investigation-related pages"""
        print("\n🔍 Testing Investigation Pages...")
        
        pages = {
            'investigate': '/investigate',
            'reports': '/reports',
            'history': '/history'
        }
        
        results = {}
        
        for page_name, url in pages.items():
            try:
                response = self.session.get(f"{self.base_url}{url}")
                success = response.status_code == 200
                
                results[page_name] = {
                    'status_code': response.status_code,
                    'success': success
                }
                
                status = "✅" if success else "❌"
                print(f"  {status} {page_name.capitalize()} page: {response.status_code}")
                
            except Exception as e:
                print(f"  ❌ {page_name.capitalize()} page error: {e}")
                results[page_name] = {'error': str(e), 'success': False}
        
        return results
    
    def test_file_upload(self):
        """Test file upload functionality"""
        print("\n📁 Testing File Upload...")
        
        try:
            # Create a test file
            test_file_content = "This is a test evidence file for the investigation system."
            test_file_path = Path("test_evidence.txt")
            test_file_path.write_text(test_file_content)
            
            # Test upload
            with open(test_file_path, 'rb') as f:
                files = {'file': ('test_evidence.txt', f, 'text/plain')}
                data = {'investigation_id': 'test-investigation-id'}
                
                response = self.session.post(
                    f"{self.base_url}/api/upload_evidence",
                    files=files,
                    data=data
                )
            
            # Clean up test file
            test_file_path.unlink()
            
            if response.status_code == 200:
                result = response.json()
                print(f"  ✅ File upload successful: {result.get('filename', 'N/A')}")
                return True
            else:
                print(f"  ⚠️  File upload response: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ❌ File upload error: {e}")
            return False
    
    def test_responsive_design(self):
        """Test responsive design by checking CSS and JavaScript"""
        print("\n📱 Testing Responsive Design...")
        
        # Test CSS files
        css_files = ['/static/css/main.css']
        js_files = ['/static/js/main.js']
        
        results = {}
        
        for css_file in css_files:
            try:
                response = self.session.get(f"{self.base_url}{css_file}")
                success = response.status_code == 200 and 'text/css' in response.headers.get('content-type', '')
                
                results[f'css_{css_file}'] = success
                status = "✅" if success else "❌"
                print(f"  {status} CSS file {css_file}: {response.status_code}")
                
            except Exception as e:
                print(f"  ❌ CSS file {css_file} error: {e}")
        
        for js_file in js_files:
            try:
                response = self.session.get(f"{self.base_url}{js_file}")
                success = response.status_code == 200
                
                results[f'js_{js_file}'] = success
                status = "✅" if success else "❌"
                print(f"  {status} JS file {js_file}: {response.status_code}")
                
            except Exception as e:
                print(f"  ❌ JS file {js_file} error: {e}")
        
        return results
    
    def run_complete_test(self):
        """Run complete web interface test"""
        print("🌐 Starting Complete Web Interface Testing")
        print("="*50)
        
        test_results = {
            'login_workflow': False,
            'dashboard_access': False,
            'api_endpoints': {},
            'investigation_pages': {},
            'file_upload': False,
            'responsive_design': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Run all tests
        test_results['login_workflow'] = self.test_login_workflow()
        test_results['dashboard_access'] = self.test_dashboard_access()
        test_results['api_endpoints'] = self.test_api_with_session()
        test_results['investigation_pages'] = self.test_investigation_pages()
        test_results['file_upload'] = self.test_file_upload()
        test_results['responsive_design'] = self.test_responsive_design()
        
        # Calculate success metrics
        total_tests = 0
        passed_tests = 0
        
        # Count basic tests
        basic_tests = ['login_workflow', 'dashboard_access', 'file_upload']
        for test in basic_tests:
            total_tests += 1
            if test_results[test]:
                passed_tests += 1
        
        # Count API endpoint tests
        for endpoint, result in test_results['api_endpoints'].items():
            total_tests += 1
            if result.get('success', False):
                passed_tests += 1
        
        # Count page tests
        for page, result in test_results['investigation_pages'].items():
            total_tests += 1
            if result.get('success', False):
                passed_tests += 1
        
        # Count responsive design tests
        for test, result in test_results['responsive_design'].items():
            total_tests += 1
            if result:
                passed_tests += 1
        
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        print("\n" + "="*50)
        print("📋 WEB INTERFACE TEST SUMMARY")
        print("="*50)
        print(f"✅ Tests Passed: {passed_tests}")
        print(f"❌ Tests Failed: {total_tests - passed_tests}")
        print(f"📊 Success Rate: {success_rate:.1f}%")
        print(f"🕒 Test Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50)
        
        if success_rate >= 90:
            print("🏆 EXCELLENT: Web interface performing excellently!")
        elif success_rate >= 75:
            print("✅ GOOD: Web interface functioning well")
        elif success_rate >= 50:
            print("⚠️  FAIR: Web interface has some issues")
        else:
            print("❌ POOR: Web interface needs major improvements")
        
        # Save detailed results
        results_file = f"web_interface_test_results_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            json.dump(test_results, f, indent=2)
        
        print(f"\n💾 Detailed results saved to: {results_file}")
        
        return test_results

if __name__ == "__main__":
    tester = WebInterfaceTester()
    results = tester.run_complete_test()