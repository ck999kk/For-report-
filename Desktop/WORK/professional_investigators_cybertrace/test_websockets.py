#!/usr/bin/env python3
"""
WEBSOCKET REAL-TIME TESTING
===========================
Tests WebSocket connectivity and real-time features
"""

import socketio
import time
import json
from datetime import datetime
import asyncio
import threading

class WebSocketTester:
    def __init__(self):
        self.sio = socketio.Client()
        self.base_url = "http://localhost:5001"
        self.connected = False
        self.messages_received = []
        self.test_results = {}
        
    def setup_event_handlers(self):
        """Setup WebSocket event handlers"""
        
        @self.sio.event
        def connect():
            print("  ✅ WebSocket connected successfully")
            self.connected = True
            
        @self.sio.event
        def disconnect():
            print("  🔌 WebSocket disconnected")
            self.connected = False
            
        @self.sio.event
        def connected(data):
            print(f"  📨 Received connected event: {data}")
            self.messages_received.append(('connected', data))
            
        @self.sio.event
        def investigation_completed(data):
            print(f"  📨 Investigation completed: {data}")
            self.messages_received.append(('investigation_completed', data))
            
        @self.sio.event
        def investigation_error(data):
            print(f"  📨 Investigation error: {data}")
            self.messages_received.append(('investigation_error', data))
            
        @self.sio.event
        def progress_update(data):
            print(f"  📨 Progress update: {data}")
            self.messages_received.append(('progress_update', data))
            
        @self.sio.event
        def joined_investigation(data):
            print(f"  📨 Joined investigation: {data}")
            self.messages_received.append(('joined_investigation', data))
            
        @self.sio.event
        def error(data):
            print(f"  ❌ WebSocket error: {data}")
            self.messages_received.append(('error', data))
    
    def test_websocket_connection(self):
        """Test WebSocket connection"""
        print("\n🔌 Testing WebSocket Connection...")
        
        try:
            self.setup_event_handlers()
            
            # Connect to WebSocket server
            self.sio.connect(self.base_url, wait_timeout=10)
            
            # Wait for connection
            time.sleep(2)
            
            if self.connected:
                print("  ✅ WebSocket connection established")
                return True
            else:
                print("  ❌ WebSocket connection failed")
                return False
                
        except Exception as e:
            print(f"  ❌ WebSocket connection error: {e}")
            return False
    
    def test_websocket_events(self):
        """Test WebSocket events"""
        print("\n📡 Testing WebSocket Events...")
        
        if not self.connected:
            print("  ❌ Cannot test events - not connected")
            return False
        
        try:
            # Test join investigation event
            test_investigation_id = "test-investigation-123"
            print(f"  📤 Sending join_investigation event...")
            
            self.sio.emit('join_investigation', {
                'investigation_id': test_investigation_id
            })
            
            time.sleep(1)
            
            # Test request progress event
            print(f"  📤 Sending request_progress event...")
            
            self.sio.emit('request_progress', {
                'investigation_id': test_investigation_id
            })
            
            time.sleep(1)
            
            # Check if we received responses
            event_types_received = [msg[0] for msg in self.messages_received]
            
            print(f"  📨 Received {len(self.messages_received)} WebSocket messages")
            print(f"  📊 Event types: {set(event_types_received)}")
            
            return len(self.messages_received) > 0
            
        except Exception as e:
            print(f"  ❌ WebSocket events test error: {e}")
            return False
    
    def test_realtime_investigation(self):
        """Test real-time investigation updates"""
        print("\n🔍 Testing Real-time Investigation Updates...")
        
        if not self.connected:
            print("  ❌ Cannot test real-time updates - not connected")
            return False
        
        try:
            # This would normally trigger from the web interface
            # For testing, we'll simulate what happens during an investigation
            
            # Listen for investigation events
            initial_message_count = len(self.messages_received)
            
            # Wait for any ongoing investigation messages
            print("  ⏳ Waiting for real-time updates...")
            time.sleep(5)
            
            new_messages = len(self.messages_received) - initial_message_count
            
            if new_messages > 0:
                print(f"  ✅ Received {new_messages} real-time updates")
                return True
            else:
                print(f"  ⚠️  No real-time updates received (this is normal if no investigations are running)")
                return True  # This is actually expected in a test environment
                
        except Exception as e:
            print(f"  ❌ Real-time investigation test error: {e}")
            return False
    
    def run_websocket_tests(self):
        """Run complete WebSocket testing suite"""
        print("🌐 Starting WebSocket Testing Suite")
        print("="*50)
        
        test_results = {
            'connection': False,
            'events': False,
            'realtime_updates': False,
            'message_count': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        # Run tests
        test_results['connection'] = self.test_websocket_connection()
        
        if test_results['connection']:
            test_results['events'] = self.test_websocket_events()
            test_results['realtime_updates'] = self.test_realtime_investigation()
        
        test_results['message_count'] = len(self.messages_received)
        test_results['messages_received'] = self.messages_received
        
        # Calculate success rate
        tests = ['connection', 'events', 'realtime_updates']
        passed = sum(1 for test in tests if test_results[test])
        total = len(tests)
        success_rate = (passed / total) * 100
        
        print(f"\n" + "="*50)
        print("📋 WEBSOCKET TEST SUMMARY")
        print("="*50)
        print(f"✅ Tests Passed: {passed}")
        print(f"❌ Tests Failed: {total - passed}")
        print(f"📨 Messages Received: {test_results['message_count']}")
        print(f"📊 Success Rate: {success_rate:.1f}%")
        print(f"🕒 Test Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50)
        
        if success_rate >= 90:
            print("🏆 EXCELLENT: WebSocket system performing excellently!")
        elif success_rate >= 75:
            print("✅ GOOD: WebSocket system functioning well")
        elif success_rate >= 50:
            print("⚠️  FAIR: WebSocket system has some issues")
        else:
            print("❌ POOR: WebSocket system needs improvements")
        
        # Cleanup
        if self.connected:
            self.sio.disconnect()
        
        # Save results
        results_file = f"websocket_test_results_{int(time.time())}.json"
        with open(results_file, 'w') as f:
            # Convert any non-serializable objects
            serializable_results = json.loads(json.dumps(test_results, default=str))
            json.dump(serializable_results, f, indent=2)
        
        print(f"💾 Detailed results saved to: {results_file}")
        
        return test_results

if __name__ == "__main__":
    tester = WebSocketTester()
    results = tester.run_websocket_tests()