#!/usr/bin/env python3
"""
Advanced Interactive Test Runner
Provides menu-driven interface for sophisticated testing scenarios.
"""
import sys
import time
from sophisticated_test_suite import (
    SignatureMatchingTest,
    MLAnomalyTest,
    ThreatCorrelationTest,
    MixedTrafficTest,
    BurstAttackTest,
    API_URL
)

def print_menu():
    """Print test menu"""
    print("\n" + "="*60)
    print("🎯 QuantumDefender Advanced Test Runner")
    print("="*60)
    print(f"\nTarget: {API_URL}\n")
    print("Available Tests:")
    print("  1. Signature Matching Test")
    print("     - SQL injection patterns")
    print("     - XSS patterns")
    print("     - Signature-based detection")
    print()
    print("  2. ML Anomaly Detection Test")
    print("     - Baseline normal traffic")
    print("     - Anomalous patterns")
    print("     - ML-based detection")
    print()
    print("  3. Threat Correlation Test")
    print("     - Multiple agents")
    print("     - Same target IP")
    print("     - Correlation detection")
    print()
    print("  4. Mixed Traffic Test")
    print("     - Realistic traffic mix")
    print("     - Normal + malicious")
    print("     - Real-world scenario")
    print()
    print("  5. Burst Attack Test")
    print("     - Rapid-fire attacks")
    print("     - High-volume scenario")
    print("     - Stress testing")
    print()
    print("  6. Run All Tests")
    print("  0. Exit")
    print("="*60)

def main():
    """Main interactive loop"""
    tests = {
        "1": ("Signature Matching", SignatureMatchingTest),
        "2": ("ML Anomaly Detection", MLAnomalyTest),
        "3": ("Threat Correlation", ThreatCorrelationTest),
        "4": ("Mixed Traffic", MixedTrafficTest),
        "5": ("Burst Attack", BurstAttackTest),
    }
    
    while True:
        print_menu()
        choice = input("\nSelect test (0-6): ").strip()
        
        if choice == "0":
            print("\n👋 Goodbye!")
            break
        elif choice == "6":
            print("\n🚀 Running all tests...")
            for name, test_class in tests.values():
                print(f"\n▶️  Running {name}...")
                try:
                    scenario = test_class()
                    scenario.run()
                    time.sleep(2)
                except KeyboardInterrupt:
                    print("\n⚠️  Interrupted")
                    break
                except Exception as e:
                    print(f"❌ Error: {e}")
            print("\n✅ All tests completed!")
        elif choice in tests:
            name, test_class = tests[choice]
            print(f"\n▶️  Running {name}...")
            try:
                scenario = test_class()
                scenario.run()
            except KeyboardInterrupt:
                print("\n⚠️  Test interrupted")
            except Exception as e:
                print(f"❌ Error: {e}")
        else:
            print("❌ Invalid choice")
        
        if choice != "0":
            input("\nPress ENTER to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)



