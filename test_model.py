import requests
import pandas as pd
import json
from datetime import datetime
import time

def test_model_predictions():
    # Test cases with expected outcomes
    test_cases = [
        # Normal HTTPS traffic
        {
            "Protocol": 1,  # HTTPS
            "Traffic Type": 0,  # Normal
            "Action Taken": 0,  # Allow
            "Severity Level": 0,  # Low
            "Network Segment": 0,  # Internal
            "User-Agent": 1,  # Standard Browser
            "Source Port": 443,
            "Destination Port": 443,
            "Packet Length": 1024,
            "Anomaly Scores": 0.1,
            "expected": "Allowed",
            "description": "Normal HTTPS traffic"
        },
        
        # Suspicious scanning activity
        {
            "Protocol": 0,  # HTTP
            "Traffic Type": 1,  # Suspicious
            "Action Taken": 1,  # Block
            "Severity Level": 2,  # High
            "Network Segment": 2,  # DMZ
            "User-Agent": 3,  # Unknown
            "Source Port": 31337,
            "Destination Port": 22,
            "Packet Length": 64,
            "Anomaly Scores": 0.9,
            "expected": "Blocked",
            "description": "Suspicious port scanning"
        },
        
        # Large packet anomaly
        {
            "Protocol": 1,
            "Traffic Type": 0,
            "Action Taken": 0,
            "Severity Level": 1,
            "Network Segment": 0,
            "User-Agent": 1,
            "Source Port": 443,
            "Destination Port": 443,
            "Packet Length": 65535,  # Very large packet
            "Anomaly Scores": 0.7,
            "expected": "Blocked",
            "description": "Abnormally large packet size"
        },
        
        # Unusual port combination
        {
            "Protocol": 1,
            "Traffic Type": 0,
            "Action Taken": 0,
            "Severity Level": 1,
            "Network Segment": 1,
            "User-Agent": 2,
            "Source Port": 1337,
            "Destination Port": 4444,
            "Packet Length": 512,
            "Anomaly Scores": 0.6,
            "expected": "Blocked",
            "description": "Unusual port combination"
        },
        
        # Normal internal traffic
        {
            "Protocol": 0,
            "Traffic Type": 0,
            "Action Taken": 0,
            "Severity Level": 0,
            "Network Segment": 0,
            "User-Agent": 1,
            "Source Port": 80,
            "Destination Port": 80,
            "Packet Length": 1500,
            "Anomaly Scores": 0.2,
            "expected": "Allowed",
            "description": "Normal internal HTTP traffic"
        }
    ]
    
    # Initialize results storage
    results = []
    
    # Create timestamp for report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print("\nStarting model testing...")
    print("=" * 80)
    
    # Test each case
    for i, test_case in enumerate(test_cases, 1):
        try:
            # Extract test metadata
            expected = test_case.pop("expected")
            description = test_case.pop("description")
            
            # Make prediction request
            print(f"\nTest Case {i}: {description}")
            print("-" * 80)
            print("Input:", json.dumps(test_case, indent=2))
            
            response = requests.post("http://localhost:8000/predict/", json=test_case)
            result = response.json()
            
            # Add test case details back
            test_case["expected"] = expected
            test_case["description"] = description
            
            # Prepare result entry
            result_entry = {
                "test_case": i,
                "description": description,
                "expected": expected,
                "actual": result["status"],
                "confidence": result.get("confidence", None),
                "risk_score": result.get("risk_score", None),
                "key_indicators": result.get("key_indicators", {}),
                "passed": result["status"] == expected
            }
            
            results.append(result_entry)
            
            # Print results
            print("\nResult:", json.dumps(result, indent=2))
            print(f"Test {'PASSED' if result_entry['passed'] else 'FAILED'}")
            
            # Add small delay to avoid overwhelming the API
            time.sleep(0.5)
            
        except Exception as e:
            print(f"Error in test case {i}: {str(e)}")
            results.append({
                "test_case": i,
                "description": description,
                "error": str(e),
                "passed": False
            })
    
    # Generate summary report
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.get("passed", False))
    
    print(f"\nTotal Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.2f}%")
    
    # Save detailed results to CSV
    results_df = pd.DataFrame(results)
    report_filename = f"test_results_{timestamp}.csv"
    results_df.to_csv(report_filename, index=False)
    print(f"\nDetailed results saved to: {report_filename}")
    
    return results_df

if __name__ == "__main__":
    test_model_predictions()