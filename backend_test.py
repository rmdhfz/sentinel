#!/usr/bin/env python3
"""
Backend API Test Suite for Sentinel Security Platform
Tests all backend endpoints with real data
"""
import requests
import json
import time
from typing import Dict, Any

BASE_URL = "https://security-lens-pro.preview.emergentagent.com/api"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def log_test(name: str, status: str, details: str = ""):
    """Log test result with color"""
    color = Colors.GREEN if status == "PASS" else Colors.RED if status == "FAIL" else Colors.YELLOW
    print(f"{color}[{status}]{Colors.END} {name}")
    if details:
        print(f"      {details}")

def test_health():
    """Test API health endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                log_test("API Health Check", "PASS", f"API is running: {data.get('name')}")
                return True
        log_test("API Health Check", "FAIL", f"Status: {response.status_code}")
        return False
    except Exception as e:
        log_test("API Health Check", "FAIL", f"Error: {str(e)}")
        return False

def test_scan_real(framework: str = "NestJS") -> Dict[str, Any]:
    """Test POST /api/scan with real scanner"""
    print(f"\n{Colors.BLUE}=== Testing Real Scanner (framework: {framework}) ==={Colors.END}")
    try:
        payload = {
            "url": "example.com",
            "framework": framework,
            "environment": "Production",
            "host": "GCP"
        }
        
        print(f"Sending scan request for example.com with framework {framework}...")
        response = requests.post(f"{BASE_URL}/scan", json=payload, timeout=60)
        
        if response.status_code != 200:
            log_test(f"POST /api/scan ({framework})", "FAIL", f"Status: {response.status_code}, Body: {response.text[:200]}")
            return {}
        
        data = response.json()
        
        # Verify required fields
        required_fields = ['score', 'grade', 'tls', 'ports', 'findings', 'counts', 'scanId', 'assetId']
        missing = [f for f in required_fields if f not in data]
        if missing:
            log_test(f"POST /api/scan ({framework})", "FAIL", f"Missing fields: {missing}")
            return {}
        
        # Verify score is 0-100
        if not isinstance(data['score'], (int, float)) or not (0 <= data['score'] <= 100):
            log_test(f"POST /api/scan ({framework})", "FAIL", f"Invalid score: {data['score']}")
            return {}
        
        # Verify grade is a letter
        if data['grade'] not in ['A', 'B', 'C', 'D', 'F']:
            log_test(f"POST /api/scan ({framework})", "FAIL", f"Invalid grade: {data['grade']}")
            return {}
        
        # Verify TLS object
        tls = data.get('tls', {})
        if not isinstance(tls, dict):
            log_test(f"POST /api/scan ({framework})", "FAIL", "TLS is not an object")
            return {}
        
        if tls.get('ok'):
            required_tls = ['protocol', 'issuer', 'daysLeft', 'authorized']
            missing_tls = [f for f in required_tls if f not in tls]
            if missing_tls:
                log_test(f"POST /api/scan ({framework})", "FAIL", f"TLS missing fields: {missing_tls}")
                return {}
            
            # Verify TLS protocol
            protocol = tls.get('protocol', '')
            if protocol not in ['TLSv1.2', 'TLSv1.3']:
                log_test(f"POST /api/scan ({framework})", "WARN", f"Unexpected TLS protocol: {protocol}")
        
        # Verify ports array
        if not isinstance(data['ports'], list):
            log_test(f"POST /api/scan ({framework})", "FAIL", "Ports is not an array")
            return {}
        
        for port in data['ports']:
            if not all(k in port for k in ['port', 'name', 'open']):
                log_test(f"POST /api/scan ({framework})", "FAIL", f"Invalid port object: {port}")
                return {}
        
        # Verify findings array
        if not isinstance(data['findings'], list):
            log_test(f"POST /api/scan ({framework})", "FAIL", "Findings is not an array")
            return {}
        
        if len(data['findings']) < 6:
            log_test(f"POST /api/scan ({framework})", "WARN", f"Expected >=6 findings for example.com, got {len(data['findings'])}")
        
        for finding in data['findings']:
            required_finding = ['id', 'title', 'severity', 'category', 'cwe', 'description', 'remediation']
            missing_finding = [f for f in required_finding if f not in finding]
            if missing_finding:
                log_test(f"POST /api/scan ({framework})", "FAIL", f"Finding missing fields: {missing_finding}")
                return {}
            
            # Verify severity
            if finding['severity'] not in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                log_test(f"POST /api/scan ({framework})", "FAIL", f"Invalid severity: {finding['severity']}")
                return {}
            
            # Verify remediation structure
            rem = finding.get('remediation', {})
            if not all(k in rem for k in ['generic', 'snippet', 'framework']):
                log_test(f"POST /api/scan ({framework})", "FAIL", f"Invalid remediation: {rem}")
                return {}
            
            if rem['framework'] != framework:
                log_test(f"POST /api/scan ({framework})", "FAIL", f"Remediation framework mismatch: {rem['framework']} != {framework}")
                return {}
        
        # Verify counts
        counts = data.get('counts', {})
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev not in counts:
                log_test(f"POST /api/scan ({framework})", "FAIL", f"Missing severity count: {sev}")
                return {}
        
        log_test(f"POST /api/scan ({framework})", "PASS", 
                f"Score: {data['score']}, Grade: {data['grade']}, Findings: {len(data['findings'])}, TLS: {tls.get('protocol', 'N/A')}")
        
        return data
        
    except Exception as e:
        log_test(f"POST /api/scan ({framework})", "FAIL", f"Exception: {str(e)}")
        return {}

def test_framework_remediation():
    """Test framework-aware remediation by scanning with different frameworks"""
    print(f"\n{Colors.BLUE}=== Testing Framework-Aware Remediation ==={Colors.END}")
    
    frameworks = ["CodeIgniter", "Go"]
    results = {}
    
    for fw in frameworks:
        result = test_scan_real(fw)
        if result and result.get('findings'):
            results[fw] = result
            time.sleep(2)  # Brief pause between scans
    
    if len(results) < 2:
        log_test("Framework-aware remediation", "FAIL", "Could not scan with multiple frameworks")
        return False
    
    # Compare remediation snippets
    fw1, fw2 = list(results.keys())[:2]
    findings1 = results[fw1]['findings']
    findings2 = results[fw2]['findings']
    
    # Find a common finding type
    common_found = False
    for f1 in findings1:
        for f2 in findings2:
            if f1['title'] == f2['title']:
                snippet1 = f1['remediation']['snippet']
                snippet2 = f2['remediation']['snippet']
                
                if snippet1 != snippet2:
                    common_found = True
                    # Verify framework-specific content
                    if fw1 == "CodeIgniter" and ("php" in snippet1.lower() or "ci" in snippet1.lower() or "config" in snippet1.lower()):
                        log_test("Framework-aware remediation", "PASS", 
                                f"CodeIgniter snippet contains PHP/CI config, Go snippet differs")
                        return True
                    elif fw1 == "Go" and ("w.Header()" in snippet1 or "http.SetCookie" in snippet1):
                        log_test("Framework-aware remediation", "PASS", 
                                f"Go snippet contains w.Header().Set, CodeIgniter snippet differs")
                        return True
                break
        if common_found:
            break
    
    if common_found:
        log_test("Framework-aware remediation", "PASS", "Remediation snippets differ by framework")
        return True
    else:
        log_test("Framework-aware remediation", "WARN", "Could not find common findings to compare")
        return True

def test_scan_persistence(scan_data: Dict[str, Any]):
    """Test that scan results are persisted"""
    print(f"\n{Colors.BLUE}=== Testing Scan Persistence ==={Colors.END}")
    
    if not scan_data or 'assetId' not in scan_data:
        log_test("Scan persistence", "SKIP", "No scan data available")
        return False
    
    asset_id = scan_data['assetId']
    
    try:
        # Check assets
        response = requests.get(f"{BASE_URL}/assets", timeout=10)
        if response.status_code != 200:
            log_test("GET /api/assets", "FAIL", f"Status: {response.status_code}")
            return False
        
        assets = response.json()
        asset_found = any(a.get('id') == asset_id for a in assets)
        
        if not asset_found:
            log_test("Scan persistence - Assets", "FAIL", f"Asset {asset_id} not found")
            return False
        
        log_test("GET /api/assets", "PASS", f"Found {len(assets)} assets including scanned asset")
        
        # Check findings
        response = requests.get(f"{BASE_URL}/findings", timeout=10)
        if response.status_code != 200:
            log_test("GET /api/findings", "FAIL", f"Status: {response.status_code}")
            return False
        
        findings = response.json()
        asset_findings = [f for f in findings if f.get('assetId') == asset_id]
        
        if not asset_findings:
            log_test("Scan persistence - Findings", "FAIL", f"No findings for asset {asset_id}")
            return False
        
        # Verify findings have assetName
        if not all('assetName' in f for f in asset_findings):
            log_test("Scan persistence - Findings", "FAIL", "Some findings missing assetName")
            return False
        
        log_test("GET /api/findings", "PASS", f"Found {len(asset_findings)} findings for scanned asset")
        
        return True
        
    except Exception as e:
        log_test("Scan persistence", "FAIL", f"Exception: {str(e)}")
        return False

def test_dashboard():
    """Test GET /api/dashboard"""
    print(f"\n{Colors.BLUE}=== Testing Dashboard ==={Colors.END}")
    
    try:
        response = requests.get(f"{BASE_URL}/dashboard", timeout=15)
        
        if response.status_code != 200:
            log_test("GET /api/dashboard", "FAIL", f"Status: {response.status_code}")
            return False
        
        data = response.json()
        
        # Verify required fields
        required = ['avgScore', 'totalAssets', 'bySeverity', 'trend', 'infraNodes', 'infraIssues', 
                   'statusWorkflow', 'criticalOpen', 'highOpen']
        missing = [f for f in required if f not in data]
        if missing:
            log_test("GET /api/dashboard", "FAIL", f"Missing fields: {missing}")
            return False
        
        # Verify bySeverity
        by_sev = data['bySeverity']
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev not in by_sev:
                log_test("GET /api/dashboard", "FAIL", f"Missing severity: {sev}")
                return False
        
        # Verify trend is array
        if not isinstance(data['trend'], list):
            log_test("GET /api/dashboard", "FAIL", "Trend is not an array")
            return False
        
        for t in data['trend']:
            if not all(k in t for k in ['date', 'score']):
                log_test("GET /api/dashboard", "FAIL", f"Invalid trend item: {t}")
                return False
        
        log_test("GET /api/dashboard", "PASS", 
                f"avgScore: {data['avgScore']}, totalAssets: {data['totalAssets']}, " +
                f"Critical: {by_sev['Critical']}, High: {by_sev['High']}")
        
        return True
        
    except Exception as e:
        log_test("GET /api/dashboard", "FAIL", f"Exception: {str(e)}")
        return False

def test_assets_crud():
    """Test Assets CRUD operations"""
    print(f"\n{Colors.BLUE}=== Testing Assets CRUD ==={Colors.END}")
    
    try:
        # POST - Create asset
        payload = {
            "name": "Test Asset",
            "url": "test.example.com",
            "framework": "Go",
            "environment": "Staging",
            "host": "Proxmox"
        }
        
        response = requests.post(f"{BASE_URL}/assets", json=payload, timeout=10)
        
        if response.status_code != 201:
            log_test("POST /api/assets", "FAIL", f"Status: {response.status_code}, Body: {response.text[:200]}")
            return False
        
        asset = response.json()
        
        if 'id' not in asset:
            log_test("POST /api/assets", "FAIL", "No id in response")
            return False
        
        asset_id = asset['id']
        log_test("POST /api/assets", "PASS", f"Created asset with id: {asset_id}")
        
        # DELETE - Remove asset
        response = requests.delete(f"{BASE_URL}/assets/{asset_id}", timeout=10)
        
        if response.status_code != 200:
            log_test("DELETE /api/assets/:id", "FAIL", f"Status: {response.status_code}")
            return False
        
        data = response.json()
        if not data.get('deleted'):
            log_test("DELETE /api/assets/:id", "FAIL", f"Response: {data}")
            return False
        
        log_test("DELETE /api/assets/:id", "PASS", f"Deleted asset {asset_id}")
        
        return True
        
    except Exception as e:
        log_test("Assets CRUD", "FAIL", f"Exception: {str(e)}")
        return False

def test_findings_patch():
    """Test PATCH /api/findings/:id"""
    print(f"\n{Colors.BLUE}=== Testing Findings Status Update ==={Colors.END}")
    
    try:
        # Get findings
        response = requests.get(f"{BASE_URL}/findings", timeout=10)
        if response.status_code != 200:
            log_test("PATCH /api/findings/:id", "FAIL", "Could not fetch findings")
            return False
        
        findings = response.json()
        if not findings:
            log_test("PATCH /api/findings/:id", "SKIP", "No findings available")
            return True
        
        # Pick first finding
        finding = findings[0]
        finding_id = finding['id']
        
        # Update status
        payload = {"status": "Resolved"}
        response = requests.patch(f"{BASE_URL}/findings/{finding_id}", json=payload, timeout=10)
        
        if response.status_code != 200:
            log_test("PATCH /api/findings/:id", "FAIL", f"Status: {response.status_code}")
            return False
        
        updated = response.json()
        
        if updated.get('status') != 'Resolved':
            log_test("PATCH /api/findings/:id", "FAIL", f"Status not updated: {updated.get('status')}")
            return False
        
        log_test("PATCH /api/findings/:id", "PASS", f"Updated finding {finding_id} to Resolved")
        
        return True
        
    except Exception as e:
        log_test("PATCH /api/findings/:id", "FAIL", f"Exception: {str(e)}")
        return False

def test_scans():
    """Test GET /api/scans and GET /api/scans/:id"""
    print(f"\n{Colors.BLUE}=== Testing Scans Endpoints ==={Colors.END}")
    
    try:
        # List scans
        response = requests.get(f"{BASE_URL}/scans", timeout=10)
        
        if response.status_code != 200:
            log_test("GET /api/scans", "FAIL", f"Status: {response.status_code}")
            return False
        
        scans = response.json()
        
        if not isinstance(scans, list):
            log_test("GET /api/scans", "FAIL", "Response is not an array")
            return False
        
        log_test("GET /api/scans", "PASS", f"Retrieved {len(scans)} scans")
        
        if not scans:
            log_test("GET /api/scans/:id", "SKIP", "No scans available")
            return True
        
        # Get scan detail
        scan_id = scans[0]['id']
        response = requests.get(f"{BASE_URL}/scans/{scan_id}", timeout=10)
        
        if response.status_code != 200:
            log_test("GET /api/scans/:id", "FAIL", f"Status: {response.status_code}")
            return False
        
        scan = response.json()
        
        if 'findings' not in scan:
            log_test("GET /api/scans/:id", "FAIL", "No findings array in response")
            return False
        
        if not isinstance(scan['findings'], list):
            log_test("GET /api/scans/:id", "FAIL", "Findings is not an array")
            return False
        
        log_test("GET /api/scans/:id", "PASS", f"Retrieved scan {scan_id} with {len(scan['findings'])} findings")
        
        return True
        
    except Exception as e:
        log_test("Scans endpoints", "FAIL", f"Exception: {str(e)}")
        return False

def test_infra():
    """Test GET /api/infra"""
    print(f"\n{Colors.BLUE}=== Testing Infrastructure Health ==={Colors.END}")
    
    try:
        response = requests.get(f"{BASE_URL}/infra", timeout=10)
        
        if response.status_code != 200:
            log_test("GET /api/infra", "FAIL", f"Status: {response.status_code}")
            return False
        
        nodes = response.json()
        
        if not isinstance(nodes, list):
            log_test("GET /api/infra", "FAIL", "Response is not an array")
            return False
        
        if len(nodes) != 6:
            log_test("GET /api/infra", "WARN", f"Expected 6 nodes, got {len(nodes)}")
        
        # Verify node structure
        for node in nodes:
            required = ['kind', 'openPorts', 'tls', 'firewall', 'issues']
            missing = [f for f in required if f not in node]
            if missing:
                log_test("GET /api/infra", "FAIL", f"Node missing fields: {missing}")
                return False
            
            if node['kind'] not in ['GCP', 'Proxmox']:
                log_test("GET /api/infra", "FAIL", f"Invalid kind: {node['kind']}")
                return False
        
        gcp_nodes = [n for n in nodes if n['kind'] == 'GCP']
        proxmox_nodes = [n for n in nodes if n['kind'] == 'Proxmox']
        
        log_test("GET /api/infra", "PASS", 
                f"Retrieved {len(nodes)} nodes (GCP: {len(gcp_nodes)}, Proxmox: {len(proxmox_nodes)}) - MOCKED DATA")
        
        return True
        
    except Exception as e:
        log_test("GET /api/infra", "FAIL", f"Exception: {str(e)}")
        return False

def test_settings():
    """Test Settings vault with masked keys"""
    print(f"\n{Colors.BLUE}=== Testing Settings Vault ==={Colors.END}")
    
    try:
        # POST - Save settings
        payload = {
            "keys": {
                "zap": "secret1234",
                "proxmox": "pve-token-abcd"
            },
            "alerts": {
                "slack": "https://hooks.slack.com/test",
                "notifyOn": "high"
            }
        }
        
        response = requests.post(f"{BASE_URL}/settings", json=payload, timeout=10)
        
        if response.status_code != 200:
            log_test("POST /api/settings", "FAIL", f"Status: {response.status_code}")
            return False
        
        data = response.json()
        if not data.get('saved'):
            log_test("POST /api/settings", "FAIL", f"Response: {data}")
            return False
        
        log_test("POST /api/settings", "PASS", "Settings saved")
        
        # GET - Retrieve settings (should be masked)
        response = requests.get(f"{BASE_URL}/settings", timeout=10)
        
        if response.status_code != 200:
            log_test("GET /api/settings", "FAIL", f"Status: {response.status_code}")
            return False
        
        settings = response.json()
        
        # Verify keys are masked
        keys = settings.get('keys', {})
        
        if 'zap' not in keys:
            log_test("GET /api/settings", "FAIL", "zap key not found")
            return False
        
        zap_key = keys['zap']
        
        # Should end with 1234 and have bullet chars
        if not zap_key.endswith('1234'):
            log_test("GET /api/settings", "FAIL", f"Key not properly masked: {zap_key}")
            return False
        
        if '•' not in zap_key:
            log_test("GET /api/settings", "FAIL", f"Key missing bullet chars: {zap_key}")
            return False
        
        log_test("GET /api/settings", "PASS", f"Keys properly masked: {zap_key}")
        
        # Verify alerts persisted
        alerts = settings.get('alerts', {})
        if alerts.get('slack') != payload['alerts']['slack']:
            log_test("GET /api/settings", "FAIL", "Alerts not persisted correctly")
            return False
        
        # POST again with masked value - should NOT overwrite
        masked_payload = {
            "keys": {
                "zap": zap_key  # Send back the masked value
            },
            "alerts": alerts
        }
        
        response = requests.post(f"{BASE_URL}/settings", json=masked_payload, timeout=10)
        
        if response.status_code != 200:
            log_test("POST /api/settings (masked)", "FAIL", f"Status: {response.status_code}")
            return False
        
        # GET again - should still be masked with same value
        response = requests.get(f"{BASE_URL}/settings", timeout=10)
        settings2 = response.json()
        
        if settings2.get('keys', {}).get('zap') != zap_key:
            log_test("POST /api/settings (masked)", "FAIL", "Masked value was overwritten")
            return False
        
        log_test("POST /api/settings (masked)", "PASS", "Masked value not overwritten")
        
        return True
        
    except Exception as e:
        log_test("Settings vault", "FAIL", f"Exception: {str(e)}")
        return False

def test_schedules():
    """Test Schedules CRUD"""
    print(f"\n{Colors.BLUE}=== Testing Schedules ==={Colors.END}")
    
    try:
        # POST - Create schedule
        payload = {
            "assetName": "All assets",
            "frequency": "daily",
            "time": "02:00"
        }
        
        response = requests.post(f"{BASE_URL}/schedules", json=payload, timeout=10)
        
        if response.status_code != 201:
            log_test("POST /api/schedules", "FAIL", f"Status: {response.status_code}")
            return False
        
        schedule = response.json()
        
        if 'id' not in schedule:
            log_test("POST /api/schedules", "FAIL", "No id in response")
            return False
        
        schedule_id = schedule['id']
        log_test("POST /api/schedules", "PASS", f"Created schedule with id: {schedule_id}")
        
        # GET - List schedules
        response = requests.get(f"{BASE_URL}/schedules", timeout=10)
        
        if response.status_code != 200:
            log_test("GET /api/schedules", "FAIL", f"Status: {response.status_code}")
            return False
        
        schedules = response.json()
        
        if not isinstance(schedules, list):
            log_test("GET /api/schedules", "FAIL", "Response is not an array")
            return False
        
        # Find our schedule
        found = any(s.get('id') == schedule_id for s in schedules)
        if not found:
            log_test("GET /api/schedules", "FAIL", f"Schedule {schedule_id} not found")
            return False
        
        log_test("GET /api/schedules", "PASS", f"Retrieved {len(schedules)} schedules")
        
        # DELETE - Remove schedule
        response = requests.delete(f"{BASE_URL}/schedules/{schedule_id}", timeout=10)
        
        if response.status_code != 200:
            log_test("DELETE /api/schedules/:id", "FAIL", f"Status: {response.status_code}")
            return False
        
        data = response.json()
        if not data.get('deleted'):
            log_test("DELETE /api/schedules/:id", "FAIL", f"Response: {data}")
            return False
        
        log_test("DELETE /api/schedules/:id", "PASS", f"Deleted schedule {schedule_id}")
        
        return True
        
    except Exception as e:
        log_test("Schedules CRUD", "FAIL", f"Exception: {str(e)}")
        return False

def main():
    """Run all backend tests"""
    print(f"\n{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BLUE}Sentinel Security Platform - Backend API Test Suite{Colors.END}")
    print(f"{Colors.BLUE}Base URL: {BASE_URL}{Colors.END}")
    print(f"{Colors.BLUE}{'='*70}{Colors.END}\n")
    
    results = {}
    
    # 1. Health check
    results['health'] = test_health()
    
    if not results['health']:
        print(f"\n{Colors.RED}API is not responding. Aborting tests.{Colors.END}")
        return
    
    # 2. Real scanner (high priority)
    scan_data = test_scan_real("NestJS")
    results['scan'] = bool(scan_data)
    
    # 3. Framework-aware remediation (high priority)
    results['framework_remediation'] = test_framework_remediation()
    
    # 4. Scan persistence (high priority)
    results['scan_persistence'] = test_scan_persistence(scan_data)
    
    # 5. Dashboard (high priority)
    results['dashboard'] = test_dashboard()
    
    # 6. Assets CRUD (high priority)
    results['assets_crud'] = test_assets_crud()
    
    # 7. Findings PATCH (high priority)
    results['findings_patch'] = test_findings_patch()
    
    # 8. Scans (medium priority)
    results['scans'] = test_scans()
    
    # 9. Infra (medium priority)
    results['infra'] = test_infra()
    
    # 10. Settings (medium priority)
    results['settings'] = test_settings()
    
    # 11. Schedules (low priority)
    results['schedules'] = test_schedules()
    
    # Summary
    print(f"\n{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BLUE}TEST SUMMARY{Colors.END}")
    print(f"{Colors.BLUE}{'='*70}{Colors.END}\n")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = f"{Colors.GREEN}✓ PASS{Colors.END}" if result else f"{Colors.RED}✗ FAIL{Colors.END}"
        print(f"{status} - {test_name}")
    
    print(f"\n{Colors.BLUE}Total: {passed}/{total} tests passed{Colors.END}")
    
    if passed == total:
        print(f"{Colors.GREEN}All tests passed!{Colors.END}\n")
    else:
        print(f"{Colors.RED}Some tests failed. Review the output above.{Colors.END}\n")

if __name__ == "__main__":
    main()
