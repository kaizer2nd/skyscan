"""
Test Script for Vulnerability Scanner
This demonstrates how each component works
"""
import asyncio
import json
from app.scan.network_scanner import NetworkScanner
from app.scan.fingerprint import FingerprintService
from app.scan.match_engine import CVEMatcher
from app.scan.cvss_engine import CVSSEngine

async def test_scanner():
    print("=" * 60)
    print("VULNERABILITY SCANNER TEST")
    print("=" * 60)
    
    # Target to scan (localhost)
    target = "127.0.0.1"
    print(f"\n🎯 Target: {target}")
    print("-" * 60)
    
    # Step 1: Network Scanning
    print("\n📡 STEP 1: NETWORK SCANNING (Using Nmap)")
    print("-" * 60)
    scanner = NetworkScanner()
    scan_results = await scanner.scan_network(target)
    
    print(f"✓ Scan completed!")
    print(f"  - Hosts scanned: {len(scan_results.get('hosts', []))}")
    
    for host in scan_results.get('hosts', []):
        print(f"\n  Host: {host['ip']}")
        print(f"  Status: {host['status']}")
        print(f"  Open Ports: {len(host.get('ports', []))}")
        
        for port in host.get('ports', [])[:3]:  # Show first 3 ports
            print(f"    - Port {port['port']}: {port['service']} (State: {port['state']})")
            if port.get('version'):
                print(f"      Version: {port['version']}")
    
    # Step 2: Service Fingerprinting
    print("\n\n🔍 STEP 2: SERVICE FINGERPRINTING")
    print("-" * 60)
    fingerprint_service = FingerprintService()
    
    services_found = []
    for host in scan_results.get('hosts', []):
        for port in host.get('ports', []):
            service_name = port.get('service', 'unknown')
            version = port.get('version', '')
            
            if service_name != 'unknown':
                fingerprint = fingerprint_service.fingerprint_service(
                    service_name, 
                    version
                )
                services_found.append(fingerprint)
                print(f"  ✓ Detected: {fingerprint['service']} {fingerprint['version']}")
    
    # Step 3: CVE Matching
    print("\n\n🐛 STEP 3: CVE MATCHING (Checking vulnerability database)")
    print("-" * 60)
    cve_matcher = CVEMatcher()
    
    vulnerabilities = []
    for service in services_found:
        matches = cve_matcher.find_vulnerabilities(
            service['service'],
            service['version']
        )
        vulnerabilities.extend(matches)
        
        if matches:
            print(f"\n  ⚠️  {service['service']} {service['version']}:")
            for vuln in matches[:2]:  # Show first 2 vulnerabilities
                print(f"    - {vuln['cve_id']}: {vuln['description'][:80]}...")
    
    if not vulnerabilities:
        print("  ✓ No known vulnerabilities found in database")
    
    # Step 4: CVSS Scoring
    print("\n\n📊 STEP 4: CVSS RISK SCORING")
    print("-" * 60)
    cvss_engine = CVSSEngine()
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for vuln in vulnerabilities:
        score_data = cvss_engine.calculate_score(vuln)
        severity_counts[score_data['severity']] += 1
    
    print(f"  Critical: {severity_counts['critical']}")
    print(f"  High:     {severity_counts['high']}")
    print(f"  Medium:   {severity_counts['medium']}")
    print(f"  Low:      {severity_counts['low']}")
    
    # Summary
    print("\n\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"  Hosts Scanned:        {len(scan_results.get('hosts', []))}")
    print(f"  Services Detected:    {len(services_found)}")
    print(f"  Vulnerabilities:      {len(vulnerabilities)}")
    print(f"  Highest Severity:     {max(severity_counts.items(), key=lambda x: x[1])[0].upper() if vulnerabilities else 'NONE'}")
    print("=" * 60)
    
    return {
        'scan_results': scan_results,
        'services': services_found,
        'vulnerabilities': vulnerabilities,
        'severity_counts': severity_counts
    }

if __name__ == "__main__":
    print("\n🚀 Starting Vulnerability Scanner Test...\n")
    try:
        results = asyncio.run(test_scanner())
        print("\n✅ Test completed successfully!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
