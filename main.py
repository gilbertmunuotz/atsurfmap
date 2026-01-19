from utils.http_client import HttpClient
from core.robots import RobotsAnalyzer
from core.headers import HeaderAnalyzer
from core.auth_endpoints import AuthEndpointScanner
from core.directory_scanner import DirectoryScanner
from core.port_scanner import PortScanner
from core.risk_analyzer import RiskAnalyzer
from core.report import ReportGenerator


def main():
    findings = {}

    print("Web Application Attack Surface Mapping Tool")
    target = input("Enter the target URL (e.g. https://example.com): ").strip()

    client = HttpClient()

    print("[*] Connecting to target...")
    response = client.get(target)
    print("[*] Connection attempt completed")

    if response is None:
        print("[-] Failed to reach target")
        return

    print(f"[+] Target reachable: {target}")
    print(f"[+] HTTP Status: {response.status_code}")

    # robots.txt
    print("\n[+] Checking robots.txt...")
    robots = RobotsAnalyzer(target)
    content = robots.fetch()

    if not content:
        print("[-] robots.txt not found")
    else:
        paths = robots.parse(content)
        if paths:
            print("[!] Disallowed paths discovered:")
            for p in paths:
                print(f"    - {p}")
        else:
            print("[+] No disallowed paths found")

    # Headers
    print("\n[+] Analyzing HTTP headers and cookies...")
    header_analyzer = HeaderAnalyzer(response)

    header_results = header_analyzer.analyze_headers()
    cookie_results = header_analyzer.analyze_cookies()

    print("\n[+] Header Findings:")
    for key, value in header_results.items():
        print(f"  {key}: {value}")

    if cookie_results:
        print("\n[+] Cookies Detected:")
        for c in cookie_results:
            print(f"  - {c}")
    else:
        print("\n[+] No cookies detected")

    findings["missing_headers"] = [k for k, v in header_results["Security Headers"].items() if v == "Missing"]

    # Auth endpoints
    print("\n[+] Scanning for login and admin endpoints...")
    auth_scanner = AuthEndpointScanner(target)
    auth_results = auth_scanner.scan()

    if auth_results:
        print("[!] Authentication-related endpoints discovered:")
        for item in auth_results:
            print(f"  - {item['endpoint']} (HTTP {item['status']})")
    else:
        print("[+] No common login/admin endpoints discovered")

    findings["auth_endpoints"] = auth_results

    # Directories
    print("\n[+] Scanning for common directories and sensitive paths...")
    dir_scanner = DirectoryScanner(target)
    dir_results = dir_scanner.scan()

    if dir_results:
        print("[!] Potentially exposed directories discovered:")
        for item in dir_results:
            print(f"  - {item['path']} (HTTP {item['status']})")
    else:
        print("[+] No common directories exposed")

    findings["directories"] = dir_results

    # Ports
    print("\n[+] Scanning for open ports and exposed services...")
    port_scanner = PortScanner(target)
    ports = port_scanner.scan()

    if ports:
        print("[!] Open ports discovered:")
        for p in ports:
            print(f"  - Port {p['port']} ({p['service']})")
    else:
        print("[+] No common open ports detected")

    findings["open_ports"] = ports

    # Risk analysis
    print("\n[+] Performing risk analysis...")
    analyzer = RiskAnalyzer()
    risks = analyzer.analyze(findings)

    if risks:
        print("[!] Risk Summary:")
        for r in risks:
            print(f"  - [{r['risk']}] {r['issue']}")
            print(f"      Impact: {r['impact']}")
    else:
        print("[+] No significant risks identified")

    # Report
    report = ReportGenerator(target)
    final_report = report.generate(findings, risks)
    report.save(final_report)

    print("\n[+] Report saved in reporting/attack_surface_report.json")


if __name__ == "__main__":
    main()